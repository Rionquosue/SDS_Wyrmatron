//! Media endpoints (SDS §8): JSON URL jobs, streamed multipart uploads, and
//! owner-only status, download and cancellation.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Multipart, Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;
use tower::ServiceExt;

use super::auth::{Consumer, sha256};
use super::notifications::idempotency_key;
use super::{ApiError, ApiJson, AppState};
use crate::config::Scope;
use crate::media::jobs::{self, Created, JobRow, JobView, NewJob, SourceKind};
use crate::media::service::MediaService;
use crate::media::spec::{Action, CompressPreset, JobOptions};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSpec {
    pub url: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaJobRequest {
    pub source: SourceSpec,
    pub action: Action,
    #[serde(default)]
    pub preset: Option<String>,
    #[serde(default)]
    pub destination: Option<String>,
    #[serde(default)]
    pub options: JobOptions,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadRequest {
    pub action: Action,
    pub size_bytes: u64,
    #[serde(default)]
    pub preset: Option<String>,
    #[serde(default)]
    pub destination: Option<String>,
    #[serde(default)]
    pub options: JobOptions,
    #[serde(default)]
    pub file_name: Option<String>,
}

fn media(state: &AppState) -> Result<Arc<MediaService>, ApiError> {
    state
        .media
        .clone()
        .ok_or_else(|| ApiError::unavailable("media_unavailable", 60))
}

/// Maps the SDS preset names onto the action's options.
fn apply_preset(
    action: Action,
    preset: Option<&str>,
    options: &mut JobOptions,
) -> Result<(), ApiError> {
    let Some(p) = preset else { return Ok(()) };
    let ok = match action {
        Action::Compress => match p.parse::<CompressPreset>() {
            Ok(cp) => {
                options.preset = Some(cp);
                true
            }
            Err(()) => false,
        },
        Action::Gif => p == "telegram-gif",
        Action::Mp4 => p == "mp4",
        Action::Mute => p == "mute",
        Action::Fetch => false,
    };
    if ok {
        Ok(())
    } else {
        Err(ApiError::invalid(
            "preset",
            "That preset does not apply to this action.",
        ))
    }
}

struct Target {
    destination: Option<String>,
    chat_id: Option<i64>,
    thread_id: Option<i64>,
}

fn check_request(
    state: &AppState,
    svc: &MediaService,
    consumer: &Consumer,
    action: Action,
    preset: Option<&str>,
    destination: Option<&str>,
    options: &mut JobOptions,
) -> Result<Target, ApiError> {
    consumer.require(Scope::Media)?;
    apply_preset(action, preset, options)?;
    options
        .validate(action, state.config.media.gif_max_seconds)
        .map_err(|m| ApiError::invalid("options", &m))?;
    if let Some(why) = svc.unavailable_reason(action) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "action_unavailable",
            format!("{action} is unavailable: {why}."),
        )
        .with_field("action"));
    }
    match destination {
        None => Ok(Target {
            destination: None,
            chat_id: None,
            thread_id: None,
        }),
        Some(d) => {
            consumer.require_destination(d)?;
            let dest = state
                .config
                .destinations
                .get(d)
                .ok_or_else(|| ApiError::invalid("destination", "Unknown destination."))?;
            Ok(Target {
                destination: Some(d.to_owned()),
                chat_id: Some(dest.chat_id),
                thread_id: dest.thread_id,
            })
        }
    }
}

fn accepted(state: &AppState, created: Created) -> Result<Response, ApiError> {
    let _ = state;
    let (status, id) = match created {
        Created::New(id) => (StatusCode::ACCEPTED, id),
        Created::Existing(id) => (StatusCode::OK, id),
        Created::Limited(n) => {
            let mut e = ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "consumer_limit",
                format!("This key already has {n} unfinished jobs."),
            );
            e.retry_after = Some(30);
            return Err(e);
        }
        Created::Conflict => {
            return Err(ApiError::conflict(
                "idempotency_conflict",
                "This Idempotency-Key was used with a different request.",
            ));
        }
    };
    let location = format!("/v1/jobs/{id}");
    let mut res = (
        status,
        Json(json!({ "job_id": id, "status_url": location, "state": "queued" })),
    )
        .into_response();
    if let Ok(v) = HeaderValue::from_str(&location) {
        res.headers_mut().insert(header::LOCATION, v);
    }
    Ok(res)
}

pub async fn create_job(
    State(state): State<AppState>,
    Extension(consumer): Extension<Arc<Consumer>>,
    headers: HeaderMap,
    ApiJson(mut req): ApiJson<MediaJobRequest>,
) -> Result<Response, ApiError> {
    let svc = media(&state)?;
    let key = idempotency_key(&headers)?.ok_or_else(|| {
        ApiError::invalid("Idempotency-Key", "An Idempotency-Key header is required.")
    })?;
    let url = url::Url::parse(&req.source.url)
        .map_err(|_| ApiError::invalid("source.url", "source.url must be an absolute URL."))?;
    if url.scheme() != "https" {
        return Err(ApiError::invalid(
            "source.url",
            "source.url must use HTTPS.",
        ));
    }
    let request_hash = hex::encode(sha256(
        &serde_json::to_vec(&req).map_err(anyhow::Error::from)?,
    ));
    let target = check_request(
        &state,
        &svc,
        &consumer,
        req.action,
        req.preset.as_deref(),
        req.destination.as_deref(),
        &mut req.options,
    )?;
    let created = svc
        .create(NewJob {
            owner_kind: "api",
            owner_id: consumer.id.clone(),
            idempotency_key: Some(key),
            request_hash: Some(request_hash),
            action: req.action,
            options: req.options,
            source_kind: SourceKind::Url,
            source_ref: url.to_string(),
            source_path: None,
            input_bytes: None,
            destination: target.destination,
            chat_id: target.chat_id,
            thread_id: target.thread_id,
            reply_to: None,
            status_message: None,
        })
        .await?;
    accepted(&state, created)
}

fn malformed(msg: &str) -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, "malformed_request", msg)
}

pub async fn upload(
    State(state): State<AppState>,
    Extension(consumer): Extension<Arc<Consumer>>,
    headers: HeaderMap,
    mut form: Multipart,
) -> Result<Response, ApiError> {
    let svc = media(&state)?;
    let key = idempotency_key(&headers)?.ok_or_else(|| {
        ApiError::invalid("Idempotency-Key", "An Idempotency-Key header is required.")
    })?;
    // Part 1: the JSON request, read before any file bytes.
    let first = form
        .next_field()
        .await
        .map_err(|_| malformed("Malformed multipart body."))?
        .ok_or_else(|| malformed("Missing request part."))?;
    if first.name() != Some("request") {
        return Err(malformed("The first part must be named request.").with_field("request"));
    }
    let raw = first
        .bytes()
        .await
        .map_err(|_| malformed("Unreadable request part."))?;
    if raw.len() > 16 * 1024 {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "body_too_large",
            "The request part is too large.",
        ));
    }
    let mut req: UploadRequest = serde_json::from_slice(&raw).map_err(|e| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_parameter",
            e.to_string(),
        )
    })?;
    let max = state.config.media.max_source_bytes;
    if req.size_bytes == 0 || req.size_bytes > max {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "upload_too_large",
            format!("Uploads are limited to {max} bytes."),
        )
        .with_field("size_bytes"));
    }
    let request_hash = hex::encode(sha256(&raw));
    let target = check_request(
        &state,
        &svc,
        &consumer,
        req.action,
        req.preset.as_deref(),
        req.destination.as_deref(),
        &mut req.options,
    )?;
    // Reserve work space before reading the file (SDS §2).
    let reserved = jobs::reserved_bytes(&state.db).await?;
    if reserved + (req.size_bytes as i64) * 3 > state.config.storage.work_budget_bytes as i64 {
        return Err(ApiError::unavailable("storage_busy", 30));
    }
    // Part 2: the file, streamed to disk with the declared size enforced.
    let mut file_part = form
        .next_field()
        .await
        .map_err(|_| malformed("Malformed multipart body."))?
        .ok_or_else(|| malformed("Missing file part."))?;
    if file_part.name() != Some("file") {
        return Err(malformed("The second part must be named file.").with_field("file"));
    }
    let id = jobs::new_id();
    let dir = svc.job_dir(&id);
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(anyhow::Error::from)?;
    let path = dir.join("source");
    let mut out = tokio::fs::File::create(&path)
        .await
        .map_err(anyhow::Error::from)?;
    let mut received = 0u64;
    let cleanup = |dir: std::path::PathBuf| async move {
        let _ = tokio::fs::remove_dir_all(dir).await;
    };
    loop {
        let chunk = match file_part.chunk().await {
            Ok(Some(c)) => c,
            Ok(None) => break,
            Err(_) => {
                cleanup(dir).await;
                return Err(malformed("The upload was interrupted."));
            }
        };
        received += chunk.len() as u64;
        if received > req.size_bytes {
            cleanup(dir).await;
            return Err(ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "upload_too_large",
                "The file is larger than size_bytes.",
            ));
        }
        out.write_all(&chunk).await.map_err(anyhow::Error::from)?;
    }
    if received != req.size_bytes {
        cleanup(dir).await;
        return Err(malformed("The file is shorter than size_bytes.").with_field("size_bytes"));
    }
    out.sync_all().await.map_err(anyhow::Error::from)?;
    if form.next_field().await.ok().flatten().is_some() {
        cleanup(dir).await;
        return Err(malformed("Unexpected extra parts."));
    }
    let created = svc
        .create(NewJob {
            owner_kind: "api",
            owner_id: consumer.id.clone(),
            idempotency_key: Some(key),
            request_hash: Some(request_hash),
            action: req.action,
            options: req.options,
            source_kind: SourceKind::Upload,
            source_ref: req.file_name.unwrap_or_else(|| "upload".into()),
            source_path: Some(path.to_string_lossy().into_owned()),
            input_bytes: Some(received as i64),
            destination: target.destination,
            chat_id: target.chat_id,
            thread_id: target.thread_id,
            reply_to: None,
            status_message: None,
        })
        .await;
    match created {
        Ok(c @ Created::New(_)) => accepted(&state, c),
        Ok(other) => {
            // A replay: the original job keeps its own copy.
            cleanup(dir).await;
            accepted(&state, other)
        }
        Err(e) => {
            cleanup(dir).await;
            Err(e.into())
        }
    }
}

async fn owned(state: &AppState, consumer: &Consumer, id: &str) -> Result<JobRow, ApiError> {
    if id.len() > 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError::not_found());
    }
    let job = jobs::get(&state.db, id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    // Another consumer's job looks exactly like a missing one.
    if job.owned_by("api", &consumer.id) {
        Ok(job)
    } else {
        Err(ApiError::not_found())
    }
}

pub async fn status(
    State(state): State<AppState>,
    Extension(consumer): Extension<Arc<Consumer>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    consumer.require(Scope::Media)?;
    let job = owned(&state, &consumer, &id).await?;
    Ok(Json(
        serde_json::to_value(JobView::from(&job)).map_err(anyhow::Error::from)?,
    ))
}

pub async fn download(
    State(state): State<AppState>,
    Extension(consumer): Extension<Arc<Consumer>>,
    Path(id): Path<String>,
    req: Request,
) -> Result<Response, ApiError> {
    consumer.require(Scope::Media)?;
    let job = owned(&state, &consumer, &id).await?;
    let path = match (&job.state[..], &job.result_path, job.expires_at) {
        ("completed", Some(p), Some(exp)) if exp > crate::db::now() => p.clone(),
        ("completed", _, _) => {
            return Err(ApiError::new(
                StatusCode::GONE,
                "result_expired",
                "The result is no longer available.",
            ));
        }
        _ => {
            return Err(ApiError::conflict(
                "result_not_ready",
                "The job has no result yet.",
            ));
        }
    };
    let ext = std::path::Path::new(&path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("mp4")
        .to_owned();
    let mut res = tower_http::services::ServeFile::new(&path)
        .oneshot(req)
        .await
        .map_err(|e| ApiError::internal(anyhow::anyhow!(e)))?
        .map(Body::new);
    let disposition = format!("attachment; filename=\"{}-{}.{ext}\"", job.action, job.id);
    if let Ok(v) = HeaderValue::from_str(&disposition) {
        res.headers_mut().insert(header::CONTENT_DISPOSITION, v);
    }
    if let Some(ct) = job
        .result_type
        .as_deref()
        .and_then(|t| HeaderValue::from_str(t).ok())
    {
        res.headers_mut().insert(header::CONTENT_TYPE, ct);
    }
    Ok(res)
}

pub async fn delete(
    State(state): State<AppState>,
    Extension(consumer): Extension<Arc<Consumer>>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    consumer.require(Scope::Media)?;
    let svc = media(&state)?;
    let job = owned(&state, &consumer, &id).await?;
    if job.is_active() {
        svc.cancel(&job).await?;
        let job = jobs::get(&state.db, &id)
            .await?
            .ok_or_else(ApiError::not_found)?;
        return Ok((
            StatusCode::ACCEPTED,
            Json(serde_json::to_value(JobView::from(&job)).map_err(anyhow::Error::from)?),
        )
            .into_response());
    }
    let jid = job.id.clone();
    state
        .db
        .write(move |tx| {
            Ok(tx.execute(
                "UPDATE jobs SET result_path = NULL, expires_at = NULL WHERE id = ?1",
                [jid],
            )?)
        })
        .await?;
    let _ = tokio::fs::remove_dir_all(svc.job_dir(&job.id)).await;
    Ok(StatusCode::NO_CONTENT.into_response())
}
