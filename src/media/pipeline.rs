//! The media worker: claims jobs and runs them through resolve → download →
//! metadata → encode → thumbnail → deliver (SDS §6, §7, §10).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use rusqlite::{OptionalExtension, params};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use url::Url;

use super::jobs::{self, Finished, JobRow, SourceKind};
use super::plan::{Delivery, Rung, plan};
use super::service::{MediaService, human_bytes};
use super::spec::Action;
use crate::db::now;
use crate::extract::{choose_candidate, parse_link, select};
use crate::fetch::HostPolicy;
use crate::ffmpeg::types::{MediaInfo, Operation, thumbnail_box};
use crate::ffmpeg::{Attempt, FfError, Input};
use crate::telegram::client::{MediaKind, MediaUpload, TgError};
use crate::telegram::handler::TelegramSource;
use crate::text::escape;

const LEASE_SECS: i64 = 300;

/// Claims of one job before a temporary failure becomes permanent.
const MAX_ATTEMPTS: i64 = 6;

/// A failure reported to the job owner.
#[derive(Debug)]
pub struct JobFailure {
    pub code: String,
    pub message: String,
    /// Temporary condition: requeue after this many seconds.
    pub retry_in: Option<i64>,
}

impl JobFailure {
    fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            retry_in: None,
        }
    }
}

impl From<std::io::Error> for JobFailure {
    fn from(e: std::io::Error) -> Self {
        error!(error = %e, "local file error");
        Self::new("io_error", "A local storage error occurred.")
    }
}

impl From<anyhow::Error> for JobFailure {
    fn from(e: anyhow::Error) -> Self {
        error!(error = %e, "internal error");
        Self::new("internal_error", "An internal error occurred.")
    }
}

fn from_ff(e: FfError) -> JobFailure {
    let message = match &e {
        FfError::Failed { code, .. } | FfError::Rejected { code, .. } => match code.as_str() {
            "invalid_media" | "unsupported_media" => {
                "That file could not be read, or its format is not supported.".to_owned()
            }
            "duration_exceeded" => {
                "That video is longer than the encoder allows. Try clipping it.".to_owned()
            }
            "dimensions_exceeded" => {
                "That video's resolution is too large for the encoder.".to_owned()
            }
            "range_out_of_bounds" => "The clip extends past the end of the video.".to_owned(),
            "output_too_large" => "The result was too large. Try a smaller preset.".to_owned(),
            "upload_too_large" => "That file is larger than the encoder accepts.".to_owned(),
            "cancelled" => "The encoder stopped the job; try again.".to_owned(),
            _ => "The media service failed. Try again later.".to_owned(),
        },
        FfError::Unavailable(m) => format!("Media processing is unavailable: {m}."),
        FfError::Cancelled => "Cancelled.".to_owned(),
        FfError::Timeout => "The media service took too long. Try a shorter clip.".to_owned(),
        _ => "The media service failed. Try again later.".to_owned(),
    };
    JobFailure::new(e.code(), message)
}

/// Runs workers until shutdown.
pub async fn run_worker(svc: Arc<MediaService>, name: String, shutdown: CancellationToken) {
    loop {
        if shutdown.is_cancelled() {
            return;
        }
        match jobs::claim(&svc.db, &name, LEASE_SECS).await {
            Ok(Some(job)) => {
                let id = job.id.clone();
                let token = shutdown.child_token();
                svc.running
                    .lock()
                    .expect("running lock")
                    .insert(id.clone(), token.clone());
                let (s, t) = (svc.clone(), token.clone());
                // A separate task, so a panic fails only this job.
                let outcome = tokio::spawn(async move { process(&s, job, &t).await }).await;
                svc.running.lock().expect("running lock").remove(&id);
                if let Err(e) = outcome {
                    error!(job = %id, error = %e, "media job panicked");
                    let _ = jobs::fail(
                        &svc.db,
                        &id,
                        "internal_error",
                        "An internal error occurred.",
                    )
                    .await;
                }
                continue;
            }
            Ok(None) => {}
            Err(e) => warn!(error = %e, "claiming a media job failed"),
        }
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = svc.wake.notified() => {}
            _ = tokio::time::sleep(Duration::from_secs(15)) => {}
        }
    }
}

async fn process(svc: &MediaService, job: JobRow, cancel: &CancellationToken) {
    // Lease heartbeat; also turns a cancel request into a cancelled token.
    let heartbeat = {
        let (db, id, cancel) = (svc.db.clone(), job.id.clone(), cancel.clone());
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                if let Ok(true) = jobs::renew_lease(&db, &id, LEASE_SECS).await {
                    cancel.cancel();
                }
            }
        })
    };
    let result = if job.cancel_requested {
        Err(JobFailure::new("cancelled", "Cancelled."))
    } else {
        run(svc, &job, cancel).await
    };
    heartbeat.abort();
    match result {
        Ok(()) => info!(job = %job.id, action = %job.action, "media job completed"),
        Err(f) if cancel.is_cancelled() || f.code == "cancelled" => {
            let _ = svc
                .db
                .write({
                    let id = job.id.clone();
                    move |tx| {
                        let t = now();
                        Ok(tx.execute(
                            "UPDATE jobs SET state = 'cancelled', lease_owner = NULL, lease_until = NULL, completed_at = ?2, updated_at = ?2 WHERE id = ?1",
                            params![id, t],
                        )?)
                    }
                })
                .await;
            let _ = tokio::fs::remove_dir_all(svc.job_dir(&job.id)).await;
            status(svc, &job, "🚫 Cancelled.").await;
        }
        // Temporary conditions are retried, but never indefinitely.
        Err(JobFailure {
            retry_in: Some(secs),
            message,
            ..
        }) if job.attempts < MAX_ATTEMPTS => {
            let _ = jobs::defer(&svc.db, &job.id, secs, &message).await;
        }
        Err(mut f) => {
            if f.retry_in.is_some() {
                f.message = format!("{} Gave up after {MAX_ATTEMPTS} attempts.", f.message);
            }
            warn!(job = %job.id, code = %f.code, "media job failed");
            let _ = jobs::fail(&svc.db, &job.id, &f.code, &f.message).await;
            let _ = tokio::fs::remove_dir_all(svc.job_dir(&job.id)).await;
            status(svc, &job, &format!("⚠️ {}", escape(&f.message))).await;
        }
    }
}

/// Best-effort progress edit of the Telegram status message.
async fn status(svc: &MediaService, job: &JobRow, html: &str) {
    if let (Some(bot), Some(chat), Some(msg)) = (&svc.bot, job.chat_id, job.status_message) {
        let text = format!(
            "{html}\n<i>{} · job <code>{}</code></i>",
            job.action.label(),
            job.id
        );
        if let Err(e) = bot.edit_message(chat, msg, &text, None).await {
            warn!(job = %job.id, error = %e, "status update failed");
        }
    }
}

async fn stage(
    svc: &MediaService,
    job: &JobRow,
    state: &'static str,
    html: &str,
    cancel: &CancellationToken,
) -> Result<(), JobFailure> {
    if cancel.is_cancelled() {
        return Err(JobFailure::new("cancelled", "Cancelled."));
    }
    jobs::set_state(&svc.db, &job.id, state, None).await?;
    status(svc, job, html).await;
    Ok(())
}

struct Source {
    input: Input,
    attribution: Option<(Option<String>, String)>,
}

async fn run(
    svc: &MediaService,
    job: &JobRow,
    cancel: &CancellationToken,
) -> Result<(), JobFailure> {
    let dir = svc.job_dir(&job.id);
    tokio::fs::create_dir_all(&dir).await?;
    let source = obtain_source(svc, job, &dir, cancel).await?;
    jobs::set_source(
        &svc.db,
        &job.id,
        &source.input.path.to_string_lossy(),
        source.input.size as i64,
    )
    .await?;

    let need_ffmpeg = job.action != Action::Fetch;
    let client = svc.ffmpeg.clone();
    if need_ffmpeg && let Some(why) = svc.unavailable_reason(job.action) {
        return Err(JobFailure::new(
            "media_unavailable",
            format!("/{} is unavailable: {why}.", job.action),
        ));
    }
    stage(svc, job, "processing", "⚙️ Processing…", cancel).await?;
    // Metadata is required for processing and optional for fetch.
    let info = match &client {
        Some(c) if need_ffmpeg || c.capabilities().is_some() => {
            match metadata(svc, job, &source.input, cancel).await {
                Ok(i) => Some(i),
                Err(e) if need_ffmpeg => return Err(e),
                Err(e) => {
                    warn!(job = %job.id, error = %e.message, "metadata unavailable for fetch");
                    None
                }
            }
        }
        _ => None,
    };
    if let (Some(info), Some(max)) = (
        &info,
        client
            .as_ref()
            .and_then(|c| c.capabilities())
            .and_then(|c| c.limit("max_duration_seconds")),
    ) && need_ffmpeg
        && info.duration_seconds > max as f64
        && !job.options.is_clip()
    {
        return Err(JobFailure::new(
            "duration_exceeded",
            format!("That video is over {max} seconds. Add start= and duration= to clip it."),
        ));
    }

    let (result_path, delivery, dims, duration) = if job.action == Action::Fetch {
        let mp4 = info
            .as_ref()
            .is_some_and(|i| i.format.contains("mp4") && i.video_codec.as_deref() == Some("h264"));
        let delivery = if mp4 {
            Delivery::Video
        } else {
            Delivery::Document
        };
        let dims = info
            .as_ref()
            .map(|i| (i.width, i.height))
            .unwrap_or_default();
        (
            source.input.path.clone(),
            delivery,
            dims,
            info.as_ref().map(|i| i.duration_seconds),
        )
    } else {
        let info = info.expect("metadata is required for processing");
        let gif_seconds = if job.options.is_clip() {
            job.options
                .duration_seconds
                .unwrap_or(info.duration_seconds - job.options.start_seconds.unwrap_or(0.0))
        } else {
            info.duration_seconds
        };
        if job.action == Action::Gif && gif_seconds > svc.config.media.gif_max_seconds {
            return Err(JobFailure::new(
                "gif_too_long",
                format!(
                    "That video is {gif_seconds:.0} s; GIFs are limited to {:.0} s. Add start= and duration= to choose a part.",
                    svc.config.media.gif_max_seconds
                ),
            ));
        }
        let caps = client
            .as_ref()
            .and_then(|c| c.capabilities())
            .ok_or_else(|| {
                JobFailure::new("media_unavailable", "Media processing is unavailable.")
            })?;
        let rungs = plan(
            job.action,
            &job.options,
            &info,
            &caps,
            svc.config.media.gif_target_bytes,
        )
        .map_err(|m| JobFailure::new("unsupported_request", m))?;
        let (path, rung) = encode(svc, job, &source.input, &rungs, &info, cancel).await?;
        let seconds = if job.options.is_clip() {
            Some(gif_seconds)
        } else {
            Some(info.duration_seconds)
        };
        (path, rung.delivery, rung.dims, seconds)
    };

    let result = Input::from_file(&result_path).await?;
    deliver(svc, job, &source, &result, delivery, dims, duration, cancel).await
}

async fn obtain_source(
    svc: &MediaService,
    job: &JobRow,
    dir: &Path,
    cancel: &CancellationToken,
) -> Result<Source, JobFailure> {
    // A retained source from an earlier attempt is reused.
    if let Some(p) = job
        .source_path
        .as_deref()
        .map(PathBuf::from)
        .filter(|p| p.exists())
    {
        let attribution = if job.source_kind == SourceKind::Url {
            Some((None, job.source_ref.clone()))
        } else {
            None
        };
        return Ok(Source {
            input: Input::from_file(&p).await?,
            attribution,
        });
    }
    if job.source_kind == SourceKind::Upload {
        return Err(JobFailure::new(
            "source_missing",
            "The uploaded file is no longer available.",
        ));
    }
    // Work-storage budget (SDS §2): defer rather than overcommit.
    let budget = svc.config.storage.work_budget_bytes as i64;
    let needed = (svc.config.media.max_source_bytes as i64) * 2;
    if jobs::reserved_bytes(&svc.db).await? + needed > budget {
        return Err(JobFailure {
            retry_in: Some(30),
            ..JobFailure::new("storage_busy", "Waiting for work space…")
        });
    }
    stage(svc, job, "downloading", "⬇️ Downloading…", cancel).await?;
    let dest = dir.join("source");
    match job.source_kind {
        SourceKind::TelegramFile => {
            let bot = svc.bot.as_ref().ok_or_else(|| {
                JobFailure::new("telegram_unavailable", "Telegram is not configured.")
            })?;
            let src: TelegramSource =
                serde_json::from_str(&job.source_ref).map_err(anyhow::Error::from)?;
            let TelegramSource::File { file_id, .. } = src else {
                return Err(JobFailure::new("internal_error", "Invalid source."));
            };
            let max = svc
                .config
                .telegram
                .max_download_bytes
                .min(svc.config.media.max_source_bytes);
            let file = bot.get_file(&file_id).await.map_err(tg_failure)?;
            if file.file_size.is_some_and(|n| n > max) {
                return Err(tg_failure(TgError::TooLarge));
            }
            let path = file.file_path.ok_or_else(|| {
                JobFailure::new("telegram_file", "Telegram did not provide the file.")
            })?;
            bot.download_file(&path, &dest, max)
                .await
                .map_err(tg_failure)?;
            Ok(Source {
                input: Input::from_file(&dest).await?,
                attribution: None,
            })
        }
        SourceKind::Url => {
            let url = Url::parse(&job.source_ref)
                .map_err(|_| JobFailure::new("invalid_source", "The source link is not valid."))?;
            let max = svc.config.media.max_source_bytes;
            if let Some(link) = parse_link(&url) {
                stage(svc, job, "resolving", "🔎 Looking up the post…", cancel).await?;
                let resolved = svc
                    .extractor
                    .resolve(&link)
                    .await
                    .map_err(|e| extract_failure(&e))?;
                let item = select(&resolved, job.options.media_index.or(link.media_index))
                    .map_err(|e| extract_failure(&e))?;
                stage(svc, job, "downloading", "⬇️ Downloading…", cancel).await?;
                let preferred = choose_candidate(&item, max).clone();
                let mut ordered = vec![preferred.clone()];
                ordered.extend(item.candidates.iter().filter(|c| **c != preferred).cloned());
                let mut last = None;
                for c in ordered {
                    match svc
                        .fetcher
                        .download(&c.url, &resolved.media_hosts, &dest, max)
                        .await
                    {
                        Ok(_) => {
                            return Ok(Source {
                                input: Input::from_file(&dest).await?,
                                attribution: Some((
                                    resolved.author.clone(),
                                    resolved.post_url.clone(),
                                )),
                            });
                        }
                        Err(crate::fetch::FetchError::TooLarge) => {
                            last = Some(JobFailure::new(
                                "source_too_large",
                                format!("That video is larger than {}.", human_bytes(max)),
                            ))
                        }
                        Err(e) => {
                            warn!(job = %job.id, error = %e, "media download failed; trying the next rendition");
                            last = Some(JobFailure::new(
                                "download_failed",
                                "Downloading the video failed.",
                            ));
                        }
                    }
                }
                Err(last.unwrap_or_else(|| {
                    JobFailure::new("download_failed", "Downloading the video failed.")
                }))
            } else if job.owner_kind == "api" {
                // Direct HTTPS media URLs: API-only, same fetch restrictions.
                let policy = HostPolicy::new([url.host_str().unwrap_or_default().to_owned()]);
                svc.fetcher
                    .download(&url, &policy, &dest, max)
                    .await
                    .map_err(|e| match e {
                        crate::fetch::FetchError::TooLarge => {
                            JobFailure::new("source_too_large", "The source is too large.")
                        }
                        crate::fetch::FetchError::Blocked(m) => JobFailure::new(
                            "source_blocked",
                            format!("That URL is not allowed: {m}."),
                        ),
                        other => JobFailure::new(
                            "download_failed",
                            format!("Downloading failed: {other}."),
                        ),
                    })?;
                Ok(Source {
                    input: Input::from_file(&dest).await?,
                    attribution: None,
                })
            } else {
                Err(JobFailure::new(
                    "unsupported_link",
                    "Only X/Twitter and Bluesky post links are supported.",
                ))
            }
        }
        SourceKind::Upload => unreachable!("handled above"),
    }
}

fn tg_failure(e: TgError) -> JobFailure {
    match e {
        TgError::TooLarge => JobFailure::new(
            "source_too_large",
            "That file is over Telegram's bot download limit.",
        ),
        // Telegram refused the request (bad file_id, missing file): permanent.
        TgError::Api { code, description } if (400..500).contains(&code) => {
            warn!(code, error = %description, "Telegram refused the file download");
            JobFailure::new("telegram_file", "Telegram could not provide that file.")
        }
        other => {
            warn!(error = %other, "Telegram file download failed");
            JobFailure {
                retry_in: Some(30),
                ..JobFailure::new("telegram_unavailable", "Telegram download failed.")
            }
        }
    }
}

fn extract_failure(e: &crate::extract::ExtractError) -> JobFailure {
    use crate::extract::ExtractError as E;
    let code = match e {
        E::NotFound => "post_not_found",
        E::Private => "post_private",
        E::NoVideo | E::NotAVideo | E::NoSuchItem(_) => "no_video",
        E::Ambiguous(_) => "multiple_videos",
        E::HlsOnly => "hls_unsupported",
        E::Upstream(_) => "upstream_error",
    };
    JobFailure::new(code, e.to_string())
}

fn attempt_base(job: &JobRow) -> u32 {
    (job.attempts.max(1) as u32) * 100
}

/// Runs one service operation with the §6.7 retry rules.
#[allow(clippy::too_many_arguments)]
async fn run_op(
    svc: &MediaService,
    job: &JobRow,
    step: &'static str,
    slot: u32,
    input: &Input,
    mut op: Operation,
    format: &'static str,
    out: &Path,
    cancel: &CancellationToken,
) -> Result<crate::ffmpeg::Completed, FfError> {
    let client = svc
        .ffmpeg
        .as_ref()
        .ok_or_else(|| FfError::Unavailable("disabled".into()))?;
    let mut tries = 0;
    let mut fell_back = false;
    loop {
        let attempt = Attempt {
            job_id: job.id.clone(),
            step,
            number: attempt_base(job) + slot * 10 + tries,
        };
        match client
            .run(&attempt, input, op.clone(), format, out, cancel)
            .await
        {
            Ok(done) => return Ok(done),
            // A wrong remux choice falls back to transcoding once.
            Err(FfError::Failed { code, .. }) if code == "incompatible_output" && !fell_back => {
                fell_back = true;
                if let Operation::Remux { audio_mode } = op {
                    op = Operation::Transcode(crate::ffmpeg::types::VideoParams {
                        quality: Some(23),
                        audio_mode,
                        ..Default::default()
                    });
                }
            }
            // A geometry mistake retries once without explicit dimensions.
            Err(FfError::Failed { code, .. }) if code == "upscale_not_allowed" && !fell_back => {
                warn!(job = %job.id, "upscale_not_allowed; retrying without width/height");
                fell_back = true;
                if let Operation::Transcode(p) | Operation::Trim { video: p, .. } = &mut op {
                    p.width = None;
                    p.height = None;
                }
            }
            Err(e) if e.retryable() && tries < svc.config.ffmpeg.max_retries => {
                warn!(job = %job.id, step, error = %e, "retryable FFmpeg failure");
                tries += 1;
                if matches!(e, FfError::Lost) {
                    let _ = client.refresh_capabilities().await;
                }
                tokio::time::sleep(Duration::from_secs(2 << tries)).await;
            }
            Err(e) => return Err(e),
        }
        if cancel.is_cancelled() {
            return Err(FfError::Cancelled);
        }
    }
}

async fn metadata(
    svc: &MediaService,
    job: &JobRow,
    input: &Input,
    cancel: &CancellationToken,
) -> Result<MediaInfo, JobFailure> {
    let sha = input.sha256.clone();
    let cached: Option<String> = svc
        .db
        .read(move |c| {
            Ok(c.query_row(
                "SELECT payload FROM metadata_cache WHERE sha256 = ?1",
                [sha],
                |r| r.get(0),
            )
            .optional()?)
        })
        .await?;
    if let Some(info) = cached.and_then(|c| serde_json::from_str::<MediaInfo>(&c).ok()) {
        return Ok(info);
    }
    let out = svc.job_dir(&job.id).join("metadata.json");
    run_op(
        svc,
        job,
        "meta",
        0,
        input,
        Operation::Metadata {},
        "json",
        &out,
        cancel,
    )
    .await
    .map_err(from_ff)?;
    let raw = tokio::fs::read_to_string(&out).await?;
    let info: MediaInfo = serde_json::from_str(&raw).map_err(anyhow::Error::from)?;
    let (sha, payload) = (
        input.sha256.clone(),
        serde_json::to_string(&info).map_err(anyhow::Error::from)?,
    );
    svc.db
        .write(move |tx| {
            Ok(tx.execute(
                "INSERT OR REPLACE INTO metadata_cache (sha256, payload, created_at) VALUES (?1, ?2, ?3)",
                params![sha, payload, now()],
            )?)
        })
        .await?;
    Ok(info)
}

/// Runs the plan. For GIFs, each rung starts again from the source and the
/// ladder stops at the first result within the size target.
async fn encode(
    svc: &MediaService,
    job: &JobRow,
    input: &Input,
    rungs: &[Rung],
    _info: &MediaInfo,
    cancel: &CancellationToken,
) -> Result<(PathBuf, Rung), JobFailure> {
    let dir = svc.job_dir(&job.id);
    let target = svc.config.media.gif_target_bytes;
    let mut last_size = 0;
    for (i, rung) in rungs.iter().enumerate() {
        if i > 0 {
            status(
                svc,
                job,
                &format!(
                    "⚙️ Result was {}; trying a smaller size ({}/{})…",
                    human_bytes(last_size),
                    i + 1,
                    rungs.len()
                ),
            )
            .await;
        }
        let out = dir.join(format!("result-{i}.{}", rung.format));
        let done = run_op(
            svc,
            job,
            "main",
            1 + i as u32,
            input,
            rung.op.clone(),
            rung.format,
            &out,
            cancel,
        )
        .await
        .map_err(from_ff)?;
        last_size = done.size;
        if rung.delivery != Delivery::Animation || done.size <= target {
            return Ok((out, rung.clone()));
        }
        let _ = tokio::fs::remove_file(&out).await;
    }
    Err(JobFailure::new(
        "gif_too_large",
        format!(
            "Could not get the GIF under {} after {} attempts. Try a shorter clip with start= and duration=.",
            human_bytes(target),
            rungs.len()
        ),
    ))
}

#[allow(clippy::too_many_arguments)]
async fn deliver(
    svc: &MediaService,
    job: &JobRow,
    source: &Source,
    result: &Input,
    delivery: Delivery,
    dims: (u32, u32),
    duration: Option<f64>,
    cancel: &CancellationToken,
) -> Result<(), JobFailure> {
    let content_type = match result.path.extension().and_then(|e| e.to_str()) {
        Some("webm") => "video/webm",
        _ if job.action == Action::Fetch => "video/mp4",
        _ => "video/mp4",
    };
    let retention = svc.config.storage.download_retention_secs as i64;
    let mut uncertain = false;
    let mut keep_for_download = job.owner_kind == "api";
    if let (Some(chat), Some(bot)) = (job.chat_id, svc.bot.clone()) {
        stage(svc, job, "delivering", "📤 Sending…", cancel).await?;
        if result.size > svc.config.telegram.max_upload_bytes {
            keep_for_download = true;
            let msg = format!(
                "The result is {}, over Telegram's {} bot upload limit.",
                human_bytes(result.size),
                human_bytes(svc.config.telegram.max_upload_bytes)
            );
            if job.owner_kind == "telegram" {
                return Err(JobFailure::new("result_too_large", msg));
            }
            let _ = bot
                .send_message(chat, job.thread_id, &escape(&msg), job.reply_to, None)
                .await;
        } else {
            let thumb = thumbnail(svc, job, result, dims, delivery, cancel).await;
            let ext = result
                .path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("mp4");
            let name = format!(
                "{}-{}.{ext}",
                job.action,
                &job.id[job.id.len().saturating_sub(8)..]
            );
            let mut caption = format!("<b>{}</b>", job.action.label());
            if job.action != Action::Fetch {
                caption.push_str(&format!(
                    " · {} → {}",
                    human_bytes(source.input.size),
                    human_bytes(result.size)
                ));
            }
            if let Some((author, url)) = &source.attribution {
                caption.push('\n');
                if let Some(a) = author {
                    caption.push_str(&format!("{} · ", escape(a)));
                }
                caption.push_str(&escape(url));
            }
            let upload = MediaUpload {
                kind: match delivery {
                    Delivery::Animation => MediaKind::Animation,
                    Delivery::Video => MediaKind::Video,
                    Delivery::Document => MediaKind::Document,
                },
                chat_id: chat,
                thread_id: job.thread_id,
                reply_to: job.reply_to,
                path: &result.path,
                file_name: &name,
                mime: content_type,
                caption_html: Some(caption),
                width: (dims.0 > 0).then_some(dims.0),
                height: (dims.1 > 0).then_some(dims.1),
                duration: duration.filter(|d| *d > 0.0).map(|d| d.round() as u32),
                thumbnail: thumb.as_deref(),
            };
            match bot.send_media(upload).await {
                Ok(_) => {}
                Err(TgError::Ambiguous(e)) => {
                    // At-least-once: record the uncertainty instead of resending.
                    warn!(job = %job.id, error = %e, "delivery outcome unknown");
                    uncertain = true;
                }
                Err(TgError::RetryAfter(s)) => {
                    return Err(JobFailure {
                        retry_in: Some(s as i64 + 1),
                        ..JobFailure::new("rate_limited", "Telegram rate limit; retrying.")
                    });
                }
                Err(e) => {
                    warn!(job = %job.id, error = %e, "delivery failed");
                    keep_for_download = job.owner_kind == "api";
                    if job.owner_kind == "telegram" {
                        return Err(JobFailure::new(
                            "delivery_failed",
                            "Telegram rejected the result.",
                        ));
                    }
                }
            }
        }
    }
    let result_path = if keep_for_download {
        let kept = svc.job_dir(&job.id).join(format!(
            "result.{}",
            result
                .path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("mp4")
        ));
        if kept != result.path {
            tokio::fs::copy(&result.path, &kept).await?;
        }
        Some(kept.to_string_lossy().into_owned())
    } else {
        None
    };
    jobs::complete(
        &svc.db,
        &job.id,
        Finished {
            result_path: result_path.clone(),
            size: result.size as i64,
            sha256: result.sha256.clone(),
            content_type: content_type.into(),
            expires_at: result_path.as_ref().map(|_| now() + retention),
            delivery_uncertain: uncertain,
        },
    )
    .await?;
    // Transient media goes as soon as it is delivered (SDS §6.6 step 7).
    remove_except(&svc.job_dir(&job.id), result_path.as_deref()).await;
    let done = match job.action {
        Action::Fetch => "✅ Done".to_owned(),
        _ => format!(
            "✅ Done · {} → {}",
            human_bytes(source.input.size),
            human_bytes(result.size)
        ),
    };
    status(svc, job, &done).await;
    Ok(())
}

/// Telegram thumbnail from the result; failures are not fatal.
async fn thumbnail(
    svc: &MediaService,
    job: &JobRow,
    result: &Input,
    dims: (u32, u32),
    delivery: Delivery,
    cancel: &CancellationToken,
) -> Option<PathBuf> {
    if delivery == Delivery::Document || svc.unavailable_reason(Action::Mp4).is_some() {
        return None;
    }
    let (width, height) = thumbnail_box(dims.0, dims.1)?;
    let out = svc.job_dir(&job.id).join("thumb.jpg");
    for quality in [80u8, 60] {
        let op = Operation::Thumbnail {
            timestamp_seconds: 0.5,
            width,
            height,
            jpeg_quality: quality,
        };
        match run_op(
            svc,
            job,
            "thumb",
            quality as u32,
            result,
            op,
            "jpg",
            &out,
            cancel,
        )
        .await
        {
            Ok(done) if done.size < 200 * 1024 => return Some(out),
            Ok(_) => continue,
            Err(e) => {
                warn!(job = %job.id, error = %e, "thumbnail failed; sending without one");
                return None;
            }
        }
    }
    None
}

async fn remove_except(dir: &Path, keep: Option<&str>) {
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else {
        return;
    };
    while let Ok(Some(e)) = entries.next_entry().await {
        let p = e.path();
        if keep.is_none_or(|k| Path::new(k) != p) {
            let _ = tokio::fs::remove_file(&p).await;
        }
    }
    if keep.is_none() {
        let _ = tokio::fs::remove_dir(dir).await;
    }
}

/// Deletes expired results and old job rows, and removes job directories
/// that no longer belong to a job (SDS §10).
pub async fn housekeeping(svc: &MediaService) -> Result<()> {
    let t = now();
    let expired: Vec<String> = svc
        .db
        .write(move |tx| {
            let mut st = tx.prepare("SELECT id FROM jobs WHERE result_path IS NOT NULL AND expires_at < ?1")?;
            let ids = st.query_map([t], |r| r.get(0))?.collect::<rusqlite::Result<Vec<String>>>()?;
            drop(st);
            tx.execute("UPDATE jobs SET result_path = NULL WHERE result_path IS NOT NULL AND expires_at < ?1", [t])?;
            Ok(ids)
        })
        .await?;
    for id in expired {
        let _ = tokio::fs::remove_dir_all(svc.job_dir(&id)).await;
    }
    let cutoff = t - svc.config.storage.metadata_retention_secs as i64;
    svc.db
        .write(move |tx| {
            tx.execute(
                &format!("DELETE FROM jobs WHERE state NOT IN ({}) AND COALESCE(completed_at, updated_at) < ?1", jobs::ACTIVE_STATES),
                [cutoff],
            )?;
            tx.execute("DELETE FROM metadata_cache WHERE created_at < ?1", [cutoff])?;
            Ok(())
        })
        .await?;
    // Orphan directories: no job row, or a finished job without a retained result.
    let root = svc.config.storage.work_dir.join("jobs");
    if let Ok(mut entries) = tokio::fs::read_dir(&root).await {
        while let Ok(Some(e)) = entries.next_entry().await {
            // Uploads write their directory before the job row exists.
            let recent = e
                .metadata()
                .await
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|m| m.elapsed().ok())
                .is_some_and(|age| age < Duration::from_secs(3600));
            if recent {
                continue;
            }
            let name = e.file_name().to_string_lossy().into_owned();
            let keep = match jobs::get(&svc.db, &name).await? {
                Some(j) => {
                    j.is_active()
                        || j.result_path.is_some()
                        || j.source_kind == SourceKind::Upload && j.state == "queued"
                }
                None => false,
            };
            if !keep {
                let _ = tokio::fs::remove_dir_all(e.path()).await;
            }
        }
    }
    Ok(())
}
