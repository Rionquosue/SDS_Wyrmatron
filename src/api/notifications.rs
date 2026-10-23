//! `POST /v1/notifications`: generic text notifications (SDS §8).

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::auth::{sha256, Consumer};
use super::{ApiError, ApiJson, AppState};
use crate::config::Scope;
use crate::notify::{self, Enqueued, NewNotification};
use crate::text;

pub const MAX_TEXT_CHARS: usize = 16_000;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Ok,
    Warning,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Ok => "ok",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
    fn icon(self) -> &'static str {
        match self {
            Self::Info => "ℹ️",
            Self::Ok => "✅",
            Self::Warning => "🟡",
            Self::Critical => "🔴",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationRequest {
    pub destination: String,
    pub text: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub severity: Option<Severity>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub event_id: Option<String>,
}

/// Renders a notification as Telegram HTML. All caller text is escaped.
pub fn render(severity: Severity, title: Option<&str>, body: &str, source: Option<&str>) -> String {
    let mut html = format!("{} ", severity.icon());
    match title {
        Some(t) => html.push_str(&format!("<b>{}</b>", text::escape(t))),
        None => html.push_str(&format!("<b>{}</b>", severity.as_str().to_uppercase())),
    }
    if let Some(s) = source {
        html.push_str(&format!(" · <i>{}</i>", text::escape(s)));
    }
    if !body.is_empty() {
        html.push('\n');
        html.push_str(&text::escape(body));
    }
    html
}

fn validate(req: &NotificationRequest) -> Result<(), ApiError> {
    let len = req.text.chars().count();
    if len == 0 || len > MAX_TEXT_CHARS {
        return Err(ApiError::invalid("text", "Text must be 1 to 16000 characters."));
    }
    let short = |v: &Option<String>, field: &str, max: usize| match v {
        Some(s) if s.is_empty() || s.chars().count() > max => {
            Err(ApiError::invalid(field, &format!("{field} must be 1 to {max} characters.")))
        }
        _ => Ok(()),
    };
    short(&req.title, "title", 200)?;
    short(&req.source, "source", 100)?;
    short(&req.event_id, "event_id", 200)?;
    Ok(())
}

pub fn idempotency_key(headers: &HeaderMap) -> Result<Option<String>, ApiError> {
    let Some(v) = headers.get("idempotency-key") else { return Ok(None) };
    let s = v.to_str().map_err(|_| ApiError::invalid("Idempotency-Key", "Idempotency-Key must be printable ASCII."))?;
    if !(8..=200).contains(&s.len()) || !s.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(ApiError::invalid("Idempotency-Key", "Idempotency-Key must be 8 to 200 printable ASCII characters."));
    }
    Ok(Some(s.to_owned()))
}

pub async fn submit(
    State(state): State<AppState>,
    Extension(consumer): Extension<Arc<Consumer>>,
    headers: HeaderMap,
    ApiJson(req): ApiJson<NotificationRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    consumer.require(Scope::Notify)?;
    validate(&req)?;
    consumer.require_destination(&req.destination)?;
    let dest = state.config.destinations.get(&req.destination).ok_or_else(|| ApiError::invalid("destination", "Unknown destination."))?;
    let dedupe_key = req.event_id.clone().or(idempotency_key(&headers)?);
    let severity = req.severity.unwrap_or(Severity::Info);
    let request_hash = hex::encode(sha256(&serde_json::to_vec(&req).map_err(anyhow::Error::from)?));
    let outcome = notify::enqueue(
        &state.db,
        NewNotification {
            consumer: consumer.id.clone(),
            destination: req.destination.clone(),
            chat_id: dest.chat_id,
            thread_id: dest.thread_id,
            body_html: render(severity, req.title.as_deref(), &req.text, req.source.as_deref()),
            severity: Some(severity.as_str().into()),
            source: req.source.clone(),
            dedupe_key,
            request_hash,
        },
    )
    .await?;
    respond(&state, outcome)
}

pub fn respond(state: &AppState, outcome: Enqueued) -> Result<(StatusCode, Json<Value>), ApiError> {
    match outcome {
        Enqueued::Accepted(id) => {
            state.outbox.notify_one();
            Ok((StatusCode::ACCEPTED, Json(json!({ "id": id, "status": "accepted" }))))
        }
        Enqueued::Duplicate(id) => Ok((StatusCode::OK, Json(json!({ "id": id, "status": "duplicate" })))),
        Enqueued::Conflict => Err(ApiError::conflict("idempotency_conflict", "This event ID was already used with a different body.")),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::api::tests::{call, state, MEDIA_KEY, NOTIFY_KEY};

    #[test]
    fn renders_escaped_html() {
        assert_eq!(
            render(Severity::Critical, Some("Disk <full>"), "a & b", Some("nas")),
            "🔴 <b>Disk &lt;full&gt;</b> · <i>nas</i>\na &amp; b"
        );
        assert_eq!(render(Severity::Info, None, "", None), "ℹ️ <b>INFO</b>");
    }

    #[tokio::test]
    async fn accepts_dedupes_and_conflicts() {
        let s = state().await;
        let body = json!({ "destination": "ops", "text": "Storage server is down", "severity": "critical",
                           "source": "uptime-kuma", "event_id": "storage-down-20261022-01" });
        let (status, first) = call(&s, "POST", "/v1/notifications", Some(NOTIFY_KEY), Some(body.clone())).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{first}");
        let (status, again) = call(&s, "POST", "/v1/notifications", Some(NOTIFY_KEY), Some(body)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(again["id"], first["id"]);
        let changed = json!({ "destination": "ops", "text": "different", "event_id": "storage-down-20261022-01" });
        let (status, err) = call(&s, "POST", "/v1/notifications", Some(NOTIFY_KEY), Some(changed)).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(err["error"]["code"], "idempotency_conflict");
    }

    #[tokio::test]
    async fn enforces_scope_destination_and_schema() {
        let s = state().await;
        let ok = json!({ "destination": "ops", "text": "hi" });
        assert_eq!(call(&s, "POST", "/v1/notifications", Some(MEDIA_KEY), Some(ok)).await.0, StatusCode::FORBIDDEN);
        let wrong_dest = json!({ "destination": "personal", "text": "hi" });
        assert_eq!(call(&s, "POST", "/v1/notifications", Some(NOTIFY_KEY), Some(wrong_dest)).await.0, StatusCode::FORBIDDEN);
        let unknown_field = json!({ "destination": "ops", "text": "hi", "chat_id": 1 });
        let (status, err) = call(&s, "POST", "/v1/notifications", Some(NOTIFY_KEY), Some(unknown_field)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(err["error"]["code"], "invalid_parameter");
        let empty = json!({ "destination": "ops", "text": "" });
        let (status, err) = call(&s, "POST", "/v1/notifications", Some(NOTIFY_KEY), Some(empty)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(err["error"]["field"], "text");
        let bad_severity = json!({ "destination": "ops", "text": "x", "severity": "apocalyptic" });
        assert_eq!(call(&s, "POST", "/v1/notifications", Some(NOTIFY_KEY), Some(bad_severity)).await.0, StatusCode::UNPROCESSABLE_ENTITY);
    }
}
