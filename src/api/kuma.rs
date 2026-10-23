//! Uptime Kuma webhook adapter (SDS §9). Accepts Kuma's native payload as JSON
//! or as the `data` field of a form-data body.

use std::sync::Arc;

use axum::extract::{FromRequest, Multipart, Path, Request, State};
use axum::http::{header::CONTENT_TYPE, StatusCode};
use axum::Json;
use bytes::Bytes;
use serde_json::Value;

use super::auth::{bearer, secret_matches, sha256, Consumer};
use super::notifications::{render, respond, Severity};
use super::{ApiError, AppState};
use crate::config::{KumaAuth, KumaRoute, Scope};
use crate::db::now;
use crate::notify::{self, NewNotification};
use crate::text;

/// Kuma heartbeat statuses (src/util.ts).
const DOWN: i64 = 0;
const UP: i64 = 1;
const PENDING: i64 = 2;
const MAINTENANCE: i64 = 3;

/// Window for deduplicating events that carry no monitor/heartbeat identity.
const MESSAGE_DEDUPE_WINDOW_SECS: i64 = 300;

#[derive(Debug, PartialEq)]
pub struct KumaEvent {
    pub severity: Severity,
    pub title: String,
    pub detail: Option<String>,
    pub url: Option<String>,
    pub status: Option<i64>,
    /// Stable identity of the event when Kuma supplies one.
    pub identity: Option<String>,
    pub msg: String,
}

fn str_field<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty())
}

/// Normalizes Kuma's `{heartbeat, monitor, msg}` payload. Test and
/// certificate notifications have null heartbeat and monitor.
pub fn parse(payload: &Value) -> KumaEvent {
    let heartbeat = payload.get("heartbeat").filter(|v| v.is_object());
    let monitor = payload.get("monitor").filter(|v| v.is_object());
    let msg = str_field(payload, "msg").unwrap_or("Uptime Kuma notification").to_owned();
    let name = monitor.and_then(|m| str_field(m, "name")).map(str::to_owned);
    let status = heartbeat.and_then(|h| h.get("status")).and_then(Value::as_i64);
    let (severity, title) = match (status, &name) {
        (Some(DOWN), Some(n)) => (Severity::Critical, format!("{n} is DOWN")),
        (Some(UP), Some(n)) => (Severity::Ok, format!("{n} is UP")),
        (Some(PENDING), Some(n)) => (Severity::Warning, format!("{n} is PENDING")),
        (Some(MAINTENANCE), Some(n)) => (Severity::Info, format!("{n} is in MAINTENANCE")),
        (_, Some(n)) => (Severity::Info, n.clone()),
        (_, None) => (Severity::Info, "Uptime Kuma".to_owned()),
    };
    let detail = heartbeat.and_then(|h| str_field(h, "msg")).map(str::to_owned).or_else(|| (name.is_none()).then(|| msg.clone()));
    let url = monitor.and_then(|m| str_field(m, "url")).filter(|u| u.starts_with("http") && *u != "https://").map(str::to_owned);
    let monitor_id = heartbeat
        .and_then(|h| h.get("monitorID"))
        .or_else(|| monitor.and_then(|m| m.get("id")))
        .and_then(Value::as_i64);
    let time = heartbeat.and_then(|h| str_field(h, "time"));
    let identity = match (monitor_id, status, time) {
        (Some(m), Some(s), Some(t)) => Some(format!("{m}:{s}:{t}")),
        _ => None,
    };
    KumaEvent { severity, title, detail, url, status, identity, msg }
}

fn render_event(e: &KumaEvent) -> String {
    let mut body = String::new();
    if let Some(d) = &e.detail {
        body.push_str(&text::truncate(d, 1000));
    }
    let mut html = render(e.severity, Some(&e.title), &body, None);
    if let Some(u) = &e.url {
        html.push('\n');
        html.push_str(&text::escape(&text::truncate(u, 300)));
    }
    html
}

/// Finds the route and the consumer identity it acts as.
fn authorize(state: &AppState, route_id: &str, req: &Request) -> Result<(KumaRoute, String), ApiError> {
    if let Some(route) = state.config.uptime_kuma.get(route_id).filter(|r| r.auth == KumaAuth::Bearer) {
        let consumer: Arc<Consumer> = bearer(req).and_then(|k| state.consumers.authenticate(k)).ok_or_else(ApiError::unauthorized)?;
        consumer.require(Scope::Notify)?;
        consumer.require_destination(&route.destination)?;
        return Ok((route.clone(), consumer.id.clone()));
    }
    // Secret routes: the path segment is the credential. Compare against all.
    let mut found = None;
    for (label, route) in &state.config.uptime_kuma {
        if route.auth == KumaAuth::RouteSecret
            && secret_matches(route_id, route.secret_sha256.as_deref().unwrap_or_default())
        {
            found = Some((route.clone(), format!("kuma:{label}")));
        }
    }
    found.ok_or_else(ApiError::not_found)
}

async fn read_payload(req: Request, state: &AppState) -> Result<Value, ApiError> {
    let content_type = req.headers().get(CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or_default().to_owned();
    let raw: Bytes = if content_type.starts_with("multipart/form-data") {
        let mut form = Multipart::from_request(req, state)
            .await
            .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "malformed_request", "Malformed form data."))?;
        let mut data = None;
        while let Some(field) = form.next_field().await.map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "malformed_request", "Malformed form data."))? {
            if field.name() == Some("data") {
                data = Some(field.bytes().await.map_err(|_| ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large", "Request body is too large."))?);
            }
        }
        data.ok_or_else(|| ApiError::invalid("data", "Form data must contain a data field."))?
    } else if content_type.starts_with("application/json") {
        Bytes::from_request(req, state)
            .await
            .map_err(|_| ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large", "Request body is too large."))?
    } else {
        return Err(ApiError::new(StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_content_type", "Expected JSON or form data."));
    };
    let value: Value = serde_json::from_slice(&raw).map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "malformed_request", "Malformed JSON."))?;
    if !value.is_object() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "malformed_request", "Expected a JSON object."));
    }
    Ok(value)
}

pub async fn hook(
    State(state): State<AppState>,
    Path(route_id): Path<String>,
    req: Request,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let (route, consumer) = authorize(&state, &route_id, &req)?;
    let payload = read_payload(req, &state).await?;
    let event = parse(&payload);
    let suppressed = (event.status == Some(PENDING) && route.suppress_pending)
        || (event.status == Some(MAINTENANCE) && route.suppress_maintenance);
    if suppressed {
        return Ok((StatusCode::OK, Json(serde_json::json!({ "status": "suppressed" }))));
    }
    let dest = state.config.destinations.get(&route.destination).ok_or_else(|| ApiError::invalid("destination", "Unknown destination."))?;
    let html = render_event(&event);
    let dedupe_key = match &event.identity {
        Some(id) => format!("kuma:{}:{id}", route.destination),
        None => format!(
            "kuma:{}:msg:{}:{}",
            route.destination,
            hex::encode(&sha256(event.msg.as_bytes())[..8]),
            now() / MESSAGE_DEDUPE_WINDOW_SECS
        ),
    };
    let outcome = notify::enqueue(
        &state.db,
        NewNotification {
            consumer,
            destination: route.destination.clone(),
            chat_id: dest.chat_id,
            thread_id: dest.thread_id,
            request_hash: hex::encode(sha256(html.as_bytes())),
            body_html: html,
            severity: Some(event.severity.as_str().into()),
            source: Some("uptime-kuma".into()),
            dedupe_key: Some(dedupe_key),
        },
    )
    .await?;
    respond(&state, outcome)
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use http_body_util::BodyExt;
    use serde_json::json;
    use tower::ServiceExt;

    use super::*;
    use crate::api::router;
    use crate::api::tests::{call, state, MEDIA_KEY, NOTIFY_KEY};

    fn down() -> Value {
        json!({
            "heartbeat": { "monitorID": 3, "status": 0, "time": "2026-10-22 14:00:00.000", "msg": "connect ECONNREFUSED",
                           "ping": null, "important": true, "duration": 60 },
            "monitor": { "id": 3, "name": "Storage", "url": "https://nas.example", "type": "http" },
            "msg": "[Storage] [🔴 Down] connect ECONNREFUSED"
        })
    }

    #[test]
    fn parses_status_alerts() {
        let e = parse(&down());
        assert_eq!(e.severity, Severity::Critical);
        assert_eq!(e.title, "Storage is DOWN");
        assert_eq!(e.detail.as_deref(), Some("connect ECONNREFUSED"));
        assert_eq!(e.identity.as_deref(), Some("3:0:2026-10-22 14:00:00.000"));
        let mut up = down();
        up["heartbeat"]["status"] = json!(1);
        assert_eq!(parse(&up).title, "Storage is UP");
        assert_ne!(parse(&up).identity, e.identity, "recovery must stay distinct from the outage");
    }

    #[test]
    fn parses_test_and_certificate_messages() {
        let e = parse(&json!({ "heartbeat": null, "monitor": null, "msg": "Uptime Kuma <test> message" }));
        assert_eq!(e.title, "Uptime Kuma");
        assert_eq!(e.detail.as_deref(), Some("Uptime Kuma <test> message"));
        assert!(e.identity.is_none());
        assert!(render_event(&e).contains("&lt;test&gt;"));
        let cert = parse(&json!({ "heartbeat": null, "monitor": { "id": 3, "name": "Storage" }, "msg": "Certificate expires in 7 days" }));
        assert_eq!(cert.title, "Storage");
        // Odd types never break parsing.
        let odd = parse(&json!({ "heartbeat": { "status": "0" }, "monitor": { "name": 5 }, "msg": 1 }));
        assert_eq!(odd.title, "Uptime Kuma");
    }

    #[tokio::test]
    async fn bearer_route_accepts_dedupes_and_suppresses_pending() {
        let s = state().await;
        let (status, first) = call(&s, "POST", "/v1/hooks/uptime-kuma/main", Some(NOTIFY_KEY), Some(down())).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{first}");
        let (status, again) = call(&s, "POST", "/v1/hooks/uptime-kuma/main", Some(NOTIFY_KEY), Some(down())).await;
        assert_eq!((status, &again["id"]), (StatusCode::OK, &first["id"]));
        let mut pending = down();
        pending["heartbeat"]["status"] = json!(2);
        let (status, body) = call(&s, "POST", "/v1/hooks/uptime-kuma/main", Some(NOTIFY_KEY), Some(pending)).await;
        assert_eq!((status, body["status"].as_str()), (StatusCode::OK, Some("suppressed")));
        assert_eq!(call(&s, "POST", "/v1/hooks/uptime-kuma/main", None, Some(down())).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(call(&s, "POST", "/v1/hooks/uptime-kuma/main", Some(MEDIA_KEY), Some(down())).await.0, StatusCode::FORBIDDEN);
        assert_eq!(call(&s, "POST", "/v1/hooks/uptime-kuma/nope", Some(NOTIFY_KEY), Some(down())).await.0, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn secret_route_and_form_data() {
        let s = state().await;
        let boundary = "XBOUNDARYX";
        let body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"data\"\r\n\r\n{}\r\n--{boundary}--\r\n",
            down()
        );
        let req = Request::builder()
            .method("POST")
            .uri("/v1/hooks/uptime-kuma/legacy-secret-route-0123456789")
            .header("content-type", format!("multipart/form-data; boundary={boundary}"))
            .body(Body::from(body))
            .unwrap();
        let res = router(s.clone()).oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(status, StatusCode::ACCEPTED, "{}", String::from_utf8_lossy(&bytes));
        // The label of a secret route is not itself a valid path.
        assert_eq!(call(&s, "POST", "/v1/hooks/uptime-kuma/legacy", None, Some(down())).await.0, StatusCode::NOT_FOUND);
        let stored: String = s
            .db
            .read(|c| Ok(c.query_row("SELECT consumer FROM notifications", [], |r| r.get(0))?))
            .await
            .unwrap();
        assert_eq!(stored, "kuma:legacy");
    }
}
