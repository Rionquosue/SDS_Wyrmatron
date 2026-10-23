//! Public HTTP API (SDS §8). Notification and hook routes have their own
//! concurrency limit so media traffic cannot starve them.

pub mod auth;
mod kuma;
mod notifications;

use std::sync::Arc;
use std::time::Duration;

use axum::error_handling::HandleErrorLayer;
use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, FromRequest, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{BoxError, Json, Router, middleware};
use serde::Serialize;
use serde_json::json;
use tokio::sync::Notify;
use tower::ServiceBuilder;

use crate::config::Config;
use crate::db::Db;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: Db,
    pub consumers: Arc<auth::Consumers>,
    /// Wakes the notification worker after a row is stored.
    pub outbox: Arc<Notify>,
    pub status: Arc<dyn StatusProvider>,
}

/// Runtime state reported by `/v1/capabilities` and readiness, supplied by
/// the media subsystem.
pub trait StatusProvider: Send + Sync {
    fn capabilities(&self) -> serde_json::Value;
}

/// Error envelope shared by every endpoint.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub field: Option<String>,
    pub retry_after: Option<u64>,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            field: None,
            retry_after: None,
        }
    }
    pub fn with_field(mut self, field: impl Into<String>) -> Self {
        self.field = Some(field.into());
        self
    }
    pub fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "invalid_authentication",
            "A valid bearer key is required.",
        )
    }
    pub fn forbidden(message: &str) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", message)
    }
    pub fn invalid(field: &str, message: &str) -> Self {
        Self::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_parameter",
            message,
        )
        .with_field(field)
    }
    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", "No such resource.")
    }
    pub fn conflict(code: &'static str, message: &str) -> Self {
        Self::new(StatusCode::CONFLICT, code, message)
    }
    pub fn unavailable(code: &'static str, retry_after: u64) -> Self {
        let mut e = Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            code,
            "Temporarily unavailable; retry later.",
        );
        e.retry_after = Some(retry_after);
        e
    }
    pub fn internal(err: anyhow::Error) -> Self {
        tracing::error!(error = %err, "request failed");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Internal error.",
        )
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        Self::internal(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let retryable = matches!(self.status.as_u16(), 429 | 503);
        let body = json!({ "error": {
            "code": self.code,
            "message": self.message,
            "field": self.field,
            "retryable": retryable,
        }});
        let mut res = (self.status, Json(body)).into_response();
        if let Some(secs) = self.retry_after {
            res.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(secs));
        }
        if self.status == StatusCode::UNAUTHORIZED {
            res.headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        res
    }
}

/// JSON extractor that reports rejections in the API's error envelope.
pub struct ApiJson<T>(pub T);

impl<T, S> FromRequest<S> for ApiJson<T>
where
    Json<T>: FromRequest<S, Rejection = JsonRejection>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(v)) => Ok(Self(v)),
            Err(JsonRejection::MissingJsonContentType(_)) => Err(ApiError::new(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported_content_type",
                "Expected application/json.",
            )),
            Err(JsonRejection::JsonDataError(e)) => Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_parameter",
                e.body_text(),
            )),
            Err(JsonRejection::BytesRejection(_)) => Err(ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "body_too_large",
                "Request body is too large.",
            )),
            Err(e) => Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "malformed_request",
                e.body_text(),
            )),
        }
    }
}

#[derive(Serialize)]
struct Health {
    ok: bool,
}

async fn live() -> Json<Health> {
    Json(Health { ok: true })
}

async fn ready(State(state): State<AppState>) -> Result<Json<Health>, ApiError> {
    state
        .db
        .read(|c| Ok(c.query_row("SELECT 1", [], |_| Ok(()))?))
        .await
        .map_err(|_| ApiError::unavailable("database_unavailable", 5))?;
    Ok(Json(Health { ok: true }))
}

async fn capabilities(State(state): State<AppState>) -> Json<serde_json::Value> {
    let mut caps = state.status.capabilities();
    if let Some(obj) = caps.as_object_mut() {
        obj.insert("api_version".into(), json!("1"));
        obj.insert("notifications".into(), json!({ "available": true }));
        obj.insert(
            "uptime_kuma_routes".into(),
            json!(state.config.uptime_kuma.len()),
        );
    }
    Json(caps)
}

async fn overloaded(_: BoxError) -> ApiError {
    ApiError::unavailable("capacity_exhausted", 2)
}

pub fn router(state: AppState) -> Router {
    let cfg = &state.config.server;
    let authenticated = middleware::from_fn_with_state(state.clone(), auth::require_consumer);
    let limit = |n: usize| {
        ServiceBuilder::new()
            .layer(HandleErrorLayer::new(overloaded))
            .load_shed()
            .concurrency_limit(n)
            .timeout(Duration::from_secs(cfg.request_timeout_secs))
    };

    let notify_routes = Router::new()
        .route(
            "/v1/notifications",
            post(notifications::submit).route_layer(authenticated.clone()),
        )
        .route("/v1/hooks/uptime-kuma/{route_id}", post(kuma::hook))
        .layer(DefaultBodyLimit::max(cfg.json_body_limit))
        .layer(limit(cfg.notification_concurrency));

    let general = Router::new()
        .route(
            "/v1/capabilities",
            get(capabilities).route_layer(authenticated),
        )
        .layer(DefaultBodyLimit::max(cfg.json_body_limit));

    Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .merge(notify_routes)
        .merge(general)
        .with_state(state)
}

#[cfg(test)]
pub mod tests {
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;
    use crate::config::{ConsumerConfig, Destination, KumaAuth, KumaRoute, Scope};

    pub const NOTIFY_KEY: &str = "notify-key-0123456789";
    pub const MEDIA_KEY: &str = "media-key-0123456789";

    struct NoMedia;
    impl StatusProvider for NoMedia {
        fn capabilities(&self) -> serde_json::Value {
            json!({ "media": { "available": false } })
        }
    }

    pub async fn state() -> AppState {
        let mut config: Config = figment::Figment::new().extract().unwrap();
        config.destinations.insert(
            "ops".into(),
            Destination {
                chat_id: -100123,
                thread_id: Some(9),
            },
        );
        config.destinations.insert(
            "personal".into(),
            Destination {
                chat_id: 42,
                thread_id: None,
            },
        );
        config.consumers = vec![
            ConsumerConfig {
                id: "kuma".into(),
                key_sha256: vec![hex::encode(auth::sha256(NOTIFY_KEY.as_bytes()))],
                scopes: vec![Scope::Notify],
                destinations: vec!["ops".into()],
            },
            ConsumerConfig {
                id: "media".into(),
                key_sha256: vec![hex::encode(auth::sha256(MEDIA_KEY.as_bytes()))],
                scopes: vec![Scope::Media],
                destinations: vec!["personal".into()],
            },
        ];
        config.uptime_kuma.insert(
            "main".into(),
            KumaRoute {
                destination: "ops".into(),
                auth: KumaAuth::Bearer,
                secret_sha256: None,
                suppress_pending: true,
                suppress_maintenance: false,
            },
        );
        config.uptime_kuma.insert(
            "legacy".into(),
            KumaRoute {
                destination: "ops".into(),
                auth: KumaAuth::RouteSecret,
                secret_sha256: Some(hex::encode(auth::sha256(b"legacy-secret-route-0123456789"))),
                suppress_pending: true,
                suppress_maintenance: false,
            },
        );
        config.validate().unwrap();
        let consumers = Arc::new(auth::Consumers::new(&config.consumers));
        AppState {
            config: Arc::new(config),
            db: Db::open_in_memory().await.unwrap(),
            consumers,
            outbox: Arc::new(Notify::new()),
            status: Arc::new(NoMedia),
        }
    }

    pub async fn call(
        state: &AppState,
        method: &str,
        uri: &str,
        key: Option<&str>,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let mut req = Request::builder().method(method).uri(uri);
        if let Some(k) = key {
            req = req.header("authorization", format!("Bearer {k}"));
        }
        let body = match body {
            Some(b) => {
                req = req.header("content-type", "application/json");
                Body::from(b.to_string())
            }
            None => Body::empty(),
        };
        let res = router(state.clone())
            .oneshot(req.body(body).unwrap())
            .await
            .unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    #[tokio::test]
    async fn health_and_auth() {
        let s = state().await;
        assert_eq!(
            call(&s, "GET", "/health/live", None, None).await.0,
            StatusCode::OK
        );
        assert_eq!(
            call(&s, "GET", "/health/ready", None, None).await.0,
            StatusCode::OK
        );
        let (status, body) = call(&s, "GET", "/v1/capabilities", None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], "invalid_authentication");
        let (status, body) = call(&s, "GET", "/v1/capabilities", Some(NOTIFY_KEY), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["api_version"], "1");
        assert_eq!(body["media"]["available"], false);
    }

    #[tokio::test]
    async fn oversized_body_is_413() {
        let s = state().await;
        let text = "x".repeat(70 * 1024);
        let (status, _) = call(
            &s,
            "POST",
            "/v1/notifications",
            Some(NOTIFY_KEY),
            Some(json!({ "destination": "ops", "text": text })),
        )
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    }
}
