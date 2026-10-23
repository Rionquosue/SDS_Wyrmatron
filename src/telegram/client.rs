//! Thin Bot API client. Every Bot API URL contains the token, so errors are
//! stripped of their URL before they can reach a log (SDS §11).

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;

use async_trait::async_trait;
use futures_util::StreamExt;
use reqwest::multipart::{Form, Part};
use secrecy::{ExposeSecret, SecretString};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;

use super::types::{File, InlineKeyboard, Message, User};
use crate::notify::{MessageSink, SendError};

#[derive(Debug, thiserror::Error)]
pub enum TgError {
    #[error("rate limited for {0}s")]
    RetryAfter(u64),
    #[error("Telegram API error {code}: {description}")]
    Api { code: u16, description: String },
    /// The request never reached Telegram.
    #[error("connection failed: {0}")]
    Connect(String),
    /// The request may or may not have been processed.
    #[error("request outcome unknown: {0}")]
    Ambiguous(String),
    #[error("invalid response: {0}")]
    Decode(String),
    #[error("file too large")]
    TooLarge,
    #[error("local file error: {0}")]
    Io(#[from] std::io::Error),
}

impl TgError {
    fn from_reqwest(e: reqwest::Error) -> Self {
        let connect = e.is_connect();
        // Never keep the URL: it contains the bot token.
        let message = e.without_url().to_string();
        if connect {
            Self::Connect(message)
        } else {
            Self::Ambiguous(message)
        }
    }
}

#[derive(Deserialize)]
struct Envelope<T> {
    ok: bool,
    result: Option<T>,
    description: Option<String>,
    error_code: Option<u16>,
    parameters: Option<ResponseParameters>,
}

#[derive(Deserialize)]
struct ResponseParameters {
    retry_after: Option<u64>,
}

/// Per-chat and global pacing: about one message per second per private
/// chat, 20 per minute per group, and 25 per second overall.
#[derive(Default)]
pub struct RateLimiter {
    next: Mutex<(Option<Instant>, HashMap<i64, Instant>)>,
}

impl RateLimiter {
    pub async fn acquire(&self, chat_id: i64) {
        let wait = {
            let mut guard = self.next.lock().expect("rate limiter lock");
            let now = Instant::now();
            let (global, chats) = &mut *guard;
            let chat_gap = if chat_id < 0 {
                Duration::from_secs(3)
            } else {
                Duration::from_secs(1)
            };
            let at = [
                global.unwrap_or(now),
                chats.get(&chat_id).copied().unwrap_or(now),
                now,
            ]
            .into_iter()
            .max()
            .unwrap_or(now);
            *global = Some(at + Duration::from_millis(40));
            chats.insert(chat_id, at + chat_gap);
            if chats.len() > 10_000 {
                chats.retain(|_, t| *t > now);
            }
            at.saturating_duration_since(now)
        };
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }
}

/// Longest Telegram flood-control wait retried inside a single call.
const MAX_INLINE_RETRY_SECS: u64 = 30;

pub enum MediaKind {
    Animation,
    Video,
    Document,
}

impl MediaKind {
    fn method(&self) -> (&'static str, &'static str) {
        match self {
            Self::Animation => ("sendAnimation", "animation"),
            Self::Video => ("sendVideo", "video"),
            Self::Document => ("sendDocument", "document"),
        }
    }
}

pub struct MediaUpload<'a> {
    pub kind: MediaKind,
    pub chat_id: i64,
    pub thread_id: Option<i64>,
    pub reply_to: Option<i64>,
    pub path: &'a Path,
    pub file_name: &'a str,
    pub mime: &'a str,
    pub caption_html: Option<String>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub duration: Option<u32>,
    pub thumbnail: Option<&'a Path>,
}

pub struct Bot {
    http: reqwest::Client,
    base: String,
    token: SecretString,
    pub limiter: RateLimiter,
    request_timeout: Duration,
}

impl Bot {
    pub fn new(http: reqwest::Client, base: &str, token: SecretString) -> Self {
        Self {
            http,
            base: base.trim_end_matches('/').to_owned(),
            token,
            limiter: RateLimiter::default(),
            request_timeout: Duration::from_secs(30),
        }
    }

    fn method_url(&self, method: &str) -> String {
        format!("{}/bot{}/{}", self.base, self.token.expose_secret(), method)
    }

    async fn decode<T: DeserializeOwned>(res: reqwest::Response) -> Result<T, TgError> {
        let status = res.status();
        let bytes = res.bytes().await.map_err(TgError::from_reqwest)?;
        let env: Envelope<T> = serde_json::from_slice(&bytes)
            .map_err(|e| TgError::Decode(format!("HTTP {status}: {e}")))?;
        if env.ok {
            return env
                .result
                .ok_or_else(|| TgError::Decode("missing result".into()));
        }
        if let Some(secs) = env.parameters.and_then(|p| p.retry_after) {
            return Err(TgError::RetryAfter(secs));
        }
        Err(TgError::Api {
            code: env.error_code.unwrap_or(status.as_u16()),
            description: env.description.unwrap_or_default(),
        })
    }

    /// Calls a Bot API method. Short flood-control waits requested by
    /// Telegram (429 `retry_after`) are honoured and retried, so replies are
    /// delayed rather than lost under load.
    pub async fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        body: &impl Serialize,
        timeout: Duration,
    ) -> Result<T, TgError> {
        let mut attempt = 0;
        loop {
            let res = self
                .http
                .post(self.method_url(method))
                .json(body)
                .timeout(timeout)
                .send()
                .await
                .map_err(TgError::from_reqwest)?;
            match Self::decode(res).await {
                Err(TgError::RetryAfter(secs)) if secs <= MAX_INLINE_RETRY_SECS && attempt < 3 => {
                    attempt += 1;
                    tokio::time::sleep(Duration::from_secs(secs)).await;
                }
                other => return other,
            }
        }
    }

    pub async fn get_me(&self) -> Result<User, TgError> {
        self.call("getMe", &json!({}), self.request_timeout).await
    }

    pub async fn delete_webhook(&self) -> Result<bool, TgError> {
        self.call(
            "deleteWebhook",
            &json!({ "drop_pending_updates": false }),
            self.request_timeout,
        )
        .await
    }

    /// Long poll. The request timeout exceeds the poll timeout (SDS §4).
    /// Long poll. Updates are returned as raw JSON so that one update with an
    /// unexpected shape cannot fail the whole batch (and stall the offset).
    pub async fn get_updates(
        &self,
        offset: i64,
        poll_timeout: Duration,
    ) -> Result<Vec<Value>, TgError> {
        let body = json!({
            "offset": offset,
            "timeout": poll_timeout.as_secs(),
            "allowed_updates": ["message", "callback_query"],
        });
        self.call("getUpdates", &body, poll_timeout + Duration::from_secs(15))
            .await
    }

    pub async fn send_message(
        &self,
        chat_id: i64,
        thread_id: Option<i64>,
        html: &str,
        reply_to: Option<i64>,
        keyboard: Option<&InlineKeyboard>,
    ) -> Result<Message, TgError> {
        self.limiter.acquire(chat_id).await;
        let mut body = json!({
            "chat_id": chat_id,
            "text": html,
            "parse_mode": "HTML",
            "link_preview_options": { "is_disabled": true },
        });
        if let Some(t) = thread_id {
            body["message_thread_id"] = json!(t);
        }
        if let Some(r) = reply_to {
            body["reply_parameters"] =
                json!({ "message_id": r, "allow_sending_without_reply": true });
        }
        if let Some(k) = keyboard {
            body["reply_markup"] = serde_json::to_value(k).unwrap_or(Value::Null);
        }
        self.call("sendMessage", &body, self.request_timeout).await
    }

    pub async fn edit_message(
        &self,
        chat_id: i64,
        message_id: i64,
        html: &str,
        keyboard: Option<&InlineKeyboard>,
    ) -> Result<(), TgError> {
        let mut body = json!({
            "chat_id": chat_id,
            "message_id": message_id,
            "text": html,
            "parse_mode": "HTML",
            "link_preview_options": { "is_disabled": true },
        });
        body["reply_markup"] = match keyboard {
            Some(k) => serde_json::to_value(k).unwrap_or(Value::Null),
            None => json!({ "inline_keyboard": [] }),
        };
        match self
            .call::<Value>("editMessageText", &body, self.request_timeout)
            .await
        {
            // Editing to identical content is not an error for us.
            Err(TgError::Api {
                code: 400,
                description,
            }) if description.contains("message is not modified") => Ok(()),
            other => other.map(|_| ()),
        }
    }

    pub async fn answer_callback(
        &self,
        callback_id: &str,
        text: Option<&str>,
    ) -> Result<(), TgError> {
        let mut body = json!({ "callback_query_id": callback_id });
        if let Some(t) = text {
            body["text"] = json!(t);
        }
        self.call::<bool>("answerCallbackQuery", &body, self.request_timeout)
            .await
            .map(|_| ())
    }

    pub async fn get_file(&self, file_id: &str) -> Result<File, TgError> {
        self.call(
            "getFile",
            &json!({ "file_id": file_id }),
            self.request_timeout,
        )
        .await
    }

    /// Streams a file from Telegram to `dest`, stopping at `max_bytes`.
    pub async fn download_file(
        &self,
        file_path: &str,
        dest: &Path,
        max_bytes: u64,
    ) -> Result<u64, TgError> {
        let url = format!(
            "{}/file/bot{}/{}",
            self.base,
            self.token.expose_secret(),
            file_path
        );
        let res = self
            .http
            .get(url)
            .timeout(Duration::from_secs(300))
            .send()
            .await
            .map_err(TgError::from_reqwest)?;
        if !res.status().is_success() {
            return Err(TgError::Api {
                code: res.status().as_u16(),
                description: "file download failed".into(),
            });
        }
        if res.content_length().is_some_and(|n| n > max_bytes) {
            return Err(TgError::TooLarge);
        }
        let mut file = tokio::fs::File::create(dest).await?;
        let mut stream = res.bytes_stream();
        let mut total = 0u64;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(TgError::from_reqwest)?;
            total += chunk.len() as u64;
            if total > max_bytes {
                return Err(TgError::TooLarge);
            }
            file.write_all(&chunk).await?;
        }
        file.sync_all().await?;
        Ok(total)
    }

    async fn file_part(path: &Path, name: &str, mime: &str) -> Result<Part, TgError> {
        let file = tokio::fs::File::open(path).await?;
        let len = file.metadata().await?.len();
        let stream = tokio_util::io::ReaderStream::new(file);
        Part::stream_with_length(reqwest::Body::wrap_stream(stream), len)
            .file_name(name.to_owned())
            .mime_str(mime)
            .map_err(|e| TgError::Decode(e.without_url().to_string()))
    }

    pub async fn send_media(&self, m: MediaUpload<'_>) -> Result<Message, TgError> {
        self.limiter.acquire(m.chat_id).await;
        let (method, field) = m.kind.method();
        let mut form = Form::new().text("chat_id", m.chat_id.to_string());
        if let Some(t) = m.thread_id {
            form = form.text("message_thread_id", t.to_string());
        }
        if let Some(r) = m.reply_to {
            form = form.text(
                "reply_parameters",
                json!({ "message_id": r, "allow_sending_without_reply": true }).to_string(),
            );
        }
        if let Some(c) = &m.caption_html {
            form = form.text("caption", c.clone()).text("parse_mode", "HTML");
        }
        for (k, v) in [
            ("width", m.width),
            ("height", m.height),
            ("duration", m.duration),
        ] {
            if let (Some(v), MediaKind::Animation | MediaKind::Video) = (v, &m.kind) {
                form = form.text(k, v.to_string());
            }
        }
        if matches!(m.kind, MediaKind::Video) {
            form = form.text("supports_streaming", "true");
        }
        form = form.part(field, Self::file_part(m.path, m.file_name, m.mime).await?);
        if let Some(thumb) = m.thumbnail {
            form = form.text("thumbnail", "attach://thumb").part(
                "thumb",
                Self::file_part(thumb, "thumb.jpg", "image/jpeg").await?,
            );
        }
        let res = self
            .http
            .post(self.method_url(method))
            .multipart(form)
            .timeout(Duration::from_secs(600))
            .send()
            .await
            .map_err(TgError::from_reqwest)?;
        Self::decode(res).await
    }
}

#[async_trait]
impl MessageSink for Bot {
    async fn send_html(
        &self,
        chat_id: i64,
        thread_id: Option<i64>,
        html: &str,
    ) -> Result<(), SendError> {
        match self
            .send_message(chat_id, thread_id, html, None, None)
            .await
        {
            Ok(_) => Ok(()),
            Err(TgError::RetryAfter(s)) => Err(SendError::RetryAfter(Duration::from_secs(s))),
            Err(TgError::Api { code, description }) if code >= 500 => {
                Err(SendError::Transient(format!("{code}: {description}")))
            }
            Err(TgError::Api { code, description }) => {
                Err(SendError::Permanent(format!("{code}: {description}")))
            }
            Err(TgError::Connect(m)) => Err(SendError::Transient(m)),
            Err(e) => Err(SendError::Ambiguous(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    const TOKEN: &str = "123456:SECRET-TOKEN-VALUE";

    fn bot(server: &MockServer) -> Bot {
        Bot::new(
            crate::http::client(),
            &server.uri(),
            SecretString::from(TOKEN),
        )
    }

    #[tokio::test]
    async fn sends_html_with_reply_and_thread() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("/bot{TOKEN}/sendMessage")))
            .and(body_partial_json(
                json!({ "chat_id": -1001, "message_thread_id": 4, "parse_mode": "HTML",
                                            "reply_parameters": { "message_id": 9 } }),
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "ok": true, "result": {
                "message_id": 77, "date": 1, "chat": { "id": -1001, "type": "supergroup" } } })),
            )
            .expect(1)
            .mount(&server)
            .await;
        let m = bot(&server)
            .send_message(-1001, Some(4), "<b>hi</b>", Some(9), None)
            .await
            .unwrap();
        assert_eq!(m.message_id, 77);
    }

    #[tokio::test]
    async fn maps_errors_without_leaking_the_token() {
        let server = MockServer::start().await;
        Mock::given(path(format!("/bot{TOKEN}/sendMessage")))
            .respond_with(ResponseTemplate::new(429).set_body_json(json!({ "ok": false, "error_code": 429,
                "description": "Too Many Requests: retry after 60", "parameters": { "retry_after": 60 } })))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(path(format!("/bot{TOKEN}/sendMessage")))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({ "ok": false, "error_code": 400, "description": "Bad Request: chat not found" })))
            .mount(&server)
            .await;
        let b = bot(&server);
        assert!(
            // Long waits are left to the caller (the outbox reschedules).
            matches!(b.send_html(1, None, "x").await, Err(SendError::RetryAfter(d)) if d.as_secs() == 60)
        );
        assert!(
            matches!(b.send_html(2, None, "x").await, Err(SendError::Permanent(m)) if m.contains("chat not found"))
        );

        // A transport failure must not mention the token.
        let dead = Bot::new(
            crate::http::client(),
            "http://127.0.0.1:9",
            SecretString::from(TOKEN),
        );
        let err = dead.get_me().await.unwrap_err();
        assert!(matches!(err, TgError::Connect(_)));
        let text = format!("{err} {err:?}");
        assert!(!text.contains("SECRET-TOKEN-VALUE"), "{text}");
    }

    #[tokio::test]
    async fn short_flood_waits_are_retried() {
        let server = MockServer::start().await;
        Mock::given(path(format!("/bot{TOKEN}/sendMessage")))
            .respond_with(ResponseTemplate::new(429).set_body_json(json!({ "ok": false, "error_code": 429,
                "description": "Too Many Requests: retry after 1", "parameters": { "retry_after": 1 } })))
            .up_to_n_times(2)
            .mount(&server)
            .await;
        Mock::given(path(format!("/bot{TOKEN}/sendMessage")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "ok": true, "result": {
                "message_id": 5, "date": 1, "chat": { "id": 1, "type": "private" } } })),
            )
            .mount(&server)
            .await;
        let started = std::time::Instant::now();
        let m = bot(&server)
            .send_message(1, None, "x", None, None)
            .await
            .unwrap();
        assert_eq!(m.message_id, 5);
        assert!(
            started.elapsed() >= Duration::from_secs(2),
            "each retry waits retry_after"
        );
    }

    #[tokio::test]
    async fn downloads_with_a_size_limit() {
        let server = MockServer::start().await;
        Mock::given(path(format!("/file/bot{TOKEN}/videos/a.mp4")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![7u8; 1000]))
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("a.mp4");
        assert_eq!(
            bot(&server)
                .download_file("videos/a.mp4", &dest, 5000)
                .await
                .unwrap(),
            1000
        );
        assert!(matches!(
            bot(&server).download_file("videos/a.mp4", &dest, 999).await,
            Err(TgError::TooLarge)
        ));
    }

    #[tokio::test]
    async fn rate_limiter_spaces_messages_per_chat() {
        tokio::time::pause();
        let l = RateLimiter::default();
        let start = tokio::time::Instant::now();
        l.acquire(1).await;
        l.acquire(1).await;
        assert!(start.elapsed() >= Duration::from_millis(990));
        let before = tokio::time::Instant::now();
        l.acquire(2).await;
        assert!(
            before.elapsed() < Duration::from_millis(100),
            "another chat is not delayed by chat 1"
        );
    }
}
