//! Turns Telegram updates into replies and media jobs (SDS §4).

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use base64::Engine;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use super::access::{AccessList, Verdict};
use super::client::{Bot, TgError};
use super::commands::{arg_url, find_urls, parse_command};
use super::types::{
    CallbackQuery, Chat, FileRef, InlineButton, InlineKeyboard, Message, Update, User,
};
use crate::config::Config;
use crate::db::{Db, now};
use crate::media::spec::{Action, JobOptions, parse_args};
use crate::text::escape;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TelegramSource {
    Url {
        url: String,
    },
    File {
        file_id: String,
        file_size: Option<u64>,
        mime: Option<String>,
        file_name: Option<String>,
    },
}

impl TelegramSource {
    fn from_file(f: &FileRef) -> Self {
        Self::File {
            file_id: f.file_id.clone(),
            file_size: f.file_size,
            mime: f.mime_type.clone(),
            file_name: f.file_name.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TelegramJob {
    pub action: Action,
    pub options: JobOptions,
    pub source: TelegramSource,
    pub user_id: i64,
    pub chat_id: i64,
    pub thread_id: Option<i64>,
    pub reply_to: i64,
    /// The "queued" message the pipeline edits with progress.
    pub status_message: i64,
}

/// The media subsystem as seen from Telegram. Errors are user-facing text.
#[async_trait]
pub trait MediaJobs: Send + Sync {
    /// Why an action cannot run right now, if it cannot.
    fn unavailable(&self, action: Action) -> Option<String>;
    fn supported_link(&self, url: &url::Url) -> bool;
    async fn submit(&self, job: TelegramJob) -> Result<String, String>;
    async fn status(&self, job_id: &str, user_id: i64, admin: bool) -> Result<String, String>;
    async fn cancel(&self, job_id: &str, user_id: i64, admin: bool) -> Result<String, String>;
}

pub struct Handler {
    pub bot: Arc<Bot>,
    pub db: Db,
    pub config: Arc<Config>,
    pub username: String,
    pub media: Arc<dyn MediaJobs>,
    pub access: Arc<AccessList>,
}

const FILE_ACTIONS: [Action; 4] = [Action::Gif, Action::Mute, Action::Compress, Action::Mp4];
const LINK_ACTIONS: [Action; 2] = [Action::Fetch, Action::Gif];

struct TokenRow {
    user: i64,
    chat: i64,
    thread: Option<i64>,
    message_id: i64,
    action: String,
    payload: String,
    expires_at: i64,
}

#[derive(Serialize, Deserialize)]
struct ButtonPayload {
    source: TelegramSource,
    reply_to: i64,
}

fn new_token() -> String {
    let bytes: [u8; 16] = rand::random();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

impl Handler {
    fn is_admin(&self, user: i64) -> bool {
        self.config.telegram.admins.contains(&user)
    }

    /// Numeric IDs only; usernames are mutable (SDS §10).
    fn chat_allowed(&self, chat: &Chat) -> bool {
        chat.is_private() || self.config.telegram.allowed_chats.contains(&chat.id)
    }

    /// Screens the account before the bot does anything: non-whitelisted
    /// accounts are blocklisted and get no response at all.
    fn admitted(&self, user: &User, context: &str) -> bool {
        match self.access.check(user, context) {
            Verdict::Allowed => true,
            Verdict::Blocked => {
                debug!(user = user.id, context, "ignoring a blocked account");
                false
            }
            Verdict::NewlyBlocked => false,
        }
    }

    pub async fn handle(&self, update: Update) -> Result<()> {
        if let Some(m) = update.message {
            self.on_message(m).await
        } else if let Some(q) = update.callback_query {
            self.on_callback(q).await
        } else {
            Ok(())
        }
    }

    async fn reply(&self, m: &Message, html: &str) -> Result<Message, TgError> {
        self.bot
            .send_message(m.chat.id, m.thread(), html, Some(m.message_id), None)
            .await
    }

    async fn on_message(&self, m: Message) -> Result<()> {
        let Some(from) = m.from.clone() else {
            return Ok(());
        };
        if from.is_bot {
            return Ok(());
        }
        let (text, entities) = m.content();
        let command = parse_command(text, entities, &self.username);
        // Interactions are private messages and commands addressed to the
        // bot; other group chatter is not screened (or answered).
        let context = match (&command, m.chat.is_private()) {
            (_, true) => "private chat".to_owned(),
            (Some(c), false) => format!("chat {} command /{}", m.chat.id, c.name),
            (None, false) => return Ok(()),
        };
        if !self.admitted(&from, &context) {
            return Ok(());
        }
        if !self.chat_allowed(&m.chat) {
            debug!(
                chat = m.chat.id,
                "ignoring a command in a chat that is not allowed"
            );
            return Ok(());
        }
        match command {
            Some(c) => self.on_command(&m, from.id, &c.name, &c.args).await,
            // Command-less offers only in private chats; groups use privacy mode.
            None if m.chat.is_private() => self.offer(&m, from.id).await,
            None => Ok(()),
        }
    }

    fn help(&self) -> String {
        let t = &self.config.telegram;
        let m = &self.config.media;
        let mut lines = vec![
            "<b>Wyrmatron</b>".to_owned(),
            "Reply to a video with a command, or add a link after it:".to_owned(),
            "/gif [URL] [start=S] [duration=S] — silent looping animation".to_owned(),
            "/mute [URL] — remove the audio".to_owned(),
            "/compress [URL] [light|balanced|small] — smaller file".to_owned(),
            "/mp4 [URL] — convert to H.264/AAC MP4".to_owned(),
            "/fetch URL — download the video from an X/Twitter or Bluesky post".to_owned(),
            "/status JOB_ID · /cancel JOB_ID".to_owned(),
            String::new(),
            format!(
                "Limits: Telegram files up to {} MB, GIFs up to {:.0} s, sources up to {} MB.",
                t.max_download_bytes / 1_000_000,
                m.gif_max_seconds,
                m.max_source_bytes / (1024 * 1024)
            ),
        ];
        let unavailable: Vec<String> = Action::ALL
            .iter()
            .filter_map(|a| {
                self.media
                    .unavailable(*a)
                    .map(|why| format!("/{a}: {}", escape(&why)))
            })
            .collect();
        if !unavailable.is_empty() {
            lines.push("Currently unavailable:".into());
            lines.extend(unavailable);
        }
        lines.join("\n")
    }

    async fn on_command(&self, m: &Message, user: i64, name: &str, args: &[&str]) -> Result<()> {
        if let Ok(action) = name.parse::<Action>() {
            return self.on_media_command(m, user, action, args).await;
        }
        match name {
            "start" | "help" => {
                self.reply(m, &self.help()).await?;
            }
            "status" | "cancel" => {
                let Some(id) = args.first() else {
                    self.reply(m, &format!("Usage: /{name} JOB_ID")).await?;
                    return Ok(());
                };
                let admin = self.is_admin(user);
                let out = if name == "status" {
                    self.media.status(id, user, admin).await
                } else {
                    self.media.cancel(id, user, admin).await
                };
                self.reply(m, &out.unwrap_or_else(|e| escape(&e))).await?;
            }
            _ => {
                if m.chat.is_private() {
                    self.reply(m, "Unknown command. Try /help.").await?;
                }
            }
        }
        Ok(())
    }

    /// The source for a media command: a URL argument, a link in the
    /// message, or the video or link in the replied-to message.
    fn source_for(&self, m: &Message, rest: &[&str]) -> Option<TelegramSource> {
        if let Some(u) = rest.iter().find_map(|a| arg_url(a)) {
            return Some(TelegramSource::Url { url: u.to_string() });
        }
        if let Some(f) = m.video_file() {
            return Some(TelegramSource::from_file(f));
        }
        let reply = m.reply_to_message.as_deref()?;
        if let Some(f) = reply.video_file() {
            return Some(TelegramSource::from_file(f));
        }
        let (text, entities) = reply.content();
        find_urls(text, entities)
            .into_iter()
            .next()
            .map(|u| TelegramSource::Url { url: u.to_string() })
    }

    async fn on_media_command(
        &self,
        m: &Message,
        user: i64,
        action: Action,
        args: &[&str],
    ) -> Result<()> {
        if let Some(why) = self.media.unavailable(action) {
            self.reply(m, &format!("/{action} is unavailable: {}", escape(&why)))
                .await?;
            return Ok(());
        }
        let (options, rest) = match parse_args(action, args) {
            Ok(v) => v,
            Err(e) => {
                self.reply(m, &escape(&e)).await?;
                return Ok(());
            }
        };
        if let Err(e) = options.validate(action, self.config.media.gif_max_seconds) {
            self.reply(m, &escape(&e)).await?;
            return Ok(());
        }
        let Some(source) = self.source_for(m, &rest) else {
            let usage = if action == Action::Fetch {
                "Usage: /fetch URL".to_owned()
            } else {
                format!("Reply to a video with /{action}, or send /{action} URL.")
            };
            self.reply(m, &usage).await?;
            return Ok(());
        };
        if action == Action::Fetch && !matches!(source, TelegramSource::Url { .. }) {
            self.reply(m, "/fetch needs a post link.").await?;
            return Ok(());
        }
        self.start_job(
            m.chat.id,
            m.thread(),
            m.message_id,
            user,
            action,
            options,
            source,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn start_job(
        &self,
        chat_id: i64,
        thread_id: Option<i64>,
        reply_to: i64,
        user: i64,
        action: Action,
        options: JobOptions,
        source: TelegramSource,
    ) -> Result<()> {
        if let TelegramSource::File {
            file_size: Some(size),
            ..
        } = &source
            && *size > self.config.telegram.max_download_bytes
        {
            let mb = self.config.telegram.max_download_bytes / 1_000_000;
            self.bot
                    .send_message(chat_id, thread_id, &format!("That file is over Telegram's {mb} MB bot download limit. Send a link instead."), Some(reply_to), None)
                    .await?;
            return Ok(());
        }
        // Refused up front, so no "Queued" placeholder appears for it.
        if let TelegramSource::Url { url } = &source
            && !url::Url::parse(url).is_ok_and(|u| self.media.supported_link(&u))
        {
            self.bot
                .send_message(
                    chat_id,
                    thread_id,
                    "⚠️ Only X/Twitter and Bluesky post links are supported.",
                    Some(reply_to),
                    None,
                )
                .await?;
            return Ok(());
        }
        let status = self
            .bot
            .send_message(
                chat_id,
                thread_id,
                &format!("⏳ Queued <b>{}</b>…", action.label()),
                Some(reply_to),
                None,
            )
            .await?;
        let job = TelegramJob {
            action,
            options,
            source,
            user_id: user,
            chat_id,
            thread_id,
            reply_to,
            status_message: status.message_id,
        };
        match self.media.submit(job).await {
            Ok(id) => {
                info!(job = %id, user, chat = chat_id, action = %action, "job queued from Telegram");
                self.bot
                    .edit_message(
                        chat_id,
                        status.message_id,
                        &format!(
                            "⏳ Queued <b>{}</b> · job <code>{id}</code>",
                            action.label()
                        ),
                        None,
                    )
                    .await?;
            }
            Err(e) => {
                self.bot
                    .edit_message(
                        chat_id,
                        status.message_id,
                        &format!("⚠️ {}", escape(&e)),
                        None,
                    )
                    .await?;
            }
        }
        Ok(())
    }

    /// Private chats: offer buttons for a bare video or supported link.
    async fn offer(&self, m: &Message, user: i64) -> Result<()> {
        let (source, actions): (TelegramSource, &[Action]) = if let Some(f) = m.video_file() {
            (TelegramSource::from_file(f), &FILE_ACTIONS)
        } else {
            let (text, entities) = m.content();
            match find_urls(text, entities)
                .into_iter()
                .find(|u| self.media.supported_link(u))
            {
                Some(u) => (TelegramSource::Url { url: u.to_string() }, &LINK_ACTIONS),
                None => return Ok(()),
            }
        };
        let actions: Vec<Action> = actions
            .iter()
            .copied()
            .filter(|a| self.media.unavailable(*a).is_none())
            .collect();
        if actions.is_empty() {
            return Ok(());
        }
        let tokens: Vec<(Action, String)> = actions.iter().map(|a| (*a, new_token())).collect();
        let keyboard = InlineKeyboard {
            inline_keyboard: vec![
                tokens
                    .iter()
                    .map(|(a, t)| InlineButton {
                        text: a.label().into(),
                        callback_data: t.clone(),
                    })
                    .collect(),
            ],
        };
        let prompt = self
            .bot
            .send_message(
                m.chat.id,
                m.thread(),
                "What should I do with this?",
                Some(m.message_id),
                Some(&keyboard),
            )
            .await?;
        let payload = serde_json::to_string(&ButtonPayload {
            source,
            reply_to: m.message_id,
        })?;
        let expires = now() + self.config.telegram.button_ttl_secs as i64;
        let (chat, thread, msg_id) = (m.chat.id, m.thread(), prompt.message_id);
        self.db
            .write(move |tx| {
                for (action, token) in tokens {
                    tx.execute(
                        "INSERT INTO callback_tokens (token, user_id, chat_id, thread_id, message_id, action, payload, expires_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                        params![token, user, chat, thread, msg_id, action.as_str(), payload, expires],
                    )?;
                }
                Ok(())
            })
            .await
    }

    async fn on_callback(&self, q: CallbackQuery) -> Result<()> {
        // Screened before the press is even acknowledged.
        let chat = q.message.as_ref().map(|m| m.chat.id).unwrap_or_default();
        if !self.admitted(&q.from, &format!("button in chat {chat}")) {
            return Ok(());
        }
        let (Some(data), Some(msg)) = (q.data.as_deref(), q.message.as_ref()) else {
            self.bot.answer_callback(&q.id, None).await?;
            return Ok(());
        };
        if !self.chat_allowed(&msg.chat) {
            self.bot.answer_callback(&q.id, None).await?;
            return Ok(());
        }
        let token = data.to_owned();
        let (from, chat_id, message_id, t) = (q.from.id, msg.chat.id, msg.message_id, now());
        // Checked and consumed in one transaction, so two presses (or two
        // buttons on the same prompt) can never both succeed.
        let valid: Option<TokenRow> = self
            .db
            .write(move |tx| {
                let row = tx
                    .query_row(
                        "SELECT user_id, chat_id, thread_id, message_id, action, payload, expires_at FROM callback_tokens WHERE token = ?1",
                        [token],
                        |r| {
                            Ok(TokenRow {
                                user: r.get(0)?,
                                chat: r.get(1)?,
                                thread: r.get(2)?,
                                message_id: r.get(3)?,
                                action: r.get(4)?,
                                payload: r.get(5)?,
                                expires_at: r.get(6)?,
                            })
                        },
                    )
                    .optional()?;
                // Bound to the requesting user, chat and prompt message.
                let row = row.filter(|r| {
                    r.user == from && r.chat == chat_id && r.message_id == message_id && r.expires_at > t
                });
                if let Some(r) = &row {
                    // Consume every button on the prompt.
                    tx.execute(
                        "DELETE FROM callback_tokens WHERE chat_id = ?1 AND message_id = ?2",
                        params![r.chat, r.message_id],
                    )?;
                }
                Ok(row)
            })
            .await?;
        let Some(TokenRow {
            user,
            chat,
            thread,
            message_id: msg_id,
            action,
            payload,
            ..
        }) = valid
        else {
            warn!(user = q.from.id, "rejected stale or foreign callback");
            self.bot
                .answer_callback(&q.id, Some("This button has expired or is not yours."))
                .await?;
            return Ok(());
        };
        self.bot.answer_callback(&q.id, None).await?;
        let (Ok(action), Ok(p)) = (
            action.parse::<Action>(),
            serde_json::from_str::<ButtonPayload>(&payload),
        ) else {
            return Ok(());
        };
        let _ = self
            .bot
            .edit_message(
                chat,
                msg_id,
                &format!("Selected <b>{}</b>.", action.label()),
                None,
            )
            .await;
        if let Some(why) = self.media.unavailable(action) {
            self.bot
                .send_message(
                    chat,
                    thread,
                    &format!("/{action} is unavailable: {}", escape(&why)),
                    Some(p.reply_to),
                    None,
                )
                .await?;
            return Ok(());
        }
        self.start_job(
            chat,
            thread,
            p.reply_to,
            user,
            action,
            JobOptions::default(),
            p.source,
        )
        .await
    }
}

/// Removes expired button bindings.
pub async fn prune_tokens(db: &Db) -> Result<usize> {
    db.write(|tx| Ok(tx.execute("DELETE FROM callback_tokens WHERE expires_at < ?1", [now()])?))
        .await
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use secrecy::SecretString;
    use serde_json::json;
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    use super::*;

    #[derive(Default)]
    struct FakeMedia {
        submitted: Mutex<Vec<TelegramJob>>,
        gif_unavailable: bool,
    }

    #[async_trait]
    impl MediaJobs for FakeMedia {
        fn unavailable(&self, action: Action) -> Option<String> {
            (self.gif_unavailable && action == Action::Gif)
                .then(|| "the FFmpeg service lacks audio removal".into())
        }
        fn supported_link(&self, url: &url::Url) -> bool {
            url.host_str() == Some("x.com")
        }
        async fn submit(&self, job: TelegramJob) -> Result<String, String> {
            self.submitted.lock().unwrap().push(job);
            Ok("job1".into())
        }
        async fn status(&self, id: &str, _: i64, _: bool) -> Result<String, String> {
            Ok(format!("status of {id}"))
        }
        async fn cancel(&self, _: &str, _: i64, _: bool) -> Result<String, String> {
            Err("not yours".into())
        }
    }

    /// Records every Bot API call and answers like Telegram.
    async fn telegram() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(
                r"^/botTOKEN/(sendMessage|editMessageText|answerCallbackQuery)$",
            ))
            .respond_with(|req: &Request| {
                if req.url.path().ends_with("answerCallbackQuery") {
                    return ResponseTemplate::new(200)
                        .set_body_json(json!({ "ok": true, "result": true }));
                }
                let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
                let chat = body["chat_id"].as_i64().unwrap_or(0);
                ResponseTemplate::new(200).set_body_json(json!({ "ok": true, "result": {
                    "message_id": 500, "date": 1, "chat": { "id": chat, "type": "private" } } }))
            })
            .mount(&server)
            .await;
        server
    }

    async fn handler(server: &MockServer, media: Arc<FakeMedia>) -> Handler {
        let mut config: Config = figment::Figment::new().extract().unwrap();
        config.telegram.allowed_chats = vec![-1001];
        // Each handler gets its own config directory with 42 whitelisted.
        config.config_dir = tempfile::tempdir().unwrap().keep();
        std::fs::write(config.whitelist_path(), "42 # tester\n").unwrap();
        let access = Arc::new(AccessList::new(
            config.whitelist_path(),
            config.blocklist_path(),
            &config.telegram.admins,
        ));
        Handler {
            bot: Arc::new(Bot::new(
                crate::http::client(),
                &server.uri(),
                SecretString::from("TOKEN"),
            )),
            db: Db::open_in_memory().await.unwrap(),
            config: Arc::new(config),
            username: "wyrmbot".into(),
            media,
            access,
        }
    }

    fn blocklisted(h: &Handler) -> std::collections::HashSet<i64> {
        std::fs::read_to_string(h.config.blocklist_path())
            .map(|t| super::super::access::parse_ids(&t))
            .unwrap_or_default()
    }

    fn message(chat: i64, kind: &str, user: i64, text: &str) -> Message {
        let mut entities = vec![];
        if text.starts_with('/') {
            let len = text.split_whitespace().next().unwrap().len();
            entities.push(json!({ "type": "bot_command", "offset": 0, "length": len }));
        }
        serde_json::from_value(
            json!({ "message_id": 10, "chat": { "id": chat, "type": kind },
            "from": { "id": user, "is_bot": false }, "text": text, "entities": entities }),
        )
        .unwrap()
    }

    async fn sent(server: &MockServer, method_name: &str) -> Vec<serde_json::Value> {
        server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.url.path().ends_with(method_name))
            .map(|r| serde_json::from_slice(&r.body).unwrap())
            .collect()
    }

    #[tokio::test]
    async fn command_with_url_submits_job() {
        let server = telegram().await;
        let media = Arc::new(FakeMedia::default());
        let h = handler(&server, media.clone()).await;
        let m = message(
            -1001,
            "supergroup",
            42,
            "/gif@wyrmbot https://x.com/a/status/1 start=2 duration=5",
        );
        h.handle(Update {
            update_id: 1,
            message: Some(m),
            callback_query: None,
        })
        .await
        .unwrap();
        {
            let jobs = media.submitted.lock().unwrap();
            assert_eq!(jobs.len(), 1);
            assert_eq!(jobs[0].action, Action::Gif);
            assert_eq!(jobs[0].options.duration_seconds, Some(5.0));
            assert_eq!(
                jobs[0].source,
                TelegramSource::Url {
                    url: "https://x.com/a/status/1".into()
                }
            );
            assert_eq!(jobs[0].status_message, 500);
        }
        let edits = sent(&server, "editMessageText").await;
        assert!(edits[0]["text"].as_str().unwrap().contains("job1"));
    }

    #[tokio::test]
    async fn reply_to_video_uses_the_file() {
        let server = telegram().await;
        let media = Arc::new(FakeMedia::default());
        let h = handler(&server, media.clone()).await;
        let mut m = message(42, "private", 42, "/compress small");
        m.reply_to_message = Some(Box::new(
            serde_json::from_value(
                json!({ "message_id": 9, "chat": { "id": 42, "type": "private" },
                "video": { "file_id": "VID", "file_size": 1000, "mime_type": "video/mp4" } }),
            )
            .unwrap(),
        ));
        h.handle(Update {
            update_id: 1,
            message: Some(m),
            callback_query: None,
        })
        .await
        .unwrap();
        let jobs = media.submitted.lock().unwrap();
        assert!(
            matches!(&jobs[0].source, TelegramSource::File { file_id, .. } if file_id == "VID")
        );
        assert_eq!(
            jobs[0].options.preset,
            Some(crate::media::spec::CompressPreset::Small)
        );
    }

    #[tokio::test]
    async fn rejects_unauthorized_and_oversized() {
        let server = telegram().await;
        let media = Arc::new(FakeMedia::default());
        let h = handler(&server, media.clone()).await;
        // Unknown accounts get no reply anywhere and are blocklisted.
        h.handle(Update {
            update_id: 1,
            message: Some(message(7, "private", 7, "/gif https://x.com/a/status/1")),
            callback_query: None,
        })
        .await
        .unwrap();
        h.handle(Update {
            update_id: 2,
            message: Some(message(
                -1001,
                "supergroup",
                7,
                "/gif https://x.com/a/status/1",
            )),
            callback_query: None,
        })
        .await
        .unwrap();
        // Allowed user in a chat that is not allowed.
        h.handle(Update {
            update_id: 3,
            message: Some(message(-999, "group", 42, "/gif https://x.com/a/status/1")),
            callback_query: None,
        })
        .await
        .unwrap();
        assert!(media.submitted.lock().unwrap().is_empty());
        assert!(
            sent(&server, "sendMessage").await.is_empty(),
            "no replies at all"
        );
        assert_eq!(blocklisted(&h), std::collections::HashSet::from([7]));
        let entry = std::fs::read_to_string(h.config.blocklist_path()).unwrap();
        assert_eq!(
            entry.lines().filter(|l| l.starts_with("7\t")).count(),
            1,
            "blocked once"
        );
        // A blocked account stays ignored, even with a valid command.
        h.handle(Update {
            update_id: 5,
            message: Some(message(7, "private", 7, "/help")),
            callback_query: None,
        })
        .await
        .unwrap();
        assert!(sent(&server, "sendMessage").await.is_empty());
        // 25 MB file exceeds the hosted getFile limit.
        let mut m = message(42, "private", 42, "/mp4");
        m.video = Some(
            serde_json::from_value(json!({ "file_id": "BIG", "file_size": 25_000_000 })).unwrap(),
        );
        h.handle(Update {
            update_id: 4,
            message: Some(m),
            callback_query: None,
        })
        .await
        .unwrap();
        assert!(media.submitted.lock().unwrap().is_empty());
        assert!(
            sent(&server, "sendMessage").await.last().unwrap()["text"]
                .as_str()
                .unwrap()
                .contains("20 MB")
        );
    }

    #[tokio::test]
    async fn private_video_gets_buttons_and_callback_is_bound() {
        let server = telegram().await;
        let media = Arc::new(FakeMedia {
            gif_unavailable: true,
            ..Default::default()
        });
        let h = handler(&server, media.clone()).await;
        let mut m = message(42, "private", 42, "");
        m.text = None;
        m.video =
            Some(serde_json::from_value(json!({ "file_id": "VID", "file_size": 1000 })).unwrap());
        h.handle(Update {
            update_id: 1,
            message: Some(m),
            callback_query: None,
        })
        .await
        .unwrap();
        let prompt = sent(&server, "sendMessage").await.pop().unwrap();
        let buttons = prompt["reply_markup"]["inline_keyboard"][0]
            .as_array()
            .unwrap()
            .clone();
        // GIF is unavailable, so only Mute, Compress and MP4 are offered.
        let labels: Vec<&str> = buttons
            .iter()
            .map(|b| b["text"].as_str().unwrap())
            .collect();
        assert_eq!(labels, vec!["Mute", "Compress", "MP4"]);
        let token = buttons[0]["callback_data"].as_str().unwrap().to_owned();
        assert!(token.len() <= 64);

        let callback = |from: i64, data: &str| -> CallbackQuery {
            serde_json::from_value(json!({ "id": "cb", "from": { "id": from }, "data": data,
                "message": { "message_id": 500, "chat": { "id": 42, "type": "private" } } }))
            .unwrap()
        };
        // Another user, and a forged token, are rejected.
        h.handle(Update {
            update_id: 2,
            message: None,
            callback_query: Some(callback(43, &token)),
        })
        .await
        .unwrap();
        h.handle(Update {
            update_id: 3,
            message: None,
            callback_query: Some(callback(42, "forged")),
        })
        .await
        .unwrap();
        assert!(media.submitted.lock().unwrap().is_empty());
        // The owner's click starts the job and consumes all buttons.
        h.handle(Update {
            update_id: 4,
            message: None,
            callback_query: Some(callback(42, &token)),
        })
        .await
        .unwrap();
        assert_eq!(media.submitted.lock().unwrap()[0].action, Action::Mute);
        h.handle(Update {
            update_id: 5,
            message: None,
            callback_query: Some(callback(42, &token)),
        })
        .await
        .unwrap();
        assert_eq!(
            media.submitted.lock().unwrap().len(),
            1,
            "a token works once"
        );
        let answers = sent(&server, "answerCallbackQuery").await;
        assert_eq!(
            answers.len(),
            3,
            "whitelisted presses are answered; 43 is ignored"
        );
        assert_eq!(blocklisted(&h), std::collections::HashSet::from([43]));
    }

    #[tokio::test]
    async fn groups_get_no_unsolicited_offers() {
        let server = telegram().await;
        let h = handler(&server, Arc::new(FakeMedia::default())).await;
        let mut m = message(-1001, "supergroup", 42, "look https://x.com/a/status/1");
        m.entities = vec![
            serde_json::from_value(json!({ "type": "url", "offset": 5, "length": 24 })).unwrap(),
        ];
        h.handle(Update {
            update_id: 1,
            message: Some(m),
            callback_query: None,
        })
        .await
        .unwrap();
        assert!(sent(&server, "sendMessage").await.is_empty());
    }

    #[tokio::test]
    async fn group_chatter_is_not_screened_but_commands_are() {
        let server = telegram().await;
        let h = handler(&server, Arc::new(FakeMedia::default())).await;
        // Plain messages from strangers in an allowed group are not interactions.
        h.handle(Update {
            update_id: 1,
            message: Some(message(-1001, "supergroup", 8, "hello everyone")),
            callback_query: None,
        })
        .await
        .unwrap();
        assert!(blocklisted(&h).is_empty());
        // A command addressed to the bot is.
        h.handle(Update {
            update_id: 2,
            message: Some(message(-1001, "supergroup", 8, "/help")),
            callback_query: None,
        })
        .await
        .unwrap();
        assert_eq!(blocklisted(&h), std::collections::HashSet::from([8]));
        assert!(sent(&server, "sendMessage").await.is_empty());
        // Whitelisting on the host takes effect without a restart.
        std::fs::write(h.config.whitelist_path(), "42\n8\n").unwrap();
        h.handle(Update {
            update_id: 3,
            message: Some(message(-1001, "supergroup", 8, "/help")),
            callback_query: None,
        })
        .await
        .unwrap();
        assert_eq!(sent(&server, "sendMessage").await.len(), 1);
    }

    #[tokio::test]
    async fn admins_are_always_allowed() {
        let server = telegram().await;
        let mut h = handler(&server, Arc::new(FakeMedia::default())).await;
        let mut config = (*h.config).clone();
        config.telegram.admins = vec![99];
        h.access = Arc::new(AccessList::new(
            config.whitelist_path(),
            config.blocklist_path(),
            &config.telegram.admins,
        ));
        h.config = Arc::new(config);
        h.handle(Update {
            update_id: 1,
            message: Some(message(99, "private", 99, "/help")),
            callback_query: None,
        })
        .await
        .unwrap();
        assert_eq!(sent(&server, "sendMessage").await.len(), 1);
        assert!(blocklisted(&h).is_empty());
    }
}
