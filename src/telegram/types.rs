//! The subset of Bot API types the bot reads. Unknown fields are ignored.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Update {
    pub update_id: i64,
    #[serde(default)]
    pub message: Option<Message>,
    #[serde(default)]
    pub callback_query: Option<CallbackQuery>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct User {
    pub id: i64,
    #[serde(default)]
    pub is_bot: bool,
    #[serde(default)]
    pub username: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Chat {
    pub id: i64,
    #[serde(rename = "type")]
    pub kind: String,
}

impl Chat {
    pub fn is_private(&self) -> bool {
        self.kind == "private"
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MessageEntity {
    #[serde(rename = "type")]
    pub kind: String,
    pub offset: usize,
    pub length: usize,
    #[serde(default)]
    pub url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FileRef {
    pub file_id: String,
    #[serde(default)]
    pub file_unique_id: Option<String>,
    #[serde(default)]
    pub file_size: Option<u64>,
    #[serde(default)]
    pub mime_type: Option<String>,
    #[serde(default)]
    pub file_name: Option<String>,
    #[serde(default)]
    pub width: Option<u32>,
    #[serde(default)]
    pub height: Option<u32>,
    #[serde(default)]
    pub duration: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Message {
    pub message_id: i64,
    #[serde(default)]
    pub message_thread_id: Option<i64>,
    #[serde(default)]
    pub is_topic_message: Option<bool>,
    #[serde(default)]
    pub from: Option<User>,
    pub chat: Chat,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub caption: Option<String>,
    #[serde(default)]
    pub entities: Vec<MessageEntity>,
    #[serde(default)]
    pub caption_entities: Vec<MessageEntity>,
    #[serde(default)]
    pub video: Option<FileRef>,
    #[serde(default)]
    pub animation: Option<FileRef>,
    #[serde(default)]
    pub document: Option<FileRef>,
    #[serde(default)]
    pub video_note: Option<FileRef>,
    #[serde(default)]
    pub reply_to_message: Option<Box<Message>>,
}

impl Message {
    /// Text and entities, whether the message is text or a captioned file.
    pub fn content(&self) -> (&str, &[MessageEntity]) {
        match (&self.text, &self.caption) {
            (Some(t), _) => (t, &self.entities),
            (None, Some(c)) => (c, &self.caption_entities),
            _ => ("", &[]),
        }
    }

    /// A video the bot can process: a video, animation, video note or a
    /// document with a video MIME type.
    pub fn video_file(&self) -> Option<&FileRef> {
        self.video
            .as_ref()
            .or(self.animation.as_ref())
            .or(self.video_note.as_ref())
            .or_else(|| {
                self.document.as_ref().filter(|d| {
                    d.mime_type
                        .as_deref()
                        .is_some_and(|m| m.starts_with("video/"))
                })
            })
    }

    /// Thread to reply into, for forum topics.
    pub fn thread(&self) -> Option<i64> {
        if self.is_topic_message == Some(true) {
            self.message_thread_id
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CallbackQuery {
    pub id: String,
    pub from: User,
    /// Absent or inaccessible for old messages.
    #[serde(default)]
    pub message: Option<Message>,
    #[serde(default)]
    pub data: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct File {
    #[serde(default)]
    pub file_size: Option<u64>,
    #[serde(default)]
    pub file_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InlineButton {
    pub text: String,
    pub callback_data: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct InlineKeyboard {
    pub inline_keyboard: Vec<Vec<InlineButton>>,
}

/// Returns the substring of `text` addressed by Telegram's UTF-16 offsets.
pub fn utf16_slice(text: &str, offset: usize, length: usize) -> Option<String> {
    let units: Vec<u16> = text.encode_utf16().collect();
    let end = offset.checked_add(length)?;
    units
        .get(offset..end)
        .and_then(|s| String::from_utf16(s).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slices_by_utf16_offsets() {
        let text = "🐉 see https://x.com/a/status/1";
        // The dragon is two UTF-16 units.
        assert_eq!(
            utf16_slice(text, 7, 24).as_deref(),
            Some("https://x.com/a/status/1")
        );
        assert_eq!(utf16_slice(text, 0, 2).as_deref(), Some("🐉"));
        assert_eq!(utf16_slice(text, 30, 10), None);
        // Splitting a surrogate pair is invalid UTF-16.
        assert_eq!(utf16_slice(text, 0, 1), None);
    }

    #[test]
    fn parses_update_with_unknown_fields() {
        let raw = r#"{"update_id":10,"message":{"message_id":5,"date":1,"chat":{"id":-1001,"type":"supergroup","title":"x"},
            "from":{"id":42,"is_bot":false,"first_name":"R"},"is_topic_message":true,"message_thread_id":3,
            "document":{"file_id":"F","mime_type":"video/webm","file_size":10},"caption":"/gif","caption_entities":[{"type":"bot_command","offset":0,"length":4}],
            "brand_new_field":{"a":1}}}"#;
        let u: Update = serde_json::from_str(raw).unwrap();
        let m = u.message.unwrap();
        assert_eq!(m.video_file().unwrap().file_id, "F");
        assert_eq!(m.thread(), Some(3));
        assert_eq!(m.content().0, "/gif");
        assert!(!m.chat.is_private());
    }
}
