//! Command and link parsing for incoming messages.

use url::Url;

use super::types::{MessageEntity, utf16_slice};

#[derive(Debug, PartialEq, Eq)]
pub struct Command<'a> {
    pub name: String,
    pub args: Vec<&'a str>,
}

/// Parses a leading bot command. `/gif@OtherBot` addressed to another bot
/// yields `None`; `/gif@ThisBot` and `/gif` are accepted.
pub fn parse_command<'a>(
    text: &'a str,
    entities: &[MessageEntity],
    my_username: &str,
) -> Option<Command<'a>> {
    let e = entities
        .iter()
        .find(|e| e.kind == "bot_command" && e.offset == 0)?;
    let raw = utf16_slice(text, 0, e.length)?;
    let raw = raw.strip_prefix('/')?;
    let (name, target) = match raw.split_once('@') {
        Some((n, t)) => (n, Some(t)),
        None => (raw, None),
    };
    // Telegram's command syntax: 1-32 of [A-Za-z0-9_]. Anything else
    // (control characters, lookalike letters, spaces) is not a command, so it
    // can never reach logs, replies or the blocklist as one.
    let valid = |s: &str, max: usize| {
        !s.is_empty() && s.len() <= max && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    };
    if !valid(name, 32) || target.is_some_and(|t| !valid(t, 64)) {
        return None;
    }
    if target.is_some_and(|t| !t.eq_ignore_ascii_case(my_username)) {
        return None;
    }
    // The command entity is ASCII, so its UTF-16 length equals its byte length.
    let rest = text.get(e.length..).unwrap_or_default();
    Some(Command {
        name: name.to_ascii_lowercase(),
        args: rest.split_whitespace().collect(),
    })
}

/// HTTP(S) links in a message, from `url` and `text_link` entities.
pub fn find_urls(text: &str, entities: &[MessageEntity]) -> Vec<Url> {
    entities
        .iter()
        .filter_map(|e| match e.kind.as_str() {
            "url" => utf16_slice(text, e.offset, e.length),
            "text_link" => e.url.clone(),
            _ => None,
        })
        .filter_map(|s| {
            // Telegram detects bare domains too; assume https for those.
            let s = if s.contains("://") {
                s
            } else {
                format!("https://{s}")
            };
            Url::parse(&s).ok()
        })
        .filter(|u| matches!(u.scheme(), "http" | "https"))
        .collect()
}

/// Parses a command argument as an HTTP(S) URL.
pub fn arg_url(arg: &str) -> Option<Url> {
    Url::parse(arg)
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entity(kind: &str, offset: usize, length: usize) -> MessageEntity {
        MessageEntity {
            kind: kind.into(),
            offset,
            length,
            url: None,
        }
    }

    #[test]
    fn parses_commands_and_targets() {
        let t = "/gif@WyrmBot https://x.com/a/status/1 start=3";
        let c = parse_command(t, &[entity("bot_command", 0, 12)], "wyrmbot").unwrap();
        assert_eq!(c.name, "gif");
        assert_eq!(c.args, vec!["https://x.com/a/status/1", "start=3"]);
        assert!(
            parse_command("/gif@OtherBot", &[entity("bot_command", 0, 13)], "wyrmbot").is_none()
        );
        assert_eq!(
            parse_command("/HELP", &[entity("bot_command", 0, 5)], "wyrmbot")
                .unwrap()
                .name,
            "help"
        );
        // Malformed or lookalike command names are not commands.
        for bad in ["/gif\n42", "/g\u{200b}if", "/gіf", "/", "/a b"] {
            let len = bad.encode_utf16().count();
            assert!(
                parse_command(bad, &[entity("bot_command", 0, len)], "wyrmbot").is_none(),
                "{bad:?}"
            );
        }
        let long = format!("/{}", "a".repeat(33));
        assert!(parse_command(&long, &[entity("bot_command", 0, 34)], "wyrmbot").is_none());
        // A command later in the message is not a command.
        assert!(parse_command("see /gif", &[entity("bot_command", 4, 4)], "wyrmbot").is_none());
    }

    #[test]
    fn finds_links() {
        let t = "🐉 https://bsky.app/profile/a.bsky.social/post/3k and bsky.app/x";
        let mut link = entity("text_link", 0, 2);
        link.url = Some("https://fixupx.com/a/status/9".into());
        let urls = find_urls(
            t,
            &[
                entity("url", 3, 46),
                entity("url", 54, 10),
                link,
                entity("url", 0, 0),
            ],
        );
        let urls: Vec<String> = urls.iter().map(|u| u.to_string()).collect();
        assert_eq!(
            urls,
            vec![
                "https://bsky.app/profile/a.bsky.social/post/3k",
                "https://bsky.app/x",
                "https://fixupx.com/a/status/9",
            ]
        );
        assert!(find_urls("ftp://x", &[entity("url", 0, 7)]).is_empty());
    }
}
