//! Telegram HTML formatting helpers (SDS §4, Sending).

/// Telegram's limit is 4096 characters after entity parsing; keep a margin.
pub const MESSAGE_LIMIT: usize = 4000;

/// Characters removed from untrusted text: bidirectional overrides,
/// embeddings and isolates (used to make text read differently from what it
/// is, "Trojan Source"), direction marks, the BOM, and control characters
/// other than newline and tab. Zero-width joiners stay: emoji need them.
pub fn is_spoofing_char(c: char) -> bool {
    matches!(c,
        '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' | '\u{061C}' | '\u{FEFF}')
        || (c.is_control() && c != '\n' && c != '\t')
}

/// Escapes untrusted text for `parse_mode=HTML` (only `<`, `>` and `&` need
/// escaping) and drops spoofing characters.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            c if is_spoofing_char(c) => {}
            _ => out.push(c),
        }
    }
    out
}

/// Truncates plain text to at most `max` characters, adding an ellipsis.
pub fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_owned();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

enum Token<'a> {
    Tag(&'a str),
    Entity(&'a str),
    Char(char),
}

fn tokens(html: &str) -> Vec<Token<'_>> {
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(c) = rest.chars().next() {
        let end = match c {
            '<' => rest.find('>').map(|i| i + 1),
            '&' => rest.find(';').filter(|&i| i <= 10).map(|i| i + 1),
            _ => None,
        };
        match (c, end) {
            ('<', Some(e)) => out.push(Token::Tag(&rest[..e])),
            ('&', Some(e)) => out.push(Token::Entity(&rest[..e])),
            _ => out.push(Token::Char(c)),
        }
        rest = &rest[end.unwrap_or(c.len_utf8())..];
    }
    out
}

fn tag_name(tag: &str) -> &str {
    tag.trim_start_matches('<')
        .trim_start_matches('/')
        .trim_end_matches('>')
        .split_whitespace()
        .next()
        .unwrap_or("")
}

/// Splits Telegram HTML into messages of at most `limit` visible characters
/// (counted in UTF-16 units, as Telegram does). Splits never fall inside a
/// tag or entity; open tags are closed at a split and reopened in the next
/// part. Prefers to split at a newline.
pub fn split_html(html: &str, limit: usize) -> Vec<String> {
    let toks = tokens(html);
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut visible = 0usize;
    let mut open: Vec<String> = Vec::new();
    // Position in `cur` (and the open-tag stack) just after the last newline.
    let mut last_break: Option<(usize, usize, Vec<String>)> = None;

    let close_all = |s: &mut String, open: &[String]| {
        for t in open.iter().rev() {
            s.push_str("</");
            s.push_str(tag_name(t));
            s.push('>');
        }
    };

    for tok in toks {
        let (text, width) = match tok {
            Token::Tag(t) => {
                if t.starts_with("</") {
                    open.pop();
                } else if !t.ends_with("/>") {
                    open.push(t.to_owned());
                }
                cur.push_str(t);
                continue;
            }
            Token::Entity(e) => (e.to_owned(), 1),
            Token::Char(c) => (c.to_string(), c.len_utf16()),
        };
        if visible + width > limit && visible > 0 {
            // Break at the last newline if it is in the second half, else here.
            let (cut, cut_visible, cut_open) = match last_break.take() {
                Some((pos, vis, o)) if vis > limit / 2 => (pos, vis, o),
                _ => (cur.len(), visible, open.clone()),
            };
            let tail = cur.split_off(cut);
            let mut head = std::mem::take(&mut cur);
            close_all(&mut head, &cut_open);
            parts.push(head.trim_end().to_owned());
            for t in &cut_open {
                cur.push_str(t);
            }
            cur.push_str(&tail);
            visible -= cut_visible;
        }
        cur.push_str(&text);
        visible += width;
        if text == "\n" {
            last_break = Some((cur.len(), visible, open.clone()));
        }
    }
    if !cur.trim().is_empty() {
        parts.push(cur);
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_only_html_specials() {
        assert_eq!(escape("a<b>&c\"'"), "a&lt;b&gt;&amp;c\"'");
    }

    #[test]
    fn strips_spoofing_characters() {
        // "Storage is UP" written with a right-to-left override.
        assert_eq!(escape("Storage is \u{202E}NWOD\u{202C}"), "Storage is NWOD");
        assert_eq!(
            escape("a\u{2066}b\u{2069}\u{200F}c\u{FEFF}\u{0}\u{1b}[31m\r"),
            "abc[31m"
        );
        // Newlines, tabs and emoji joiners are kept.
        assert_eq!(
            escape("line1\nline2\t👩\u{200D}💻"),
            "line1\nline2\t👩\u{200D}💻"
        );
    }

    #[test]
    fn short_text_is_one_part() {
        assert_eq!(split_html("<b>hi</b> there", 100), vec!["<b>hi</b> there"]);
    }

    #[test]
    fn splits_without_breaking_entities_or_tags() {
        let html = format!("<b>{}</b>", "&amp;".repeat(30));
        let parts = split_html(&html, 10);
        assert_eq!(parts.len(), 3);
        for p in &parts {
            assert!(p.starts_with("<b>") && p.ends_with("</b>"), "{p}");
            assert_eq!(p.matches("&amp;").count(), 10);
        }
    }

    #[test]
    fn prefers_newlines_and_handles_multibyte() {
        let line = "é".repeat(8);
        let html = format!("{line}\n{line}\n{line}");
        let parts = split_html(&html, 20);
        assert_eq!(parts, vec![format!("{line}\n{line}"), line.clone()]);
        // Characters outside the BMP count as two UTF-16 units.
        assert_eq!(split_html(&"🐉".repeat(6), 4).len(), 3);
    }

    #[test]
    fn truncates_on_char_boundaries() {
        assert_eq!(truncate("dragon", 4), "dra…");
        assert_eq!(truncate("龍龍龍", 3), "龍龍龍");
    }
}
