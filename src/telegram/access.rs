//! Account whitelist and blocklist. Both are plain files in the config
//! directory so they can be edited on the host; changes are picked up on the
//! next update without a restart.
//!
//! Every interaction is screened before the bot does anything: a whitelisted
//! account (or a configured admin) is served; any other account is added to
//! the blocklist and ignored from then on. Telegram has no Bot API method to
//! block a user, so a block means the bot never responds to that account.

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::{error, warn};

use super::types::User;

const WHITELIST_TEMPLATE: &str = "\
# Wyrmatron account whitelist.
# One numeric Telegram user ID per line; text after # is a comment.
# Usernames are not accepted because they can change.
# Any other account that messages the bot, sends it a command or presses one
# of its buttons is added to blocklist.cfg and ignored from then on.
# Admins from config.toml are always allowed. Changes apply without a restart.
";

const BLOCKLIST_HEADER: &str = "\
# Wyrmatron blocklist: accounts that contacted the bot without being on the
# whitelist. The bot ignores these accounts completely. Delete a line (or add
# the ID to whitelist.cfg) to unblock. Text after # is informational.
";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allowed,
    /// Already on the blocklist.
    Blocked,
    /// Not whitelisted: just added to the blocklist.
    NewlyBlocked,
}

/// File identity used to notice edits: modification time and length.
type Stamp = Option<(SystemTime, u64)>;

#[derive(Default)]
struct Listed {
    ids: HashSet<i64>,
    stamp: Stamp,
    /// The file does not exist.
    missing: bool,
    /// The missing whitelist has been reported.
    reported: bool,
}

impl Listed {
    /// Re-reads the file if it changed since the last read.
    fn refresh(&mut self, path: &Path) {
        let stamp = std::fs::metadata(path)
            .ok()
            .and_then(|m| Some((m.modified().ok()?, m.len())));
        if stamp == self.stamp && stamp.is_some() {
            return;
        }
        self.missing = false;
        self.ids = match std::fs::read_to_string(path) {
            Ok(text) => parse_ids(&text),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                self.missing = true;
                HashSet::new()
            }
            Err(e) => {
                // Keep the previous list rather than dropping everyone.
                error!(path = %path.display(), error = %e, "reading access list failed");
                return;
            }
        };
        self.stamp = stamp;
    }
}

/// Parses one ID per line, ignoring blank lines and `#` comments.
pub fn parse_ids(text: &str) -> HashSet<i64> {
    text.lines()
        .filter_map(|line| line.split('#').next())
        .filter_map(|line| line.split_whitespace().next())
        .filter_map(|token| token.parse::<i64>().ok())
        .collect()
}

pub struct AccessList {
    whitelist_path: PathBuf,
    blocklist_path: PathBuf,
    admins: HashSet<i64>,
    state: Mutex<(Listed, Listed)>,
}

impl AccessList {
    pub fn new(whitelist_path: PathBuf, blocklist_path: PathBuf, admins: &[i64]) -> Self {
        Self {
            whitelist_path,
            blocklist_path,
            admins: admins.iter().copied().collect(),
            state: Mutex::new((Listed::default(), Listed::default())),
        }
    }

    pub fn whitelist_path(&self) -> &Path {
        &self.whitelist_path
    }

    pub fn blocklist_path(&self) -> &Path {
        &self.blocklist_path
    }

    /// Creates a commented, empty whitelist if none exists. Returns whether
    /// a file was created.
    pub fn ensure_whitelist(&self) -> io::Result<bool> {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.whitelist_path)
        {
            Ok(mut f) => {
                f.write_all(WHITELIST_TEMPLATE.as_bytes())?;
                Ok(true)
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// (whitelisted accounts, blocked accounts), after re-reading the files.
    pub fn counts(&self) -> (usize, usize) {
        let mut guard = self.state.lock().expect("access lock");
        let (white, black) = &mut *guard;
        white.refresh(&self.whitelist_path);
        black.refresh(&self.blocklist_path);
        (
            white.ids.len()
                + self
                    .admins
                    .iter()
                    .filter(|a| !white.ids.contains(a))
                    .count(),
            black.ids.len(),
        )
    }

    /// Screens an account before the bot acts. `context` describes where the
    /// contact happened and is written to the blocklist as a comment.
    pub fn check(&self, user: &User, context: &str) -> Verdict {
        if self.admins.contains(&user.id) {
            return Verdict::Allowed;
        }
        let mut guard = self.state.lock().expect("access lock");
        let (white, black) = &mut *guard;
        white.refresh(&self.whitelist_path);
        // The whitelist wins over an older blocklist entry.
        if white.ids.contains(&user.id) {
            return Verdict::Allowed;
        }
        if white.missing {
            // Deleted, or caught mid-replace: serve admins only, and do not
            // blocklist whitelisted users who happen to write meanwhile.
            if !std::mem::replace(&mut white.reported, true) {
                error!(path = %self.whitelist_path.display(), "the whitelist is missing; only admins are served");
            }
            return Verdict::Blocked;
        }
        white.reported = false;
        black.refresh(&self.blocklist_path);
        if black.ids.contains(&user.id) {
            return Verdict::Blocked;
        }
        black.ids.insert(user.id);
        match self.append_block(user, context) {
            Ok(()) => warn!(
                user = user.id,
                context, "blocked an account that is not on the whitelist"
            ),
            // Still blocked for this process; the file entry is what persists it.
            Err(e) => error!(user = user.id, path = %self.blocklist_path.display(), error = %e,
                             "blocked an account but could not write the blocklist"),
        }
        Verdict::NewlyBlocked
    }

    fn append_block(&self, user: &User, context: &str) -> io::Result<()> {
        let mut file: File = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.blocklist_path)?;
        if file.metadata()?.len() == 0 {
            file.write_all(BLOCKLIST_HEADER.as_bytes())?;
        }
        // Usernames are informational only; keep them to their legal charset.
        let username: String = user
            .username
            .as_deref()
            .unwrap_or("-")
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
            .take(32)
            .collect();
        // One entry per line: nothing caller-supplied may add lines.
        let context: String = context
            .chars()
            .map(|c| {
                if c.is_ascii_graphic() || c == ' ' {
                    c
                } else {
                    '?'
                }
            })
            .take(80)
            .collect();
        let line = format!(
            "{}\t# @{} blocked {} ({})\n",
            user.id,
            if username.is_empty() { "-" } else { &username },
            utc_now(),
            context
        );
        file.write_all(line.as_bytes())?;
        file.sync_data()
    }
}

/// Current UTC time as `YYYY-MM-DDTHH:MM:SSZ`.
fn utc_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    format_utc(secs)
}

fn format_utc(secs: i64) -> String {
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Civil-from-days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(id: i64, name: Option<&str>) -> User {
        User {
            id,
            is_bot: false,
            username: name.map(str::to_owned),
        }
    }

    fn lists(dir: &Path) -> AccessList {
        AccessList::new(dir.join("whitelist.cfg"), dir.join("blocklist.cfg"), &[1])
    }

    #[test]
    fn parses_ids_and_comments() {
        let ids = parse_ids("# header\n42\n  43   # friend\n\nnot-a-number\n-100 x\n44# tight\n");
        assert_eq!(ids, HashSet::from([42, 43, -100, 44]));
    }

    #[test]
    fn whitelisted_and_admins_are_allowed() {
        let dir = tempfile::tempdir().unwrap();
        let a = lists(dir.path());
        assert!(a.ensure_whitelist().unwrap());
        assert!(
            !a.ensure_whitelist().unwrap(),
            "an existing whitelist is never overwritten"
        );
        std::fs::write(a.whitelist_path(), format!("{WHITELIST_TEMPLATE}42 # me\n")).unwrap();
        assert_eq!(a.check(&user(42, None), "private chat"), Verdict::Allowed);
        assert_eq!(
            a.check(&user(1, None), "private chat"),
            Verdict::Allowed,
            "admins are always allowed"
        );
        assert!(!a.blocklist_path().exists());
        assert_eq!(a.counts(), (2, 0));
    }

    #[test]
    fn unknown_accounts_are_blocked_once_and_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let a = lists(dir.path());
        a.ensure_whitelist().unwrap();
        assert_eq!(
            a.check(&user(7, Some("spam\nmer")), "chat -1001 command /gif"),
            Verdict::NewlyBlocked
        );
        assert_eq!(a.check(&user(7, None), "private chat"), Verdict::Blocked);
        let text = std::fs::read_to_string(a.blocklist_path()).unwrap();
        assert!(text.starts_with("# Wyrmatron blocklist"));
        let entries: Vec<&str> = text.lines().filter(|l| !l.starts_with('#')).collect();
        assert_eq!(entries.len(), 1, "{text}");
        assert!(
            entries[0].starts_with("7\t# @spammer blocked 20"),
            "{}",
            entries[0]
        );
        assert!(entries[0].ends_with("(chat -1001 command /gif)"));
        // A new process reads the persisted blocklist.
        assert_eq!(
            lists(dir.path()).check(&user(7, None), "private chat"),
            Verdict::Blocked
        );
    }

    #[test]
    fn host_edits_apply_without_restart() {
        let dir = tempfile::tempdir().unwrap();
        let a = lists(dir.path());
        a.ensure_whitelist().unwrap();
        assert_eq!(
            a.check(&user(7, None), "private chat"),
            Verdict::NewlyBlocked
        );
        // Unblock by deleting the line.
        std::fs::write(a.blocklist_path(), BLOCKLIST_HEADER).unwrap();
        assert_eq!(
            a.check(&user(7, None), "private chat"),
            Verdict::NewlyBlocked,
            "still not whitelisted"
        );
        // Whitelisting overrides the blocklist entry.
        std::fs::write(a.whitelist_path(), "7\n").unwrap();
        assert_eq!(a.check(&user(7, None), "private chat"), Verdict::Allowed);
        // Removing from the whitelist blocks again on next contact.
        std::fs::write(a.whitelist_path(), "# nobody\n").unwrap();
        assert_eq!(a.check(&user(7, None), "private chat"), Verdict::Blocked);
    }

    #[test]
    fn a_missing_whitelist_blocks_without_blocklisting() {
        let dir = tempfile::tempdir().unwrap();
        let a = lists(dir.path());
        std::fs::write(a.whitelist_path(), "42\n").unwrap();
        assert_eq!(a.check(&user(42, None), "x"), Verdict::Allowed);
        std::fs::remove_file(a.whitelist_path()).unwrap();
        assert_eq!(a.check(&user(42, None), "x"), Verdict::Blocked);
        assert_eq!(a.check(&user(7, None), "x"), Verdict::Blocked);
        assert_eq!(
            a.check(&user(1, None), "x"),
            Verdict::Allowed,
            "admins are still served"
        );
        assert!(
            !a.blocklist_path().exists(),
            "nothing is recorded while the whitelist is missing"
        );
        std::fs::write(a.whitelist_path(), "42\n").unwrap();
        assert_eq!(a.check(&user(42, None), "x"), Verdict::Allowed);
        assert_eq!(a.check(&user(7, None), "x"), Verdict::NewlyBlocked);
    }

    #[test]
    fn blocks_even_when_the_blocklist_cannot_be_written() {
        let dir = tempfile::tempdir().unwrap();
        // A directory where the file should be makes the append fail.
        std::fs::create_dir(dir.path().join("blocklist.cfg")).unwrap();
        let a = lists(dir.path());
        a.ensure_whitelist().unwrap();
        assert_eq!(
            a.check(&user(9, None), "private chat"),
            Verdict::NewlyBlocked
        );
        assert_eq!(a.check(&user(9, None), "private chat"), Verdict::Blocked);
    }

    #[test]
    fn context_cannot_inject_lines() {
        let dir = tempfile::tempdir().unwrap();
        let a = lists(dir.path());
        a.ensure_whitelist().unwrap();
        a.check(
            &user(7, Some("x\n42")),
            "chat 1 command /gif\n42 # injected\r\n43",
        );
        let text = std::fs::read_to_string(a.blocklist_path()).unwrap();
        let entries: Vec<&str> = text.lines().filter(|l| !l.starts_with('#')).collect();
        assert_eq!(entries.len(), 1, "{text}");
        assert_eq!(parse_ids(&text), HashSet::from([7]));
    }

    #[test]
    fn formats_utc_dates() {
        assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_utc(1_792_738_800), "2026-10-23T07:00:00Z");
        assert_eq!(format_utc(951_782_400), "2000-02-29T00:00:00Z");
    }
}
