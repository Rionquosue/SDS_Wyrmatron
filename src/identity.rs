//! Who the process runs as, and whether its directories are usable by that
//! user. The bot runs under any UID/GID (set with `BOT_UID`/`BOT_GID`), so
//! permission problems are reported in terms the operator can act on.

use std::path::Path;

use anyhow::{Result, bail};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Identity {
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    /// UID 0 in the host's user namespace: real root, not rootless.
    pub host_root: bool,
}

impl Identity {
    pub fn current() -> Self {
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let (uid, gid) = parse_status(&status);
        let uid_map = std::fs::read_to_string("/proc/self/uid_map").unwrap_or_default();
        Self {
            uid,
            gid,
            host_root: uid == Some(0) && is_initial_namespace(&uid_map),
        }
    }

    pub fn describe(&self) -> String {
        let show = |v: Option<u32>| v.map_or_else(|| "?".to_owned(), |v| v.to_string());
        format!("uid {} gid {}", show(self.uid), show(self.gid))
    }
}

/// Effective UID and GID from `/proc/self/status`
/// (`Uid:` and `Gid:` lines list real, effective, saved and filesystem IDs).
pub fn parse_status(status: &str) -> (Option<u32>, Option<u32>) {
    let field = |name: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .and_then(|rest| rest.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
    };
    (field("Uid:"), field("Gid:"))
}

/// The initial user namespace maps every ID to itself.
pub fn is_initial_namespace(uid_map: &str) -> bool {
    let fields: Vec<&str> = uid_map.split_whitespace().collect();
    fields == ["0", "0", "4294967295"]
}

/// Creates `dir` if needed and proves a file can be written in it.
pub fn check_writable(dir: &Path, who: &Identity, purpose: &str) -> Result<()> {
    let probe = dir.join(format!(".wyrmatron-write-test-{}", std::process::id()));
    let result = std::fs::create_dir_all(dir)
        .and_then(|()| std::fs::write(&probe, b""))
        .and_then(|()| std::fs::remove_file(&probe));
    if let Err(e) = result {
        let ids = match (who.uid, who.gid) {
            (Some(u), Some(g)) => format!("{u}:{g}"),
            _ => "<uid>:<gid>".to_owned(),
        };
        bail!(
            "{purpose} {} is not writable by {} ({e}). Make it owned by that user \
             (chown -R {ids} on the host) or set BOT_UID/BOT_GID to its owner.",
            dir.display(),
            who.describe()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_effective_ids() {
        let status = "Name:\twyrmatron\nUid:\t1000\t1001\t1001\t1001\nGid:\t100\t101\t101\t101\nGroups:\t101\n";
        assert_eq!(parse_status(status), (Some(1001), Some(101)));
        assert_eq!(parse_status("Name:\tx\n"), (None, None));
    }

    #[test]
    fn recognises_the_initial_namespace() {
        assert!(is_initial_namespace("         0          0 4294967295\n"));
        // Rootless Docker/Podman: container root maps to an unprivileged host user.
        assert!(!is_initial_namespace(
            "         0       1000          1\n         1     100000      65536\n"
        ));
        assert!(!is_initial_namespace(""));
    }

    #[test]
    fn reports_unwritable_directories_with_a_fix() {
        let dir = tempfile::tempdir().unwrap();
        let who = Identity {
            uid: Some(1234),
            gid: Some(5678),
            host_root: false,
        };
        check_writable(&dir.path().join("new/sub"), &who, "Data directory").unwrap();
        // A file where the directory should be cannot be written into.
        let blocked = dir.path().join("file");
        std::fs::write(&blocked, b"x").unwrap();
        let err = check_writable(&blocked, &who, "Work directory")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("not writable by uid 1234 gid 5678") && err.contains("chown -R 1234:5678"),
            "{err}"
        );
    }

    #[test]
    fn reads_the_current_process() {
        let me = Identity::current();
        assert!(me.uid.is_some() && me.gid.is_some());
    }
}
