//! Configuration: a read-only TOML file, `WYRMATRON_*` environment overrides
//! (`__` separates nested keys) and file-mounted secrets.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use figment::Figment;
use figment::providers::{Env, Format, Toml};
use secrecy::SecretString;
use serde::Deserialize;

pub const DEFAULT_CONFIG_PATH: &str = "/etc/wyrmatron/config.toml";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Directory of the configuration file; access lists live here.
    #[serde(skip, default = "default_config_dir")]
    pub config_dir: PathBuf,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub telegram: TelegramConfig,
    #[serde(default)]
    pub ffmpeg: FfmpegConfig,
    #[serde(default)]
    pub media: MediaConfig,
    #[serde(default)]
    pub fetch: FetchConfig,
    /// Human-facing destination names mapped to Telegram chats.
    #[serde(default)]
    pub destinations: BTreeMap<String, Destination>,
    /// HTTP API consumers. Keys are stored only as SHA-256 hashes.
    #[serde(default)]
    pub consumers: Vec<ConsumerConfig>,
    /// Uptime Kuma webhook routes, keyed by route ID.
    #[serde(default)]
    pub uptime_kuma: BTreeMap<String, KumaRoute>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    /// Body limit for JSON routes (notifications, hooks, JSON media jobs).
    pub json_body_limit: usize,
    /// Concurrent requests allowed on notification and hook routes.
    pub notification_concurrency: usize,
    /// Concurrent requests allowed on media routes.
    pub media_concurrency: usize,
    pub request_timeout_secs: u64,
    /// Grace period for in-flight work after SIGTERM.
    pub shutdown_grace_secs: u64,
    pub worker_threads: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:8080".parse().expect("static address"),
            json_body_limit: 64 * 1024,
            notification_concurrency: 16,
            media_concurrency: 4,
            request_timeout_secs: 30,
            shutdown_grace_secs: 15,
            worker_threads: 2,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct StorageConfig {
    pub data_dir: PathBuf,
    pub work_dir: PathBuf,
    /// Global budget for spooled sources, results and retained downloads.
    pub work_budget_bytes: u64,
    /// Completed API results stay downloadable this long.
    pub download_retention_secs: u64,
    /// Durable sources are kept this long for retries.
    pub source_retention_secs: u64,
    /// Job, notification and error metadata retention.
    pub metadata_retention_secs: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("/data"),
            work_dir: PathBuf::from("/work"),
            work_budget_bytes: 1 << 30,
            download_retention_secs: 3600,
            source_retention_secs: 3600,
            metadata_retention_secs: 7 * 24 * 3600,
        }
    }
}

impl StorageConfig {
    pub fn database_path(&self) -> PathBuf {
        self.data_dir.join("wyrmatron.sqlite3")
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TelegramConfig {
    pub enabled: bool,
    pub api_base: String,
    pub token_file: PathBuf,
    pub poll_timeout_secs: u64,
    /// Account whitelist file (one user ID per line). Defaults to
    /// `whitelist.cfg` in the config directory.
    pub whitelist_file: Option<PathBuf>,
    /// Where non-whitelisted accounts are recorded. Defaults to
    /// `blocklist.cfg` in the config directory.
    pub blocklist_file: Option<PathBuf>,
    /// Group or channel chat IDs where commands are accepted.
    pub allowed_chats: Vec<i64>,
    /// Users who may act on any job (status/cancel). Always whitelisted.
    pub admins: Vec<i64>,
    /// Lifetime of inline action buttons.
    pub button_ttl_secs: u64,
    /// Hosted Bot API download limit for getFile.
    pub max_download_bytes: u64,
    /// Hosted Bot API upload limit.
    pub max_upload_bytes: u64,
}

impl Default for TelegramConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            api_base: "https://api.telegram.org".into(),
            token_file: PathBuf::from("/run/secrets/telegram_token"),
            poll_timeout_secs: 50,
            whitelist_file: None,
            blocklist_file: None,
            allowed_chats: Vec::new(),
            admins: Vec::new(),
            button_ttl_secs: 900,
            max_download_bytes: 20 * 1000 * 1000,
            max_upload_bytes: 50 * 1000 * 1000,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FfmpegConfig {
    pub enabled: bool,
    pub base_url: String,
    pub key_file: PathBuf,
    /// Mirrors the service's PROCESS_TIMEOUT_SECONDS when it is not advertised.
    pub process_timeout_secs: u64,
    /// Mirrors the service's UPLOAD_TIMEOUT_SECONDS when it is not advertised.
    pub upload_timeout_secs: u64,
    /// Queue allowance added to the process timeout when polling.
    pub queue_allowance_secs: u64,
    /// Retries for retryable processing failures.
    pub max_retries: u32,
}

impl Default for FfmpegConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            base_url: "http://ffmpeg:8080".into(),
            key_file: PathBuf::from("/run/secrets/ffmpeg_key"),
            process_timeout_secs: 120,
            upload_timeout_secs: 120,
            queue_allowance_secs: 180,
            max_retries: 2,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct MediaConfig {
    /// Largest source the bot downloads or accepts.
    pub max_source_bytes: u64,
    pub gif_max_seconds: f64,
    pub gif_target_bytes: u64,
    pub download_workers: usize,
    /// Unfinished jobs allowed per Telegram user or API consumer, so one
    /// account (or a compromised one) cannot flood the queue.
    pub max_active_jobs_per_owner: u32,
}

impl Default for MediaConfig {
    fn default() -> Self {
        Self {
            max_source_bytes: 200 * 1024 * 1024,
            gif_max_seconds: 30.0,
            gif_target_bytes: 8 * 1024 * 1024,
            download_workers: 2,
            max_active_jobs_per_owner: 3,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FetchConfig {
    pub fxtwitter_api: String,
    pub fxbsky_api: String,
    pub bsky_appview: String,
    pub plc_directory: String,
    pub user_agent: String,
    pub max_redirects: usize,
    pub max_metadata_bytes: u64,
    pub connect_timeout_secs: u64,
    pub total_timeout_secs: u64,
    /// Explicit proxy for the public fetch client. Never read from the
    /// environment. With a proxy, address checks happen at the proxy, so only
    /// set this in development or behind a filtering egress proxy.
    pub proxy: Option<String>,
}

impl Default for FetchConfig {
    fn default() -> Self {
        Self {
            fxtwitter_api: "https://api.fxtwitter.com".into(),
            fxbsky_api: "https://api.fxbsky.app".into(),
            bsky_appview: "https://public.api.bsky.app".into(),
            plc_directory: "https://plc.directory".into(),
            user_agent: concat!(
                "Wyrmatron/",
                env!("CARGO_PKG_VERSION"),
                " (+https://github.com/Rionquosue)"
            )
            .into(),
            max_redirects: 5,
            max_metadata_bytes: 2 * 1024 * 1024,
            connect_timeout_secs: 10,
            total_timeout_secs: 300,
            proxy: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    pub chat_id: i64,
    pub thread_id: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Notify,
    Media,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumerConfig {
    pub id: String,
    /// Lowercase hex SHA-256 of each accepted key (`wyrmatron hash-key`).
    pub key_sha256: Vec<String>,
    pub scopes: Vec<Scope>,
    /// Destination names this consumer may target.
    pub destinations: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum KumaAuth {
    /// Bearer key of a consumer with the notify scope, sent as a custom header.
    #[default]
    Bearer,
    /// The route ID itself is the credential; `secret_sha256` holds its hash.
    RouteSecret,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KumaRoute {
    pub destination: String,
    #[serde(default)]
    pub auth: KumaAuth,
    pub secret_sha256: Option<String>,
    /// Suppress PENDING (status 2) heartbeats.
    #[serde(default = "yes")]
    pub suppress_pending: bool,
    /// Suppress MAINTENANCE (status 3) heartbeats.
    #[serde(default)]
    pub suppress_maintenance: bool,
}

fn default_config_dir() -> PathBuf {
    PathBuf::from("/etc/wyrmatron")
}

fn yes() -> bool {
    true
}

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let explicit = path
            .map(Path::to_path_buf)
            .or_else(|| std::env::var_os("WYRMATRON_CONFIG").map(PathBuf::from));
        let path = explicit
            .clone()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));
        // A config that exists but cannot be read must never fall back to
        // defaults; neither may one that was named explicitly but is missing.
        std::fs::read_to_string(&path)
            .map(drop)
            .or_else(|e| match e.kind() {
                std::io::ErrorKind::NotFound if explicit.is_none() => Ok(()),
                _ => Err(e),
            })
            .with_context(|| format!("cannot read configuration {}", path.display()))?;
        let mut figment = Figment::new();
        if path.exists() {
            figment = figment.merge(Toml::file(&path));
        }
        let mut config: Config = figment
            .merge(
                Env::prefixed("WYRMATRON_")
                    .ignore(&["config", "log_format"])
                    .split("__"),
            )
            .extract()
            .with_context(|| format!("reading configuration from {}", path.display()))?;
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            config.config_dir = dir.to_path_buf();
        }
        config.validate()?;
        Ok(config)
    }

    pub fn whitelist_path(&self) -> PathBuf {
        self.telegram
            .whitelist_file
            .clone()
            .unwrap_or_else(|| self.config_dir.join("whitelist.cfg"))
    }

    pub fn blocklist_path(&self) -> PathBuf {
        self.telegram
            .blocklist_file
            .clone()
            .unwrap_or_else(|| self.config_dir.join("blocklist.cfg"))
    }

    pub fn validate(&self) -> Result<()> {
        for c in &self.consumers {
            if c.key_sha256.is_empty() {
                bail!("consumer {} has no keys", c.id);
            }
            for h in &c.key_sha256 {
                if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
                    bail!(
                        "consumer {} has a key hash that is not 64 hex characters",
                        c.id
                    );
                }
            }
            for d in &c.destinations {
                if !self.destinations.contains_key(d) {
                    bail!("consumer {} references unknown destination {d}", c.id);
                }
            }
        }
        for (id, route) in &self.uptime_kuma {
            if !self.destinations.contains_key(&route.destination) {
                bail!(
                    "Uptime Kuma route {id} references unknown destination {}",
                    route.destination
                );
            }
            if route.auth == KumaAuth::RouteSecret && route.secret_sha256.is_none() {
                bail!("Uptime Kuma route {id} uses route_secret auth without secret_sha256");
            }
        }
        if self.server.worker_threads < 2 {
            bail!(
                "server.worker_threads must be at least 2 so blocking work cannot stall notifications"
            );
        }
        if !(1.0..=600.0).contains(&self.media.gif_max_seconds) {
            bail!("media.gif_max_seconds must be between 1 and 600");
        }
        Ok(())
    }
}

/// Reads a file-mounted secret, trimming trailing whitespace.
pub fn read_secret(path: &Path) -> Result<SecretString> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading secret {}", path.display()))?;
    let value = raw.trim_end().to_owned();
    if value.is_empty() {
        bail!("secret {} is empty", path.display());
    }
    Ok(SecretString::from(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_validate() {
        let c: Config = Figment::new().extract().unwrap();
        c.validate().unwrap();
        assert_eq!(
            c.storage.database_path(),
            PathBuf::from("/data/wyrmatron.sqlite3")
        );
    }

    #[test]
    fn rejects_unknown_destination() {
        let c: Config = Figment::new()
            .merge(Toml::string(
                r#"
                [[consumers]]
                id = "kuma"
                key_sha256 = ["0000000000000000000000000000000000000000000000000000000000000000"]
                scopes = ["notify"]
                destinations = ["ops"]
                "#,
            ))
            .extract()
            .unwrap();
        assert!(
            c.validate()
                .unwrap_err()
                .to_string()
                .contains("unknown destination")
        );
    }

    #[test]
    fn missing_or_unreadable_config_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.toml");
        let err = Config::load(Some(&missing)).unwrap_err();
        assert!(
            format!("{err:#}").contains("cannot read configuration"),
            "{err:#}"
        );
        // A directory where the file should be cannot be read as a file.
        let not_a_file = dir.path().join("config.toml");
        std::fs::create_dir(&not_a_file).unwrap();
        assert!(Config::load(Some(&not_a_file)).is_err());
    }

    #[test]
    #[allow(clippy::result_large_err)]
    fn access_lists_live_next_to_the_config_file() {
        figment::Jail::expect_with(|jail| {
            jail.create_file("config.toml", "[telegram]\nadmins = [1]\n")?;
            let path = jail.directory().join("config.toml");
            let c = Config::load(Some(&path)).map_err(|e| e.to_string())?;
            assert_eq!(c.whitelist_path(), jail.directory().join("whitelist.cfg"));
            assert_eq!(c.blocklist_path(), jail.directory().join("blocklist.cfg"));
            Ok(())
        });
        let c: Config = Figment::new().extract().unwrap();
        assert_eq!(
            c.blocklist_path(),
            PathBuf::from("/etc/wyrmatron/blocklist.cfg")
        );
    }

    #[test]
    // figment::Jail's closure returns figment's large error type.
    #[allow(clippy::result_large_err)]
    fn non_config_environment_variables_are_ignored() {
        figment::Jail::expect_with(|jail| {
            jail.set_env("WYRMATRON_LOG_FORMAT", "text");
            jail.create_file("empty.toml", "")?;
            let file = jail.directory().join("empty.toml");
            jail.set_env("WYRMATRON_CONFIG", file.display());
            jail.set_env("WYRMATRON_TELEGRAM__ENABLED", "false");
            let c = Config::load(None).map_err(|e| e.to_string())?;
            assert!(!c.telegram.enabled);
            Ok(())
        });
    }

    #[test]
    fn rejects_unknown_fields() {
        let r: Result<Config, _> = Figment::new()
            .merge(Toml::string("[server]\nlisten_typo = 1"))
            .extract();
        assert!(r.is_err());
    }
}
