//! Process assembly: configuration, runtime, background tasks and graceful
//! shutdown (SDS §2, Runtime behaviour).

use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::sync::Notify;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::api::{self, AppState, StatusProvider};
use crate::config::{Config, read_secret};
use crate::db::Db;
use crate::extract::Extractor;
use crate::fetch::Fetcher;
use crate::ffmpeg::FfmpegClient;
use crate::identity::{Identity, check_writable};
use crate::media::service::MediaService;
use crate::notify::{self, MessageSink, SendError};
use crate::telegram::access::AccessList;
use crate::telegram::client::Bot;
use crate::telegram::handler::Handler;
use crate::{media, telegram};

pub fn serve() -> ExitCode {
    init_logging();
    let config = match Config::load(None) {
        Ok(c) => c,
        Err(e) => {
            error!(error = format!("{e:#}"), "invalid configuration");
            return ExitCode::FAILURE;
        }
    };
    // Sized explicitly: the cgroup CPU quota would otherwise yield one worker
    // thread, and the default blocking pool allows 512 threads.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(config.server.worker_threads)
        .max_blocking_threads(8)
        .thread_name("wyrmatron")
        .enable_all()
        .build();
    let runtime = match runtime {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "building the runtime failed");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!(error = format!("{e:#}"), "fatal error");
            ExitCode::FAILURE
        }
    }
}

fn init_logging() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let json = std::env::var("WYRMATRON_LOG_FORMAT")
        .map(|v| v != "text")
        .unwrap_or(true);
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);
    if json {
        builder.json().init();
    } else {
        builder.init();
    }
}

/// Used when Telegram is disabled: notifications stay queued.
struct NoTelegram;

#[async_trait]
impl MessageSink for NoTelegram {
    async fn send_html(&self, _: i64, _: Option<i64>, _: &str) -> Result<(), SendError> {
        Err(SendError::Transient("Telegram is disabled".into()))
    }
}

struct NoMedia;

impl StatusProvider for NoMedia {
    fn capabilities(&self) -> serde_json::Value {
        serde_json::json!({ "media": { "available": false } })
    }
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut term =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "cannot listen for SIGTERM");
                    let _ = ctrl_c.await;
                    return;
                }
            };
        tokio::select! {
            _ = ctrl_c => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = ctrl_c.await;
}

async fn run(config: Config) -> Result<()> {
    crate::http::init_tls();
    let config = Arc::new(config);
    let me = Identity::current();
    info!(version = env!("CARGO_PKG_VERSION"), user = %me.describe(), "starting Wyrmatron");
    if me.host_root {
        warn!("running as root on the host; set BOT_UID/BOT_GID to an unprivileged user");
    }
    // Fail early, with a fix, if the mounted directories don't belong to us.
    check_writable(&config.storage.data_dir, &me, "Data directory")?;
    check_writable(&config.storage.work_dir.join("jobs"), &me, "Work directory")?;
    if config.telegram.enabled {
        // Not fatal: blocked accounts are still ignored, just not persisted.
        if let Some(dir) = config.blocklist_path().parent()
            && let Err(e) = check_writable(dir, &me, "Config directory (for blocklist.cfg)")
        {
            warn!(error = format!("{e:#}"), "the blocklist cannot be saved");
        }
    }
    let db = Db::open(&config.storage.database_path()).await?;
    let shutdown = CancellationToken::new();
    let mut tasks = JoinSet::new();

    // Telegram.
    let bot = if config.telegram.enabled {
        let token = read_secret(&config.telegram.token_file)?;
        let http = crate::http::builder()
            .connect_timeout(Duration::from_secs(10))
            .build()?;
        Some(Arc::new(Bot::new(http, &config.telegram.api_base, token)))
    } else {
        warn!("Telegram is disabled; notifications will stay queued");
        None
    };

    // Notification outbox: its own worker, independent of media.
    let outbox = Arc::new(Notify::new());
    let sink: Arc<dyn MessageSink> = match &bot {
        Some(b) => b.clone(),
        None => Arc::new(NoTelegram),
    };
    tasks.spawn(notify::run_worker(
        db.clone(),
        sink,
        outbox.clone(),
        shutdown.clone(),
    ));

    // Media.
    let fetcher = Arc::new(Fetcher::new(&config.fetch)?);
    let extractor = Arc::new(Extractor::new(fetcher.clone(), &config.fetch)?);
    let ffmpeg = if config.ffmpeg.enabled {
        let key = read_secret(&config.ffmpeg.key_file)?;
        Some(Arc::new(FfmpegClient::new(
            &config.ffmpeg.base_url,
            key,
            db.clone(),
            config.ffmpeg.clone(),
        )?))
    } else {
        warn!("FFmpeg service disabled; only /fetch and notifications are available");
        None
    };
    let media_wake = Arc::new(Notify::new());
    let media = Arc::new(MediaService {
        db: db.clone(),
        config: config.clone(),
        ffmpeg: ffmpeg.clone(),
        extractor,
        fetcher,
        bot: bot.clone(),
        wake: media_wake,
        running: Mutex::new(Default::default()),
    });
    if let Some(client) = ffmpeg.clone() {
        let stop = shutdown.clone();
        tasks.spawn(async move {
            client.recover_after_restart().await;
            capabilities_loop(client, stop).await;
        });
    }
    for n in 0..config.media.download_workers.max(1) {
        tasks.spawn(media::pipeline::run_worker(
            media.clone(),
            format!("media-{n}"),
            shutdown.clone(),
        ));
    }

    // Telegram polling and update processing.
    if let Some(bot) = bot.clone() {
        let username = loop {
            match telegram::log_identity(&bot).await {
                Ok(name) => break name,
                Err(e) => {
                    warn!(error = %e, "getMe failed; retrying");
                    tokio::select! {
                        _ = shutdown_signal() => return Ok(()),
                        _ = tokio::time::sleep(Duration::from_secs(10)) => {}
                    }
                }
            }
        };
        let access = Arc::new(AccessList::new(
            config.whitelist_path(),
            config.blocklist_path(),
            &config.telegram.admins,
        ));
        match access.ensure_whitelist() {
            Ok(true) => {
                info!(path = %access.whitelist_path().display(), "created an empty account whitelist")
            }
            Ok(false) => {}
            Err(e) => {
                warn!(path = %access.whitelist_path().display(), error = %e, "cannot create the account whitelist")
            }
        }
        let (whitelisted, blocked) = access.counts();
        info!(whitelisted, blocked, blocklist = %access.blocklist_path().display(), "account access lists loaded");
        if whitelisted == 0 {
            warn!(
                "the account whitelist is empty and there are no admins: every account will be blocked"
            );
        }
        let handler = Arc::new(Handler {
            bot: bot.clone(),
            db: db.clone(),
            config: config.clone(),
            username,
            media: media.clone(),
            access,
        });
        let inbox = Arc::new(Notify::new());
        let poll = Duration::from_secs(config.telegram.poll_timeout_secs);
        tasks.spawn(telegram::run_poller(
            bot,
            db.clone(),
            poll,
            inbox.clone(),
            shutdown.clone(),
        ));
        tasks.spawn(telegram::run_processor(
            handler,
            db.clone(),
            inbox,
            shutdown.clone(),
        ));
    }

    tasks.spawn(maintenance(db.clone(), media.clone(), shutdown.clone()));

    // HTTP API.
    let state = AppState {
        config: config.clone(),
        db: db.clone(),
        consumers: Arc::new(api::auth::Consumers::new(&config.consumers)),
        outbox,
        status: if config.ffmpeg.enabled {
            media.clone()
        } else {
            Arc::new(NoMedia)
        },
        media: Some(media.clone()),
    };
    let listener = tokio::net::TcpListener::bind(config.server.listen)
        .await
        .with_context(|| format!("binding {}", config.server.listen))?;
    info!(addr = %config.server.listen, "HTTP API listening");
    let stop = shutdown.clone();
    let server = axum::serve(listener, api::router(state)).with_graceful_shutdown(async move {
        shutdown_signal().await;
        info!("shutdown requested");
        stop.cancel();
    });
    let served = server.await;
    shutdown.cancel();

    // Let workers release leases and finish bookkeeping.
    let grace = Duration::from_secs(config.server.shutdown_grace_secs);
    let drained =
        tokio::time::timeout(grace, async { while tasks.join_next().await.is_some() {} }).await;
    if drained.is_err() {
        warn!("background tasks did not stop within the grace period");
        tasks.abort_all();
    }
    release_leases(&db).await;
    info!("stopped");
    served.context("HTTP server")
}

/// Jobs interrupted by shutdown become claimable immediately on restart.
async fn release_leases(db: &Db) {
    let r = db
        .write(|tx| {
            Ok(tx.execute(
                &format!(
                    "UPDATE jobs SET lease_until = 0, lease_owner = NULL WHERE state IN ({})",
                    media::jobs::ACTIVE_STATES
                ),
                [],
            )?)
        })
        .await;
    if let Err(e) = r {
        warn!(error = %e, "releasing job leases failed");
    }
}

/// Keeps FFmpeg capabilities fresh so restarts and upgrades are noticed.
async fn capabilities_loop(client: Arc<FfmpegClient>, stop: CancellationToken) {
    let mut failures = 0u32;
    loop {
        let wait = match client.refresh_capabilities().await {
            Ok(_) => {
                failures = 0;
                client.sweep_cleanup().await;
                Duration::from_secs(300)
            }
            Err(e) => {
                failures += 1;
                if failures == 1 || failures.is_multiple_of(10) {
                    warn!(error = %e, failures, "FFmpeg service capabilities unavailable");
                }
                Duration::from_secs(30)
            }
        };
        tokio::select! {
            _ = stop.cancelled() => return,
            _ = tokio::time::sleep(wait) => {}
        }
    }
}

async fn maintenance(db: Db, media: Arc<MediaService>, stop: CancellationToken) {
    loop {
        tokio::select! {
            _ = stop.cancelled() => return,
            _ = tokio::time::sleep(Duration::from_secs(600)) => {}
        }
        let retention = media.config.storage.metadata_retention_secs;
        if let Err(e) = notify::prune(&db, retention).await {
            warn!(error = %e, "pruning notifications failed");
        }
        if let Err(e) = telegram::handler::prune_tokens(&db).await {
            warn!(error = %e, "pruning callback tokens failed");
        }
        if let Err(e) = media::pipeline::housekeeping(&media).await {
            warn!(error = %e, "media housekeeping failed");
        }
        if let Err(e) = db.checkpoint().await {
            warn!(error = %e, "WAL checkpoint failed");
        }
    }
}
