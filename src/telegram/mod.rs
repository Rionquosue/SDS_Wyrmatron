//! Telegram long polling. Updates are written to an inbox in the same
//! transaction that advances the offset, then processed in order (SDS §4).

pub mod access;
pub mod client;
pub mod commands;
pub mod handler;
pub mod types;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use rusqlite::params;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::db::{Db, now, set_kv};
use client::{Bot, TgError};
use handler::Handler;
use types::Update;

const OFFSET_KEY: &str = "telegram_offset";

/// Stores updates and the next offset atomically.
pub async fn store_updates(db: &Db, updates: Vec<Update>) -> Result<usize> {
    let Some(max) = updates.iter().map(|u| u.update_id).max() else {
        return Ok(0);
    };
    let rows: Vec<(i64, String)> = updates
        .iter()
        .map(|u| Ok((u.update_id, serde_json::to_string(u)?)))
        .collect::<Result<_>>()?;
    db.write(move |tx| {
        let t = now();
        let mut n = 0;
        for (id, payload) in rows {
            n += tx.execute("INSERT OR IGNORE INTO telegram_inbox (update_id, payload, received_at) VALUES (?1, ?2, ?3)", params![id, payload, t])?;
        }
        set_kv(tx, OFFSET_KEY, &(max + 1).to_string())?;
        Ok(n)
    })
    .await
}

pub async fn run_poller(
    bot: Arc<Bot>,
    db: Db,
    poll_timeout: Duration,
    wake: Arc<Notify>,
    shutdown: CancellationToken,
) {
    // Polling and webhooks are mutually exclusive.
    loop {
        match bot.delete_webhook().await {
            Ok(_) => break,
            Err(e) => {
                warn!(error = %e, "deleteWebhook failed; retrying");
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = tokio::time::sleep(Duration::from_secs(10)) => {}
                }
            }
        }
    }
    let mut failures = 0u32;
    loop {
        let offset = match db.get_kv(OFFSET_KEY).await {
            Ok(v) => v.and_then(|s| s.parse().ok()).unwrap_or(0i64),
            Err(e) => {
                error!(error = %e, "reading the update offset failed");
                0
            }
        };
        let result = tokio::select! {
            _ = shutdown.cancelled() => return,
            r = bot.get_updates(offset, poll_timeout) => r,
        };
        let delay = match result {
            Ok(updates) => {
                failures = 0;
                match store_updates(&db, updates).await {
                    Ok(0) => None,
                    Ok(n) => {
                        wake.notify_one();
                        tracing::debug!(count = n, "stored Telegram updates");
                        None
                    }
                    Err(e) => {
                        error!(error = %e, "storing Telegram updates failed");
                        Some(Duration::from_secs(5))
                    }
                }
            }
            Err(TgError::RetryAfter(s)) => Some(Duration::from_secs(s)),
            Err(e) => {
                failures += 1;
                warn!(error = %e, failures, "getUpdates failed");
                Some(Duration::from_secs((1u64 << failures.min(5)).min(30)))
            }
        };
        if let Some(d) = delay {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(d) => {}
            }
        }
    }
}

/// Processes stored updates in order. Each update runs in its own task so a
/// panic affects only that update.
pub async fn run_processor(
    handler: Arc<Handler>,
    db: Db,
    wake: Arc<Notify>,
    shutdown: CancellationToken,
) {
    loop {
        let batch: Result<Vec<(i64, String)>> = db
            .read(|c| {
                let mut st = c.prepare(
                    "SELECT update_id, payload FROM telegram_inbox ORDER BY update_id LIMIT 20",
                )?;
                let rows = st
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .await;
        let batch = match batch {
            Ok(b) => b,
            Err(e) => {
                error!(error = %e, "reading the Telegram inbox failed");
                Vec::new()
            }
        };
        let idle = batch.is_empty();
        for (id, payload) in batch {
            if shutdown.is_cancelled() {
                return;
            }
            match serde_json::from_str::<Update>(&payload) {
                Ok(update) => {
                    let h = handler.clone();
                    match tokio::spawn(async move { h.handle(update).await }).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => warn!(update = id, error = %e, "handling update failed"),
                        Err(e) => error!(update = id, error = %e, "update handler panicked"),
                    }
                }
                Err(e) => warn!(update = id, error = %e, "dropping undecodable update"),
            }
            if let Err(e) = db
                .write(move |tx| {
                    Ok(tx.execute("DELETE FROM telegram_inbox WHERE update_id = ?1", [id])?)
                })
                .await
            {
                error!(error = %e, "removing a processed update failed");
            }
        }
        if idle {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = wake.notified() => {}
                _ = tokio::time::sleep(Duration::from_secs(30)) => {}
            }
        }
    }
}

pub async fn log_identity(bot: &Bot) -> Result<String> {
    let me = bot.get_me().await?;
    let name = me.username.unwrap_or_default();
    info!(bot = %name, id = me.id, "connected to Telegram");
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stores_updates_and_offset_atomically() {
        let db = Db::open_in_memory().await.unwrap();
        let u = |id| Update {
            update_id: id,
            message: None,
            callback_query: None,
        };
        assert_eq!(store_updates(&db, vec![u(5), u(6)]).await.unwrap(), 2);
        assert_eq!(db.get_kv(OFFSET_KEY).await.unwrap().as_deref(), Some("7"));
        // A redelivered update is not stored twice.
        assert_eq!(store_updates(&db, vec![u(6), u(7)]).await.unwrap(), 1);
        assert_eq!(db.get_kv(OFFSET_KEY).await.unwrap().as_deref(), Some("8"));
        assert_eq!(store_updates(&db, vec![]).await.unwrap(), 0);
    }
}
