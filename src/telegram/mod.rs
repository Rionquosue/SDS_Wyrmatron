//! Telegram long polling. Updates are written to an inbox in the same
//! transaction that advances the offset, then processed in order within each chat (SDS §4).

pub mod access;
pub mod client;
pub mod commands;
pub mod handler;
pub mod types;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use rusqlite::params;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::db::{Db, now, set_kv};
use client::{Bot, TgError};
use handler::Handler;
use types::Update;

const OFFSET_KEY: &str = "telegram_offset";

/// Consecutive unparseable getUpdates responses before the backlog is skipped.
const UNDECODABLE_LIMIT: u32 = 3;

/// Stores raw updates and the next offset atomically. Each update is parsed
/// later on its own, so a malformed one is skipped instead of blocking the
/// queue; only `update_id` is needed here.
pub async fn store_updates(db: &Db, updates: Vec<serde_json::Value>) -> Result<usize> {
    let rows: Vec<(i64, String)> = updates
        .iter()
        .filter_map(
            |u| match u.get("update_id").and_then(serde_json::Value::as_i64) {
                Some(id) => Some((id, u.to_string())),
                None => {
                    warn!("dropping an update without a numeric update_id");
                    None
                }
            },
        )
        .collect();
    let Some(max) = rows.iter().map(|(id, _)| *id).max() else {
        return Ok(0);
    };
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
    let mut undecodable = 0u32;
    loop {
        let mut offset = match db.get_kv(OFFSET_KEY).await {
            Ok(v) => v.and_then(|s| s.parse().ok()).unwrap_or(0i64),
            Err(e) => {
                error!(error = %e, "reading the update offset failed");
                0
            }
        };
        if undecodable >= UNDECODABLE_LIMIT {
            // The pending batch can never be parsed, so the offset cannot
            // advance past it. Offset -1 confirms everything up to the newest
            // update; the skipped updates are lost, but the bot recovers.
            error!(
                failures = undecodable,
                "skipping Telegram updates that cannot be parsed"
            );
            offset = -1;
            undecodable = 0;
        }
        let result = tokio::select! {
            _ = shutdown.cancelled() => return,
            r = bot.get_updates(offset, poll_timeout) => r,
        };
        let delay = match result {
            Ok(updates) => {
                failures = 0;
                undecodable = 0;
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
            Err(TgError::Decode(e)) => {
                undecodable += 1;
                warn!(error = %e, failures = undecodable, "getUpdates returned a response that cannot be parsed");
                Some(Duration::from_secs(1))
            }
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

/// Updates handled at the same time, across all chats.
const MAX_CONCURRENT_UPDATES: usize = 32;
/// Updates dispatched to chat lanes but not yet finished.
const MAX_PENDING_UPDATES: usize = 1024;
/// A lane with nothing to do for this long shuts down.
const LANE_IDLE: Duration = Duration::from_secs(30);

/// Updates from one chat are handled in order; chats are independent, so a
/// slow chat (flood control, a slow Telegram answer) cannot hold up the rest.
fn lane_key(u: &Update) -> i64 {
    if let Some(m) = &u.message {
        return m.chat.id;
    }
    if let Some(q) = &u.callback_query {
        return q.message.as_ref().map_or(q.from.id, |m| m.chat.id);
    }
    0
}

struct Item {
    id: i64,
    update: Option<Update>,
    _pending: OwnedSemaphorePermit,
}

struct Lane {
    tx: mpsc::UnboundedSender<Item>,
    task: JoinHandle<()>,
}

struct Ctx {
    handler: Arc<Handler>,
    db: Db,
    running: Arc<Semaphore>,
    shutdown: CancellationToken,
}

impl Ctx {
    async fn process(&self, item: Item) {
        let id = item.id;
        if let Some(update) = item.update {
            let Ok(_slot) = self.running.acquire().await else {
                return;
            };
            // Each update runs in its own task so a panic affects only it.
            let h = self.handler.clone();
            match tokio::spawn(async move { h.handle(update).await }).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => warn!(update = id, error = %e, "handling update failed"),
                Err(e) => error!(update = id, error = %e, "update handler panicked"),
            }
        }
        if let Err(e) = self
            .db
            .write(move |tx| {
                Ok(tx.execute("DELETE FROM telegram_inbox WHERE update_id = ?1", [id])?)
            })
            .await
        {
            error!(error = %e, "removing a processed update failed");
        }
    }

    async fn run_lane(self: Arc<Self>, mut rx: mpsc::UnboundedReceiver<Item>) {
        loop {
            let next = tokio::select! {
                _ = self.shutdown.cancelled() => return,
                n = tokio::time::timeout(LANE_IDLE, rx.recv()) => n,
            };
            match next {
                Ok(Some(item)) => self.process(item).await,
                Ok(None) => return,
                Err(_) => break,
            }
        }
        // Idle: refuse new items (the dispatcher starts a new lane for them,
        // which waits for this one) and finish what is already queued.
        rx.close();
        while let Ok(item) = rx.try_recv() {
            if self.shutdown.is_cancelled() {
                return;
            }
            self.process(item).await;
        }
    }
}

/// Dispatches stored updates to per-chat lanes in `update_id` order. A row
/// leaves the inbox only once handled, so after a crash anything unfinished
/// is processed again, still in order within each chat.
pub async fn run_processor(
    handler: Arc<Handler>,
    db: Db,
    wake: Arc<Notify>,
    shutdown: CancellationToken,
) {
    let ctx = Arc::new(Ctx {
        handler,
        db: db.clone(),
        running: Arc::new(Semaphore::new(MAX_CONCURRENT_UPDATES)),
        shutdown: shutdown.clone(),
    });
    let pending = Arc::new(Semaphore::new(MAX_PENDING_UPDATES));
    let mut lanes: HashMap<i64, Lane> = HashMap::new();
    let mut dispatched = i64::MIN;
    'outer: loop {
        let batch: Result<Vec<(i64, String)>> = db
            .read(move |c| {
                let mut st = c.prepare(
                    "SELECT update_id, payload FROM telegram_inbox WHERE update_id > ?1 ORDER BY update_id LIMIT 100",
                )?;
                let rows = st
                    .query_map([dispatched], |r| Ok((r.get(0)?, r.get(1)?)))?
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
        lanes.retain(|_, l| !l.task.is_finished());
        for (id, payload) in batch {
            let permit = tokio::select! {
                _ = shutdown.cancelled() => break 'outer,
                p = pending.clone().acquire_owned() => match p {
                    Ok(p) => p,
                    Err(_) => break 'outer,
                },
            };
            dispatched = id;
            let update = match serde_json::from_str::<Update>(&payload) {
                Ok(u) => Some(u),
                Err(e) => {
                    warn!(update = id, error = %e, "dropping undecodable update");
                    None
                }
            };
            let key = update.as_ref().map_or(0, lane_key);
            let mut item = Item {
                id,
                update,
                _pending: permit,
            };
            let mut previous = None;
            if let Some(lane) = lanes.get(&key) {
                match lane.tx.send(item) {
                    Ok(()) => continue,
                    // The lane is shutting down; start a successor.
                    Err(mpsc::error::SendError(back)) => item = back,
                }
                previous = lanes.remove(&key).map(|l| l.task);
            }
            let (tx, rx) = mpsc::unbounded_channel();
            let _ = tx.send(item);
            let c = ctx.clone();
            let task = tokio::spawn(async move {
                if let Some(p) = previous {
                    let _ = p.await;
                }
                c.run_lane(rx).await;
            });
            lanes.insert(key, Lane { tx, task });
        }
        if idle {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = wake.notified() => {}
                _ = tokio::time::sleep(Duration::from_secs(30)) => {}
            }
        }
    }
    // Lanes finish the update in hand and stop.
    for (_, lane) in lanes {
        let _ = lane.task.await;
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
        let u = |id: i64| serde_json::json!({ "update_id": id });
        assert_eq!(store_updates(&db, vec![u(5), u(6)]).await.unwrap(), 2);
        assert_eq!(db.get_kv(OFFSET_KEY).await.unwrap().as_deref(), Some("7"));
        // A redelivered update is not stored twice.
        assert_eq!(store_updates(&db, vec![u(6), u(7)]).await.unwrap(), 1);
        assert_eq!(db.get_kv(OFFSET_KEY).await.unwrap().as_deref(), Some("8"));
        assert_eq!(store_updates(&db, vec![]).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn malformed_updates_do_not_stall_the_queue() {
        let db = Db::open_in_memory().await.unwrap();
        // Wrong types inside an update must not fail the batch.
        let batch = vec![
            serde_json::json!({ "update_id": 10, "message": { "chat": "not an object", "message_id": "x" } }),
            serde_json::json!({ "no_id": true }),
            serde_json::json!({ "update_id": 11, "message": { "message_id": 1, "chat": { "id": 5, "type": "private" } } }),
        ];
        assert_eq!(store_updates(&db, batch).await.unwrap(), 2);
        assert_eq!(db.get_kv(OFFSET_KEY).await.unwrap().as_deref(), Some("12"));
    }
}
