//! Notification outbox (SDS §9). Requests are acknowledged only after a row
//! is stored; a dedicated worker delivers rows with retries, so media work can
//! never block notifications.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use rusqlite::{OptionalExtension, params};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::db::{Db, now};
use crate::text;

const MAX_ATTEMPTS: i64 = 12;
const LEASE_SECS: i64 = 120;

/// Outcome of sending one message, as reported by a [`MessageSink`].
#[derive(Debug)]
pub enum SendError {
    /// Telegram asked us to wait (429 `retry_after`).
    RetryAfter(Duration),
    /// Network or 5xx failure before Telegram accepted the message.
    Transient(String),
    /// The request may have been delivered (timeout after sending).
    Ambiguous(String),
    /// Telegram rejected the message; retrying will not help.
    Permanent(String),
}

#[async_trait]
pub trait MessageSink: Send + Sync {
    async fn send_html(
        &self,
        chat_id: i64,
        thread_id: Option<i64>,
        html: &str,
    ) -> Result<(), SendError>;
}

pub struct NewNotification {
    pub consumer: String,
    pub destination: String,
    pub chat_id: i64,
    pub thread_id: Option<i64>,
    pub body_html: String,
    pub severity: Option<String>,
    pub source: Option<String>,
    pub dedupe_key: Option<String>,
    /// Hash of the normalized request, to detect a reused key with a new body.
    pub request_hash: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Enqueued {
    Accepted(String),
    Duplicate(String),
    Conflict,
}

pub async fn enqueue(db: &Db, n: NewNotification) -> Result<Enqueued> {
    db.write(move |tx| {
        if let Some(key) = &n.dedupe_key {
            let existing: Option<(String, String)> = tx
                .query_row(
                    "SELECT id, request_hash FROM notifications WHERE consumer = ?1 AND dedupe_key = ?2",
                    params![n.consumer, key],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if let Some((id, hash)) = existing {
                return Ok(if hash == n.request_hash { Enqueued::Duplicate(id) } else { Enqueued::Conflict });
            }
        }
        let id = uuid::Uuid::now_v7().simple().to_string();
        let t = now();
        tx.execute(
            "INSERT INTO notifications (id, consumer, destination, chat_id, thread_id, body_html, severity, source,
                                        dedupe_key, request_hash, state, next_attempt_at, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'pending', ?11, ?11, ?11)",
            params![
                id,
                n.consumer,
                n.destination,
                n.chat_id,
                n.thread_id,
                n.body_html,
                n.severity,
                n.source,
                n.dedupe_key,
                n.request_hash,
                t
            ],
        )?;
        Ok(Enqueued::Accepted(id))
    })
    .await
}

#[derive(Debug)]
struct Claimed {
    id: String,
    chat_id: i64,
    thread_id: Option<i64>,
    body_html: String,
    parts_sent: i64,
    attempts: i64,
}

async fn claim(db: &Db) -> Result<Option<Claimed>> {
    db.write(|tx| {
        let t = now();
        // Leases left by a crash are reclaimed once they expire.
        Ok(tx
            .query_row(
                "UPDATE notifications SET state = 'sending', lease_until = ?1 + ?2, attempts = attempts + 1, updated_at = ?1
                 WHERE id = (SELECT id FROM notifications
                             WHERE (state = 'pending' AND next_attempt_at <= ?1)
                                OR (state = 'sending' AND lease_until < ?1)
                             ORDER BY next_attempt_at, created_at LIMIT 1)
                 RETURNING id, chat_id, thread_id, body_html, parts_sent, attempts",
                params![t, LEASE_SECS],
                |r| {
                    Ok(Claimed {
                        id: r.get(0)?,
                        chat_id: r.get(1)?,
                        thread_id: r.get(2)?,
                        body_html: r.get(3)?,
                        parts_sent: r.get(4)?,
                        attempts: r.get(5)?,
                    })
                },
            )
            .optional()?)
    })
    .await
}

fn backoff(attempts: i64) -> i64 {
    (5i64 << attempts.clamp(0, 8)).min(1800)
}

async fn deliver(db: &Db, sink: &dyn MessageSink, n: Claimed) -> Result<()> {
    let parts = text::split_html(&n.body_html, text::MESSAGE_LIMIT);
    let mut sent = n.parts_sent as usize;
    let mut uncertain = false;
    let mut failure: Option<(SendError, i64)> = None;
    while sent < parts.len() {
        match sink.send_html(n.chat_id, n.thread_id, &parts[sent]).await {
            Ok(()) => {
                sent += 1;
                let (id, s) = (n.id.clone(), sent as i64);
                db.write(move |tx| {
                    tx.execute(
                        "UPDATE notifications SET parts_sent = ?2, updated_at = ?3 WHERE id = ?1",
                        params![id, s, now()],
                    )?;
                    Ok(())
                })
                .await?;
            }
            Err(e) => {
                let delay = match &e {
                    SendError::RetryAfter(d) => d.as_secs() as i64 + 1,
                    SendError::Ambiguous(_) => {
                        // At-least-once: retry, but record that a duplicate is possible.
                        uncertain = true;
                        backoff(n.attempts)
                    }
                    _ => backoff(n.attempts),
                };
                failure = Some((e, delay));
                break;
            }
        }
    }
    let id = n.id.clone();
    match failure {
        None => {
            db.write(move |tx| {
                tx.execute(
                    "UPDATE notifications SET state = 'sent', lease_until = NULL, last_error = NULL, updated_at = ?2 WHERE id = ?1",
                    params![id, now()],
                )?;
                Ok(())
            })
            .await?;
            info!(notification = %n.id, parts = parts.len(), "notification delivered");
        }
        Some((e, delay)) => {
            let permanent = matches!(e, SendError::Permanent(_)) || n.attempts >= MAX_ATTEMPTS;
            let message = match &e {
                SendError::RetryAfter(d) => format!("rate limited for {}s", d.as_secs()),
                SendError::Transient(m) | SendError::Ambiguous(m) | SendError::Permanent(m) => {
                    m.clone()
                }
            };
            warn!(notification = %n.id, attempts = n.attempts, permanent, error = %message, "notification delivery failed");
            db.write(move |tx| {
                let t = now();
                tx.execute(
                    "UPDATE notifications SET state = ?2, next_attempt_at = ?3, lease_until = NULL, last_error = ?4,
                         uncertain = uncertain OR ?5, updated_at = ?6 WHERE id = ?1",
                    params![id, if permanent { "failed" } else { "pending" }, t + delay, message, uncertain, t],
                )?;
                Ok(())
            })
            .await?;
        }
    }
    Ok(())
}

/// Delivers due notifications until `shutdown` fires. `wake` is notified when
/// new rows are stored so delivery starts immediately.
pub async fn run_worker(
    db: Db,
    sink: Arc<dyn MessageSink>,
    wake: Arc<Notify>,
    shutdown: CancellationToken,
) {
    loop {
        match claim(&db).await {
            Ok(Some(n)) => {
                if let Err(e) = deliver(&db, sink.as_ref(), n).await {
                    warn!(error = %e, "notification bookkeeping failed");
                }
                continue;
            }
            Ok(None) => {}
            Err(e) => warn!(error = %e, "claiming notifications failed"),
        }
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = wake.notified() => {}
            _ = tokio::time::sleep(Duration::from_secs(5)) => {}
        }
    }
}

/// Removes delivered and failed notifications older than `retention_secs`.
pub async fn prune(db: &Db, retention_secs: u64) -> Result<usize> {
    let cutoff = now() - retention_secs as i64;
    db.write(move |tx| {
        Ok(tx.execute(
            "DELETE FROM notifications WHERE state IN ('sent', 'failed') AND updated_at < ?1",
            [cutoff],
        )?)
    })
    .await
}

#[cfg(test)]
pub mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    pub struct RecordingSink {
        pub sent: Mutex<Vec<(i64, Option<i64>, String)>>,
        pub fail_next: Mutex<Vec<SendError>>,
    }

    #[async_trait]
    impl MessageSink for RecordingSink {
        async fn send_html(
            &self,
            chat_id: i64,
            thread_id: Option<i64>,
            html: &str,
        ) -> Result<(), SendError> {
            if let Some(e) = self.fail_next.lock().unwrap().pop() {
                return Err(e);
            }
            self.sent
                .lock()
                .unwrap()
                .push((chat_id, thread_id, html.to_owned()));
            Ok(())
        }
    }

    pub fn sample(key: Option<&str>, body: &str) -> NewNotification {
        NewNotification {
            consumer: "kuma".into(),
            destination: "ops".into(),
            chat_id: -100123,
            thread_id: Some(7),
            body_html: body.into(),
            severity: Some("critical".into()),
            source: None,
            dedupe_key: key.map(str::to_owned),
            request_hash: format!("hash-{body}"),
        }
    }

    async fn state(db: &Db, id: &str) -> (String, i64, i64) {
        let id = id.to_owned();
        db.read(move |c| {
            Ok(c.query_row(
                "SELECT state, parts_sent, uncertain FROM notifications WHERE id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?)
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn dedupes_and_detects_conflicts() {
        let db = Db::open_in_memory().await.unwrap();
        let Enqueued::Accepted(id) = enqueue(&db, sample(Some("e1"), "down")).await.unwrap() else {
            panic!()
        };
        assert_eq!(
            enqueue(&db, sample(Some("e1"), "down")).await.unwrap(),
            Enqueued::Duplicate(id)
        );
        assert_eq!(
            enqueue(&db, sample(Some("e1"), "up")).await.unwrap(),
            Enqueued::Conflict
        );
        assert!(matches!(
            enqueue(&db, sample(None, "x")).await.unwrap(),
            Enqueued::Accepted(_)
        ));
    }

    #[tokio::test]
    async fn delivers_split_messages_and_resumes_after_failure() {
        let db = Db::open_in_memory().await.unwrap();
        let body = format!("{}\n{}", "a".repeat(3000), "b".repeat(3000));
        let Enqueued::Accepted(id) = enqueue(&db, sample(None, &body)).await.unwrap() else {
            panic!()
        };
        let sink = RecordingSink::default();
        // The second part times out: the first part must not be resent.
        let first = claim(&db).await.unwrap().unwrap();
        deliver(
            &db,
            &FailSecond {
                inner: &sink,
                calls: Mutex::new(0),
            },
            first,
        )
        .await
        .unwrap();
        assert_eq!(state(&db, &id).await, ("pending".into(), 1, 1));
        assert_eq!(sink.sent.lock().unwrap().len(), 1);
        // Make it due and retry.
        db.write(|tx| Ok(tx.execute("UPDATE notifications SET next_attempt_at = 0", [])?))
            .await
            .unwrap();
        let again = claim(&db).await.unwrap().unwrap();
        deliver(&db, &sink, again).await.unwrap();
        assert_eq!(state(&db, &id).await.0, "sent");
        let sent = sink.sent.lock().unwrap();
        assert_eq!(sent.len(), 2);
        assert!(sent[0].2.starts_with('a') && sent[1].2.starts_with('b'));
        assert_eq!(sent[0].1, Some(7));
    }

    struct FailSecond<'a> {
        inner: &'a RecordingSink,
        calls: Mutex<usize>,
    }

    #[async_trait]
    impl MessageSink for FailSecond<'_> {
        async fn send_html(
            &self,
            chat_id: i64,
            thread_id: Option<i64>,
            html: &str,
        ) -> Result<(), SendError> {
            let n = {
                let mut c = self.calls.lock().unwrap();
                *c += 1;
                *c
            };
            if n == 2 {
                return Err(SendError::Ambiguous("timeout".into()));
            }
            self.inner.send_html(chat_id, thread_id, html).await
        }
    }

    #[tokio::test]
    async fn permanent_errors_fail_without_retry() {
        let db = Db::open_in_memory().await.unwrap();
        let Enqueued::Accepted(id) = enqueue(&db, sample(None, "x")).await.unwrap() else {
            panic!()
        };
        let sink = RecordingSink::default();
        sink.fail_next
            .lock()
            .unwrap()
            .push(SendError::Permanent("chat not found".into()));
        let n = claim(&db).await.unwrap().unwrap();
        deliver(&db, &sink, n).await.unwrap();
        assert_eq!(state(&db, &id).await.0, "failed");
        assert!(claim(&db).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn expired_leases_are_reclaimed() {
        let db = Db::open_in_memory().await.unwrap();
        enqueue(&db, sample(None, "x")).await.unwrap();
        claim(&db).await.unwrap().unwrap();
        assert!(
            claim(&db).await.unwrap().is_none(),
            "leased row must not be claimed twice"
        );
        db.write(|tx| Ok(tx.execute("UPDATE notifications SET lease_until = 0", [])?))
            .await
            .unwrap();
        assert!(claim(&db).await.unwrap().is_some());
    }
}
