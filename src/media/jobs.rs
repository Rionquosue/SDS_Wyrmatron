//! Media job records (SDS §10).

use anyhow::Result;
use rusqlite::{OptionalExtension, Row, params};
use serde::Serialize;

use super::spec::{Action, JobOptions};
use crate::db::{Db, now};

pub const ACTIVE_STATES: &str = "'queued', 'resolving', 'downloading', 'processing', 'delivering'";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    Url,
    Upload,
    TelegramFile,
}

impl SourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Url => "url",
            Self::Upload => "upload",
            Self::TelegramFile => "telegram_file",
        }
    }
    fn parse(s: &str) -> Self {
        match s {
            "upload" => Self::Upload,
            "telegram_file" => Self::TelegramFile,
            _ => Self::Url,
        }
    }
}

#[derive(Debug, Clone)]
pub struct JobRow {
    pub id: String,
    pub owner_kind: String,
    pub owner_id: String,
    pub action: Action,
    pub options: JobOptions,
    pub source_kind: SourceKind,
    pub source_ref: String,
    pub destination: Option<String>,
    pub chat_id: Option<i64>,
    pub thread_id: Option<i64>,
    pub reply_to: Option<i64>,
    pub status_message: Option<i64>,
    pub state: String,
    pub detail: Option<String>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub attempts: i64,
    pub cancel_requested: bool,
    pub source_path: Option<String>,
    pub input_bytes: Option<i64>,
    pub result_path: Option<String>,
    pub result_size: Option<i64>,
    pub result_sha256: Option<String>,
    pub result_type: Option<String>,
    pub delivery_uncertain: bool,
    pub created_at: i64,
    pub completed_at: Option<i64>,
    pub expires_at: Option<i64>,
}

pub const COLUMNS: &str = "id, owner_kind, owner_id, action, options, source_kind, source_ref, destination, chat_id, thread_id,
    reply_to, status_message, state, detail, error_code, error_message, attempts, cancel_requested, source_path, input_bytes,
    result_path, result_size, result_sha256, result_type, delivery_uncertain, created_at, completed_at, expires_at";

impl JobRow {
    pub fn from_row(r: &Row<'_>) -> rusqlite::Result<Self> {
        let action: String = r.get(3)?;
        let options: String = r.get(4)?;
        let source_kind: String = r.get(5)?;
        Ok(Self {
            id: r.get(0)?,
            owner_kind: r.get(1)?,
            owner_id: r.get(2)?,
            action: action.parse().unwrap_or(Action::Fetch),
            options: serde_json::from_str(&options).unwrap_or_default(),
            source_kind: SourceKind::parse(&source_kind),
            source_ref: r.get(6)?,
            destination: r.get(7)?,
            chat_id: r.get(8)?,
            thread_id: r.get(9)?,
            reply_to: r.get(10)?,
            status_message: r.get(11)?,
            state: r.get(12)?,
            detail: r.get(13)?,
            error_code: r.get(14)?,
            error_message: r.get(15)?,
            attempts: r.get(16)?,
            cancel_requested: r.get(17)?,
            source_path: r.get(18)?,
            input_bytes: r.get(19)?,
            result_path: r.get(20)?,
            result_size: r.get(21)?,
            result_sha256: r.get(22)?,
            result_type: r.get(23)?,
            delivery_uncertain: r.get(24)?,
            created_at: r.get(25)?,
            completed_at: r.get(26)?,
            expires_at: r.get(27)?,
        })
    }

    pub fn is_active(&self) -> bool {
        matches!(
            self.state.as_str(),
            "queued" | "resolving" | "downloading" | "processing" | "delivering"
        )
    }

    /// Ownership check for status, cancellation and downloads (SDS §10).
    pub fn owned_by(&self, kind: &str, id: &str) -> bool {
        self.owner_kind == kind && self.owner_id == id
    }
}

/// API representation of a job.
#[derive(Debug, Serialize)]
pub struct JobView {
    pub job_id: String,
    pub action: Action,
    pub destination: Option<String>,
    pub state: String,
    pub detail: Option<String>,
    pub error: Option<serde_json::Value>,
    pub result: Option<serde_json::Value>,
    pub delivery_uncertain: bool,
    pub created_at: i64,
    pub completed_at: Option<i64>,
    pub expires_at: Option<i64>,
    pub status_url: String,
    pub download_url: Option<String>,
}

impl From<&JobRow> for JobView {
    fn from(j: &JobRow) -> Self {
        let downloadable = j.state == "completed"
            && j.result_path.is_some()
            && j.expires_at.is_some_and(|e| e > now());
        Self {
            job_id: j.id.clone(),
            action: j.action,
            destination: j.destination.clone(),
            state: j.state.clone(),
            detail: j.detail.clone(),
            error: j.error_code.as_ref().map(|c| serde_json::json!({ "code": c, "message": j.error_message })),
            result: j.result_size.map(|s| {
                serde_json::json!({ "size_bytes": s, "sha256": j.result_sha256, "content_type": j.result_type, "input_bytes": j.input_bytes })
            }),
            delivery_uncertain: j.delivery_uncertain,
            created_at: j.created_at,
            completed_at: j.completed_at,
            expires_at: j.expires_at,
            status_url: format!("/v1/jobs/{}", j.id),
            download_url: downloadable.then(|| format!("/v1/jobs/{}/download", j.id)),
        }
    }
}

pub struct NewJob {
    pub owner_kind: &'static str,
    pub owner_id: String,
    pub idempotency_key: Option<String>,
    pub request_hash: Option<String>,
    pub action: Action,
    pub options: JobOptions,
    pub source_kind: SourceKind,
    pub source_ref: String,
    pub source_path: Option<String>,
    pub input_bytes: Option<i64>,
    pub destination: Option<String>,
    pub chat_id: Option<i64>,
    pub thread_id: Option<i64>,
    pub reply_to: Option<i64>,
    pub status_message: Option<i64>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Created {
    New(String),
    Existing(String),
    Conflict,
    /// The owner already has this many unfinished jobs.
    Limited(u32),
}

pub fn new_id() -> String {
    uuid::Uuid::now_v7().simple().to_string()
}

/// Inserts a queued job without a per-owner limit (tests only).
#[cfg(test)]
pub async fn create(db: &Db, id: String, job: NewJob) -> Result<Created> {
    create_limited(db, id, job, None).await
}

/// Inserts a queued job, honouring the owner's idempotency key and refusing
/// a new job while the owner already has
/// `max_active` unfinished ones. The count and insert share a transaction.
pub async fn create_limited(
    db: &Db,
    id: String,
    job: NewJob,
    max_active: Option<u32>,
) -> Result<Created> {
    db.write(move |tx| {
        if let Some(key) = &job.idempotency_key {
            let existing: Option<(String, Option<String>)> = tx
                .query_row(
                    "SELECT id, request_hash FROM jobs WHERE owner_kind = ?1 AND owner_id = ?2 AND idempotency_key = ?3",
                    params![job.owner_kind, job.owner_id, key],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if let Some((existing, hash)) = existing {
                return Ok(if hash == job.request_hash { Created::Existing(existing) } else { Created::Conflict });
            }
        }
        if let Some(max) = max_active {
            let active: u32 = tx.query_row(
                &format!("SELECT COUNT(*) FROM jobs WHERE owner_kind = ?1 AND owner_id = ?2 AND state IN ({ACTIVE_STATES})"),
                params![job.owner_kind, job.owner_id],
                |r| r.get(0),
            )?;
            if active >= max {
                return Ok(Created::Limited(max));
            }
        }
        let t = now();
        tx.execute(
            "INSERT INTO jobs (id, owner_kind, owner_id, idempotency_key, request_hash, action, options, source_kind, source_ref,
                               source_path, input_bytes, destination, chat_id, thread_id, reply_to, status_message, state,
                               created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, 'queued', ?17, ?17)",
            params![
                id,
                job.owner_kind,
                job.owner_id,
                job.idempotency_key,
                job.request_hash,
                job.action.as_str(),
                serde_json::to_string(&job.options)?,
                job.source_kind.as_str(),
                job.source_ref,
                job.source_path,
                job.input_bytes,
                job.destination,
                job.chat_id,
                job.thread_id,
                job.reply_to,
                job.status_message,
                t
            ],
        )?;
        Ok(Created::New(id))
    })
    .await
}

pub async fn get(db: &Db, id: &str) -> Result<Option<JobRow>> {
    let id = id.to_owned();
    db.read(move |c| {
        Ok(c.query_row(
            &format!("SELECT {COLUMNS} FROM jobs WHERE id = ?1"),
            [id],
            JobRow::from_row,
        )
        .optional()?)
    })
    .await
}

/// Claims the oldest runnable job: queued and due, or active with an
/// expired lease (left by a crash).
pub async fn claim(db: &Db, worker: &str, lease_secs: i64) -> Result<Option<JobRow>> {
    let worker = worker.to_owned();
    db.write(move |tx| {
        let t = now();
        Ok(tx
            .query_row(
                &format!(
                    "UPDATE jobs SET state = CASE WHEN state = 'queued' THEN 'resolving' ELSE state END,
                                     lease_owner = ?1, lease_until = ?2 + ?3, attempts = attempts + 1, updated_at = ?2
                     WHERE id = (SELECT id FROM jobs
                                 WHERE cancel_requested = 0
                                   AND ((state = 'queued' AND COALESCE(lease_until, 0) <= ?2)
                                        OR (state IN ({ACTIVE_STATES}) AND state <> 'queued' AND lease_until < ?2))
                                 ORDER BY created_at LIMIT 1)
                     RETURNING {COLUMNS}"
                ),
                params![worker, t, lease_secs],
                JobRow::from_row,
            )
            .optional()?)
    })
    .await
}

pub async fn set_state(
    db: &Db,
    id: &str,
    state: &'static str,
    detail: Option<String>,
) -> Result<()> {
    let id = id.to_owned();
    db.write(move |tx| {
        tx.execute(
            "UPDATE jobs SET state = ?2, detail = ?3, updated_at = ?4 WHERE id = ?1",
            params![id, state, detail, now()],
        )?;
        Ok(())
    })
    .await
}

pub async fn renew_lease(db: &Db, id: &str, lease_secs: i64) -> Result<bool> {
    let id = id.to_owned();
    db.write(move |tx| {
        let t = now();
        let cancelled: bool = tx.query_row(
            "UPDATE jobs SET lease_until = ?2 + ?3 WHERE id = ?1 RETURNING cancel_requested",
            params![id, t, lease_secs],
            |r| r.get(0),
        )?;
        Ok(cancelled)
    })
    .await
}

/// Puts a job back in the queue after a temporary condition.
pub async fn defer(db: &Db, id: &str, delay_secs: i64, detail: &str) -> Result<()> {
    let (id, detail) = (id.to_owned(), detail.to_owned());
    db.write(move |tx| {
        let t = now();
        tx.execute(
            "UPDATE jobs SET state = 'queued', detail = ?2, lease_owner = NULL, lease_until = ?3, updated_at = ?4 WHERE id = ?1",
            params![id, detail, t + delay_secs, t],
        )?;
        Ok(())
    })
    .await
}

pub async fn fail(db: &Db, id: &str, code: &str, message: &str) -> Result<()> {
    let (id, code, message) = (id.to_owned(), code.to_owned(), message.to_owned());
    db.write(move |tx| {
        let t = now();
        tx.execute(
            "UPDATE jobs SET state = 'failed', error_code = ?2, error_message = ?3, lease_owner = NULL, lease_until = NULL,
                             completed_at = ?4, updated_at = ?4 WHERE id = ?1",
            params![id, code, message, t],
        )?;
        Ok(())
    })
    .await
}

pub struct Finished {
    pub result_path: Option<String>,
    pub size: i64,
    pub sha256: String,
    pub content_type: String,
    pub expires_at: Option<i64>,
    pub delivery_uncertain: bool,
}

pub async fn complete(db: &Db, id: &str, f: Finished) -> Result<()> {
    let id = id.to_owned();
    db.write(move |tx| {
        let t = now();
        tx.execute(
            "UPDATE jobs SET state = 'completed', detail = NULL, result_path = ?2, result_size = ?3, result_sha256 = ?4,
                             result_type = ?5, expires_at = ?6, delivery_uncertain = ?7, lease_owner = NULL, lease_until = NULL,
                             completed_at = ?8, updated_at = ?8 WHERE id = ?1",
            params![id, f.result_path, f.size, f.sha256, f.content_type, f.expires_at, f.delivery_uncertain, t],
        )?;
        Ok(())
    })
    .await
}

pub async fn set_source(db: &Db, id: &str, path: &str, size: i64) -> Result<()> {
    let (id, path) = (id.to_owned(), path.to_owned());
    db.write(move |tx| {
        tx.execute(
            "UPDATE jobs SET source_path = ?2, input_bytes = ?3, reserved_bytes = ?3 * 3, updated_at = ?4 WHERE id = ?1",
            params![id, path, size, now()],
        )?;
        Ok(())
    })
    .await
}

/// Requests cancellation. Queued jobs are cancelled at once; running jobs
/// stop at the next checkpoint.
pub async fn request_cancel(db: &Db, id: &str) -> Result<Option<String>> {
    let id = id.to_owned();
    db.write(move |tx| {
        let t = now();
        let state: Option<String> = tx.query_row("SELECT state FROM jobs WHERE id = ?1", [&id], |r| r.get(0)).optional()?;
        match state.as_deref() {
            Some("queued") => {
                tx.execute(
                    "UPDATE jobs SET state = 'cancelled', cancel_requested = 1, completed_at = ?2, updated_at = ?2 WHERE id = ?1",
                    params![id, t],
                )?;
            }
            Some("resolving" | "downloading" | "processing" | "delivering") => {
                tx.execute("UPDATE jobs SET cancel_requested = 1, updated_at = ?2 WHERE id = ?1", params![id, t])?;
            }
            _ => {}
        }
        Ok(state)
    })
    .await
}

/// Bytes reserved by unfinished jobs plus retained results.
pub async fn reserved_bytes(db: &Db) -> Result<i64> {
    db.read(|c| {
        Ok(c.query_row(
            &format!(
                "SELECT COALESCE(SUM(reserved_bytes), 0) + (SELECT COALESCE(SUM(result_size), 0) FROM jobs
                                                            WHERE state = 'completed' AND result_path IS NOT NULL)
                 FROM jobs WHERE state IN ({ACTIVE_STATES})"
            ),
            [],
            |r| r.get(0),
        )?)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn sample(key: Option<&str>) -> NewJob {
        NewJob {
            owner_kind: "api",
            owner_id: "media".into(),
            idempotency_key: key.map(str::to_owned),
            request_hash: Some("h1".into()),
            action: Action::Mp4,
            options: JobOptions::default(),
            source_kind: SourceKind::Url,
            source_ref: "https://x.com/a/status/1".into(),
            source_path: None,
            input_bytes: None,
            destination: None,
            chat_id: None,
            thread_id: None,
            reply_to: None,
            status_message: None,
        }
    }

    #[tokio::test]
    async fn create_claim_and_cancel() {
        let db = Db::open_in_memory().await.unwrap();
        let Created::New(id) = create(&db, new_id(), sample(Some("k1"))).await.unwrap() else {
            panic!()
        };
        assert_eq!(
            create(&db, new_id(), sample(Some("k1"))).await.unwrap(),
            Created::Existing(id.clone())
        );
        let mut other = sample(Some("k1"));
        other.request_hash = Some("h2".into());
        assert_eq!(
            create(&db, new_id(), other).await.unwrap(),
            Created::Conflict
        );

        let job = claim(&db, "w1", 60).await.unwrap().unwrap();
        assert_eq!(
            (job.id.as_str(), job.state.as_str(), job.attempts),
            (id.as_str(), "resolving", 1)
        );
        assert!(
            claim(&db, "w2", 60).await.unwrap().is_none(),
            "leased jobs are not claimed twice"
        );
        // An expired lease is reclaimed in its current state.
        db.write(|tx| Ok(tx.execute("UPDATE jobs SET lease_until = 0", [])?))
            .await
            .unwrap();
        let again = claim(&db, "w2", 60).await.unwrap().unwrap();
        assert_eq!((again.state.as_str(), again.attempts), ("resolving", 2));
        // Cancelling a running job only sets the flag.
        assert_eq!(
            request_cancel(&db, &id).await.unwrap().as_deref(),
            Some("resolving")
        );
        assert!(renew_lease(&db, &id, 60).await.unwrap());
    }

    #[tokio::test]
    async fn limits_unfinished_jobs_per_owner() {
        let db = Db::open_in_memory().await.unwrap();
        for _ in 0..2 {
            assert!(matches!(
                create_limited(&db, new_id(), sample(None), Some(2))
                    .await
                    .unwrap(),
                Created::New(_)
            ));
        }
        assert_eq!(
            create_limited(&db, new_id(), sample(None), Some(2))
                .await
                .unwrap(),
            Created::Limited(2)
        );
        // Another owner is unaffected.
        let mut other = sample(None);
        other.owner_id = "someone-else".into();
        assert!(matches!(
            create_limited(&db, new_id(), other, Some(2)).await.unwrap(),
            Created::New(_)
        ));
        // Finished jobs no longer count.
        db.write(|tx| {
            Ok(tx.execute(
                "UPDATE jobs SET state = 'completed' WHERE owner_id = 'media'",
                [],
            )?)
        })
        .await
        .unwrap();
        assert!(matches!(
            create_limited(&db, new_id(), sample(None), Some(2))
                .await
                .unwrap(),
            Created::New(_)
        ));
    }

    #[tokio::test]
    async fn deferred_jobs_wait_and_queued_cancel_is_immediate() {
        let db = Db::open_in_memory().await.unwrap();
        let Created::New(id) = create(&db, new_id(), sample(None)).await.unwrap() else {
            panic!()
        };
        claim(&db, "w", 60).await.unwrap().unwrap();
        defer(&db, &id, 300, "waiting for disk space")
            .await
            .unwrap();
        assert!(claim(&db, "w", 60).await.unwrap().is_none());
        request_cancel(&db, &id).await.unwrap();
        assert_eq!(get(&db, &id).await.unwrap().unwrap().state, "cancelled");
        let view = JobView::from(&get(&db, &id).await.unwrap().unwrap());
        assert!(view.download_url.is_none());
    }
}
