//! FFmpeg service client (SDS §6): capabilities negotiation, streaming
//! multipart submission, ETag polling, resumable verified download, DELETE
//! cleanup and attempt bookkeeping for restart recovery.

pub mod types;

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::Context as _;
use futures_util::StreamExt;
use reqwest::header::{ETAG, IF_NONE_MATCH, RANGE, RETRY_AFTER};
use reqwest::multipart::{Form, Part};
use reqwest::{Response, StatusCode};
use rusqlite::params;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use url::Url;

use crate::config::FfmpegConfig;
use crate::db::{Db, now};
use types::{Capabilities, ErrorEnvelope, InputDecl, Job, JobRequest, Operation};

#[derive(Debug, thiserror::Error)]
pub enum FfError {
    #[error("media processing is unavailable: {0}")]
    Unavailable(String),
    /// A synchronous error response.
    #[error("FFmpeg service returned {status} {code}")]
    Rejected {
        status: u16,
        code: String,
        field: Option<String>,
        retryable: bool,
    },
    /// The job failed during processing (`job.error`).
    #[error("processing failed: {code}")]
    Failed {
        code: String,
        field: Option<String>,
        retryable: bool,
    },
    /// The service no longer knows the job (restart or expiry).
    #[error("the FFmpeg service lost the job")]
    Lost,
    #[error("cancelled")]
    Cancelled,
    #[error("timed out waiting for the FFmpeg service")]
    Timeout,
    #[error("could not reach the FFmpeg service: {0}")]
    Transport(String),
    #[error("result verification failed: {0}")]
    Integrity(String),
    #[error("local file error: {0}")]
    Io(#[from] std::io::Error),
}

impl FfError {
    /// Whether a new attempt (with a new idempotency key) may succeed.
    pub fn retryable(&self) -> bool {
        match self {
            Self::Rejected { retryable, .. } | Self::Failed { retryable, .. } => *retryable,
            Self::Lost | Self::Timeout | Self::Transport(_) | Self::Integrity(_) => true,
            Self::Unavailable(_) | Self::Cancelled | Self::Io(_) => false,
        }
    }

    pub fn code(&self) -> &str {
        match self {
            Self::Rejected { code, .. } | Self::Failed { code, .. } => code,
            Self::Unavailable(_) => "media_unavailable",
            Self::Lost => "remote_lost",
            Self::Cancelled => "cancelled",
            Self::Timeout => "processing_timeout",
            Self::Transport(_) => "media_unreachable",
            Self::Integrity(_) => "integrity_error",
            Self::Io(_) => "io_error",
        }
    }
}

fn transport(e: reqwest::Error) -> FfError {
    FfError::Transport(e.without_url().to_string())
}

fn retry_after(res: &Response) -> Duration {
    let secs = res
        .headers()
        .get(RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(2);
    Duration::from_secs(secs.clamp(1, 60))
}

fn jitter() -> Duration {
    Duration::from_millis(rand::random_range(0..500))
}

async fn rejection(res: Response) -> FfError {
    let status = res.status().as_u16();
    match res.json::<ErrorEnvelope>().await {
        Ok(env) => FfError::Rejected {
            status,
            code: env.error.code,
            field: env.error.field,
            retryable: env.error.retryable,
        },
        Err(_) => FfError::Rejected {
            status,
            code: format!("http_{status}"),
            field: None,
            retryable: status >= 500,
        },
    }
}

/// A file to submit, already spooled with its exact size and SHA-256.
#[derive(Debug, Clone)]
pub struct Input {
    pub path: PathBuf,
    pub size: u64,
    pub sha256: String,
}

impl Input {
    /// Hashes a local file in chunks.
    pub async fn from_file(path: &Path) -> std::io::Result<Self> {
        use tokio::io::AsyncReadExt;
        let mut file = tokio::fs::File::open(path).await?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 256 * 1024];
        let mut size = 0u64;
        loop {
            let n = file.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            size += n as u64;
        }
        Ok(Self {
            path: path.to_owned(),
            size,
            sha256: hex::encode(hasher.finalize()),
        })
    }
}

/// Identifies one attempt for idempotency and bookkeeping (SDS §6.5).
#[derive(Debug, Clone)]
pub struct Attempt {
    pub job_id: String,
    pub step: &'static str,
    pub number: u32,
}

impl Attempt {
    pub fn key(&self) -> String {
        format!("wyr-{}-{}-{}", self.job_id, self.step, self.number)
    }
}

pub struct FfmpegClient {
    http: reqwest::Client,
    base: Url,
    key: SecretString,
    db: Db,
    config: FfmpegConfig,
    caps: RwLock<Option<Capabilities>>,
    /// Remote-job slots sized from `max_jobs_per_consumer` (SDS §6.2).
    slots: RwLock<Option<(usize, Arc<Semaphore>)>>,
}

#[derive(Debug)]
pub struct Completed {
    pub path: PathBuf,
    pub size: u64,
    pub sha256: String,
    pub content_type: String,
}

impl FfmpegClient {
    pub fn new(
        base_url: &str,
        key: SecretString,
        db: Db,
        config: FfmpegConfig,
    ) -> anyhow::Result<Self> {
        // Fixed origin: no proxy, no redirects, short connect timeout.
        let http = crate::http::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .build()?;
        let base = Url::parse(base_url).context("ffmpeg.base_url")?;
        Ok(Self {
            http,
            base,
            key,
            db,
            config,
            caps: RwLock::new(None),
            slots: RwLock::new(None),
        })
    }

    fn url(&self, path: &str) -> Url {
        let mut u = self.base.clone();
        u.set_path(path);
        u.set_query(None);
        u
    }

    pub fn capabilities(&self) -> Option<Capabilities> {
        self.caps.read().expect("caps lock").clone()
    }

    pub async fn refresh_capabilities(&self) -> Result<Capabilities, FfError> {
        let res = self
            .http
            .get(self.url("/v1/capabilities"))
            .bearer_auth(self.key.expose_secret())
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(transport)?;
        if !res.status().is_success() {
            return Err(rejection(res).await);
        }
        let caps: Capabilities = res.json().await.map_err(transport)?;
        if caps.api_version != "1" {
            return Err(FfError::Unavailable(format!(
                "unsupported API version {}",
                caps.api_version
            )));
        }
        let per_consumer = caps
            .limit("max_jobs_per_consumer")
            .unwrap_or(2)
            .clamp(1, 64) as usize;
        {
            let mut slots = self.slots.write().expect("slots lock");
            // A new semaphore only when the advertised limit changes; permits
            // held on the old one are released as their jobs finish.
            if slots.as_ref().is_none_or(|(size, _)| *size != per_consumer) {
                *slots = Some((per_consumer, Arc::new(Semaphore::new(per_consumer))));
            }
        }
        let previous = self.caps.write().expect("caps lock").replace(caps.clone());
        if previous
            .as_ref()
            .is_some_and(|p| p.instance_id != caps.instance_id)
        {
            info!(instance = %caps.instance_id, "FFmpeg service restarted");
        }
        Ok(caps)
    }

    fn require(&self, op: &Operation, format: &str) -> Result<Capabilities, FfError> {
        let caps = self
            .capabilities()
            .ok_or_else(|| FfError::Unavailable("capabilities not loaded".into()))?;
        let names = op.parameter_names();
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        if !caps.supports(op.name(), format, &names) {
            return Err(FfError::Unavailable(format!(
                "{} → {format} with {names:?} is not supported by this service",
                op.name()
            )));
        }
        Ok(caps)
    }

    async fn permit(&self) -> Result<OwnedSemaphorePermit, FfError> {
        let sem = self
            .slots
            .read()
            .expect("slots lock")
            .as_ref()
            .map(|(_, s)| s.clone())
            .ok_or_else(|| FfError::Unavailable("capabilities not loaded".into()))?;
        sem.acquire_owned()
            .await
            .map_err(|_| FfError::Unavailable("shutting down".into()))
    }

    async fn record(
        &self,
        key: &str,
        f: impl FnOnce(&rusqlite::Transaction<'_>, &str, i64) -> rusqlite::Result<usize>
        + Send
        + 'static,
    ) {
        let key = key.to_owned();
        if let Err(e) = self.db.write(move |tx| Ok(f(tx, &key, now())?)).await {
            warn!(error = %e, "recording an FFmpeg attempt failed");
        }
    }

    /// Runs one operation end to end and leaves the verified result at `out`.
    pub async fn run(
        &self,
        attempt: &Attempt,
        input: &Input,
        op: Operation,
        format: &'static str,
        out: &Path,
        cancel: &CancellationToken,
    ) -> Result<Completed, FfError> {
        if !self.config.enabled {
            return Err(FfError::Unavailable("disabled in configuration".into()));
        }
        if self.capabilities().is_none() {
            self.refresh_capabilities().await?;
        }
        let caps = self.require(&op, format)?;
        if let Some(max) = caps.limit("max_upload_bytes")
            && input.size > max {
                return Err(FfError::Rejected {
                    status: 413,
                    code: "upload_too_large".into(),
                    field: None,
                    retryable: false,
                });
            }
        let _permit = self.permit().await?;
        let key = attempt.key();
        let (job_id, step, number) = (attempt.job_id.clone(), attempt.step, attempt.number);
        self.record(&key, move |tx, key, t| {
            tx.execute(
                "INSERT INTO remote_attempts (idempotency_key, job_id, step, attempt, state, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, 'submitting', ?5, ?5) ON CONFLICT (idempotency_key) DO UPDATE SET updated_at = ?5",
                params![key, job_id, step, number, t],
            )
        })
        .await;
        let request = JobRequest {
            op,
            input: InputDecl {
                size_bytes: input.size,
                sha256: input.sha256.clone(),
            },
            output_format: format,
        };
        let job = self.submit(&key, &request, input, cancel).await?;
        let (instance, remote) = (job.instance_id.clone(), job.job_id.clone());
        self.record(&key, move |tx, key, t| {
            tx.execute(
                "UPDATE remote_attempts SET state = 'submitted', instance_id = ?2, remote_job_id = ?3, updated_at = ?4 WHERE idempotency_key = ?1",
                params![key, instance, remote, t],
            )
        })
        .await;
        if self
            .capabilities()
            .is_some_and(|c| c.instance_id != job.instance_id)
        {
            let _ = self.refresh_capabilities().await;
        }
        let outcome = self.finish(&job, out, cancel).await;
        // Always release the remote job; it holds a consumer slot until deleted.
        self.delete(&job.job_id).await;
        let state = match &outcome {
            Ok(_) => "completed",
            Err(FfError::Lost) => "lost",
            Err(_) => "failed",
        };
        self.record(&key, move |tx, key, t| {
            tx.execute(
                "UPDATE remote_attempts SET state = ?2, updated_at = ?3 WHERE idempotency_key = ?1",
                params![key, state, t],
            )
        })
        .await;
        outcome
    }

    async fn submit(
        &self,
        key: &str,
        request: &JobRequest,
        input: &Input,
        cancel: &CancellationToken,
    ) -> Result<Job, FfError> {
        let json = serde_json::to_string(request).map_err(|e| FfError::Transport(e.to_string()))?;
        let deadline = tokio::time::Instant::now()
            + Duration::from_secs(
                self.config.queue_allowance_secs + self.config.process_timeout_secs,
            );
        let mut connection_failures = 0;
        loop {
            if cancel.is_cancelled() {
                return Err(FfError::Cancelled);
            }
            let file = tokio::fs::File::open(&input.path).await?;
            let stream = tokio_util::io::ReaderStream::with_capacity(file, 256 * 1024);
            let form = Form::new()
                .part(
                    "request",
                    Part::text(json.clone())
                        .mime_str("application/json")
                        .map_err(transport)?,
                )
                .part(
                    "file",
                    Part::stream_with_length(reqwest::Body::wrap_stream(stream), input.size)
                        .file_name("input")
                        .mime_str("application/octet-stream")
                        .map_err(transport)?,
                );
            let sent = self
                .http
                .post(self.url("/v1/jobs"))
                .bearer_auth(self.key.expose_secret())
                .header("Idempotency-Key", key)
                .multipart(form)
                .timeout(Duration::from_secs(self.config.upload_timeout_secs + 30))
                .send()
                .await;
            let res = match sent {
                Ok(r) => r,
                // An aborted upload creates no job: replay with the same key.
                Err(e) if connection_failures < 3 => {
                    connection_failures += 1;
                    warn!(error = %e.without_url(), attempt = connection_failures, "upload to FFmpeg service failed; replaying");
                    tokio::time::sleep(Duration::from_secs(2) + jitter()).await;
                    continue;
                }
                Err(e) => return Err(transport(e)),
            };
            let status = res.status();
            if status == StatusCode::ACCEPTED {
                return res.json::<Job>().await.map_err(transport);
            }
            let wait = retry_after(&res) + jitter();
            let err = rejection(res).await;
            let code = match &err {
                FfError::Rejected { code, .. } => code.clone(),
                _ => String::new(),
            };
            let waitable = matches!(
                (status.as_u16(), code.as_str()),
                (409, "idempotency_in_progress") | (429, _) | (503, _)
            );
            if !waitable || tokio::time::Instant::now() + wait > deadline {
                return Err(err);
            }
            if status == StatusCode::TOO_MANY_REQUESTS {
                // Should be prevented by the slot semaphore; free leftovers.
                self.sweep_cleanup().await;
            }
            debug!(
                status = status.as_u16(),
                code, "FFmpeg service busy; waiting"
            );
            tokio::select! {
                _ = cancel.cancelled() => return Err(FfError::Cancelled),
                _ = tokio::time::sleep(wait) => {}
            }
        }
    }

    async fn finish(
        &self,
        job: &Job,
        out: &Path,
        cancel: &CancellationToken,
    ) -> Result<Completed, FfError> {
        let job = self.poll(job, cancel).await?;
        match job.status.as_str() {
            "completed" => {}
            "failed" => {
                let e = job.error.unwrap_or(types::JobError {
                    code: "processing_failed".into(),
                    field: None,
                    retryable: true,
                });
                return Err(FfError::Failed {
                    code: e.code,
                    field: e.field,
                    retryable: e.retryable,
                });
            }
            // Stopped by a service shutdown or drain.
            "cancelled" => {
                return Err(FfError::Failed {
                    code: "cancelled".into(),
                    field: None,
                    retryable: true,
                });
            }
            _ => return Err(FfError::Lost),
        }
        let result = job
            .result
            .ok_or_else(|| FfError::Integrity("completed job without a result".into()))?;
        self.download(&job.job_id, &result, out).await?;
        Ok(Completed {
            path: out.to_owned(),
            size: result.size_bytes,
            sha256: result.sha256,
            content_type: result.content_type,
        })
    }

    async fn poll(&self, job: &Job, cancel: &CancellationToken) -> Result<Job, FfError> {
        let deadline = tokio::time::Instant::now()
            + Duration::from_secs(self.config.queue_allowance_secs + self.process_timeout());
        let mut current = job.clone();
        let mut etag: Option<String> = None;
        let path = format!("/v1/jobs/{}", job.job_id);
        while matches!(
            current.status.as_str(),
            "queued" | "processing" | "cancelling" | "uploading"
        ) {
            let wait = Duration::from_secs(2) + jitter();
            if tokio::time::Instant::now() + wait > deadline {
                return Err(FfError::Timeout);
            }
            tokio::select! {
                _ = cancel.cancelled() => return Err(FfError::Cancelled),
                _ = tokio::time::sleep(wait) => {}
            }
            let mut req = self
                .http
                .get(self.url(&path))
                .bearer_auth(self.key.expose_secret())
                .header("Accept", "application/json")
                .timeout(Duration::from_secs(15));
            if let Some(t) = &etag {
                req = req.header(IF_NONE_MATCH, t);
            }
            let res = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    warn!(error = %e.without_url(), "polling the FFmpeg service failed");
                    continue;
                }
            };
            match res.status() {
                StatusCode::NOT_MODIFIED => {}
                StatusCode::OK => {
                    etag = res
                        .headers()
                        .get(ETAG)
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned);
                    current = res.json().await.map_err(transport)?;
                }
                StatusCode::NOT_FOUND | StatusCode::GONE => return Err(FfError::Lost),
                s if s.is_server_error() => warn!(status = s.as_u16(), "FFmpeg status poll failed"),
                _ => return Err(rejection(res).await),
            }
        }
        Ok(current)
    }

    fn process_timeout(&self) -> u64 {
        self.capabilities()
            .and_then(|c| c.limit("process_timeout_seconds"))
            .unwrap_or(self.config.process_timeout_secs)
    }

    /// Streams the result, resuming with `Range` after interruptions, then
    /// verifies size and SHA-256 before the atomic rename.
    async fn download(
        &self,
        job_id: &str,
        result: &types::ResultInfo,
        out: &Path,
    ) -> Result<(), FfError> {
        let part = out.with_extension("part");
        let mut file = tokio::fs::File::create(&part).await?;
        let mut hasher = Sha256::new();
        let mut received = 0u64;
        let mut interruptions = 0;
        let path = format!("/v1/jobs/{job_id}/download");
        while received < result.size_bytes || received == 0 {
            let mut req = self
                .http
                .get(self.url(&path))
                .bearer_auth(self.key.expose_secret())
                .timeout(Duration::from_secs(130));
            if received > 0 {
                req = req.header(RANGE, format!("bytes={received}-"));
            }
            let res = match req.send().await {
                Ok(r) => r,
                Err(e) if interruptions < 5 => {
                    interruptions += 1;
                    warn!(error = %e.without_url(), "result download failed; resuming");
                    continue;
                }
                Err(e) => return Err(transport(e)),
            };
            match (res.status(), received) {
                (StatusCode::OK, 0) => {}
                (StatusCode::PARTIAL_CONTENT, n) if n > 0 => {}
                // The server ignored Range: start over rather than append.
                (StatusCode::OK, _) => {
                    file.set_len(0).await?;
                    file.seek(std::io::SeekFrom::Start(0)).await?;
                    hasher = Sha256::new();
                    received = 0;
                }
                (StatusCode::NOT_FOUND | StatusCode::GONE, _) => return Err(FfError::Lost),
                _ => return Err(rejection(res).await),
            }
            let mut stream = res.bytes_stream();
            let mut broke = false;
            while let Some(chunk) = stream.next().await {
                let chunk = match chunk {
                    Ok(c) => c,
                    Err(e) => {
                        warn!(error = %e.without_url(), "result stream interrupted");
                        broke = true;
                        break;
                    }
                };
                received += chunk.len() as u64;
                if received > result.size_bytes {
                    return Err(FfError::Integrity("result larger than advertised".into()));
                }
                hasher.update(&chunk);
                file.write_all(&chunk).await?;
            }
            if broke || received < result.size_bytes {
                interruptions += 1;
                if interruptions > 5 {
                    return Err(FfError::Transport("result download kept failing".into()));
                }
                continue;
            }
            break;
        }
        file.sync_all().await?;
        drop(file);
        let digest = hex::encode(hasher.finalize());
        if received != result.size_bytes || !digest.eq_ignore_ascii_case(&result.sha256) {
            let _ = tokio::fs::remove_file(&part).await;
            return Err(FfError::Integrity(format!(
                "expected {} bytes {}, got {received} bytes {digest}",
                result.size_bytes, result.sha256
            )));
        }
        tokio::fs::rename(&part, out).await?;
        Ok(())
    }

    /// DELETE until the service confirms removal; leftovers are queued.
    pub async fn delete(&self, remote_job_id: &str) {
        let path = format!("/v1/jobs/{remote_job_id}");
        for _ in 0..15 {
            match self
                .http
                .delete(self.url(&path))
                .bearer_auth(self.key.expose_secret())
                .timeout(Duration::from_secs(10))
                .send()
                .await
            {
                Ok(r) if matches!(r.status().as_u16(), 204 | 404 | 410) => {
                    let id = remote_job_id.to_owned();
                    let _ = self
                        .db
                        .write(move |tx| {
                            Ok(tx.execute(
                                "DELETE FROM remote_cleanup WHERE remote_job_id = ?1",
                                [id],
                            )?)
                        })
                        .await;
                    return;
                }
                Ok(r) if r.status() == StatusCode::ACCEPTED => {
                    tokio::time::sleep(Duration::from_secs(2)).await
                }
                Ok(r) => {
                    warn!(
                        status = r.status().as_u16(),
                        "remote job cleanup was refused"
                    );
                    break;
                }
                Err(e) => {
                    warn!(error = %e.without_url(), "remote job cleanup failed");
                    break;
                }
            }
        }
        let id = remote_job_id.to_owned();
        let _ = self
            .db
            .write(move |tx| {
                Ok(tx.execute(
                    "INSERT INTO remote_cleanup (remote_job_id, created_at) VALUES (?1, ?2)
                     ON CONFLICT (remote_job_id) DO UPDATE SET attempts = attempts + 1",
                    params![id, now()],
                )?)
            })
            .await;
    }

    /// Retries queued cleanups and, at startup, removes remote jobs left by a
    /// previous process (SDS §6.8).
    pub async fn sweep_cleanup(&self) {
        let pending: Vec<String> = self
            .db
            .write(|tx| {
                // Attempts still marked submitted belong to a previous run.
                tx.execute(
                    "INSERT OR IGNORE INTO remote_cleanup (remote_job_id, created_at)
                     SELECT remote_job_id, ?1 FROM remote_attempts WHERE state = 'submitted' AND remote_job_id IS NOT NULL AND updated_at < ?1 - 900",
                    [now()],
                )?;
                let mut st = tx.prepare("SELECT remote_job_id FROM remote_cleanup ORDER BY created_at LIMIT 50")?;
                let rows = st.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<Vec<String>>>()?;
                Ok(rows)
            })
            .await
            .unwrap_or_default();
        for id in pending {
            self.delete(&id).await;
        }
    }

    /// Marks attempts from a previous process as lost and queues their
    /// remote jobs for deletion.
    pub async fn recover_after_restart(&self) {
        let _ = self
            .db
            .write(|tx| {
                let t = now();
                tx.execute(
                    "INSERT OR IGNORE INTO remote_cleanup (remote_job_id, created_at)
                     SELECT remote_job_id, ?1 FROM remote_attempts WHERE state = 'submitted' AND remote_job_id IS NOT NULL",
                    [t],
                )?;
                Ok(tx.execute("UPDATE remote_attempts SET state = 'lost', updated_at = ?1 WHERE state IN ('submitting', 'submitted')", [t])?)
            })
            .await;
        self.sweep_cleanup().await;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use serde_json::json;
    use wiremock::matchers::{header, header_exists, method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    use super::types::{AudioMode, VideoParams};
    use super::*;

    const KEY: &str = "ffmpeg-consumer-key";

    fn caps(params: bool) -> serde_json::Value {
        let mut c = json!({ "api_version": "1", "instance_id": "inst1",
            "operations": { "metadata": ["json"], "transcode": ["mp4", "webm"], "remux": ["mp4", "webm"],
                            "trim": ["mp4"], "thumbnail": ["jpg"] },
            "limits": { "max_upload_bytes": 1_000_000, "max_jobs_per_consumer": 2, "process_timeout_seconds": 20 } });
        if params {
            c["parameters"] = json!({ "transcode": ["quality", "audio_mode", "max_dimension", "max_fps", "max_bitrate_kbps"],
                                      "remux": ["audio_mode"], "metadata": [] });
        }
        c
    }

    fn job(status: &str, result: Option<(&[u8], &str)>) -> serde_json::Value {
        let r = result.map(|(bytes, ct)| json!({ "content_type": ct, "size_bytes": bytes.len(), "sha256": hex::encode(Sha256::digest(bytes)) }));
        json!({ "api_version": "1", "instance_id": "inst1", "job_id": "a".repeat(32), "status": status,
                "status_url": format!("/v1/jobs/{}", "a".repeat(32)), "result": r, "error": null })
    }

    async fn setup(server: &MockServer, params: bool) -> (FfmpegClient, tempfile::TempDir, Input) {
        Mock::given(method("GET"))
            .and(path("/v1/capabilities"))
            .and(header("authorization", format!("Bearer {KEY}").as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(caps(params)))
            .mount(server)
            .await;
        Mock::given(method("DELETE"))
            .respond_with(ResponseTemplate::new(204))
            .mount(server)
            .await;
        let db = Db::open_in_memory().await.unwrap();
        db.write(|tx| {
            Ok(tx.execute(
                "INSERT INTO jobs (id, owner_kind, owner_id, action, options, source_kind, source_ref, state, created_at, updated_at)
                 VALUES ('job1', 'api', 'c', 'mp4', '{}', 'upload', 'x', 'processing', 0, 0)",
                [],
            )?)
        })
        .await
        .unwrap();
        let config = FfmpegConfig {
            queue_allowance_secs: 10,
            ..Default::default()
        };
        let client = FfmpegClient::new(&server.uri(), SecretString::from(KEY), db, config).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src.mp4");
        tokio::fs::write(&src, b"source bytes").await.unwrap();
        let input = Input::from_file(&src).await.unwrap();
        (client, dir, input)
    }

    fn attempt() -> Attempt {
        Attempt {
            job_id: "job1".into(),
            step: "main",
            number: 1,
        }
    }

    async fn attempt_state(c: &FfmpegClient) -> String {
        c.db.read(|c| Ok(c.query_row("SELECT state FROM remote_attempts", [], |r| r.get(0))?))
            .await
            .unwrap()
    }

    /// Answers queued first, then completed.
    struct Progress(AtomicUsize, &'static [u8]);
    impl Respond for Progress {
        fn respond(&self, _: &Request) -> ResponseTemplate {
            if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(200)
                    .set_body_json(job("processing", None))
                    .insert_header("etag", "\"v1\"")
            } else {
                ResponseTemplate::new(200)
                    .set_body_json(job("completed", Some((self.1, "video/mp4"))))
            }
        }
    }

    #[tokio::test]
    async fn runs_a_job_end_to_end() {
        let server = MockServer::start().await;
        let (client, dir, input) = setup(&server, true).await;
        Mock::given(method("POST"))
            .and(path("/v1/jobs"))
            .and(header("idempotency-key", "wyr-job1-main-1"))
            .and(header_exists("content-type"))
            .respond_with(move |req: &Request| {
                let body = String::from_utf8_lossy(&req.body);
                // The request part comes first and carries the exact size and hash.
                let req_pos = body.find("name=\"request\"").unwrap();
                let file_pos = body.find("name=\"file\"").unwrap();
                assert!(req_pos < file_pos);
                assert!(body.contains("\"audio_mode\":\"remove\""));
                assert!(body.contains("\"size_bytes\":12"));
                assert!(body.contains("application/octet-stream"));
                ResponseTemplate::new(202).set_body_json(job("queued", None))
            })
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/jobs/{}", "a".repeat(32))))
            .respond_with(Progress(AtomicUsize::new(0), b"encoded output"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/jobs/{}/download", "a".repeat(32))))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"encoded output".to_vec()))
            .mount(&server)
            .await;
        let out = dir.path().join("out.mp4");
        let op = Operation::Transcode(VideoParams {
            quality: Some(28),
            audio_mode: Some(AudioMode::Remove),
            ..Default::default()
        });
        let done = client
            .run(
                &attempt(),
                &input,
                op,
                "mp4",
                &out,
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(tokio::fs::read(&out).await.unwrap(), b"encoded output");
        assert_eq!(done.content_type, "video/mp4");
        assert_eq!(attempt_state(&client).await, "completed");
        let deletes = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.method.as_str() == "DELETE")
            .count();
        assert_eq!(deletes, 1);
    }

    #[tokio::test]
    async fn refuses_unadvertised_parameters_without_uploading() {
        let server = MockServer::start().await;
        let (client, dir, input) = setup(&server, false).await;
        let op = Operation::Remux {
            audio_mode: Some(AudioMode::Remove),
        };
        let err = client
            .run(
                &attempt(),
                &input,
                op,
                "mp4",
                &dir.path().join("o"),
                &CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, FfError::Unavailable(_)), "{err:?}");
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|r| r.method.as_str() != "POST")
        );
        // The baseline parameter set still works.
        assert!(
            client
                .require(
                    &Operation::Transcode(VideoParams {
                        quality: Some(23),
                        ..Default::default()
                    }),
                    "mp4"
                )
                .is_ok()
        );
    }

    #[tokio::test]
    async fn maps_async_failures_and_lost_jobs() {
        let server = MockServer::start().await;
        let (client, dir, input) = setup(&server, true).await;
        Mock::given(method("POST"))
            .and(path("/v1/jobs"))
            .respond_with(ResponseTemplate::new(202).set_body_json(job("queued", None)))
            .mount(&server)
            .await;
        let mut failed = job("failed", None);
        failed["error"] = json!({ "code": "duration_exceeded", "message": "duration exceeded.", "retryable": false });
        Mock::given(method("GET"))
            .and(path(format!("/v1/jobs/{}", "a".repeat(32))))
            .respond_with(ResponseTemplate::new(200).set_body_json(failed))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        let op = Operation::Metadata {};
        let err = client
            .run(
                &attempt(),
                &input,
                op.clone(),
                "json",
                &dir.path().join("o"),
                &CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(&err, FfError::Failed { code, retryable: false, .. } if code == "duration_exceeded"),
            "{err:?}"
        );
        assert!(!err.retryable());
        // After a service restart the job is unknown.
        Mock::given(method("GET"))
            .and(path(format!("/v1/jobs/{}", "a".repeat(32))))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(
                    json!({ "error": { "code": "job_not_found", "retryable": false } }),
                ),
            )
            .mount(&server)
            .await;
        let second = Attempt {
            number: 2,
            ..attempt()
        };
        let err = client
            .run(
                &second,
                &input,
                op,
                "json",
                &dir.path().join("o"),
                &CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, FfError::Lost));
        assert!(err.retryable());
    }

    #[tokio::test]
    async fn waits_on_saturation_and_reports_sync_errors() {
        let server = MockServer::start().await;
        let (client, dir, input) = setup(&server, true).await;
        Mock::given(method("POST"))
            .and(path("/v1/jobs"))
            .respond_with(
                ResponseTemplate::new(503)
                    .insert_header("retry-after", "1")
                    .set_body_json(
                        json!({ "error": { "code": "capacity_exhausted", "retryable": true } }),
                    ),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/jobs"))
            .respond_with(
                ResponseTemplate::new(422)
                    .set_body_json(json!({ "error": { "code": "invalid_parameter",
                "field": "parameters.width", "retryable": false } })),
            )
            .mount(&server)
            .await;
        let err = client
            .run(
                &attempt(),
                &input,
                Operation::Metadata {},
                "json",
                &dir.path().join("o"),
                &CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(&err, FfError::Rejected { status: 422, field: Some(f), .. } if f == "parameters.width"),
            "{err:?}"
        );
        let posts = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.method.as_str() == "POST")
            .count();
        assert_eq!(posts, 2, "the 503 was retried once");
    }

    #[tokio::test]
    async fn rejects_results_that_fail_verification() {
        let server = MockServer::start().await;
        let (client, dir, input) = setup(&server, true).await;
        Mock::given(method("POST"))
            .and(path("/v1/jobs"))
            .respond_with(
                ResponseTemplate::new(202)
                    .set_body_json(job("completed", Some((b"expected", "application/json")))),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/jobs/{}", "a".repeat(32))))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(job("completed", Some((b"expected", "application/json")))),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/jobs/{}/download", "a".repeat(32))))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"tampered".to_vec()))
            .mount(&server)
            .await;
        let out = dir.path().join("out.json");
        let err = client
            .run(
                &attempt(),
                &input,
                Operation::Metadata {},
                "json",
                &out,
                &CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, FfError::Integrity(_)), "{err:?}");
        assert!(!out.exists() && !out.with_extension("part").exists());
    }

    #[tokio::test]
    async fn resumes_interrupted_downloads_with_range() {
        let server = MockServer::start().await;
        let (client, dir, _) = setup(&server, true).await;
        let body = b"0123456789abcdef".to_vec();
        Mock::given(method("GET"))
            .and(path("/v1/jobs/r/download"))
            .and(header("range", "bytes=6-"))
            .respond_with(ResponseTemplate::new(206).set_body_bytes(body[6..].to_vec()))
            .mount(&server)
            .await;
        // The first transfer delivers only six bytes.
        Mock::given(method("GET"))
            .and(path("/v1/jobs/r/download"))
            .respond_with(ResponseTemplate::new(206).set_body_bytes(body[..6].to_vec()))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        let info = types::ResultInfo {
            content_type: "video/mp4".into(),
            size_bytes: 16,
            sha256: hex::encode(Sha256::digest(&body)),
        };
        let out = dir.path().join("r.mp4");
        // A 206 on the first request is accepted only when resuming, so
        // simulate a resumed transfer from the start state.
        let err = client.download("r", &info, &out).await;
        assert!(err.is_err(), "a 206 without a Range request is refused");
        Mock::given(method("GET"))
            .and(path("/v1/jobs/s/download"))
            .and(header("range", "bytes=6-"))
            .respond_with(ResponseTemplate::new(206).set_body_bytes(body[6..].to_vec()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/jobs/s/download"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body[..6].to_vec()))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        client.download("s", &info, &out).await.unwrap();
        assert_eq!(tokio::fs::read(&out).await.unwrap(), body);

        // A server that ignores Range and resends everything must not corrupt the file.
        Mock::given(method("GET"))
            .and(path("/v1/jobs/t/download"))
            .and(header("range", "bytes=6-"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/jobs/t/download"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body[..6].to_vec()))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        let out2 = dir.path().join("t.mp4");
        client.download("t", &info, &out2).await.unwrap();
        assert_eq!(tokio::fs::read(&out2).await.unwrap(), body);
    }

    #[tokio::test]
    async fn sweeps_leftover_remote_jobs_after_restart() {
        let server = MockServer::start().await;
        let (client, _dir, _) = setup(&server, true).await;
        client
            .db
            .write(|tx| {
                Ok(tx.execute(
                    "INSERT INTO remote_attempts (idempotency_key, job_id, step, attempt, instance_id, remote_job_id, state, created_at, updated_at)
                     VALUES ('k', 'job1', 'main', 1, 'old', 'leftover', 'submitted', 0, 0)",
                    [],
                )?)
            })
            .await
            .unwrap();
        client.recover_after_restart().await;
        let deletes: Vec<String> = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.method.as_str() == "DELETE")
            .map(|r| r.url.path().to_owned())
            .collect();
        assert_eq!(deletes, vec!["/v1/jobs/leftover"]);
        assert_eq!(attempt_state(&client).await, "lost");
        let left: i64 = client
            .db
            .read(|c| Ok(c.query_row("SELECT COUNT(*) FROM remote_cleanup", [], |r| r.get(0))?))
            .await
            .unwrap();
        assert_eq!(left, 0);
    }
}
