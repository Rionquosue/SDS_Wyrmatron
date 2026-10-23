//! Media service facade: availability, job submission, status and
//! cancellation for Telegram and the HTTP API.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::json;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use super::jobs::{self, Created, JobRow, NewJob, SourceKind};
use super::plan::requirements;
use super::spec::Action;
use crate::api::StatusProvider;
use crate::config::Config;
use crate::db::{Db, now};
use crate::extract::{Extractor, parse_link};
use crate::fetch::Fetcher;
use crate::ffmpeg::FfmpegClient;
use crate::telegram::client::Bot;
use crate::telegram::handler::{MediaJobs, TelegramJob, TelegramSource};
use crate::text::escape;

pub struct MediaService {
    pub db: Db,
    pub config: Arc<Config>,
    pub ffmpeg: Option<Arc<FfmpegClient>>,
    pub extractor: Arc<Extractor>,
    pub fetcher: Arc<Fetcher>,
    pub bot: Option<Arc<Bot>>,
    pub wake: Arc<Notify>,
    /// Cancellation tokens of jobs running in this process.
    pub running: Mutex<HashMap<String, CancellationToken>>,
}

impl MediaService {
    pub fn job_dir(&self, id: &str) -> PathBuf {
        self.config.storage.work_dir.join("jobs").join(id)
    }

    /// Why `action` cannot run, judged from the FFmpeg service's advertised
    /// capabilities (SDS §6.2).
    pub fn unavailable_reason(&self, action: Action) -> Option<String> {
        let reqs = requirements(action);
        if reqs.is_empty() {
            return None;
        }
        let Some(client) = &self.ffmpeg else {
            return Some("media processing is disabled".into());
        };
        let Some(caps) = client.capabilities() else {
            return Some("the FFmpeg service is not reachable yet".into());
        };
        reqs.iter()
            .find(|(op, format, params)| !caps.supports(op, format, params))
            .map(|_| "the FFmpeg service does not support it yet (needs service 0.2)".to_owned())
    }

    pub async fn create(&self, job: NewJob) -> anyhow::Result<Created> {
        let created = jobs::create(&self.db, jobs::new_id(), job).await?;
        if matches!(created, Created::New(_)) {
            self.wake.notify_waiters();
            self.wake.notify_one();
        }
        Ok(created)
    }

    /// Cancels a job and signals the worker running it, if any.
    pub async fn cancel(&self, job: &JobRow) -> anyhow::Result<Option<String>> {
        let state = jobs::request_cancel(&self.db, &job.id).await?;
        if let Some(token) = self.running.lock().expect("running lock").get(&job.id) {
            token.cancel();
        }
        Ok(state)
    }

    fn describe(&self, j: &JobRow) -> String {
        let mut s = format!(
            "Job <code>{}</code> · <b>{}</b> · {}",
            j.id,
            j.action.label(),
            j.state
        );
        if let Some(d) = &j.detail {
            s.push_str(&format!("\n{}", escape(d)));
        }
        if let Some(m) = &j.error_message {
            s.push_str(&format!("\n⚠️ {}", escape(m)));
        }
        if let (Some(i), Some(o)) = (j.input_bytes, j.result_size) {
            s.push_str(&format!(
                "\n{} → {}",
                human_bytes(i as u64),
                human_bytes(o as u64)
            ));
        }
        if j.delivery_uncertain {
            s.push_str("\nDelivery could not be confirmed; you may receive it twice.");
        }
        s
    }

    async fn owned_job(&self, job_id: &str, user_id: i64, admin: bool) -> Result<JobRow, String> {
        let not_found = || "No such job.".to_owned();
        if job_id.len() > 64 || !job_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(not_found());
        }
        let job = jobs::get(&self.db, job_id)
            .await
            .map_err(|_| "Could not look up that job.".to_owned())?
            .ok_or_else(not_found)?;
        // Other users' jobs are indistinguishable from missing ones.
        if admin || job.owned_by("telegram", &user_id.to_string()) {
            Ok(job)
        } else {
            Err(not_found())
        }
    }
}

pub fn human_bytes(n: u64) -> String {
    if n >= 1024 * 1024 {
        format!("{:.1} MB", n as f64 / (1024.0 * 1024.0))
    } else if n >= 1024 {
        format!("{:.0} KB", n as f64 / 1024.0)
    } else {
        format!("{n} B")
    }
}

#[async_trait]
impl MediaJobs for MediaService {
    fn unavailable(&self, action: Action) -> Option<String> {
        self.unavailable_reason(action)
    }

    fn supported_link(&self, url: &url::Url) -> bool {
        parse_link(url).is_some()
    }

    async fn submit(&self, job: TelegramJob) -> Result<String, String> {
        let (source_kind, source_ref) = match &job.source {
            TelegramSource::Url { url } => {
                let parsed =
                    url::Url::parse(url).map_err(|_| "That link is not valid.".to_owned())?;
                if parse_link(&parsed).is_none() {
                    return Err("Only X/Twitter and Bluesky post links are supported.".into());
                }
                (SourceKind::Url, url.clone())
            }
            TelegramSource::File { .. } => (
                SourceKind::TelegramFile,
                serde_json::to_string(&job.source).map_err(|e| e.to_string())?,
            ),
        };
        let mut options = job.options.clone();
        if let TelegramSource::Url { url } = &job.source
            && options.media_index.is_none()
        {
            options.media_index = url::Url::parse(url)
                .ok()
                .and_then(|u| parse_link(&u))
                .and_then(|l| l.media_index);
        }
        let created = self
            .create(NewJob {
                owner_kind: "telegram",
                owner_id: job.user_id.to_string(),
                idempotency_key: None,
                request_hash: None,
                action: job.action,
                options,
                source_kind,
                source_ref,
                source_path: None,
                input_bytes: None,
                destination: None,
                chat_id: Some(job.chat_id),
                thread_id: job.thread_id,
                reply_to: Some(job.reply_to),
                status_message: Some(job.status_message),
            })
            .await
            .map_err(|_| "Could not queue the job; try again.".to_owned())?;
        match created {
            Created::New(id) | Created::Existing(id) => Ok(id),
            Created::Conflict => Err("Could not queue the job; try again.".into()),
        }
    }

    async fn status(&self, job_id: &str, user_id: i64, admin: bool) -> Result<String, String> {
        let job = self.owned_job(job_id, user_id, admin).await?;
        Ok(self.describe(&job))
    }

    async fn cancel(&self, job_id: &str, user_id: i64, admin: bool) -> Result<String, String> {
        let job = self.owned_job(job_id, user_id, admin).await?;
        if !job.is_active() {
            return Ok(format!(
                "Job <code>{}</code> already finished ({}).",
                job.id, job.state
            ));
        }
        MediaService::cancel(self, &job)
            .await
            .map_err(|_| "Could not cancel the job.".to_owned())?;
        Ok(format!("Cancelling job <code>{}</code>.", job.id))
    }
}

impl StatusProvider for MediaService {
    fn capabilities(&self) -> serde_json::Value {
        let caps = self.ffmpeg.as_ref().and_then(|c| c.capabilities());
        let actions: serde_json::Map<String, serde_json::Value> = Action::ALL
            .iter()
            .map(|a| {
                let why = self.unavailable_reason(*a);
                (
                    a.as_str().to_owned(),
                    json!({ "available": why.is_none(), "reason": why }),
                )
            })
            .collect();
        json!({
            "media": {
                "available": caps.is_some(),
                "ffmpeg_instance": caps.as_ref().map(|c| c.instance_id.clone()),
                "actions": actions,
                "adapters": ["fxtwitter", "fxbluesky"],
                "limits": {
                    "max_source_bytes": self.config.media.max_source_bytes,
                    "gif_max_seconds": self.config.media.gif_max_seconds,
                    "gif_target_bytes": self.config.media.gif_target_bytes,
                    "download_retention_seconds": self.config.storage.download_retention_secs,
                    "ffmpeg_max_duration_seconds": caps.as_ref().and_then(|c| c.limit("max_duration_seconds")),
                },
            },
            "time": now(),
        })
    }
}
