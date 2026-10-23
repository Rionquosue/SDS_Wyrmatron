//! FFmpeg service API v1 types (`Rionquosue/FFMPEG_container`,
//! `docs/openapi.json`). Response types ignore unknown fields, as the
//! contract requires.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct Capabilities {
    pub api_version: String,
    pub instance_id: String,
    #[serde(default)]
    pub operations: HashMap<String, Vec<String>>,
    /// Added in service 0.2.0; absent means the 0.1.0 parameter set.
    #[serde(default)]
    pub parameters: Option<HashMap<String, Vec<String>>>,
    #[serde(default)]
    pub limits: HashMap<String, f64>,
}

/// Parameters accepted by service 0.1.0, which did not advertise them.
fn baseline_parameters(op: &str) -> &'static [&'static str] {
    match op {
        "transcode" => &["width", "height", "fit", "quality", "audio_bitrate_kbps"],
        "trim" => &["start_seconds", "duration_seconds", "quality"],
        "thumbnail" => &[
            "timestamp_seconds",
            "width",
            "height",
            "fit",
            "jpeg_quality",
        ],
        "resize" => &["width", "height", "fit", "jpeg_quality"],
        "extract_audio" => &["audio_bitrate_kbps", "channels"],
        _ => &[],
    }
}

impl Capabilities {
    pub fn limit(&self, name: &str) -> Option<u64> {
        self.limits
            .get(name)
            .copied()
            .filter(|v| v.is_finite() && *v >= 0.0)
            .map(|v| v as u64)
    }

    /// Whether `op` can produce `format` and accepts every name in `params`.
    pub fn supports(&self, op: &str, format: &str, params: &[&str]) -> bool {
        if !self
            .operations
            .get(op)
            .is_some_and(|f| f.iter().any(|x| x == format))
        {
            return false;
        }
        match &self.parameters {
            Some(map) => {
                let accepted = map.get(op).map(Vec::as_slice).unwrap_or_default();
                params.iter().all(|p| accepted.iter().any(|a| a == p))
            }
            None => params.iter().all(|p| baseline_parameters(op).contains(p)),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AudioMode {
    Preserve,
    Remove,
}

/// Optional video parameters shared by `transcode` and `trim`.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct VideoParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quality: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audio_bitrate_kbps: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audio_mode: Option<AudioMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_dimension: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_fps: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_bitrate_kbps: Option<u32>,
}

/// One service operation and its parameters. Absent optional parameters are
/// omitted because the service rejects `null`.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "operation", content = "parameters", rename_all = "snake_case")]
pub enum Operation {
    Metadata {},
    Remux {
        #[serde(skip_serializing_if = "Option::is_none")]
        audio_mode: Option<AudioMode>,
    },
    Transcode(VideoParams),
    Trim {
        start_seconds: f64,
        duration_seconds: f64,
        #[serde(flatten)]
        video: VideoParams,
    },
    Thumbnail {
        timestamp_seconds: f64,
        width: u32,
        height: u32,
        jpeg_quality: u8,
    },
}

impl Operation {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Metadata {} => "metadata",
            Self::Remux { .. } => "remux",
            Self::Transcode(_) => "transcode",
            Self::Trim { .. } => "trim",
            Self::Thumbnail { .. } => "thumbnail",
        }
    }

    /// Names of the parameters this request sends.
    pub fn parameter_names(&self) -> Vec<String> {
        serde_json::to_value(self)
            .ok()
            .and_then(|v| {
                v.get("parameters")
                    .and_then(|p| p.as_object())
                    .map(|m| m.keys().cloned().collect())
            })
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct InputDecl {
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct JobRequest {
    #[serde(flatten)]
    pub op: Operation,
    pub input: InputDecl,
    pub output_format: &'static str,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResultInfo {
    pub content_type: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JobError {
    pub code: String,
    #[serde(default)]
    pub field: Option<String>,
    #[serde(default)]
    pub retryable: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Job {
    pub instance_id: String,
    pub job_id: String,
    pub status: String,
    #[serde(default)]
    pub result: Option<ResultInfo>,
    #[serde(default)]
    pub error: Option<JobError>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ErrorEnvelope {
    pub error: JobError,
}

/// Result of the `metadata` operation.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct MediaInfo {
    #[serde(default)]
    pub format: String,
    #[serde(default)]
    pub duration_seconds: f64,
    #[serde(default)]
    pub width: u32,
    #[serde(default)]
    pub height: u32,
    #[serde(default)]
    pub video_codec: Option<String>,
    #[serde(default)]
    pub audio_codec: Option<String>,
    #[serde(default)]
    pub channels: Option<u32>,
    #[serde(default)]
    pub frame_rate: Option<f64>,
    #[serde(default)]
    pub still_image: bool,
}

/// Longest edge capped at `limit` without padding or upscaling (SDS §6.4).
/// Returns `None` when the source already fits; dimensions are even and at
/// least 16. Use only where the service lacks `max_dimension`.
pub fn bounded_even(width: u32, height: u32, limit: u32) -> Option<(u32, u32)> {
    let long = width.max(height);
    if long <= limit || width == 0 || height == 0 {
        return None;
    }
    let s = f64::from(limit) / f64::from(long);
    let even = |v: u32| (((f64::from(v) * s) as u32) / 2 * 2).max(16);
    Some((even(width), even(height)))
}

/// Thumbnail box within 320 px. Odd sizes are allowed; a scale of exactly 1
/// is accepted by the service.
pub fn thumbnail_box(width: u32, height: u32) -> Option<(u32, u32)> {
    if width < 16 || height < 16 {
        return None;
    }
    let long = width.max(height);
    if long <= 320 {
        return Some((width, height));
    }
    let s = 320.0 / f64::from(long);
    Some((
        ((f64::from(width) * s) as u32).max(16),
        ((f64::from(height) * s) as u32).max(16),
    ))
}

/// Capped-CRF video bitrate that fits `target_bytes` over `duration`.
pub fn bitrate_cap_kbps(target_bytes: u64, duration_seconds: f64) -> u32 {
    if duration_seconds <= 0.0 {
        return 20_000;
    }
    let kbps = target_bytes as f64 * 8.0 / 1000.0 / duration_seconds * 0.95;
    kbps.clamp(100.0, 20_000.0) as u32
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn serializes_requests_like_the_contract() {
        let req = JobRequest {
            op: Operation::Transcode(VideoParams {
                quality: Some(28),
                audio_mode: Some(AudioMode::Remove),
                max_dimension: Some(640),
                ..Default::default()
            }),
            input: InputDecl {
                size_bytes: 3,
                sha256: "a".repeat(64),
            },
            output_format: "mp4",
        };
        assert_eq!(
            serde_json::to_value(&req).unwrap(),
            json!({ "operation": "transcode", "parameters": { "quality": 28, "audio_mode": "remove", "max_dimension": 640 },
                    "input": { "size_bytes": 3, "sha256": "a".repeat(64) }, "output_format": "mp4" })
        );
        let meta = JobRequest {
            op: Operation::Metadata {},
            input: req.input.clone(),
            output_format: "json",
        };
        assert_eq!(
            serde_json::to_value(&meta).unwrap()["parameters"],
            json!({})
        );
        let trim = Operation::Trim {
            start_seconds: 1.5,
            duration_seconds: 3.0,
            video: VideoParams {
                max_fps: Some(15),
                ..Default::default()
            },
        };
        assert_eq!(
            serde_json::to_value(&trim).unwrap()["parameters"],
            json!({ "start_seconds": 1.5, "duration_seconds": 3.0, "max_fps": 15 })
        );
        let mut names = trim.parameter_names();
        names.sort();
        assert_eq!(names, vec!["duration_seconds", "max_fps", "start_seconds"]);
    }

    #[test]
    fn detects_features_with_and_without_a_parameter_map() {
        let old: Capabilities = serde_json::from_value(json!({ "api_version": "1", "instance_id": "i",
            "operations": { "transcode": ["mp4", "webm"], "remux": ["mp4", "webm"] }, "limits": { "max_jobs_per_consumer": 2 } }))
        .unwrap();
        assert!(old.supports("transcode", "mp4", &["quality", "width"]));
        assert!(!old.supports("transcode", "mp4", &["audio_mode"]));
        assert!(!old.supports("remux", "mp4", &["audio_mode"]));
        assert!(!old.supports("transcode", "gif", &[]));
        assert_eq!(old.limit("max_jobs_per_consumer"), Some(2));
        let new: Capabilities = serde_json::from_value(
            json!({ "api_version": "1", "instance_id": "i", "future": true,
            "operations": { "remux": ["mp4"] }, "parameters": { "remux": ["audio_mode"] } }),
        )
        .unwrap();
        assert!(new.supports("remux", "mp4", &["audio_mode"]));
    }

    #[test]
    fn geometry_matches_sds_6_4() {
        assert_eq!(bounded_even(1920, 1080, 1280), Some((1280, 720)));
        assert_eq!(bounded_even(1080, 1920, 854), Some((480, 854)));
        assert_eq!(bounded_even(1281, 721, 1280), Some((1280, 720)));
        assert_eq!(bounded_even(640, 360, 1280), None);
        let (w, h) = bounded_even(1919, 1079, 1280).unwrap();
        // Both scale factors stay at or below the target, so the service never sees an upscale.
        assert!(
            f64::from(w) / 1919.0 <= 1280.0 / 1919.0 && f64::from(h) / 1079.0 <= 1280.0 / 1919.0
        );
        assert_eq!(thumbnail_box(1920, 1080), Some((320, 180)));
        assert_eq!(thumbnail_box(301, 99), Some((301, 99)));
        assert_eq!(thumbnail_box(10, 10), None);
        assert_eq!(bitrate_cap_kbps(8 * 1024 * 1024, 10.0), 6375);
        assert_eq!(bitrate_cap_kbps(8 * 1024 * 1024, 100_000.0), 100);
    }
}
