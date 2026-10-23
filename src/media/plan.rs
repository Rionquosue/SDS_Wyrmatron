//! Turns an action and the source's metadata into FFmpeg-service requests
//! (SDS §5 presets, §6.3 mapping, §6.4 geometry).

use super::spec::{Action, CompressPreset, JobOptions};
use crate::ffmpeg::types::{bounded_even, bitrate_cap_kbps, AudioMode, Capabilities, MediaInfo, Operation, VideoParams};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// Telegram animation (silent H.264 MP4).
    Animation,
    Video,
    Document,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rung {
    pub op: Operation,
    pub format: &'static str,
    /// Expected output size, for Telegram's width/height and the thumbnail.
    pub dims: (u32, u32),
    pub delivery: Delivery,
}

/// GIF size ladder: (longest edge, fps cap, quality). SDS §5.
pub const GIF_LADDER: [(u32, u32, u8); 3] = [(640, 15, 28), (480, 12, 31), (360, 10, 34)];

/// Operations each action needs, for availability checks.
pub fn requirements(action: Action) -> &'static [(&'static str, &'static str, &'static [&'static str])] {
    match action {
        Action::Fetch => &[],
        Action::Mp4 | Action::Compress => &[("metadata", "json", &[]), ("transcode", "mp4", &["quality", "audio_bitrate_kbps"])],
        Action::Mute => &[("metadata", "json", &[]), ("remux", "mp4", &["audio_mode"]), ("transcode", "mp4", &["audio_mode", "quality"])],
        Action::Gif => &[
            ("metadata", "json", &[]),
            ("transcode", "mp4", &["audio_mode", "quality", "max_fps", "max_bitrate_kbps"]),
        ],
    }
}

/// Output size of the service's `max_dimension` scaling: never upscaled,
/// rounded down to even.
fn scaled(w: u32, h: u32, limit: u32) -> (u32, u32) {
    let long = w.max(h);
    let s = if long > limit { f64::from(limit) / f64::from(long) } else { 1.0 };
    let even = |v: u32| (((f64::from(v) * s) as u32) / 2 * 2).max(2);
    (even(w), even(h))
}

struct Ctx<'a> {
    info: &'a MediaInfo,
    caps: &'a Capabilities,
    opts: &'a JobOptions,
}

impl Ctx<'_> {
    fn op_name(&self) -> &'static str {
        if self.opts.is_clip() { "trim" } else { "transcode" }
    }

    fn supports(&self, params: &[&str]) -> bool {
        self.caps.supports(self.op_name(), "mp4", params)
    }

    /// Video parameters with a longest-edge cap, using `max_dimension` when
    /// advertised and the §6.4 width/height calculation otherwise.
    fn video(&self, limit: Option<u32>, mut p: VideoParams) -> (VideoParams, (u32, u32)) {
        let (w, h) = (self.info.width, self.info.height);
        let Some(limit) = limit else { return (p, (w, h)) };
        if self.supports(&["max_dimension"]) {
            p.max_dimension = Some(limit);
            (p, scaled(w, h, limit))
        } else {
            match bounded_even(w, h, limit) {
                Some((bw, bh)) => {
                    p.width = Some(bw);
                    p.height = Some(bh);
                    (p, (bw, bh))
                }
                None => (p, (w, h)),
            }
        }
    }

    fn clip_bounds(&self) -> Result<(f64, f64), String> {
        let start = self.opts.start_seconds.unwrap_or(0.0);
        let total = self.info.duration_seconds;
        if total > 0.0 && start >= total {
            return Err(format!("start={start:.1} is past the end of the {total:.1} s video."));
        }
        let remaining = if total > 0.0 { total - start } else { f64::MAX };
        let duration = self.opts.duration_seconds.unwrap_or(remaining).min(remaining);
        Ok((start, duration))
    }

    fn wrap(&self, mut video: VideoParams) -> Result<Operation, String> {
        // Optional: the service default (128 kbps) applies when unsupported.
        if !self.supports(&["audio_bitrate_kbps"]) {
            video.audio_bitrate_kbps = None;
        }
        if !self.opts.is_clip() {
            return Ok(Operation::Transcode(video));
        }
        let (start_seconds, duration_seconds) = self.clip_bounds()?;
        let op = Operation::Trim { start_seconds, duration_seconds, video };
        let names = op.parameter_names();
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        if !self.caps.supports("trim", "mp4", &names) {
            return Err("Clipping with this action needs a newer FFmpeg service.".into());
        }
        Ok(op)
    }

    /// Duration of the output in seconds, if known.
    fn output_seconds(&self) -> Option<f64> {
        if self.opts.is_clip() {
            self.clip_bounds().ok().map(|(_, d)| d).filter(|d| *d < f64::MAX)
        } else {
            Some(self.info.duration_seconds).filter(|d| *d > 0.0)
        }
    }
}

fn is_h264_mp4(info: &MediaInfo) -> bool {
    info.format.contains("mp4") && info.video_codec.as_deref() == Some("h264")
}

pub fn plan(action: Action, opts: &JobOptions, info: &MediaInfo, caps: &Capabilities, gif_target_bytes: u64) -> Result<Vec<Rung>, String> {
    if info.still_image || info.video_codec.is_none() {
        return Err("That file has no video stream.".into());
    }
    let ctx = Ctx { info, caps, opts };
    let source_dims = (info.width, info.height);
    match action {
        Action::Fetch => Err("fetch does not process media".into()),
        Action::Mp4 => {
            let audio_ok = matches!(info.audio_codec.as_deref(), None | Some("aac"));
            if !opts.is_clip() && is_h264_mp4(info) && audio_ok {
                return Ok(vec![Rung { op: Operation::Remux { audio_mode: None }, format: "mp4", dims: source_dims, delivery: Delivery::Video }]);
            }
            let p = VideoParams { quality: Some(23), audio_bitrate_kbps: Some(128), ..Default::default() };
            Ok(vec![Rung { op: ctx.wrap(p)?, format: "mp4", dims: source_dims, delivery: Delivery::Video }])
        }
        Action::Compress => {
            let preset = opts.preset.unwrap_or(CompressPreset::Balanced);
            let (quality, audio, edge, fps) = preset.settings();
            let mut p = VideoParams { quality: Some(quality), audio_bitrate_kbps: Some(audio), ..Default::default() };
            // The frame-rate cap needs service 0.2; without it compress still runs.
            if fps.is_some() && ctx.supports(&["max_fps"]) {
                p.max_fps = fps;
            }
            let (p, dims) = ctx.video(Some(edge), p);
            Ok(vec![Rung { op: ctx.wrap(p)?, format: "mp4", dims, delivery: Delivery::Video }])
        }
        Action::Mute => {
            if !opts.is_clip() {
                let codec = info.video_codec.as_deref().unwrap_or_default();
                let remux_format = match codec {
                    "h264" => Some(("mp4", Delivery::Video)),
                    "vp8" | "vp9" | "av1" => Some(("webm", Delivery::Document)),
                    _ => None,
                };
                if let Some((format, delivery)) = remux_format {
                    if caps.supports("remux", format, &["audio_mode"]) {
                        return Ok(vec![Rung { op: Operation::Remux { audio_mode: Some(AudioMode::Remove) }, format, dims: source_dims, delivery }]);
                    }
                }
            }
            let p = VideoParams { quality: Some(23), audio_mode: Some(AudioMode::Remove), ..Default::default() };
            Ok(vec![Rung { op: ctx.wrap(p)?, format: "mp4", dims: source_dims, delivery: Delivery::Video }])
        }
        Action::Gif => {
            let seconds = ctx.output_seconds();
            GIF_LADDER
                .iter()
                .map(|&(edge, fps, quality)| {
                    let mut p = VideoParams { quality: Some(quality), audio_mode: Some(AudioMode::Remove), max_fps: Some(fps), ..Default::default() };
                    if let Some(s) = seconds {
                        p.max_bitrate_kbps = Some(bitrate_cap_kbps(gif_target_bytes, s));
                    }
                    let (p, dims) = ctx.video(Some(edge), p);
                    Ok(Rung { op: ctx.wrap(p)?, format: "mp4", dims, delivery: Delivery::Animation })
                })
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn caps(v2: bool) -> Capabilities {
        let mut c = json!({ "api_version": "1", "instance_id": "i",
            "operations": { "metadata": ["json"], "transcode": ["mp4", "webm"], "trim": ["mp4", "webm"], "remux": ["mp4", "webm"] } });
        if v2 {
            let video = json!(["width", "height", "fit", "quality", "audio_bitrate_kbps", "audio_mode", "max_dimension", "max_fps", "max_bitrate_kbps"]);
            let mut trim = video.clone();
            trim.as_array_mut().unwrap().extend([json!("start_seconds"), json!("duration_seconds")]);
            c["parameters"] = json!({ "transcode": video, "trim": trim, "remux": ["audio_mode"], "metadata": [] });
        }
        serde_json::from_value(c).unwrap()
    }

    fn info(codec: &str, format: &str, w: u32, h: u32, secs: f64, audio: Option<&str>) -> MediaInfo {
        MediaInfo {
            format: format.into(),
            duration_seconds: secs,
            width: w,
            height: h,
            video_codec: Some(codec.into()),
            audio_codec: audio.map(str::to_owned),
            ..Default::default()
        }
    }

    const MP4: &str = "mov,mp4,m4a,3gp,3g2,mj2";
    const TARGET: u64 = 8 * 1024 * 1024;

    #[test]
    fn mp4_remuxes_compatible_sources_and_transcodes_others() {
        let r = plan(Action::Mp4, &JobOptions::default(), &info("h264", MP4, 1280, 720, 10.0, Some("aac")), &caps(false), TARGET).unwrap();
        assert_eq!(r[0].op, Operation::Remux { audio_mode: None });
        let r = plan(Action::Mp4, &JobOptions::default(), &info("vp9", "matroska,webm", 1280, 720, 10.0, Some("opus")), &caps(false), TARGET).unwrap();
        assert!(matches!(&r[0].op, Operation::Transcode(p) if p.quality == Some(23)));
    }

    #[test]
    fn compress_uses_width_height_on_v1_and_max_dimension_on_v2() {
        let opts = JobOptions { preset: Some(CompressPreset::Small), ..Default::default() };
        let src = info("h264", MP4, 1920, 1080, 10.0, Some("aac"));
        let v1 = plan(Action::Compress, &opts, &src, &caps(false), TARGET).unwrap();
        let Operation::Transcode(p) = &v1[0].op else { panic!() };
        assert_eq!((p.width, p.height, p.max_fps, p.quality, p.audio_bitrate_kbps), (Some(854), Some(480), None, Some(31), Some(64)));
        assert_eq!(v1[0].dims, (854, 480));
        let v2 = plan(Action::Compress, &opts, &src, &caps(true), TARGET).unwrap();
        let Operation::Transcode(p) = &v2[0].op else { panic!() };
        assert_eq!((p.width, p.max_dimension, p.max_fps), (None, Some(854), Some(24)));
        // Small sources are not resized.
        let small = plan(Action::Compress, &JobOptions::default(), &info("h264", MP4, 640, 360, 10.0, None), &caps(false), TARGET).unwrap();
        assert!(matches!(&small[0].op, Operation::Transcode(p) if p.width.is_none()));
    }

    #[test]
    fn mute_prefers_remux_in_the_same_container() {
        let r = plan(Action::Mute, &JobOptions::default(), &info("h264", MP4, 1280, 720, 10.0, Some("aac")), &caps(true), TARGET).unwrap();
        assert_eq!((r[0].format, &r[0].op), ("mp4", &Operation::Remux { audio_mode: Some(AudioMode::Remove) }));
        let r = plan(Action::Mute, &JobOptions::default(), &info("vp9", "matroska,webm", 1280, 720, 10.0, Some("opus")), &caps(true), TARGET).unwrap();
        assert_eq!((r[0].format, r[0].delivery), ("webm", Delivery::Document));
        let r = plan(Action::Mute, &JobOptions::default(), &info("hevc", MP4, 1280, 720, 10.0, Some("aac")), &caps(true), TARGET).unwrap();
        assert!(matches!(&r[0].op, Operation::Transcode(p) if p.audio_mode == Some(AudioMode::Remove)));
        // A clip always re-encodes.
        let clip = JobOptions { start_seconds: Some(2.0), ..Default::default() };
        let r = plan(Action::Mute, &clip, &info("h264", MP4, 1280, 720, 10.0, Some("aac")), &caps(true), TARGET).unwrap();
        assert!(matches!(&r[0].op, Operation::Trim { start_seconds, duration_seconds, .. } if *start_seconds == 2.0 && *duration_seconds == 8.0));
    }

    #[test]
    fn gif_ladder_with_bitrate_caps() {
        let opts = JobOptions { start_seconds: Some(3.0), duration_seconds: Some(8.0), ..Default::default() };
        let r = plan(Action::Gif, &opts, &info("h264", MP4, 1080, 1920, 45.8, Some("aac")), &caps(true), TARGET).unwrap();
        assert_eq!(r.len(), 3);
        let Operation::Trim { video, duration_seconds, .. } = &r[0].op else { panic!() };
        assert_eq!(*duration_seconds, 8.0);
        assert_eq!((video.max_dimension, video.max_fps, video.quality, video.audio_mode), (Some(640), Some(15), Some(28), Some(AudioMode::Remove)));
        assert_eq!(video.max_bitrate_kbps, Some(bitrate_cap_kbps(TARGET, 8.0)));
        assert_eq!(r[0].dims, (360, 640));
        assert_eq!(r[2].dims, (202, 360));
        assert!(r.iter().all(|x| x.delivery == Delivery::Animation));
    }

    #[test]
    fn clips_need_a_capable_service_and_valid_bounds() {
        let clip = JobOptions { start_seconds: Some(1.0), ..Default::default() };
        let err = plan(Action::Compress, &clip, &info("h264", MP4, 1920, 1080, 10.0, None), &caps(false), TARGET).unwrap_err();
        assert!(err.contains("newer FFmpeg service"), "{err}");
        // A plain trim with quality works on v0.1.0.
        assert!(plan(Action::Mp4, &clip, &info("h264", MP4, 640, 360, 10.0, None), &caps(false), TARGET).is_ok());
        let late = JobOptions { start_seconds: Some(12.0), ..Default::default() };
        assert!(plan(Action::Mp4, &late, &info("h264", MP4, 640, 360, 10.0, None), &caps(true), TARGET).unwrap_err().contains("past the end"));
        let audio_only = MediaInfo { video_codec: None, ..info("h264", MP4, 0, 0, 10.0, Some("aac")) };
        assert!(plan(Action::Mp4, &JobOptions::default(), &audio_only, &caps(true), TARGET).is_err());
    }
}
