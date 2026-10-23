//! Media actions, presets and options shared by Telegram commands and the API.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Gif,
    Mute,
    Compress,
    Mp4,
    Fetch,
}

impl Action {
    pub const ALL: [Action; 5] = [
        Action::Gif,
        Action::Mute,
        Action::Compress,
        Action::Mp4,
        Action::Fetch,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gif => "gif",
            Self::Mute => "mute",
            Self::Compress => "compress",
            Self::Mp4 => "mp4",
            Self::Fetch => "fetch",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Gif => "GIF",
            Self::Mute => "Mute",
            Self::Compress => "Compress",
            Self::Mp4 => "MP4",
            Self::Fetch => "Extract video",
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Action {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        Ok(match s {
            "gif" => Self::Gif,
            "mute" => Self::Mute,
            "compress" => Self::Compress,
            "mp4" => Self::Mp4,
            "fetch" => Self::Fetch,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CompressPreset {
    Light,
    #[default]
    Balanced,
    Small,
}

impl CompressPreset {
    /// (quality, audio kbps, longest edge, fps cap) per SDS §5.
    pub fn settings(self) -> (u8, u16, u32, Option<u32>) {
        match self {
            Self::Light => (23, 128, 1920, None),
            Self::Balanced => (27, 96, 1280, None),
            Self::Small => (31, 64, 854, Some(24)),
        }
    }
}

impl FromStr for CompressPreset {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        Ok(match s.trim_start_matches("compress-") {
            "light" => Self::Light,
            "balanced" => Self::Balanced,
            "small" => Self::Small,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_seconds: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_seconds: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset: Option<CompressPreset>,
    /// 1-based media index within a post (`/video/2`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_index: Option<u32>,
}

impl JobOptions {
    pub fn is_clip(&self) -> bool {
        self.start_seconds.is_some() || self.duration_seconds.is_some()
    }

    pub fn validate(&self, action: Action, max_gif_seconds: f64) -> Result<(), String> {
        for (name, v) in [
            ("start", self.start_seconds),
            ("duration", self.duration_seconds),
        ] {
            if let Some(v) = v
                && (!v.is_finite() || !(0.0..=86_400.0).contains(&v))
            {
                return Err(format!("{name} must be a number of seconds."));
            }
        }
        if self.duration_seconds == Some(0.0) {
            return Err("duration must be greater than zero.".into());
        }
        if self.preset.is_some() && action != Action::Compress {
            return Err("A preset applies only to compress.".into());
        }
        if self.is_clip() && action == Action::Fetch {
            return Err(
                "fetch returns the original video; use gif, mp4 or compress to clip.".into(),
            );
        }
        if action == Action::Gif
            && let Some(d) = self.duration_seconds
            && d > max_gif_seconds
        {
            return Err(format!(
                "GIFs are limited to {max_gif_seconds:.0} seconds; choose a shorter duration."
            ));
        }
        Ok(())
    }
}

/// Parses command arguments such as `start=3 duration=8 small` into options.
/// Returns the options and the remaining (non-option) arguments.
pub fn parse_args<'a>(
    action: Action,
    args: &[&'a str],
) -> Result<(JobOptions, Vec<&'a str>), String> {
    let mut opts = JobOptions::default();
    let mut rest = Vec::new();
    for arg in args {
        let seconds =
            |v: &str| parse_seconds(v).ok_or_else(|| format!("Could not read {v:?} as seconds."));
        match arg.split_once('=') {
            Some(("start", v)) => opts.start_seconds = Some(seconds(v)?),
            Some(("duration", v)) => opts.duration_seconds = Some(seconds(v)?),
            Some(("preset", v)) => {
                opts.preset = Some(
                    v.parse()
                        .map_err(|_| "Preset must be light, balanced or small.".to_owned())?,
                )
            }
            Some(("video", v)) => {
                opts.media_index = Some(
                    v.parse()
                        .ok()
                        .filter(|n| *n >= 1)
                        .ok_or("video must be 1 or more.")?,
                )
            }
            Some((k, _)) => return Err(format!("Unknown option {k}.")),
            None if action == Action::Compress && arg.parse::<CompressPreset>().is_ok() => {
                opts.preset = arg.parse().ok();
            }
            None => rest.push(*arg),
        }
    }
    Ok((opts, rest))
}

/// Accepts `8`, `8.5`, `1:30` or `0:01:30`.
pub fn parse_seconds(v: &str) -> Option<f64> {
    let mut total = 0.0;
    let parts: Vec<&str> = v.split(':').collect();
    if parts.len() > 3 {
        return None;
    }
    for p in &parts {
        let n: f64 = p.parse().ok()?;
        if !n.is_finite() || n < 0.0 {
            return None;
        }
        total = total * 60.0 + n;
    }
    Some(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gif_clip_options() {
        let (o, rest) = parse_args(
            Action::Gif,
            &["https://x.com/a/status/1", "start=3", "duration=0:08"],
        )
        .unwrap();
        assert_eq!(o.start_seconds, Some(3.0));
        assert_eq!(o.duration_seconds, Some(8.0));
        assert_eq!(rest, vec!["https://x.com/a/status/1"]);
        assert!(o.validate(Action::Gif, 30.0).is_ok());
        let long = JobOptions {
            duration_seconds: Some(45.0),
            ..Default::default()
        };
        assert!(
            long.validate(Action::Gif, 30.0)
                .unwrap_err()
                .contains("30 seconds")
        );
    }

    #[test]
    fn compress_preset_bare_or_keyword() {
        assert_eq!(
            parse_args(Action::Compress, &["small"]).unwrap().0.preset,
            Some(CompressPreset::Small)
        );
        assert_eq!(
            parse_args(Action::Compress, &["preset=light"])
                .unwrap()
                .0
                .preset,
            Some(CompressPreset::Light)
        );
        // A bare word is only a preset for compress.
        assert_eq!(
            parse_args(Action::Gif, &["small"]).unwrap().1,
            vec!["small"]
        );
        assert!(parse_args(Action::Compress, &["preset=huge"]).is_err());
        let o = JobOptions {
            preset: Some(CompressPreset::Small),
            ..Default::default()
        };
        assert!(o.validate(Action::Gif, 30.0).is_err());
    }

    #[test]
    fn rejects_bad_values() {
        assert!(parse_args(Action::Gif, &["start=abc"]).is_err());
        assert!(parse_args(Action::Gif, &["speed=2"]).is_err());
        assert!(parse_args(Action::Gif, &["video=0"]).is_err());
        assert_eq!(parse_seconds("1:30"), Some(90.0));
        assert_eq!(parse_seconds("-1"), None);
        assert_eq!(parse_seconds("1:2:3:4"), None);
        let zero = JobOptions {
            duration_seconds: Some(0.0),
            ..Default::default()
        };
        assert!(zero.validate(Action::Mp4, 30.0).is_err());
        let clip = JobOptions {
            start_seconds: Some(1.0),
            ..Default::default()
        };
        assert!(clip.validate(Action::Fetch, 30.0).is_err());
    }
}
