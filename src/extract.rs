//! Social post adapters (SDS §7): structural link parsing, then FxTwitter /
//! FxBluesky API lookups that produce downloadable media candidates.

use serde::Deserialize;
use url::Url;

use crate::config::FetchConfig;
use crate::fetch::{FetchError, Fetcher, HostPolicy};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Post {
    Twitter { id: String },
    Bluesky { actor: String, rkey: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedLink {
    pub post: Post,
    /// 1-based media position from `/video/N` or `/photo/N`.
    pub media_index: Option<u32>,
}

const TWITTER_HOSTS: &[&str] = &[
    "x.com",
    "www.x.com",
    "mobile.x.com",
    "twitter.com",
    "www.twitter.com",
    "mobile.twitter.com",
    "fxtwitter.com",
    "www.fxtwitter.com",
    "d.fxtwitter.com",
    "fixupx.com",
    "www.fixupx.com",
    "d.fixupx.com",
    "vxtwitter.com",
    "fixvx.com",
];
const BLUESKY_HOSTS: &[&str] = &["bsky.app", "www.bsky.app", "fxbsky.app", "d.fxbsky.app"];

fn normalized_host(url: &Url) -> Option<String> {
    url.host_str()
        .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
}

fn is_snowflake(s: &str) -> bool {
    (2..=20).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit())
}

fn is_rkey(s: &str) -> bool {
    (1..=512).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:~-".contains(&b))
}

fn is_actor(s: &str) -> bool {
    let did = (s.starts_with("did:plc:") || s.starts_with("did:web:"))
        && s.len() <= 256
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".:-_%".contains(&b));
    let handle = s.len() <= 253
        && s.contains('.')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b));
    did || handle
}

/// Parses a supported post link by exact hostname and path structure.
/// Query strings (tracking parameters) are ignored.
pub fn parse_link(url: &Url) -> Option<ParsedLink> {
    if !matches!(url.scheme(), "https" | "http") {
        return None;
    }
    let host = normalized_host(url)?;
    let segs: Vec<&str> = url.path_segments()?.filter(|s| !s.is_empty()).collect();
    if TWITTER_HOSTS.contains(&host.as_str()) {
        // /{user}/status/{id}[/video|photo/N], /i/status/{id}, /i/web/status/{id}
        let pos = segs
            .iter()
            .position(|s| *s == "status" || *s == "statuses")?;
        let valid_prefix = pos == 1 || (pos == 2 && segs[0] == "i" && segs[1] == "web");
        if !valid_prefix {
            return None;
        }
        let id = segs
            .get(pos + 1)?
            .trim_end_matches(".mp4")
            .trim_end_matches(".jpg");
        if !is_snowflake(id) {
            return None;
        }
        let media_index = match (segs.get(pos + 2), segs.get(pos + 3)) {
            (Some(&("video" | "photo")), Some(n)) => n.parse().ok().filter(|n| *n >= 1),
            _ => None,
        };
        return Some(ParsedLink {
            post: Post::Twitter { id: id.to_owned() },
            media_index,
        });
    }
    if BLUESKY_HOSTS.contains(&host.as_str()) {
        // /profile/{actor}/post/{rkey}
        if segs.len() >= 4 && segs[0] == "profile" && segs[2] == "post" {
            let actor = percent_decode(segs[1]);
            if is_actor(&actor) && is_rkey(segs[3]) {
                return Some(ParsedLink {
                    post: Post::Bluesky {
                        actor,
                        rkey: segs[3].to_owned(),
                    },
                    media_index: None,
                });
            }
        }
    }
    None
}

fn percent_decode(s: &str) -> String {
    s.replace("%3A", ":").replace("%3a", ":")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaKind {
    Video,
    Gif,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    pub url: Url,
    pub bitrate: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MediaItem {
    pub kind: MediaKind,
    /// Progressive downloads, preferred first.
    pub candidates: Vec<Candidate>,
    /// True when the provider offered only HLS for this item.
    pub hls_only: bool,
    pub duration: Option<f64>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    /// Size from the provider, when it reports one.
    pub size: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct Resolved {
    pub items: Vec<MediaItem>,
    pub author: Option<String>,
    pub post_url: String,
    /// Hosts the media candidates may be downloaded from.
    pub media_hosts: HostPolicy,
}

#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    #[error("That post was not found or has been deleted.")]
    NotFound,
    #[error("That post is private or unavailable.")]
    Private,
    #[error("That post has no video.")]
    NoVideo,
    #[error("That media item is not a video.")]
    NotAVideo,
    #[error("That post has no media item {0}.")]
    NoSuchItem(u32),
    #[error("This post has {0} videos; add video=N to choose one.")]
    Ambiguous(usize),
    #[error(
        "This video is only available as a streaming playlist (HLS), which is not supported yet."
    )]
    HlsOnly,
    #[error("The post service is unavailable right now ({0}). Try again later.")]
    Upstream(String),
}

impl From<FetchError> for ExtractError {
    fn from(e: FetchError) -> Self {
        match e {
            FetchError::Status(404) => Self::NotFound,
            FetchError::Status(401 | 403) => Self::Private,
            other => Self::Upstream(other.to_string()),
        }
    }
}

// --- FxEmbed API v2 response shapes (fields we read; the rest is ignored) ---

#[derive(Deserialize)]
struct FxResponse {
    code: u16,
    #[serde(default)]
    status: Option<FxStatus>,
}

#[derive(Deserialize)]
struct FxStatus {
    url: String,
    #[serde(default)]
    at_uri: Option<String>,
    #[serde(default)]
    author: Option<FxAuthor>,
    #[serde(default)]
    media: Option<FxMedia>,
}

#[derive(Deserialize)]
struct FxAuthor {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    screen_name: Option<String>,
}

#[derive(Deserialize, Default)]
struct FxMedia {
    #[serde(default)]
    all: Vec<FxItem>,
    #[serde(default)]
    videos: Vec<FxItem>,
}

#[derive(Deserialize, Clone)]
struct FxItem {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    formats: Vec<FxFormat>,
    #[serde(default)]
    duration: Option<f64>,
    #[serde(default)]
    width: Option<u32>,
    #[serde(default)]
    height: Option<u32>,
}

#[derive(Deserialize, Clone)]
struct FxFormat {
    url: String,
    #[serde(default)]
    container: Option<String>,
    #[serde(default)]
    bitrate: Option<u64>,
}

fn convert(item: &FxItem) -> Option<MediaItem> {
    let kind = match item.kind.as_str() {
        "video" => MediaKind::Video,
        "gif" => MediaKind::Gif,
        _ => return None,
    };
    let mut candidates: Vec<Candidate> = item
        .formats
        .iter()
        .filter(|f| f.container.as_deref() == Some("mp4"))
        .filter_map(|f| {
            Url::parse(&f.url).ok().map(|url| Candidate {
                url,
                bitrate: f.bitrate,
            })
        })
        .collect();
    let has_hls = item
        .formats
        .iter()
        .any(|f| f.container.as_deref() == Some("m3u8"));
    if candidates.is_empty()
        && item.format.as_deref() == Some("video/mp4")
        && let Some(u) = item.url.as_deref().and_then(|u| Url::parse(u).ok())
    {
        candidates.push(Candidate {
            url: u,
            bitrate: None,
        });
    }
    candidates.sort_by_key(|c| std::cmp::Reverse(c.bitrate));
    Some(MediaItem {
        kind,
        hls_only: candidates.is_empty()
            && (has_hls || item.url.as_deref().is_some_and(|u| u.contains(".m3u8"))),
        candidates,
        duration: item.duration.filter(|d| *d > 0.0),
        width: item.width,
        height: item.height,
        size: None,
    })
}

/// Picks the media item for a post, honouring an explicit index.
pub fn select(resolved: &Resolved, index: Option<u32>) -> Result<MediaItem, ExtractError> {
    let item = match index {
        Some(n) => {
            let item = resolved
                .items
                .get((n as usize).wrapping_sub(1))
                .cloned()
                .ok_or(ExtractError::NoSuchItem(n))?;
            if item.candidates.is_empty() && !item.hls_only {
                return Err(ExtractError::NotAVideo);
            }
            item
        }
        None => match resolved.items.len() {
            0 => return Err(ExtractError::NoVideo),
            1 => resolved.items[0].clone(),
            n => return Err(ExtractError::Ambiguous(n)),
        },
    };
    if item.hls_only {
        return Err(ExtractError::HlsOnly);
    }
    if item.candidates.is_empty() {
        return Err(ExtractError::NoVideo);
    }
    Ok(item)
}

/// Highest-quality rendition whose estimated size fits `max_bytes`, else the
/// smallest one.
pub fn choose_candidate(item: &MediaItem, max_bytes: u64) -> &Candidate {
    let fits = |c: &&Candidate| match (c.bitrate, item.duration) {
        (Some(b), Some(d)) => (b as f64 / 8.0 * d * 1.1) as u64 <= max_bytes,
        _ => true,
    };
    item.candidates
        .iter()
        .find(fits)
        .unwrap_or_else(|| item.candidates.last().expect("non-empty candidates"))
}

pub struct Extractor {
    fetcher: std::sync::Arc<Fetcher>,
    fxtwitter: Url,
    fxbsky: Url,
    plc: Url,
    api_hosts: HostPolicy,
}

fn host_of(u: &Url) -> String {
    u.host_str().unwrap_or_default().to_owned()
}

impl Extractor {
    pub fn new(fetcher: std::sync::Arc<Fetcher>, cfg: &FetchConfig) -> anyhow::Result<Self> {
        let fxtwitter = Url::parse(&cfg.fxtwitter_api)?;
        let fxbsky = Url::parse(&cfg.fxbsky_api)?;
        let plc = Url::parse(&cfg.plc_directory)?;
        let api_hosts = HostPolicy::new([host_of(&fxtwitter), host_of(&fxbsky), host_of(&plc)]);
        Ok(Self {
            fetcher,
            fxtwitter,
            fxbsky,
            plc,
            api_hosts,
        })
    }

    pub async fn resolve(&self, link: &ParsedLink) -> Result<Resolved, ExtractError> {
        match &link.post {
            Post::Twitter { id } => {
                let url = self
                    .fxtwitter
                    .join(&format!("/2/status/{id}"))
                    .map_err(|e| ExtractError::Upstream(e.to_string()))?;
                let res = self.fx(&url).await?;
                Ok(twitter_resolved(res, link.media_index))
            }
            Post::Bluesky { actor, rkey } => {
                let url = self
                    .fxbsky
                    .join(&format!("/2/status/{actor}/{rkey}"))
                    .map_err(|e| ExtractError::Upstream(e.to_string()))?;
                let res = self.fx(&url).await?;
                let pds = match res
                    .status
                    .as_ref()
                    .and_then(|s| s.at_uri.as_deref())
                    .and_then(did_from_at_uri)
                {
                    Some(did) => self.pds_for(&did).await.ok().map(|p| (did, p)),
                    None => None,
                };
                Ok(bluesky_resolved(res, pds))
            }
        }
    }

    async fn fx(&self, url: &Url) -> Result<FxResponse, ExtractError> {
        let res: FxResponse = self.fetcher.get_json(url, &self.api_hosts).await?;
        // `code` mirrors upstream errors even on HTTP 200.
        match res.code {
            200 => Ok(res),
            404 => Err(ExtractError::NotFound),
            401 | 403 => Err(ExtractError::Private),
            other => Err(ExtractError::Upstream(format!("code {other}"))),
        }
    }

    /// Resolves a DID to its PDS endpoint (did:plc via the PLC directory,
    /// did:web via `/.well-known/did.json`).
    async fn pds_for(&self, did: &str) -> Result<Url, ExtractError> {
        let (url, policy) = if did.starts_with("did:plc:") {
            (
                self.plc
                    .join(&format!("/{did}"))
                    .map_err(|e| ExtractError::Upstream(e.to_string()))?,
                self.api_hosts.clone(),
            )
        } else if let Some(domain) = did.strip_prefix("did:web:") {
            let u = Url::parse(&format!("https://{domain}/.well-known/did.json"))
                .map_err(|e| ExtractError::Upstream(e.to_string()))?;
            let policy = HostPolicy::new([domain.to_owned()]);
            (u, policy)
        } else {
            return Err(ExtractError::Upstream("unsupported DID method".into()));
        };
        let doc: DidDocument = self.fetcher.get_json(&url, &policy).await?;
        pds_endpoint(&doc).ok_or_else(|| ExtractError::Upstream("no PDS in DID document".into()))
    }
}

#[derive(Deserialize)]
struct DidDocument {
    #[serde(default)]
    service: Vec<DidService>,
}

#[derive(Deserialize)]
struct DidService {
    id: String,
    #[serde(rename = "serviceEndpoint")]
    endpoint: String,
}

fn pds_endpoint(doc: &DidDocument) -> Option<Url> {
    doc.service
        .iter()
        .find(|s| s.id.ends_with("#atproto_pds"))
        .and_then(|s| Url::parse(&s.endpoint).ok())
        .filter(|u| u.scheme() == "https")
}

fn did_from_at_uri(uri: &str) -> Option<String> {
    let did = uri.strip_prefix("at://")?.split('/').next()?;
    did.starts_with("did:").then(|| did.to_owned())
}

fn author(status: &FxStatus) -> Option<String> {
    status
        .author
        .as_ref()
        .and_then(|a| match (&a.name, &a.screen_name) {
            (Some(n), Some(s)) => Some(format!("{n} (@{s})")),
            (Some(n), None) => Some(n.clone()),
            (None, Some(s)) => Some(format!("@{s}")),
            _ => None,
        })
}

fn twitter_resolved(res: FxResponse, index: Option<u32>) -> Resolved {
    let status = res.status.expect("code 200 carries a status");
    let media = status.media.as_ref();
    // An explicit index counts every media item (photos too), as X does.
    let items: Vec<MediaItem> = match index {
        Some(_) => media
            .map(|m| {
                m.all
                    .iter()
                    .map(|i| {
                        convert(i).unwrap_or(MediaItem {
                            kind: MediaKind::Video,
                            candidates: vec![],
                            hls_only: false,
                            duration: None,
                            width: None,
                            height: None,
                            size: None,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default(),
        None => media
            .map(|m| m.videos.iter().filter_map(convert).collect())
            .unwrap_or_default(),
    };
    Resolved {
        items,
        author: author(&status),
        post_url: status.url.clone(),
        media_hosts: HostPolicy::new([".twimg.com"]),
    }
}

fn bluesky_resolved(res: FxResponse, pds: Option<(String, Url)>) -> Resolved {
    let status = res.status.expect("code 200 carries a status");
    let mut hosts = vec!["pds-cache.fxbsky.app".to_owned()];
    let mut items = Vec::new();
    for v in status
        .media
        .as_ref()
        .map(|m| m.videos.as_slice())
        .unwrap_or_default()
    {
        let Some(mut item) = convert(v) else { continue };
        // The FxBluesky URL ends with the blob CID; prefer the original
        // upload straight from the author's PDS, keeping the cache as fallback.
        let cid = v
            .url
            .as_deref()
            .and_then(|u| u.rsplit('/').next())
            .filter(|c| c.starts_with("baf"))
            .map(str::to_owned);
        if let (Some(cid), Some((did, pds))) = (cid, &pds) {
            let mut blob = pds.clone();
            blob.set_path("/xrpc/com.atproto.sync.getBlob");
            blob.query_pairs_mut()
                .append_pair("did", did)
                .append_pair("cid", &cid);
            hosts.push(host_of(pds));
            item.candidates.insert(
                0,
                Candidate {
                    url: blob,
                    bitrate: None,
                },
            );
        }
        items.push(item);
    }
    Resolved {
        items,
        author: author(&status),
        post_url: status.url.clone(),
        media_hosts: HostPolicy::new(hosts),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(s: &str) -> Option<ParsedLink> {
        parse_link(&Url::parse(s).unwrap())
    }

    #[test]
    fn parses_twitter_links() {
        let tw = |id: &str, idx| {
            Some(ParsedLink {
                post: Post::Twitter { id: id.into() },
                media_index: idx,
            })
        };
        assert_eq!(
            link("https://x.com/NASA/status/2112560723603632217?s=20&t=abc"),
            tw("2112560723603632217", None)
        );
        assert_eq!(
            link("https://twitter.com/a/status/123/video/2"),
            tw("123", Some(2))
        );
        assert_eq!(
            link("https://mobile.twitter.com/i/web/status/123"),
            tw("123", None)
        );
        assert_eq!(
            link("https://fixupx.com/example/status/123456789"),
            tw("123456789", None)
        );
        assert_eq!(
            link("https://d.fxtwitter.com/a/status/123.mp4"),
            tw("123", None)
        );
        assert_eq!(link("https://X.COM./a/status/123"), tw("123", None));
        assert_eq!(link("https://x.com/a/status/abc"), None);
        assert_eq!(link("https://x.com.evil.com/a/status/123"), None);
        assert_eq!(link("https://notx.com/a/status/123"), None);
        assert_eq!(link("https://x.com/a/b/status/123"), None);
        assert_eq!(link("ftp://x.com/a/status/123"), None);
    }

    #[test]
    fn parses_bluesky_links() {
        let bs = |a: &str, r: &str| {
            Some(ParsedLink {
                post: Post::Bluesky {
                    actor: a.into(),
                    rkey: r.into(),
                },
                media_index: None,
            })
        };
        assert_eq!(
            link("https://bsky.app/profile/bsky.app/post/3myi3k45jh22z"),
            bs("bsky.app", "3myi3k45jh22z")
        );
        assert_eq!(
            link("https://bsky.app/profile/did:plc:z72i7hdynmk6r22z27h6tvur/post/3k"),
            bs("did:plc:z72i7hdynmk6r22z27h6tvur", "3k")
        );
        assert_eq!(
            link("https://fxbsky.app/profile/did%3Aplc%3Aabc/post/3k"),
            bs("did:plc:abc", "3k")
        );
        assert_eq!(link("https://bsky.app/profile/nodots/post/3k"), None);
        assert_eq!(link("https://bsky.app/profile/a.b/feed/x"), None);
    }

    fn fx(name: &str) -> FxResponse {
        let raw = std::fs::read_to_string(format!(
            "{}/tests/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        serde_json::from_str(&raw).unwrap()
    }

    #[test]
    fn twitter_fixture_yields_progressive_mp4s() {
        let r = twitter_resolved(fx("fxtwitter_video.json"), None);
        assert_eq!(r.items.len(), 1);
        let item = select(&r, None).unwrap();
        assert_eq!(item.kind, MediaKind::Video);
        assert_eq!(
            item.candidates.len(),
            4,
            "the m3u8 playlist is not a candidate"
        );
        assert!(
            item.candidates
                .windows(2)
                .all(|w| w[0].bitrate >= w[1].bitrate)
        );
        assert!(
            r.media_hosts
                .allows(item.candidates[0].url.host_str().unwrap())
        );
        // 45.8 s at 10.4 Mbit/s is ~65 MB: with a 20 MB cap the 2.2 Mbit/s rendition is chosen.
        assert_eq!(choose_candidate(&item, 20_000_000).bitrate, Some(2_176_000));
        assert_eq!(choose_candidate(&item, 1000).bitrate, Some(632_000));
        assert_eq!(r.author.as_deref(), Some("NASA (@NASA)"));
    }

    #[test]
    fn twitter_mixed_media_and_errors() {
        let r = twitter_resolved(fx("fxtwitter_mixed.json"), None);
        assert!(matches!(select(&r, None), Err(ExtractError::Ambiguous(2))));
        let indexed = twitter_resolved(fx("fxtwitter_mixed.json"), Some(1));
        assert!(
            matches!(select(&indexed, Some(1)), Err(ExtractError::NotAVideo)),
            "position 1 is a photo"
        );
        assert_eq!(select(&indexed, Some(2)).unwrap().kind, MediaKind::Gif);
        assert!(matches!(
            select(&indexed, Some(3)),
            Err(ExtractError::HlsOnly)
        ));
        assert!(matches!(
            select(&indexed, Some(9)),
            Err(ExtractError::NoSuchItem(9))
        ));
        assert_eq!(fx("fxtwitter_404.json").code, 404);
    }

    #[test]
    fn bluesky_fixture_prefers_the_pds_blob() {
        let doc: DidDocument = serde_json::from_str(
            &std::fs::read_to_string(format!(
                "{}/tests/fixtures/plc_did.json",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap(),
        )
        .unwrap();
        let pds = pds_endpoint(&doc).unwrap();
        assert_eq!(pds.as_str(), "https://puffball.us-east.host.bsky.network/");
        let res = fx("fxbsky_video.json");
        let did = did_from_at_uri(res.status.as_ref().unwrap().at_uri.as_deref().unwrap()).unwrap();
        let r = bluesky_resolved(res, Some((did, pds)));
        let item = select(&r, None).unwrap();
        assert_eq!(
            item.candidates[0].url.as_str(),
            "https://puffball.us-east.host.bsky.network/xrpc/com.atproto.sync.getBlob?did=did%3Aplc%3Az72i7hdynmk6r22z27h6tvur&cid=bafkreiew3laj2to7km3kli6g5dmb7xbqygqa7otzirszqvnousjallw6eq"
        );
        assert_eq!(
            item.candidates[1].url.host_str(),
            Some("pds-cache.fxbsky.app")
        );
        assert!(
            item.duration.is_none(),
            "FxBluesky reports 0 for unknown durations"
        );
        for c in &item.candidates {
            assert!(r.media_hosts.allows(c.url.host_str().unwrap()));
        }
        // Without a PDS the cache URL still works.
        let r = bluesky_resolved(fx("fxbsky_video.json"), None);
        assert_eq!(select(&r, None).unwrap().candidates.len(), 1);
    }
}
