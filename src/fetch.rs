//! Restricted client for untrusted public URLs (SDS §11). DNS answers are
//! filtered to public addresses inside the resolver, so the connection uses
//! only validated addresses while TLS still verifies the hostname. Redirects
//! are followed manually and every hop is checked against the same rules and
//! the caller's host allowlist.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::header::{CONTENT_LENGTH, LOCATION};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use url::{Host, Url};

use crate::config::FetchConfig;

const MAX_URL_LEN: usize = 2048;

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("blocked: {0}")]
    Blocked(String),
    #[error("response exceeds the size limit")]
    TooLarge,
    #[error("upstream returned HTTP {0}")]
    Status(u16),
    #[error("too many redirects")]
    Redirects,
    #[error("request failed: {0}")]
    Transport(String),
    #[error("invalid response: {0}")]
    Decode(String),
    #[error("local file error: {0}")]
    Io(#[from] std::io::Error),
}

/// True for addresses that are globally routable unicast.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_v4(v4);
            }
            let s = v6.segments();
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // unique local fc00::/7
                || (s[0] & 0xffc0) == 0xfe80 // link local fe80::/10
                || (s[0] & 0xffc0) == 0xfec0 // site local (deprecated)
                || (s[0] == 0x64 && s[1] == 0xff9b) // NAT64 64:ff9b::/96 and /48
                || s[0] == 0x2002 // 6to4
                || (s[0] == 0x2001 && s[1] == 0) // Teredo 2001::/32
                || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
                || (s[0] == 0x0100 && s[1..4] == [0, 0, 0]) // discard-only 100::/64
                || s[0] == 0) // ::/16 including IPv4-compatible
        }
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local() // includes 169.254.169.254 metadata
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || o[0] == 0 // 0.0.0.0/8
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // CGNAT 100.64/10
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // benchmarking 198.18/15
        || o[0] >= 240) // reserved 240/4
}

/// Resolver that returns only public addresses.
struct PublicResolver;

impl Resolve for PublicResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            let public: Vec<SocketAddr> = addrs.into_iter().filter(|a| is_public(a.ip())).collect();
            if public.is_empty() {
                return Err(format!("{host} has no public addresses").into());
            }
            Ok(Box::new(public.into_iter()) as Addrs)
        })
    }
}

/// Hosts an adapter may contact: exact names or `.suffix` entries.
#[derive(Debug, Clone)]
pub struct HostPolicy(Arc<Vec<String>>);

impl HostPolicy {
    pub fn new<I: IntoIterator<Item = S>, S: Into<String>>(hosts: I) -> Self {
        Self(Arc::new(hosts.into_iter().map(|h| h.into().to_ascii_lowercase()).collect()))
    }

    pub fn allows(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.0.iter().any(|rule| match rule.strip_prefix('.') {
            Some(suffix) => host.ends_with(&format!(".{suffix}")),
            None => host == *rule,
        })
    }
}

pub struct Fetcher {
    client: reqwest::Client,
    max_redirects: usize,
    max_metadata_bytes: u64,
    /// Tests run against a local mock server.
    allow_loopback: bool,
}

impl Fetcher {
    pub fn new(cfg: &FetchConfig) -> anyhow::Result<Self> {
        let mut b = crate::http::builder()
            .dns_resolver(Arc::new(PublicResolver))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(cfg.user_agent.clone())
            .connect_timeout(Duration::from_secs(cfg.connect_timeout_secs))
            .read_timeout(Duration::from_secs(60))
            .timeout(Duration::from_secs(cfg.total_timeout_secs))
            .pool_max_idle_per_host(2)
            .http1_max_headers(100)
            .https_only(true);
        if let Some(p) = &cfg.proxy {
            tracing::warn!("public fetches use an explicit proxy; address checks then happen at the proxy");
            b = b.proxy(reqwest::Proxy::all(p)?);
        }
        Ok(Self { client: b.build()?, max_redirects: cfg.max_redirects, max_metadata_bytes: cfg.max_metadata_bytes, allow_loopback: false })
    }

    #[cfg(test)]
    pub fn for_tests() -> Self {
        Self {
            client: crate::http::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap(),
            max_redirects: 3,
            max_metadata_bytes: 64 * 1024,
            allow_loopback: true,
        }
    }

    /// Static checks applied to every URL, including each redirect hop.
    pub fn check_url(&self, url: &Url, policy: &HostPolicy) -> Result<(), FetchError> {
        let blocked = |why: &str| Err(FetchError::Blocked(why.to_owned()));
        if url.as_str().len() > MAX_URL_LEN {
            return blocked("URL is too long");
        }
        if url.scheme() != "https" && !self.allow_loopback {
            return blocked("only HTTPS URLs are allowed");
        }
        if !url.username().is_empty() || url.password().is_some() {
            return blocked("credentials in URLs are not allowed");
        }
        if url.port().is_some_and(|p| p != 443) && !self.allow_loopback {
            return blocked("non-standard ports are not allowed");
        }
        match url.host() {
            // IP literals bypass the resolver, so check them here.
            Some(Host::Ipv4(ip)) if !self.allow_loopback && !is_public(IpAddr::V4(ip)) => blocked("non-public address"),
            Some(Host::Ipv6(ip)) if !self.allow_loopback && !is_public(IpAddr::V6(ip)) => blocked("non-public address"),
            Some(h) if self.allow_loopback || policy.allows(&h.to_string()) => Ok(()),
            Some(_) => blocked("host is not allowed for this source"),
            None => blocked("URL has no host"),
        }
    }

    /// GET with manual, checked redirects. Never forwards credentials.
    async fn get(&self, url: &Url, policy: &HostPolicy) -> Result<reqwest::Response, FetchError> {
        let mut current = url.clone();
        for _ in 0..=self.max_redirects {
            self.check_url(&current, policy)?;
            let res = self.client.get(current.clone()).send().await.map_err(|e| FetchError::Transport(e.without_url().to_string()))?;
            if res.status().is_redirection() {
                let location = res.headers().get(LOCATION).and_then(|v| v.to_str().ok()).ok_or(FetchError::Status(res.status().as_u16()))?;
                current = current.join(location).map_err(|_| FetchError::Blocked("invalid redirect".into()))?;
                continue;
            }
            if !res.status().is_success() {
                return Err(FetchError::Status(res.status().as_u16()));
            }
            return Ok(res);
        }
        Err(FetchError::Redirects)
    }

    /// Fetches and decodes a bounded JSON document.
    pub async fn get_json<T: DeserializeOwned>(&self, url: &Url, policy: &HostPolicy) -> Result<T, FetchError> {
        let bytes = self.get_bytes(url, policy, self.max_metadata_bytes).await?;
        serde_json::from_slice(&bytes).map_err(|e| FetchError::Decode(e.to_string()))
    }

    pub async fn get_bytes(&self, url: &Url, policy: &HostPolicy, max: u64) -> Result<Vec<u8>, FetchError> {
        let res = self.get(url, policy).await?;
        if res.content_length().is_some_and(|n| n > max) {
            return Err(FetchError::TooLarge);
        }
        let mut out = Vec::new();
        let mut stream = res.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| FetchError::Transport(e.without_url().to_string()))?;
            if out.len() as u64 + chunk.len() as u64 > max {
                return Err(FetchError::TooLarge);
            }
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }

    /// Streams a download to `dest`, enforcing `max` even without a
    /// Content-Length. Returns the size and SHA-256.
    pub async fn download(&self, url: &Url, policy: &HostPolicy, dest: &Path, max: u64) -> Result<(u64, String), FetchError> {
        let res = self.get(url, policy).await?;
        let declared = res.headers().get(CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok());
        if declared.is_some_and(|n| n > max) {
            return Err(FetchError::TooLarge);
        }
        let mut file = tokio::fs::File::create(dest).await?;
        let mut hasher = Sha256::new();
        let mut total = 0u64;
        let mut stream = res.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| FetchError::Transport(e.without_url().to_string()))?;
            total += chunk.len() as u64;
            if total > max {
                drop(file);
                let _ = tokio::fs::remove_file(dest).await;
                return Err(FetchError::TooLarge);
            }
            hasher.update(&chunk);
            file.write_all(&chunk).await?;
        }
        file.sync_all().await?;
        Ok((total, hex::encode(hasher.finalize())))
    }
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::path;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    #[test]
    fn classifies_addresses() {
        for blocked in [
            "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "0.0.0.0", "100.64.0.1",
            "198.18.0.1", "224.0.0.1", "255.255.255.255", "240.0.0.1", "192.0.0.8", "::1", "::", "fc00::1",
            "fd12::1", "fe80::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "64:ff9b::a00:1", "2002:a00:1::",
            "2001::1", "::127.0.0.1",
        ] {
            assert!(!is_public(blocked.parse().unwrap()), "{blocked} must be blocked");
        }
        for public in ["1.1.1.1", "8.8.8.8", "151.101.1.1", "2606:4700:4700::1111", "2a03:2880::1", "::ffff:8.8.8.8"] {
            assert!(is_public(public.parse().unwrap()), "{public} must be allowed");
        }
    }

    #[test]
    fn checks_urls() {
        let f = Fetcher::new(&FetchConfig::default()).unwrap();
        let p = HostPolicy::new(["api.fxtwitter.com", ".twimg.com"]);
        let check = |u: &str| f.check_url(&Url::parse(u).unwrap(), &p);
        assert!(check("https://api.fxtwitter.com/2/status/1").is_ok());
        assert!(check("https://video.twimg.com/a.mp4").is_ok());
        assert!(check("https://VIDEO.TWIMG.COM./a.mp4").is_ok());
        assert!(check("http://api.fxtwitter.com/").is_err());
        assert!(check("https://user:pw@api.fxtwitter.com/").is_err());
        assert!(check("https://api.fxtwitter.com:8443/").is_err());
        assert!(check("https://evil.com/").is_err());
        assert!(check("https://twimg.com.evil.com/").is_err());
        assert!(check("https://127.0.0.1/").is_err());
        assert!(check("https://[::ffff:169.254.169.254]/").is_err());
        assert!(check(&format!("https://api.fxtwitter.com/{}", "a".repeat(3000))).is_err());
    }

    #[tokio::test]
    async fn resolver_drops_private_answers() {
        let err = PublicResolver.resolve("localhost".parse().unwrap()).await.err().unwrap();
        assert!(err.to_string().contains("no public addresses"));
    }

    #[tokio::test]
    async fn enforces_limits_and_redirect_count() {
        let server = MockServer::start().await;
        Mock::given(path("/big")).respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0u8; 5000])).mount(&server).await;
        Mock::given(path("/loop")).respond_with(ResponseTemplate::new(302).insert_header("location", "/loop")).mount(&server).await;
        Mock::given(path("/hop")).respond_with(ResponseTemplate::new(302).insert_header("location", "/big")).mount(&server).await;
        let f = Fetcher::for_tests();
        let p = HostPolicy::new(["127.0.0.1"]);
        let base = Url::parse(&server.uri()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("f");
        assert!(matches!(f.download(&base.join("/big").unwrap(), &p, &dest, 1000).await, Err(FetchError::TooLarge)));
        assert!(!dest.exists(), "a partial download is removed");
        let (n, sha) = f.download(&base.join("/hop").unwrap(), &p, &dest, 10_000).await.unwrap();
        assert_eq!((n, sha), (5000, hex::encode(Sha256::digest(vec![0u8; 5000]))));
        assert!(matches!(f.get_bytes(&base.join("/loop").unwrap(), &p, 100).await, Err(FetchError::Redirects)));
    }
}
