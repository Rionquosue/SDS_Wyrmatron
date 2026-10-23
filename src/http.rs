//! HTTP client construction. reqwest is built with `rustls-no-provider`, so
//! the ring crypto provider must be installed before any client is built.

use std::sync::Once;

static INIT: Once = Once::new();

pub fn init_tls() {
    INIT.call_once(|| {
        // Fails only if another provider was installed first, which is fine.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// A client builder that never reads proxy settings from the environment.
pub fn builder() -> reqwest::ClientBuilder {
    init_tls();
    reqwest::Client::builder().no_proxy()
}

/// Plain client for tests.
#[cfg(test)]
pub fn client() -> reqwest::Client {
    builder().build().expect("building HTTP client")
}
