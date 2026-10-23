//! Bearer-key authentication for API consumers (SDS §8). Keys are stored as
//! SHA-256 hashes and compared in constant time against every configured key.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::header::AUTHORIZATION;
use axum::middleware::Next;
use axum::response::Response;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::{ApiError, AppState};
use crate::config::{ConsumerConfig, Scope};

#[derive(Debug, Clone)]
pub struct Consumer {
    pub id: String,
    pub scopes: Vec<Scope>,
    pub destinations: Vec<String>,
}

impl Consumer {
    pub fn require(&self, scope: Scope) -> Result<(), ApiError> {
        if self.scopes.contains(&scope) {
            Ok(())
        } else {
            Err(ApiError::forbidden("This key does not have the required scope."))
        }
    }

    pub fn require_destination(&self, name: &str) -> Result<(), ApiError> {
        if self.destinations.iter().any(|d| d == name) {
            Ok(())
        } else {
            Err(ApiError::forbidden("This key may not send to that destination."))
        }
    }
}

pub struct Consumers {
    entries: Vec<([u8; 32], Arc<Consumer>)>,
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

impl Consumers {
    pub fn new(config: &[ConsumerConfig]) -> Self {
        let mut entries = Vec::new();
        for c in config {
            let consumer = Arc::new(Consumer { id: c.id.clone(), scopes: c.scopes.clone(), destinations: c.destinations.clone() });
            for h in &c.key_sha256 {
                let mut hash = [0u8; 32];
                // Config validation guarantees 64 hex characters.
                if hex::decode_to_slice(h, &mut hash).is_ok() {
                    entries.push((hash, consumer.clone()));
                }
            }
        }
        Self { entries }
    }

    /// Finds the consumer for a presented key. Every entry is compared so the
    /// timing does not depend on which key matched.
    pub fn authenticate(&self, key: &str) -> Option<Arc<Consumer>> {
        let presented = sha256(key.as_bytes());
        let mut found = None;
        for (hash, consumer) in &self.entries {
            if bool::from(hash.ct_eq(&presented)) {
                found = Some(consumer.clone());
            }
        }
        found
    }
}

/// Matches a secret route ID against its stored hash in constant time.
pub fn secret_matches(presented: &str, sha256_hex: &str) -> bool {
    let mut expected = [0u8; 32];
    hex::decode_to_slice(sha256_hex, &mut expected).is_ok() && bool::from(sha256(presented.as_bytes()).ct_eq(&expected))
}

pub fn bearer(req: &Request) -> Option<&str> {
    let value = req.headers().get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| token.trim()).filter(|t| !t.is_empty())
}

/// Middleware: requires a valid consumer key and stores the consumer in the
/// request extensions.
pub async fn require_consumer(State(state): State<AppState>, mut req: Request, next: Next) -> Result<Response, ApiError> {
    let consumer = bearer(&req).and_then(|k| state.consumers.authenticate(k)).ok_or_else(ApiError::unauthorized)?;
    req.extensions_mut().insert(consumer);
    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn consumers() -> Consumers {
        Consumers::new(&[ConsumerConfig {
            id: "kuma".into(),
            key_sha256: vec![hex::encode(sha256(b"correct horse"))],
            scopes: vec![Scope::Notify],
            destinations: vec!["ops".into()],
        }])
    }

    #[test]
    fn authenticates_by_hash() {
        let c = consumers();
        assert_eq!(c.authenticate("correct horse").unwrap().id, "kuma");
        assert!(c.authenticate("wrong").is_none());
        assert!(c.authenticate("").is_none());
    }

    #[test]
    fn scopes_and_destinations() {
        let k = consumers().authenticate("correct horse").unwrap();
        assert!(k.require(Scope::Notify).is_ok());
        assert!(k.require(Scope::Media).is_err());
        assert!(k.require_destination("ops").is_ok());
        assert!(k.require_destination("personal").is_err());
    }

    #[test]
    fn route_secret() {
        let h = hex::encode(sha256(b"route-secret-value"));
        assert!(secret_matches("route-secret-value", &h));
        assert!(!secret_matches("route-secret-valuf", &h));
        assert!(!secret_matches("x", "not hex"));
    }
}
