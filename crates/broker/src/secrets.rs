//! The config-shaped cache: Cognito app client secrets (ADR-10).
//!
//! Secrets fail the CRDT test — single-writer, never self-expiring — so this is
//! not the token cache. It is an informer:
//!
//! - **Generation eviction.** Each secret is stamped with the mapping's
//!   `status.secretGeneration` when fetched. The request path tells the cache
//!   the current generation before using a secret ([`SecretCache::observe`]);
//!   a mismatch drops the entry. The controller bumps the generation when it
//!   rotates, so a rotation reaches every replica as fast as the CRD watch.
//! - **Use-time oracle.** The token endpoint is the final word: on
//!   `invalid_client` the fetcher evicts and refetches once
//!   ([`crate::cognito`]). This also covers whichever secret
//!   `DescribeUserPoolClient` returns while a client holds two — AWS does not
//!   document which — at the cost of at most one retry after the old secret is
//!   deleted.
//! - **Quota.** `DescribeUserPoolClient` spends the 5 RPS per-(operation, pool)
//!   budget the controller shares (invariant 3). Calls are limited and the
//!   limiter **fails fast**: a caller that would have to queue gets a
//!   retryable error instead, so a cold-start stampede degrades into 503s
//!   rather than a convoy. Concurrent misses for one client share one call.
//!
//! - **Mesh.** With the peer fabric on (ADR-5), a fetched secret is gossiped
//!   to peers keyed by generation, so a restarting fleet drains the 5 RPS
//!   Describe budget once per client rather than once per replica. Merging is
//!   single-writer monotone — a higher generation wins, an older one is
//!   refused — not a lattice join (ADR-10).
//!
//! Memory only (invariant 1). Nothing here is ever written anywhere.

use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use recognito_api::RateLimiter;
use tokio::sync::broadcast;

/// A client secret. Never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct ClientSecret(Arc<str>);

impl ClientSecret {
    pub fn new(raw: impl Into<Arc<str>>) -> Self {
        ClientSecret(raw.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ClientSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClientSecret(redacted)")
    }
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum SecretError {
    #[error("app client not found in the user pool")]
    NotFound,
    #[error("app client has no secret")]
    NoSecret,
    #[error("describe budget exhausted; retry in {0:?}")]
    Throttled(Duration),
    #[error("could not read the app client: {0}")]
    Unavailable(Arc<str>),
}

/// Where secrets come from. Implement with a plain `async fn`.
pub trait SecretSource: Send + Sync + 'static {
    fn describe_secret(
        &self,
        client_id: &str,
    ) -> impl Future<Output = Result<ClientSecret, SecretError>> + Send;
}

#[derive(Clone)]
struct Entry {
    secret: ClientSecret,
    generation: Option<u64>,
}

pub struct SecretCache<S> {
    source: S,
    entries: DashMap<String, Entry>,
    /// Latest generation the request path has seen per client. Read when a
    /// secret is stored, so a fetch that raced a rotation is stamped with the
    /// generation it was fetched under, not one it never saw.
    generations: DashMap<String, Option<u64>>,
    inflight: DashMap<String, Arc<tokio::sync::Mutex<()>>>,
    limiter: RateLimiter,
    fills: broadcast::Sender<(String, Option<u64>, ClientSecret)>,
}

impl<S: SecretSource> SecretCache<S> {
    pub fn new(source: S, limiter: RateLimiter) -> Self {
        SecretCache {
            source,
            entries: DashMap::new(),
            generations: DashMap::new(),
            inflight: DashMap::new(),
            limiter,
            fills: broadcast::channel(256).0,
        }
    }

    /// Secrets this replica described itself, for gossip.
    pub fn subscribe_fills(&self) -> broadcast::Receiver<(String, Option<u64>, ClientSecret)> {
        self.fills.subscribe()
    }

    /// Accept a secret from a peer if it is not older than what we hold or
    /// have observed. A higher generation replaces ours; an equal one is left
    /// alone (either is valid); an older one is refused, so a lagging peer can
    /// never roll a rotation back. Returns whether anything changed.
    pub fn merge_remote(
        &self,
        client_id: &str,
        generation: Option<u64>,
        secret: ClientSecret,
    ) -> bool {
        let observed = self.generations.get(client_id).and_then(|g| *g);
        if generation < observed {
            return false;
        }
        match self.entries.entry(client_id.to_owned()) {
            dashmap::Entry::Occupied(mut o) => {
                if generation > o.get().generation {
                    o.insert(Entry { secret, generation });
                    true
                } else {
                    false
                }
            }
            dashmap::Entry::Vacant(v) => {
                v.insert(Entry { secret, generation });
                true
            }
        }
    }

    /// `(client_id, generation)` for every held secret.
    pub fn digest(&self) -> Vec<(String, Option<u64>)> {
        self.entries
            .iter()
            .map(|e| (e.key().clone(), e.value().generation))
            .collect()
    }

    pub fn get_entry(&self, client_id: &str) -> Option<(Option<u64>, ClientSecret)> {
        self.entries
            .get(client_id)
            .map(|e| (e.generation, e.secret.clone()))
    }

    /// Record the mapping's current `secretGeneration`; drop the cached secret
    /// if it was fetched under a different one.
    pub fn observe(&self, client_id: &str, generation: Option<u64>) {
        self.generations.insert(client_id.to_owned(), generation);
        self.entries
            .remove_if(client_id, |_, e| e.generation != generation);
    }

    /// The `invalid_client` half of the oracle.
    pub fn evict(&self, client_id: &str) {
        self.entries.remove(client_id);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub async fn get(&self, client_id: &str) -> Result<ClientSecret, SecretError> {
        if let Some(e) = self.entries.get(client_id) {
            return Ok(e.secret.clone());
        }
        // Singleflight: one describe per client at a time. Waiters re-check
        // the cache once they hold the lock.
        let gate = self
            .inflight
            .entry(client_id.to_owned())
            .or_default()
            .clone();
        let _held = gate.lock().await;
        if let Some(e) = self.entries.get(client_id) {
            return Ok(e.secret.clone());
        }
        self.limiter.try_acquire().map_err(SecretError::Throttled)?;

        let generation = self.generations.get(client_id).and_then(|g| *g);
        let result = self.source.describe_secret(client_id).await;
        if let Err(SecretError::Throttled(pause)) = &result {
            self.limiter.back_off(*pause);
        }
        let secret = result?;
        self.entries.insert(
            client_id.to_owned(),
            Entry {
                secret: secret.clone(),
                generation,
            },
        );
        let _ = self
            .fills
            .send((client_id.to_owned(), generation, secret.clone()));
        Ok(secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Counting {
        calls: AtomicUsize,
    }

    impl SecretSource for Counting {
        async fn describe_secret(&self, client_id: &str) -> Result<ClientSecret, SecretError> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(20)).await;
            Ok(ClientSecret::new(format!("{client_id}-secret-{n}")))
        }
    }

    fn cache(rps: f64, burst: u32) -> Arc<SecretCache<Counting>> {
        Arc::new(SecretCache::new(
            Counting {
                calls: AtomicUsize::new(0),
            },
            RateLimiter::new(rps, burst),
        ))
    }

    #[tokio::test]
    async fn concurrent_misses_share_one_describe() {
        let cache = cache(100.0, 100);
        let handles: Vec<_> = (0..20)
            .map(|_| {
                let c = cache.clone();
                tokio::spawn(async move { c.get("client").await })
            })
            .collect();
        for h in handles {
            assert_eq!(h.await.unwrap().unwrap().expose(), "client-secret-0");
        }
        assert_eq!(cache.source.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_generation_change_evicts_and_refetches() {
        let cache = cache(100.0, 100);
        cache.observe("client", Some(1));
        assert_eq!(
            cache.get("client").await.unwrap().expose(),
            "client-secret-0"
        );
        cache.observe("client", Some(1));
        assert_eq!(
            cache.get("client").await.unwrap().expose(),
            "client-secret-0"
        );
        cache.observe("client", Some(2));
        assert_eq!(
            cache.get("client").await.unwrap().expose(),
            "client-secret-1"
        );
    }

    #[tokio::test]
    async fn the_describe_budget_fails_fast_rather_than_queueing() {
        let cache = cache(0.001, 1);
        assert!(cache.get("a").await.is_ok());
        assert!(matches!(
            cache.get("b").await,
            Err(SecretError::Throttled(_))
        ));
        // A cached secret never spends budget.
        assert!(cache.get("a").await.is_ok());
    }

    #[tokio::test]
    async fn a_peer_cannot_roll_a_rotation_back() {
        let cache = cache(100.0, 100);
        cache.observe("client", Some(2));
        assert!(!cache.merge_remote("client", Some(1), ClientSecret::new("old")));
        assert!(cache.merge_remote("client", Some(2), ClientSecret::new("current")));
        assert!(!cache.merge_remote("client", Some(2), ClientSecret::new("same-gen")));
        assert_eq!(cache.get("client").await.unwrap().expose(), "current");
        assert_eq!(
            cache.source.calls.load(Ordering::SeqCst),
            0,
            "mesh saved the Describe"
        );
        // A newer generation from a peer that saw the rotation first wins.
        assert!(cache.merge_remote("client", Some(3), ClientSecret::new("rotated")));
        assert_eq!(cache.get_entry("client").unwrap().0, Some(3));
    }

    #[tokio::test]
    async fn a_described_secret_is_published_for_gossip() {
        let cache = cache(100.0, 100);
        let mut fills = cache.subscribe_fills();
        cache.observe("client", Some(4));
        cache.get("client").await.unwrap();
        let (id, generation, _) = fills.try_recv().unwrap();
        assert_eq!((id.as_str(), generation), ("client", Some(4)));
    }

    #[test]
    fn secrets_do_not_print() {
        let s = ClientSecret::new("hunter2");
        assert!(!format!("{s:?}").contains("hunter2"));
    }
}
