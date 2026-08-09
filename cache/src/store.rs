//! v1 cache: per-replica `DashMap`, singleflight per key, jittered lazy
//! refresh. No background timers — idle keys cost nothing.

use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dashmap::DashMap;
use tokio::sync::Notify;

use crate::token::{self, CacheKey, CachedToken};
use crate::TokenFetcher;

/// Why a fetch failed. `Clone` because one fetch serves every waiter parked
/// behind it, successes and failures alike.
#[derive(Clone, Debug, thiserror::Error)]
pub enum FetchError {
    /// Cognito rejected the client credentials. The caller is expected to
    /// treat this as the use-time validity oracle from ADR-10: evict the
    /// cached secret, refetch it once, and retry.
    #[error("invalid_client: cached client secret is stale")]
    InvalidClient,
    #[error("cognito rejected the request: {0}")]
    Rejected(Arc<str>),
    #[error("transport error talking to cognito: {0}")]
    Transport(Arc<str>),
    /// The fetcher returned a token that was already expired. Caching it would
    /// pin a permanently-stale entry, so it is refused at the door.
    #[error("fetcher returned a token expiring at {expires_at}, at or before now ({now})")]
    ExpiredOnArrival { expires_at: u64, now: u64 },
}

#[derive(Clone, Debug)]
pub struct CacheConfig {
    /// A cached token with less than this much life left is treated as a miss.
    /// Callers get a token they can actually finish a request with.
    pub min_remaining: Duration,
    /// Refresh threshold band, as a fraction of token lifetime. A per-replica,
    /// per-key point is drawn from this band so that replicas do not refresh
    /// the same key at the same instant (ADR-5: jitter is the free half of
    /// what gossip buys).
    pub refresh_band: (f64, f64),
}

impl Default for CacheConfig {
    fn default() -> Self {
        CacheConfig {
            min_remaining: Duration::from_secs(60),
            refresh_band: (0.60, 0.80),
        }
    }
}

#[derive(Debug, Default)]
pub struct Metrics {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    /// Callers that parked behind an in-flight fetch instead of issuing their
    /// own. This is the number singleflight exists to produce.
    pub singleflight_waits: AtomicU64,
    /// Refreshes started while a still-valid token was served. These are the
    /// ones that keep latency off the request path.
    pub background_refreshes: AtomicU64,
    pub fetch_errors: AtomicU64,
}

impl Metrics {
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            singleflight_waits: self.singleflight_waits.load(Ordering::Relaxed),
            background_refreshes: self.background_refreshes.load(Ordering::Relaxed),
            fetch_errors: self.fetch_errors.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct MetricsSnapshot {
    pub hits: u64,
    pub misses: u64,
    pub singleflight_waits: u64,
    pub background_refreshes: u64,
    pub fetch_errors: u64,
}

/// One in-flight fetch. Waiters read `outcome` rather than re-fetching, so a
/// failing upstream produces exactly one attempt per key, not one per caller.
#[derive(Debug)]
struct InFlight {
    notify: Notify,
    outcome: Mutex<Option<Result<CachedToken, FetchError>>>,
}

impl InFlight {
    fn new() -> Self {
        InFlight {
            notify: Notify::new(),
            outcome: Mutex::new(None),
        }
    }
}

pub struct TokenCache<F> {
    entries: DashMap<CacheKey, CachedToken>,
    inflight: DashMap<CacheKey, Arc<InFlight>>,
    fetcher: F,
    config: CacheConfig,
    /// Per-replica jitter seed. Two replicas with different seeds pick
    /// different refresh points for the same key; the same replica always
    /// picks the same point for a given key, so a key does not drift its
    /// threshold every time it is read.
    replica_seed: u64,
    metrics: Metrics,
}

impl<F: TokenFetcher> TokenCache<F> {
    pub fn new(fetcher: F, config: CacheConfig, replica_seed: u64) -> Arc<Self> {
        Arc::new(TokenCache {
            entries: DashMap::new(),
            inflight: DashMap::new(),
            fetcher,
            config,
            replica_seed,
            metrics: Metrics::default(),
        })
    }

    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Drop every entry for a client. Called when a mapping is deleted or a
    /// secret generation changes — the eviction half of ADR-10's informer.
    pub fn evict_client(&self, client_id: &str) -> usize {
        let doomed: Vec<CacheKey> = self
            .entries
            .iter()
            .filter(|e| e.key().client_id == client_id)
            .map(|e| e.key().clone())
            .collect();
        let n = doomed.len();
        for key in doomed {
            self.entries.remove(&key);
        }
        n
    }

    /// Remove entries that are past their expiry. Optional hygiene: expired
    /// entries are never served, so this only reclaims memory.
    pub fn sweep_expired(&self) -> usize {
        let now = token::now();
        let before = self.entries.len();
        self.entries.retain(|_, t| !t.is_expired_at(now));
        before - self.entries.len()
    }

    /// The per-key refresh point, as an absolute unix timestamp.
    ///
    /// Deterministic in `(replica_seed, key)`: stable for a given key on a
    /// given replica, uncorrelated across replicas.
    fn refresh_at(&self, key: &CacheKey, entry: &CachedToken) -> u64 {
        let lifetime = entry.lifetime_secs();
        if lifetime == 0 {
            return entry.expires_at;
        }
        let mut hasher = std::hash::DefaultHasher::new();
        self.replica_seed.hash(&mut hasher);
        key.hash(&mut hasher);
        let unit = (hasher.finish() >> 11) as f64 / (1u64 << 53) as f64; // [0, 1)
        let (lo, hi) = self.config.refresh_band;
        let fraction = lo + (hi - lo) * unit;
        entry.issued_at + (lifetime as f64 * fraction) as u64
    }

    fn usable(&self, entry: &CachedToken, now: u64) -> bool {
        entry.remaining_secs_at(now) >= self.config.min_remaining.as_secs()
    }

    /// Serve `key`, fetching from the upstream at most once per key at a time.
    ///
    /// Three outcomes, in order of cost:
    /// 1. fresh entry, well short of its refresh point — returned as-is;
    /// 2. still-usable entry past its refresh point — returned as-is, with a
    ///    refresh started behind it so the latency never lands on a caller;
    /// 3. absent or too close to expiry — fetched inline, with concurrent
    ///    callers parked on the same fetch.
    pub async fn get_or_fetch(self: &Arc<Self>, key: CacheKey) -> Result<CachedToken, FetchError> {
        let now = token::now();

        if let Some(entry) = self.entries.get(&key).map(|e| e.clone()) {
            if self.usable(&entry, now) {
                self.metrics.hits.fetch_add(1, Ordering::Relaxed);
                if now >= self.refresh_at(&key, &entry) {
                    self.spawn_refresh(key);
                }
                return Ok(entry);
            }
        }

        self.metrics.misses.fetch_add(1, Ordering::Relaxed);
        self.fetch_singleflight(key).await
    }

    /// Start a refresh if one is not already running for this key. Never
    /// blocks the caller and never propagates its error — the caller already
    /// has a usable token, and a failed refresh just means we try again on the
    /// next request for this key.
    fn spawn_refresh(self: &Arc<Self>, key: CacheKey) {
        if self.inflight.contains_key(&key) {
            return;
        }
        self.metrics
            .background_refreshes
            .fetch_add(1, Ordering::Relaxed);
        let cache = Arc::clone(self);
        tokio::spawn(async move {
            if let Err(error) = cache.fetch_singleflight(key.clone()).await {
                tracing::debug!(%key, %error, "background refresh failed; serving cached token");
            }
        });
    }

    async fn fetch_singleflight(
        self: &Arc<Self>,
        key: CacheKey,
    ) -> Result<CachedToken, FetchError> {
        // Claim the key or find the existing claim. `entry()` holds the shard
        // lock across the check-and-insert, so exactly one caller becomes the
        // fetcher even under a burst.
        let (flight, is_leader) = match self.inflight.entry(key.clone()) {
            dashmap::Entry::Occupied(occupied) => (Arc::clone(occupied.get()), false),
            dashmap::Entry::Vacant(vacant) => {
                let flight = Arc::new(InFlight::new());
                vacant.insert(Arc::clone(&flight));
                (flight, true)
            }
        };

        if !is_leader {
            self.metrics
                .singleflight_waits
                .fetch_add(1, Ordering::Relaxed);
            // `enable()` registers this waiter before we await, so a leader
            // that finishes between here and the await still wakes us. Without
            // it, `notify_waiters()` has no permit to leave behind and the
            // wakeup is lost.
            let notified = flight.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            if flight.outcome.lock().expect("outcome mutex").is_none() {
                notified.await;
            }

            let outcome = flight.outcome.lock().expect("outcome mutex").clone();
            return match outcome {
                Some(result) => result,
                // The leader vanished without recording an outcome (its task
                // was cancelled). Fall back to serving ourselves rather than
                // hanging.
                None => Box::pin(self.fetch_singleflight(key)).await,
            };
        }

        let result = self.fetch_and_store(&key).await;

        // Publish, unclaim, then wake. Waiters must be able to read the
        // outcome the moment they are woken.
        *flight.outcome.lock().expect("outcome mutex") = Some(result.clone());
        self.inflight.remove(&key);
        flight.notify.notify_waiters();

        result
    }

    async fn fetch_and_store(&self, key: &CacheKey) -> Result<CachedToken, FetchError> {
        let fetched = self.fetcher.fetch(key).await.inspect_err(|_| {
            self.metrics.fetch_errors.fetch_add(1, Ordering::Relaxed);
        })?;

        let now = token::now();
        if fetched.is_expired_at(now) {
            self.metrics.fetch_errors.fetch_add(1, Ordering::Relaxed);
            return Err(FetchError::ExpiredOnArrival {
                expires_at: fetched.expires_at,
                now,
            });
        }

        // Store through the lattice join, never a bare insert: a slow fetch
        // that lands after a faster one must not replace a longer-lived token
        // with a shorter-lived one.
        let stored = match self.entries.get(key).map(|e| e.clone()) {
            Some(existing) => token::merge(existing, fetched),
            None => fetched,
        };
        self.entries.insert(key.clone(), stored.clone());
        Ok(stored)
    }
}
