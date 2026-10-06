//! Token cache fabric for the Cognito workload identity broker.
//!
//! # Scope
//!
//! This crate caches **token-shaped** credentials only: parallel-valid,
//! self-expiring, re-derivable (docs/DESIGN.md §Credential shapes). That is
//! what makes the merge in [`token::merge`] a lattice join and therefore what
//! makes replication coordination-free.
//!
//! Two shapes are deliberately *not* handled here:
//!
//! - **config-shaped** (Cognito client secrets): single-writer and
//!   non-expiring, so they need eviction signals rather than a join. They live
//!   behind the informer pattern in the broker (ADR-10).
//! - **linear** credentials (rotating refresh tokens): using one invalidates
//!   its siblings, so no local merge can be correct and no amount of care
//!   makes this cache safe for them (ADR-11). [`TokenFetcher`] is documented
//!   as accepting only parallel-valid credentials for this reason.
//!
//! # Layers
//!
//! Per-replica map, singleflight per key, jittered lazy refresh — plus the
//! transport-free half of the peer fabric (ADR-5): [`ring`] for cold-path
//! ownership, and [`TokenCache::merge_remote`], [`TokenCache::subscribe_fills`]
//! and [`TokenCache::digest`] for gossip and anti-entropy. The mesh itself
//! (membership, mTLS, forwarding) lives in the broker, which keeps this crate
//! free of kube and TLS.

pub mod ring;
pub mod store;
pub mod token;

pub use store::{CacheConfig, FetchError, Metrics, MetricsSnapshot, TokenCache};
pub use token::{CacheKey, CachedToken, TokenValue, merge, now};

/// The upstream this cache fills from.
///
/// # Contract
///
/// Implementations must return **parallel-valid** credentials: a token
/// returned by one call must remain valid when a later call returns another.
/// The cache assumes concurrent mints are all honored — it will serve an older
/// token to one caller while a newer one exists for another. A credential that
/// invalidates its predecessor breaks this and must not be fetched through
/// this crate (ADR-11).
///
/// Implement it with a plain `async fn fetch`. The returned future must be
/// `Send`, because the cache awaits it on a multi-thread runtime; the compiler
/// checks that at the impl.
pub trait TokenFetcher: Send + Sync + 'static {
    fn fetch(&self, key: &CacheKey)
    -> impl Future<Output = Result<CachedToken, FetchError>> + Send;
}
