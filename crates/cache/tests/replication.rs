//! The cache's side of replication (ADR-5): what it publishes for gossip,
//! what it accepts from peers, and the digest anti-entropy compares.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use recognito_cache::{
    CacheConfig, CacheKey, CachedToken, FetchError, TokenCache, TokenFetcher, TokenValue, now,
};

struct Counting(AtomicUsize);

impl TokenFetcher for Counting {
    async fn fetch(&self, _: &CacheKey) -> Result<CachedToken, FetchError> {
        let n = self.0.fetch_add(1, Ordering::SeqCst);
        Ok(token(&format!("local-{n}"), 900))
    }
}

fn token(value: &str, ttl: u64) -> CachedToken {
    let now = now();
    CachedToken {
        value: TokenValue::new(value),
        issued_at: now,
        expires_at: now + ttl,
    }
}

fn cache() -> Arc<TokenCache<Counting>> {
    TokenCache::new(Counting(AtomicUsize::new(0)), CacheConfig::default(), 1)
}

fn key() -> CacheKey {
    CacheKey::new("client", "payments/read")
}

#[tokio::test]
async fn a_local_fetch_is_published_once_for_gossip() {
    let cache = cache();
    let mut fills = cache.subscribe_fills();
    let fetched = cache.get_or_fetch(key()).await.unwrap();
    let (k, t) = fills.try_recv().unwrap();
    assert_eq!((k, t), (key(), fetched));
    // A cache hit fetches nothing and publishes nothing.
    cache.get_or_fetch(key()).await.unwrap();
    assert!(fills.try_recv().is_err());
}

#[tokio::test]
async fn remote_merges_are_not_republished() {
    // Re-broadcasting what a peer told us is how gossip storms start.
    let cache = cache();
    let mut fills = cache.subscribe_fills();
    assert!(cache.merge_remote(key(), token("remote", 900)));
    assert!(fills.try_recv().is_err());
}

#[tokio::test]
async fn a_gossiped_token_saves_the_fetch() {
    let cache = cache();
    cache.merge_remote(key(), token("from-peer", 900));
    let served = cache.get_or_fetch(key()).await.unwrap();
    assert_eq!(served.value.expose(), "from-peer");
    assert_eq!(cache.metrics().snapshot().hits, 1);
}

#[test]
fn merging_is_order_independent_and_idempotent() {
    let a = cache();
    let b = cache();
    let short = token("short", 300);
    let long = token("long", 900);

    a.merge_remote(key(), short.clone());
    a.merge_remote(key(), long.clone());
    b.merge_remote(key(), long.clone());
    b.merge_remote(key(), short.clone());
    assert_eq!(a.get_entry(&key()), b.get_entry(&key()));
    assert_eq!(a.get_entry(&key()).unwrap().value.expose(), "long");

    // Re-delivery changes nothing and reports as much.
    assert!(!a.merge_remote(key(), long.clone()));
    assert!(!a.merge_remote(key(), short));
    assert_eq!(a.metrics().snapshot().remote_merges, 2);
}

#[test]
fn expired_tokens_from_peers_are_refused() {
    let cache = cache();
    let mut dead = token("dead", 0);
    dead.expires_at = now().saturating_sub(1);
    assert!(!cache.merge_remote(key(), dead));
    assert!(cache.get_entry(&key()).is_none());
}

#[test]
fn the_digest_lists_live_entries_by_expiry() {
    let cache = cache();
    let t = token("x", 900);
    cache.merge_remote(key(), t.clone());
    assert_eq!(cache.digest(), vec![(key(), t.expires_at)]);
}
