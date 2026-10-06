//! Behaviour tests for the v1 cache: singleflight, the refresh band, and the
//! lattice-join store path.
//!
//! These are written against the quota model rather than against the
//! implementation: each one asserts a bound on how many times the upstream was
//! called, because that count is what the 150 RPS `ClientAuthentication` and
//! 5 RPS per-pool `UserPoolClientRead` budgets are spent on.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use recognito_cache::{
    CacheConfig, CacheKey, CachedToken, FetchError, TokenCache, TokenFetcher, TokenValue, now,
};

/// A fetcher that counts calls and can be told how to shape the token it
/// returns, or to fail.
struct TestFetcher {
    calls: Arc<AtomicU64>,
    delay: Duration,
    /// Seconds of life already elapsed when the token arrives. Lets a test
    /// place a token anywhere in its refresh band without waiting.
    age_on_arrival: u64,
    lifetime: u64,
    fail_with: Option<FetchError>,
}

impl TestFetcher {
    fn new(calls: Arc<AtomicU64>) -> Self {
        TestFetcher {
            calls,
            delay: Duration::from_millis(50),
            age_on_arrival: 0,
            lifetime: 900,
            fail_with: None,
        }
    }

    fn failing(calls: Arc<AtomicU64>, error: FetchError) -> Self {
        TestFetcher {
            fail_with: Some(error),
            ..TestFetcher::new(calls)
        }
    }
}

impl TokenFetcher for TestFetcher {
    async fn fetch(&self, key: &CacheKey) -> Result<CachedToken, FetchError> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(self.delay).await;
        if let Some(error) = &self.fail_with {
            return Err(error.clone());
        }
        let issued_at = now() - self.age_on_arrival;
        Ok(CachedToken {
            value: TokenValue::new(format!("tok-{}-{n}", key.client_id)),
            issued_at,
            expires_at: issued_at + self.lifetime,
        })
    }
}

fn key(client: &str) -> CacheKey {
    CacheKey::new(client, "payments/read")
}

#[tokio::test]
async fn concurrent_callers_for_one_key_produce_one_upstream_call() {
    // The property the 150 RPS budget depends on: a cold key under a burst
    // costs one exchange, not one per caller.
    let calls = Arc::new(AtomicU64::new(0));
    let cache = TokenCache::new(TestFetcher::new(calls.clone()), CacheConfig::default(), 1);

    let mut handles = Vec::new();
    for _ in 0..200 {
        let cache = Arc::clone(&cache);
        handles.push(tokio::spawn(async move {
            cache.get_or_fetch(key("payments")).await
        }));
    }
    for handle in handles {
        handle.await.unwrap().expect("fetch should succeed");
    }

    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "singleflight collapsed 200 callers"
    );
    assert_eq!(cache.metrics().snapshot().singleflight_waits, 199);
}

#[tokio::test]
async fn every_waiter_receives_the_same_token() {
    let calls = Arc::new(AtomicU64::new(0));
    let cache = TokenCache::new(TestFetcher::new(calls.clone()), CacheConfig::default(), 1);

    let mut handles = Vec::new();
    for _ in 0..50 {
        let cache = Arc::clone(&cache);
        handles.push(tokio::spawn(async move {
            cache.get_or_fetch(key("payments")).await
        }));
    }
    let mut tokens = Vec::new();
    for handle in handles {
        tokens.push(handle.await.unwrap().unwrap());
    }

    assert!(
        tokens.windows(2).all(|w| w[0] == w[1]),
        "waiters must all get the leader's token, not a mix"
    );
}

#[tokio::test]
async fn a_warm_key_costs_nothing() {
    let calls = Arc::new(AtomicU64::new(0));
    let cache = TokenCache::new(TestFetcher::new(calls.clone()), CacheConfig::default(), 1);

    for _ in 0..100 {
        cache.get_or_fetch(key("payments")).await.unwrap();
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(cache.metrics().snapshot().hits, 99);
}

#[tokio::test]
async fn distinct_keys_do_not_share_a_flight() {
    let calls = Arc::new(AtomicU64::new(0));
    let cache = TokenCache::new(TestFetcher::new(calls.clone()), CacheConfig::default(), 1);

    let a = Arc::clone(&cache);
    let b = Arc::clone(&cache);
    let (ra, rb) = tokio::join!(
        tokio::spawn(async move { a.get_or_fetch(CacheKey::new("payments", "a/read")).await }),
        tokio::spawn(async move { b.get_or_fetch(CacheKey::new("payments", "b/read")).await }),
    );
    ra.unwrap().unwrap();
    rb.unwrap().unwrap();

    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "singleflight is per key, not global"
    );
    assert_eq!(cache.len(), 2);
}

#[tokio::test]
async fn a_failing_upstream_is_called_once_per_burst_not_once_per_caller() {
    // The case that matters under a Cognito throttle: 200 queued callers must
    // not turn one throttled request into 200.
    let calls = Arc::new(AtomicU64::new(0));
    let cache = TokenCache::new(
        TestFetcher::failing(calls.clone(), FetchError::InvalidClient),
        CacheConfig::default(),
        1,
    );

    let mut handles = Vec::new();
    for _ in 0..200 {
        let cache = Arc::clone(&cache);
        handles.push(tokio::spawn(async move {
            cache.get_or_fetch(key("payments")).await
        }));
    }
    let mut errors = 0;
    for handle in handles {
        if handle.await.unwrap().is_err() {
            errors += 1;
        }
    }

    assert_eq!(errors, 200, "every caller must learn the fetch failed");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "and it must be attempted once"
    );
}

#[tokio::test]
async fn a_failure_is_not_cached() {
    // A transient throttle must not poison the key until something evicts it.
    let calls = Arc::new(AtomicU64::new(0));
    let cache = TokenCache::new(
        TestFetcher::failing(calls.clone(), FetchError::Transport("reset".into())),
        CacheConfig::default(),
        1,
    );

    assert!(cache.get_or_fetch(key("payments")).await.is_err());
    assert!(cache.get_or_fetch(key("payments")).await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 2, "the second caller retries");
    assert!(cache.is_empty(), "nothing should be cached after a failure");
}

#[tokio::test]
async fn a_token_that_arrives_expired_is_refused_rather_than_cached() {
    // Caching one would pin a permanently-stale entry that turns every
    // subsequent request into an upstream call.
    let calls = Arc::new(AtomicU64::new(0));
    let fetcher = TestFetcher {
        age_on_arrival: 1_000,
        lifetime: 900,
        ..TestFetcher::new(calls.clone())
    };
    let cache = TokenCache::new(fetcher, CacheConfig::default(), 1);

    assert!(matches!(
        cache.get_or_fetch(key("payments")).await,
        Err(FetchError::ExpiredOnArrival { .. })
    ));
    assert!(cache.is_empty());
}

#[tokio::test]
async fn a_token_too_close_to_expiry_is_treated_as_a_miss() {
    // `min_remaining` is the promise that a returned token has enough life
    // left for the caller to finish its request with.
    let calls = Arc::new(AtomicU64::new(0));
    let fetcher = TestFetcher {
        age_on_arrival: 880, // 20s of a 900s lifetime left, floor is 60s
        lifetime: 900,
        ..TestFetcher::new(calls.clone())
    };
    let cache = TokenCache::new(fetcher, CacheConfig::default(), 1);

    cache.get_or_fetch(key("payments")).await.unwrap();
    cache.get_or_fetch(key("payments")).await.unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "a nearly-dead cached token must not be served"
    );
}

#[tokio::test]
async fn a_token_past_its_refresh_point_is_served_immediately_and_refreshed_behind_the_caller() {
    // Lazy refresh: the caller pays no latency, and the refresh happens
    // because a request arrived — not because a timer fired.
    let calls = Arc::new(AtomicU64::new(0));
    let fetcher = TestFetcher {
        age_on_arrival: 810, // 90% elapsed: past the top of the 60-80% band
        lifetime: 900,
        ..TestFetcher::new(calls.clone())
    };
    let cache = TokenCache::new(fetcher, CacheConfig::default(), 1);

    cache.get_or_fetch(key("payments")).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let started = std::time::Instant::now();
    cache.get_or_fetch(key("payments")).await.unwrap();
    assert!(
        started.elapsed() < Duration::from_millis(40),
        "the second caller must be served from cache, not made to wait on the refresh"
    );

    // The refresh runs on its own task; give it a moment to land.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 2, "a refresh should have run");
    assert_eq!(cache.metrics().snapshot().background_refreshes, 1);
}

#[tokio::test]
async fn a_token_below_the_refresh_band_triggers_nothing() {
    let calls = Arc::new(AtomicU64::new(0));
    let fetcher = TestFetcher {
        age_on_arrival: 450, // 50% elapsed: below the 60% floor of the band
        lifetime: 900,
        ..TestFetcher::new(calls.clone())
    };
    let cache = TokenCache::new(fetcher, CacheConfig::default(), 1);

    cache.get_or_fetch(key("payments")).await.unwrap();
    for _ in 0..20 {
        cache.get_or_fetch(key("payments")).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(150)).await;

    assert_eq!(calls.load(Ordering::SeqCst), 1, "idle keys must cost zero");
    assert_eq!(cache.metrics().snapshot().background_refreshes, 0);
}

#[tokio::test]
async fn replicas_pick_different_refresh_points_for_the_same_key() {
    // The jitter that desynchronizes a fleet's refreshes (ADR-5). Placed at
    // 70% — inside the 60-80% band — so whether a refresh fires depends only
    // on the replica seed.
    let mut fired = Vec::new();
    for seed in 0..24u64 {
        let calls = Arc::new(AtomicU64::new(0));
        let fetcher = TestFetcher {
            age_on_arrival: 630, // 70% of 900
            lifetime: 900,
            delay: Duration::from_millis(1),
            ..TestFetcher::new(calls.clone())
        };
        let cache = TokenCache::new(fetcher, CacheConfig::default(), seed);
        cache.get_or_fetch(key("payments")).await.unwrap();
        cache.get_or_fetch(key("payments")).await.unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        fired.push(calls.load(Ordering::SeqCst) > 1);
    }

    assert!(
        fired.iter().any(|f| *f) && fired.iter().any(|f| !*f),
        "at 70% of lifetime some replicas should have refreshed and some not; got {fired:?}"
    );
}

#[tokio::test]
async fn one_replica_picks_a_stable_refresh_point_for_a_given_key() {
    // Stability matters: a threshold redrawn on every read would make the
    // refresh moment a coin flip per request rather than a fixed point.
    let calls = Arc::new(AtomicU64::new(0));
    let fetcher = TestFetcher {
        age_on_arrival: 450,
        lifetime: 900,
        ..TestFetcher::new(calls.clone())
    };
    let cache = TokenCache::new(fetcher, CacheConfig::default(), 7);

    cache.get_or_fetch(key("payments")).await.unwrap();
    for _ in 0..200 {
        cache.get_or_fetch(key("payments")).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "200 reads below the band must not eventually roll a refresh"
    );
}

#[tokio::test]
async fn evicting_a_client_drops_all_of_its_scope_profiles() {
    // The eviction half of ADR-10's informer: a secret generation change
    // invalidates every token minted with the old secret.
    let calls = Arc::new(AtomicU64::new(0));
    let cache = TokenCache::new(TestFetcher::new(calls.clone()), CacheConfig::default(), 1);

    cache
        .get_or_fetch(CacheKey::new("payments", "a/read"))
        .await
        .unwrap();
    cache
        .get_or_fetch(CacheKey::new("payments", "b/write"))
        .await
        .unwrap();
    cache
        .get_or_fetch(CacheKey::new("billing", "c/read"))
        .await
        .unwrap();
    assert_eq!(cache.len(), 3);

    assert_eq!(cache.evict_client("payments"), 2);
    assert_eq!(
        cache.len(),
        1,
        "only the named client's entries are dropped"
    );

    cache
        .get_or_fetch(CacheKey::new("billing", "c/read"))
        .await
        .unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "the untouched client stays warm"
    );
}

#[tokio::test]
async fn sweeping_reclaims_only_expired_entries() {
    let calls = Arc::new(AtomicU64::new(0));
    let cache = TokenCache::new(TestFetcher::new(calls.clone()), CacheConfig::default(), 1);
    cache.get_or_fetch(key("payments")).await.unwrap();

    assert_eq!(
        cache.sweep_expired(),
        0,
        "a live token must survive a sweep"
    );
    assert_eq!(cache.len(), 1);
}
