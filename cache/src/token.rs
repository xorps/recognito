//! The token lattice: cache keys, cached tokens, and the merge that makes
//! replication coordination-free.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Cache key: which app client, which canonical scope set.
///
/// `scope` is the already-canonicalized, space-delimited scope string. This
/// crate does not know how to canonicalize scopes — that is the API crate's
/// job — and taking a pre-canonicalized string keeps the dependency arrow
/// pointing one way.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CacheKey {
    pub client_id: String,
    pub scope: String,
}

impl CacheKey {
    pub fn new(client_id: impl Into<String>, scope: impl Into<String>) -> Self {
        CacheKey {
            client_id: client_id.into(),
            scope: scope.into(),
        }
    }
}

impl fmt::Display for CacheKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}[{}]", self.client_id, self.scope)
    }
}

/// A bearer token that will not print itself.
///
/// Every `Debug`/`Display` in this process is a potential log line, and these
/// values are live credentials. The only way to see the bytes is to ask for
/// them by name via [`TokenValue::expose`], which greps cleanly in review.
#[derive(Clone, PartialEq, Eq)]
pub struct TokenValue(String);

impl TokenValue {
    pub fn new(raw: impl Into<String>) -> Self {
        TokenValue(raw.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for TokenValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenValue(redacted)")
    }
}

/// One cached access token.
///
/// `expires_at` (unix seconds) doubles as the lattice timestamp: the
/// later-expiring token wins a merge. That works because these tokens are
/// *parallel-valid* — concurrently minted tokens are all honored by the
/// resource server — which is exactly the property ADR-11 says rotating
/// refresh tokens lack.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedToken {
    pub value: TokenValue,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl CachedToken {
    pub fn lifetime_secs(&self) -> u64 {
        self.expires_at.saturating_sub(self.issued_at)
    }

    pub fn is_expired_at(&self, now: u64) -> bool {
        self.expires_at <= now
    }

    pub fn remaining_secs_at(&self, now: u64) -> u64 {
        self.expires_at.saturating_sub(now)
    }
}

/// The per-key join: keep the token that expires later, breaking ties on the
/// token bytes.
///
/// The tie-break is what upgrades "last writer wins" into a genuine lattice
/// join. Without it, two replicas holding different tokens with identical
/// expiries would each keep their own and never converge, and the merge would
/// not be commutative. With it the join is commutative, associative, and
/// idempotent, so replicas may exchange entries over a lossy, duplicating,
/// reordering channel and still agree (ADR-3's CALM argument).
pub fn merge(a: CachedToken, b: CachedToken) -> CachedToken {
    if (b.expires_at, b.value.expose()) > (a.expires_at, a.value.expose()) {
        b
    } else {
        a
    }
}

/// Current unix time in seconds.
///
/// Tokens carry absolute expiries from Cognito, so the cache reasons in wall
/// clock rather than `Instant`. Clock skew between replicas costs at most a
/// slightly early or late refresh; it cannot produce an invalid token, because
/// the resource server is the authority on expiry.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(value: &str, expires_at: u64) -> CachedToken {
        CachedToken {
            value: TokenValue::new(value),
            issued_at: expires_at.saturating_sub(900),
            expires_at,
        }
    }

    #[test]
    fn merge_keeps_the_later_expiry() {
        let early = token("a", 1_000);
        let late = token("b", 2_000);
        assert_eq!(merge(early.clone(), late.clone()), late);
        assert_eq!(merge(late.clone(), early), late);
    }

    #[test]
    fn merge_is_commutative_even_on_equal_expiries() {
        // The case the tie-break exists for: same expiry, different bytes.
        let a = token("aaa", 1_000);
        let b = token("bbb", 1_000);
        assert_eq!(merge(a.clone(), b.clone()), merge(b, a));
    }

    #[test]
    fn merge_is_idempotent() {
        let a = token("a", 1_000);
        assert_eq!(merge(a.clone(), a.clone()), a);
    }

    #[test]
    fn merge_is_associative() {
        let a = token("a", 1_000);
        let b = token("b", 2_000);
        let c = token("c", 2_000);
        let left = merge(merge(a.clone(), b.clone()), c.clone());
        let right = merge(a, merge(b, c));
        assert_eq!(left, right);
    }

    #[test]
    fn token_value_does_not_leak_through_debug() {
        let secret = TokenValue::new("eyJhbGciOi.super.secret");
        assert_eq!(format!("{secret:?}"), "TokenValue(redacted)");
        assert!(!format!("{:?}", token("super.secret", 1)).contains("super.secret"));
    }
}
