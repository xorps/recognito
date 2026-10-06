//! Rendezvous (highest-random-weight) hashing for cold-path fetch ownership
//! (ADR-5).
//!
//! Every replica computes `owner(key, peers)` independently and, as long as
//! their peer lists agree, gets the same answer with no coordination. When
//! they disagree — mid-rollout, mid-failure — the cost is an extra fetch or a
//! forward that fails open, never a wrong token: ownership only decides *who
//! asks Cognito*, and every token is valid wherever it came from.
//!
//! Removing a peer moves only the keys that peer owned; adding one takes
//! roughly `1/n` of the keys. That is the property consistent hashing is for,
//! here without virtual nodes or a ring structure to maintain.
//!
//! The hash is FNV-1a with a SplitMix64 finalizer, spelled out here rather
//! than taken from `std`: `DefaultHasher` makes no stability promise across
//! Rust releases, and two broker builds in one rollout must agree on owners.

use crate::token::CacheKey;

/// The peer that should fetch `key`, from `peers` (which should include this
/// replica's own ID). `None` only when `peers` is empty.
pub fn owner<'a, P: AsRef<str>>(key: &CacheKey, peers: &'a [P]) -> Option<&'a P> {
    peers.iter().max_by(|a, b| {
        let (sa, sb) = (score(key, a.as_ref()), score(key, b.as_ref()));
        // Tie-break on the ID so every replica picks the same winner.
        sa.cmp(&sb).then_with(|| a.as_ref().cmp(b.as_ref()))
    })
}

fn score(key: &CacheKey, peer: &str) -> u64 {
    let mut h = Fnv1a::new();
    h.write(key.client_id.as_bytes());
    h.write(&[0]);
    h.write(key.scope.as_bytes());
    h.write(&[0]);
    h.write(peer.as_bytes());
    splitmix64(h.0)
}

struct Fnv1a(u64);

impl Fnv1a {
    fn new() -> Self {
        Fnv1a(0xcbf2_9ce4_8422_2325)
    }

    fn write(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.0 ^= u64::from(*b);
            self.0 = self.0.wrapping_mul(0x0100_0000_01b3);
        }
    }
}

/// FNV alone distributes short, similar inputs poorly; this finalizer fixes
/// the avalanche.
fn splitmix64(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn keys(n: usize) -> Vec<CacheKey> {
        (0..n)
            .map(|i| CacheKey::new(format!("client{i}"), "payments/read"))
            .collect()
    }

    const PEERS: [&str; 3] = ["10.0.1.4", "10.0.2.7", "10.0.3.9"];

    #[test]
    fn every_replica_agrees_regardless_of_list_order() {
        let mut shuffled = PEERS;
        shuffled.reverse();
        for key in keys(200) {
            assert_eq!(owner(&key, &PEERS), owner(&key, &shuffled));
        }
    }

    #[test]
    fn ownership_is_stable_across_builds() {
        // Pinned: if this changes, a rolling upgrade would have old and new
        // replicas disagreeing about every key.
        let key = CacheKey::new("1example23client45id", "payments/read payments/write");
        assert_eq!(owner(&key, &PEERS), Some(&"10.0.2.7"));
        assert_eq!(score(&key, "10.0.1.4"), 0x29a7_d5e1_1684_afbc);
    }

    #[test]
    fn keys_spread_roughly_evenly() {
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for key in keys(3000) {
            *counts.entry(owner(&key, &PEERS).unwrap()).or_default() += 1;
        }
        for peer in PEERS {
            let n = counts[peer];
            assert!((800..1200).contains(&n), "{peer} owns {n} of 3000");
        }
    }

    #[test]
    fn removing_a_peer_moves_only_its_keys() {
        let survivors = ["10.0.1.4", "10.0.3.9"];
        for key in keys(1000) {
            let before = *owner(&key, &PEERS).unwrap();
            let after = *owner(&key, &survivors).unwrap();
            if before != "10.0.2.7" {
                assert_eq!(before, after, "{key} moved although its owner stayed");
            }
        }
    }

    #[test]
    fn no_peers_no_owner() {
        let none: [&str; 0] = [];
        assert_eq!(owner(&keys(1)[0], &none), None);
    }
}
