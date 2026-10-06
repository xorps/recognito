//! Cold-path fetch ownership (ADR-5): on a miss, ask the key's ring owner to
//! fetch it rather than every replica fetching it independently.
//!
//! Rules, each load-bearing:
//!
//! - **Hits never reach this code.** The token cache answers them locally;
//!   this wraps only the fetcher, i.e. the miss path.
//! - **Forward once.** A request that arrived as a forward is fetched locally,
//!   whatever this replica thinks of ownership (the `FORWARDED` task-local in [`super::peer`]).
//! - **Fail open.** A forward that errors or misses its deadline falls back
//!   to fetching locally. The ring saves quota; it must never cost
//!   availability.
//!
//! `recognito_cold_fetch_total{route}` is the health signal: in steady state,
//! with gossip doing its job, misses are rare and `forwarded` stays near
//! zero; `fail_open` above zero means a peer is sick or the views diverge.

use std::sync::Arc;
use std::time::Duration;

use recognito_cache::ring;
use recognito_cache::{CacheKey, CachedToken, FetchError, TokenFetcher};

use super::membership::Membership;
use super::peer::{FORWARDED, PeerClient, WireKey};
use crate::metrics::Metrics;

pub struct ClusterFetcher<F> {
    local: F,
    membership: Arc<Membership>,
    peers: PeerClient,
    deadline: Duration,
    metrics: Arc<Metrics>,
}

impl<F: TokenFetcher> ClusterFetcher<F> {
    pub fn new(
        local: F,
        membership: Arc<Membership>,
        peers: PeerClient,
        deadline: Duration,
        metrics: Arc<Metrics>,
    ) -> Self {
        metrics.describe(
            "recognito_cold_fetch_total",
            "Cache misses by route: owner (we fetched), forwarded (owner fetched for us), \
             fail_open (owner unreachable, we fetched), served_for_peer.",
        );
        ClusterFetcher {
            local,
            membership,
            peers,
            deadline,
            metrics,
        }
    }

    fn count(&self, route: &'static str) {
        self.metrics
            .inc("recognito_cold_fetch_total", &[("route", route)]);
    }
}

impl<F: TokenFetcher> TokenFetcher for ClusterFetcher<F> {
    async fn fetch(&self, key: &CacheKey) -> Result<CachedToken, FetchError> {
        if FORWARDED.try_with(|f| *f).unwrap_or(false) {
            return self.local.fetch(key).await;
        }
        let ring = self.membership.ring();
        let owner = ring::owner(key, &ring).map(String::as_str);
        let Some(peer) = owner
            .filter(|o| *o != self.membership.self_id())
            .and_then(|o| self.membership.peer(o))
        else {
            self.count("owner");
            return self.local.fetch(key).await;
        };

        match tokio::time::timeout(
            self.deadline,
            self.peers.fetch(&peer, &WireKey::from_key(key)),
        )
        .await
        {
            Ok(Ok(wire)) => {
                self.count("forwarded");
                Ok(wire.into_entry().1)
            }
            outcome => {
                let why = match outcome {
                    Ok(Err(e)) => e.to_string(),
                    _ => format!("no answer within {:?}", self.deadline),
                };
                tracing::warn!(%key, owner = %peer, %why, "forward failed; fetching locally");
                self.count("fail_open");
                self.local.fetch(key).await
            }
        }
    }
}
