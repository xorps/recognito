//! Replication loops (ADR-5): delta gossip on every fill, periodic
//! anti-entropy with one random peer, and the warm-up pull a new replica does
//! before it reports ready.
//!
//! All of it is fire-and-forget. A lost, duplicated or reordered message is
//! harmless — tokens merge by later expiry, secrets by higher generation — and
//! anything a delta missed, anti-entropy repairs within an interval.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use recognito_cache::{TokenCache, TokenFetcher};
use tokio::sync::broadcast::error::RecvError;

use super::membership::Membership;
use super::peer::{Peer, PeerClient, SyncRequest, WireSecret, WireToken};
use crate::metrics::Metrics;
use crate::secrets::{ClientSecret, SecretCache, SecretSource};

/// Deltas that arrive within this window go out as one batch.
const BATCH_WINDOW: Duration = Duration::from_millis(20);
const MAX_BATCH: usize = 256;
/// A peer that cannot take a delta this fast gets it from anti-entropy.
const PUSH_TIMEOUT: Duration = Duration::from_secs(2);

pub struct Gossip<F, S> {
    pub tokens: Arc<TokenCache<F>>,
    pub secrets: Arc<SecretCache<S>>,
    pub membership: Arc<Membership>,
    pub client: PeerClient,
    pub metrics: Arc<Metrics>,
}

impl<F: TokenFetcher, S: SecretSource> Gossip<F, S> {
    /// Push every locally fetched token to every peer.
    pub async fn token_deltas(self: Arc<Self>) {
        let mut fills = self.tokens.subscribe_fills();
        loop {
            let first = match fills.recv().await {
                Ok(fill) => fill,
                Err(RecvError::Lagged(n)) => {
                    tracing::debug!(skipped = n, "token gossip lagged; anti-entropy will repair");
                    continue;
                }
                Err(RecvError::Closed) => return,
            };
            let mut batch = vec![WireToken::from_entry(&first.0, &first.1)];
            let deadline = tokio::time::Instant::now() + BATCH_WINDOW;
            while batch.len() < MAX_BATCH {
                match tokio::time::timeout_at(deadline, fills.recv()).await {
                    Ok(Ok((k, t))) => batch.push(WireToken::from_entry(&k, &t)),
                    Ok(Err(RecvError::Lagged(_))) => continue,
                    _ => break,
                }
            }
            let peers = self.membership.peers();
            let this = &*self;
            let sends = peers.iter().map(|p| {
                let batch = &batch;
                async move {
                    let ok = matches!(
                        tokio::time::timeout(PUSH_TIMEOUT, this.client.push_tokens(p, batch)).await,
                        Ok(Ok(()))
                    );
                    this.sent("token", ok);
                }
            });
            futures::future::join_all(sends).await;
        }
    }

    /// Push every locally described secret to every peer.
    pub async fn secret_deltas(self: Arc<Self>) {
        let mut fills = self.secrets.subscribe_fills();
        loop {
            let (client_id, generation, secret) = match fills.recv().await {
                Ok(fill) => fill,
                Err(RecvError::Lagged(_)) => continue,
                Err(RecvError::Closed) => return,
            };
            let batch = [WireSecret {
                client_id,
                generation,
                secret: secret.expose().to_owned(),
            }];
            let peers = self.membership.peers();
            let this = &*self;
            let sends = peers.iter().map(|p| {
                let batch = &batch;
                async move {
                    let ok = matches!(
                        tokio::time::timeout(PUSH_TIMEOUT, this.client.push_secrets(p, batch))
                            .await,
                        Ok(Ok(()))
                    );
                    this.sent("secret", ok);
                }
            });
            futures::future::join_all(sends).await;
        }
    }

    fn sent(&self, kind: &'static str, ok: bool) {
        self.metrics.inc(
            "recognito_gossip_sent_total",
            &[("kind", kind), ("result", if ok { "ok" } else { "failed" })],
        );
    }

    /// Every `interval` (jittered ±25%), reconcile with one random peer.
    pub async fn anti_entropy(self: Arc<Self>, interval: Duration) {
        loop {
            let jitter = 0.75 + rand::random::<f64>() * 0.5;
            tokio::time::sleep(interval.mul_f64(jitter)).await;
            let peers = self.membership.peers();
            if peers.is_empty() {
                continue;
            }
            let peer = &peers[rand::random_range(0..peers.len())];
            if let Err(e) = self.sync_with(peer).await {
                tracing::debug!(peer = %peer, error = %e, "anti-entropy round failed");
            }
        }
    }

    /// One push-pull round with `peer`. Returns how many entries we merged.
    pub async fn sync_with(&self, peer: &Peer) -> Result<usize, super::peer::PeerError> {
        let request = SyncRequest {
            tokens: self
                .tokens
                .digest()
                .into_iter()
                .map(|(k, e)| (k.client_id, k.scope, e))
                .collect(),
            secrets: self.secrets.digest(),
        };
        let response = self.client.sync(peer, &request).await?;

        let mut merged = 0;
        for t in response.tokens {
            let (key, token) = t.into_entry();
            merged += usize::from(self.tokens.merge_remote(key, token));
        }
        for s in response.secrets {
            merged += usize::from(self.secrets.merge_remote(
                &s.client_id,
                s.generation,
                ClientSecret::new(s.secret),
            ));
        }
        for _ in 0..merged {
            self.metrics.inc(
                "recognito_gossip_merged_total",
                &[("kind", "any"), ("via", "anti_entropy")],
            );
        }

        // Push back what the peer said it lacks.
        let tokens: Vec<WireToken> = response
            .want_tokens
            .iter()
            .filter_map(|k| {
                let key = k.to_key();
                self.tokens
                    .get_entry(&key)
                    .map(|t| WireToken::from_entry(&key, &t))
            })
            .collect();
        if !tokens.is_empty() {
            self.client.push_tokens(peer, &tokens).await?;
        }
        let secrets: Vec<WireSecret> = response
            .want_secrets
            .iter()
            .filter_map(|c| {
                self.secrets
                    .get_entry(c)
                    .map(|(generation, secret)| WireSecret {
                        client_id: c.clone(),
                        generation,
                        secret: secret.expose().to_owned(),
                    })
            })
            .collect();
        if !secrets.is_empty() {
            self.client.push_secrets(peer, &secrets).await?;
        }
        Ok(merged)
    }

    /// Before reporting ready, pull state from up to two peers so this replica
    /// does not start by re-fetching what the fleet already holds — the
    /// predictable stampede of a rolling restart (ADR-5's trigger).
    ///
    /// Pulls from two peers, so one that missed deltas cannot leave us short;
    /// with fewer reachable, one is enough. Keeps trying, peers in random
    /// order with short attempts, until that or `settle` runs out: a brand-new pod is often briefly
    /// unreachable (NetworkPolicy programming lag for its IP) and peers may
    /// be terminating mid-rollout. Never blocks past `settle`: the first
    /// replica of a fleet has nobody to pull from and must still become ready.
    pub async fn warm_up(&self, settle: Duration, warmed: &AtomicBool) {
        const ATTEMPT: Duration = Duration::from_secs(2);
        let deadline = tokio::time::Instant::now() + settle;
        let (mut merged, mut pulled, mut attempts) = (0, 0, 0);
        'retry: while tokio::time::Instant::now() < deadline {
            let mut peers: Vec<Peer> = self.membership.peers().iter().cloned().collect();
            for i in (1..peers.len()).rev() {
                peers.swap(i, rand::random_range(0..=i));
            }
            for peer in &peers {
                attempts += 1;
                match tokio::time::timeout(ATTEMPT, self.sync_with(peer)).await {
                    Ok(Ok(n)) => {
                        merged += n;
                        pulled += 1;
                        if pulled >= 2 {
                            break 'retry;
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::debug!(peer = %peer, error = %e, "warm-up pull failed; trying another")
                    }
                    Err(_) => {
                        tracing::debug!(peer = %peer, "warm-up pull timed out; trying another")
                    }
                }
                if tokio::time::Instant::now() >= deadline {
                    break 'retry;
                }
            }
            if pulled > 0 {
                break; // every peer tried once, at least one answered
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let peers = self.membership.peers().len();
        if pulled == 0 && peers > 0 {
            tracing::warn!(
                peers,
                attempts,
                "warm-up found no reachable peer; becoming ready cold"
            );
        }
        tracing::info!(peers, merged, attempts, "warm-up complete");
        warmed.store(true, Ordering::Release);
    }
}
