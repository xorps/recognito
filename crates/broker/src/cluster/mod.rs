//! The peer fabric (ADR-5, ADR-20): broker replicas share what they fetch.
//!
//! - [`membership`] — peers are the ready endpoints of a headless Service.
//! - [`peer`] — the mTLS channel and its four calls.
//! - [`gossip`] — delta gossip on fill, anti-entropy, warm-up before ready.
//! - [`fetcher`] — rendezvous-hash ownership of the cold path.
//!
//! Hits are always served locally; the fabric only changes who fetches on a
//! miss and how quickly a fetch reaches everyone else. Every part of it fails
//! open to the v1 behaviour of a replica fetching for itself.

pub mod fetcher;
pub mod gossip;
pub mod membership;
pub mod peer;

use std::net::SocketAddr;
use std::time::Duration;

pub use fetcher::ClusterFetcher;
pub use gossip::Gossip;
pub use membership::Membership;
pub use peer::{Peer, PeerClient, PeerTls};

#[derive(Clone, Debug)]
pub struct ClusterConfig {
    /// Headless Service whose ready endpoints are the peers.
    pub service: String,
    pub namespace: String,
    /// This pod's IP, from the downward API. With the peer port it is this
    /// replica's identity in the ring.
    pub pod_ip: std::net::IpAddr,
    pub listen: SocketAddr,
    pub tls: PeerTls,
    /// How long to wait for a ring owner before fetching locally.
    pub forward_deadline: Duration,
    pub anti_entropy_interval: Duration,
}
