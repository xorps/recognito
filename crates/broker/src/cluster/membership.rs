//! Who the peers are: the ready endpoints of the broker's headless Service,
//! from an EndpointSlice watch (ADR-5). Kubernetes is the failure detector; we
//! run no heartbeat of our own.
//!
//! Only *ready* endpoints are peers. A replica still warming up is not ready,
//! so nobody forwards to it or counts it in the ring, which is what keeps a
//! cold pod from being made the owner of keys it has never seen.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};

use futures::StreamExt;
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::ResourceExt;
use kube::runtime::{WatchStreamExt, watcher};

use super::peer::Peer;

/// The current peer set. Readers take a cheap snapshot; the watch replaces it
/// wholesale.
pub struct Membership {
    self_id: String,
    peers: RwLock<Arc<Vec<Peer>>>,
}

impl Membership {
    /// `self_addr` is this replica's peer address (pod IP and peer port). It
    /// is excluded from [`Self::peers`] and always included in [`Self::ring`].
    /// Peer IDs are `ip:port`, unique in a cluster where every replica listens
    /// on the same port, and also when several share one host (tests).
    pub fn new(self_addr: SocketAddr) -> Self {
        Membership {
            self_id: self_addr.to_string(),
            peers: RwLock::new(Arc::new(Vec::new())),
        }
    }

    pub fn self_id(&self) -> &str {
        &self.self_id
    }

    /// Other ready replicas.
    pub fn peers(&self) -> Arc<Vec<Peer>> {
        self.peers.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Ring members: every ready peer plus this replica.
    pub fn ring(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.peers().iter().map(|p| p.id.clone()).collect();
        ids.push(self.self_id.clone());
        ids
    }

    pub fn peer(&self, id: &str) -> Option<Peer> {
        self.peers().iter().find(|p| p.id == id).cloned()
    }

    /// Replace the peer set. Self is filtered out here so callers can pass the
    /// raw endpoint list.
    pub fn set(&self, addrs: impl IntoIterator<Item = SocketAddr>) {
        let peers: BTreeSet<Peer> = addrs
            .into_iter()
            .map(|addr| Peer {
                id: addr.to_string(),
                addr,
            })
            .filter(|p| p.id != self.self_id)
            .collect();
        let peers: Vec<Peer> = peers.into_iter().collect();
        let mut current = self.peers.write().unwrap_or_else(|p| p.into_inner());
        if **current != peers {
            tracing::info!(peers = ?peers.iter().map(|p| p.id.as_str()).collect::<Vec<_>>(), "peer set changed");
            *current = Arc::new(peers);
        }
    }

    /// Track the ready endpoints of `service` in `namespace` until the
    /// process exits. `port` is the peer port, used when a slice does not name
    /// one called `peer`.
    pub async fn watch(
        self: Arc<Self>,
        client: kube::Client,
        namespace: String,
        service: String,
        port: u16,
    ) {
        let api = kube::Api::<EndpointSlice>::namespaced(client, &namespace);
        let config =
            watcher::Config::default().labels(&format!("kubernetes.io/service-name={service}"));
        let stream = watcher(api, config).default_backoff();
        futures::pin_mut!(stream);
        let mut slices: BTreeMap<String, Vec<SocketAddr>> = BTreeMap::new();
        let mut relist: Option<BTreeMap<String, Vec<SocketAddr>>> = None;
        while let Some(event) = stream.next().await {
            match event {
                Ok(watcher::Event::Apply(s)) => {
                    slices.insert(s.name_any(), ready_addrs(&s, port));
                }
                Ok(watcher::Event::Delete(s)) => {
                    slices.remove(&s.name_any());
                }
                Ok(watcher::Event::Init) => relist = Some(BTreeMap::new()),
                Ok(watcher::Event::InitApply(s)) => {
                    relist
                        .get_or_insert_with(BTreeMap::new)
                        .insert(s.name_any(), ready_addrs(&s, port));
                }
                Ok(watcher::Event::InitDone) => slices = relist.take().unwrap_or_default(),
                Err(e) => {
                    tracing::warn!(error = %e, "peer watch error; retrying");
                    continue;
                }
            }
            self.set(slices.values().flatten().copied());
        }
    }
}

/// Ready endpoint addresses in one slice. `conditions.ready` unset means
/// ready, per the EndpointSlice API.
pub fn ready_addrs(slice: &EndpointSlice, default_port: u16) -> Vec<SocketAddr> {
    let port = slice
        .ports
        .as_ref()
        .and_then(|ports| ports.iter().find(|p| p.name.as_deref() == Some("peer")))
        .and_then(|p| p.port)
        .and_then(|p| u16::try_from(p).ok())
        .unwrap_or(default_port);
    slice
        .endpoints
        .iter()
        .flatten()
        .filter(|e| e.conditions.as_ref().and_then(|c| c.ready).unwrap_or(true))
        .flat_map(|e| e.addresses.iter())
        .filter_map(|a| a.parse::<IpAddr>().ok())
        .map(|ip| SocketAddr::new(ip, port))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slice(json: serde_json::Value) -> EndpointSlice {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn only_ready_endpoints_become_peers_and_self_is_excluded() {
        let s = slice(serde_json::json!({
            "metadata": {"name": "cognito-broker-peers-abc"},
            "addressType": "IPv4",
            "ports": [{"name": "peer", "port": 8444}],
            "endpoints": [
                {"addresses": ["10.0.0.1"], "conditions": {"ready": true}},
                {"addresses": ["10.0.0.2"], "conditions": {"ready": false}},
                {"addresses": ["10.0.0.3"]},
                {"addresses": ["10.0.0.9"], "conditions": {"ready": true}},
            ],
        }));
        let m = Membership::new("10.0.0.9:8444".parse().unwrap());
        m.set(ready_addrs(&s, 1));
        let ids: Vec<_> = m.peers().iter().map(|p| p.id.clone()).collect();
        assert_eq!(ids, vec!["10.0.0.1:8444", "10.0.0.3:8444"]);
        assert!(
            m.ring().contains(&"10.0.0.9:8444".to_owned()),
            "self is in the ring"
        );
    }

    #[test]
    fn the_default_port_applies_when_the_slice_names_none() {
        let s = slice(serde_json::json!({
            "metadata": {"name": "x"}, "addressType": "IPv4",
            "endpoints": [{"addresses": ["10.0.0.1"]}],
        }));
        assert_eq!(
            ready_addrs(&s, 8444),
            vec!["10.0.0.1:8444".parse().unwrap()]
        );
    }
}
