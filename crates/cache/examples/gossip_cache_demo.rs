//! Gossip-replicated token cache — a worked example of the broker design.
//!
//! The cache is a state-based CRDT: a map of (client_id, scopes) -> Token,
//! where the per-key merge keeps the token that expires LATER. That merge is
//!   - commutative:  merge(a, b) == merge(b, a)
//!   - associative:  merge order doesn't matter
//!   - idempotent:   merge(a, a) == a
//!
//! so replicas may exchange entries over a lossy, duplicating, reordering
//! channel (here: fire-and-forget UDP) and still converge. No acks, no
//! leader, no tombstones — entries expire by their own clock, so deletion
//! never needs to be propagated.
//!
//! Layers demonstrated:
//!   1. Local cache + singleflight  (the mandatory v1 piece)
//!   2. Delta gossip on every fill  (new entry -> broadcast to peers)
//!   3. Anti-entropy                (periodic full-state sync to one random
//!      peer, repairs anything the deltas missed)
//!
//! In production the "fetch" is the Cognito client_credentials call and the
//! peer channel is mTLS'd (these are bearer tokens!). Here Cognito is a stub
//! with a call counter so the demo can PROVE how many real fetches happened.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

// ---------------------------------------------------------------- CRDT core

/// Cache key: which app client, which scope set. Scopes are kept sorted so
/// the same logical request always produces the same key.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct Key {
    client_id: String,
    scopes: Vec<String>,
}

impl Key {
    fn new(client_id: &str, mut scopes: Vec<String>) -> Self {
        scopes.sort();
        Key {
            client_id: client_id.into(),
            scopes,
        }
    }
}

/// One cached token. `expires_at` (unix seconds) doubles as the CRDT
/// "timestamp": a later-expiring token always wins the merge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Token {
    access_token: String,
    expires_at: u64,
}

impl Token {
    fn fresh_for(&self, min_remaining: Duration) -> bool {
        self.expires_at.saturating_sub(now()) >= min_remaining.as_secs()
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The per-key join. Total order: (expires_at, access_token) — the token
/// string tie-break makes the merge deterministic even for equal expiries,
/// which is what upgrades "last writer wins" into a true lattice join.
fn merge_token(a: Token, b: Token) -> Token {
    if (b.expires_at, &b.access_token) > (a.expires_at, &a.access_token) {
        b
    } else {
        a
    }
}

/// The replicated state. `merge_entry` is the ONLY write path for remote
/// data — every gossip message, however stale or duplicated, goes through
/// the join, so the map can only move "up" the lattice.
#[derive(Default)]
struct TokenCache {
    map: HashMap<Key, Token>,
}

impl TokenCache {
    fn get_fresh(&self, key: &Key, min_remaining: Duration) -> Option<Token> {
        self.map
            .get(key)
            .filter(|t| t.fresh_for(min_remaining))
            .cloned()
    }

    /// Join one entry into the map. Returns true if the map changed
    /// (used to decide whether a delta is worth re-gossiping).
    fn merge_entry(&mut self, key: Key, incoming: Token) -> bool {
        if incoming.expires_at <= now() {
            return false; // expired on arrival — the CRDT's "delete"
        }
        match self.map.get(&key) {
            Some(existing) => {
                let merged = merge_token(existing.clone(), incoming);
                let changed = *existing != merged;
                if changed {
                    self.map.insert(key, merged);
                }
                changed
            }
            None => {
                self.map.insert(key, incoming);
                true
            }
        }
    }

    fn sweep_expired(&mut self) {
        let t = now();
        self.map.retain(|_, tok| tok.expires_at > t);
    }
}

// ------------------------------------------------------------- gossip wire

/// State-based delta: a batch of (key, token) entries. Receiving side just
/// joins each one. Loss is fine (anti-entropy repairs), duplication is fine
/// (idempotent), reordering is fine (commutative).
#[derive(Serialize, Deserialize)]
struct Gossip {
    from: String,
    entries: Vec<(Key, Token)>,
}

// ------------------------------------------------------------- fake Cognito

/// Stand-in for the client_credentials call. The AtomicU64 lets the demo
/// assert exactly how many "real" Cognito exchanges occurred.
struct FakeCognito {
    calls: AtomicU64,
}

impl FakeCognito {
    async fn fetch_token(&self, key: &Key) -> Token {
        self.calls.fetch_add(1, Ordering::SeqCst);
        // Simulate network + Cognito latency so singleflight has a window
        // in which concurrent callers pile up.
        tokio::time::sleep(Duration::from_millis(120)).await;
        Token {
            access_token: format!("tok-{}-{}", key.client_id, now()),
            expires_at: now() + 900, // 15 min, like the real design
        }
    }
}

// ------------------------------------------------------------- broker node

struct Node {
    name: String,
    cache: Mutex<TokenCache>,
    /// Singleflight table: key -> Notify that the in-flight fetch completes.
    inflight: Mutex<HashMap<Key, Arc<Notify>>>,
    socket: UdpSocket,
    peers: Vec<String>, // peer UDP addrs
    cognito: Arc<FakeCognito>,
}

impl Node {
    async fn spawn(
        name: &str,
        addr: &str,
        peers: Vec<String>,
        cognito: Arc<FakeCognito>,
    ) -> (Arc<Node>, Vec<JoinHandle<()>>) {
        let node = Arc::new(Node {
            name: name.to_string(),
            cache: Mutex::new(TokenCache::default()),
            inflight: Mutex::new(HashMap::new()),
            socket: UdpSocket::bind(addr).await.expect("bind"),
            peers,
            cognito,
        });

        let mut tasks = Vec::new();

        // Receive loop: join every incoming entry. Note there is no reply —
        // gossip is one-way and unacknowledged.
        {
            let n = node.clone();
            tasks.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    let Ok((len, _)) = n.socket.recv_from(&mut buf).await else {
                        break;
                    };
                    if let Ok(msg) = serde_json::from_slice::<Gossip>(&buf[..len]) {
                        let mut cache = n.cache.lock().unwrap();
                        for (k, t) in msg.entries {
                            cache.merge_entry(k, t);
                        }
                    }
                }
            }));
        }

        // Anti-entropy: every second, push our whole state to one random
        // peer. This is what repairs lost deltas and warms rebooted nodes.
        // (Full-state is fine at broker scale — a few MB. Bigger systems
        // send digests/Merkle summaries first.)
        {
            let n = node.clone();
            tasks.push(tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    let entries: Vec<(Key, Token)> = {
                        let mut cache = n.cache.lock().unwrap();
                        cache.sweep_expired();
                        cache
                            .map
                            .iter()
                            .map(|(k, t)| (k.clone(), t.clone()))
                            .collect()
                    };
                    if entries.is_empty() || n.peers.is_empty() {
                        continue;
                    }
                    let peer = n.peers[rand::random_range(0..n.peers.len())].clone();
                    n.send_gossip(&peer, entries).await;
                }
            }));
        }

        (node, tasks)
    }

    async fn send_gossip(&self, peer: &str, entries: Vec<(Key, Token)>) {
        let msg = Gossip {
            from: self.name.clone(),
            entries,
        };
        let bytes = serde_json::to_vec(&msg).unwrap();
        // Fire and forget: if this datagram is lost, anti-entropy will
        // eventually carry the same state. Errors are deliberately ignored.
        let _ = self.socket.send_to(&bytes, peer).await;
    }

    /// Broadcast one new entry to all peers (the "delta" path).
    async fn gossip_delta(&self, key: Key, token: Token) {
        for peer in &self.peers {
            self.send_gossip(peer, vec![(key.clone(), token.clone())])
                .await;
        }
    }

    /// The exchange path a workload hits: serve from cache, else fetch from
    /// "Cognito" exactly once per key however many callers pile up
    /// (singleflight), then gossip the fill to peers.
    async fn get_token(self: &Arc<Self>, key: Key) -> Token {
        loop {
            // Fast path: fresh local entry (possibly learned via gossip).
            if let Some(tok) = self
                .cache
                .lock()
                .unwrap()
                .get_fresh(&key, Duration::from_secs(60))
            {
                return tok;
            }

            // Miss: become the fetcher, or wait on whoever already is.
            let waiter = {
                let mut inflight = self.inflight.lock().unwrap();
                match inflight.get(&key) {
                    Some(n) => Some(n.clone()),
                    None => {
                        inflight.insert(key.clone(), Arc::new(Notify::new()));
                        None
                    }
                }
            };

            match waiter {
                Some(notify) => {
                    // Someone else is fetching this key — park until they
                    // finish, then loop back to the fast path.
                    notify.notified().await;
                }
                None => {
                    let token = self.cognito.fetch_token(&key).await;
                    self.cache
                        .lock()
                        .unwrap()
                        .merge_entry(key.clone(), token.clone());
                    // Wake waiters and clear the inflight slot BEFORE the
                    // (slow) gossip sends, so waiters aren't held up by
                    // replication.
                    if let Some(n) = self.inflight.lock().unwrap().remove(&key) {
                        n.notify_waiters();
                    }
                    self.gossip_delta(key, token.clone()).await;
                    return token;
                }
            }
        }
    }

    fn has_fresh(&self, key: &Key) -> bool {
        self.cache
            .lock()
            .unwrap()
            .get_fresh(key, Duration::from_secs(60))
            .is_some()
    }
}

// ------------------------------------------------------------------- demo

#[tokio::main]
async fn main() {
    let cognito = Arc::new(FakeCognito {
        calls: AtomicU64::new(0),
    });

    let addrs = [
        "127.0.0.1:9101".to_string(),
        "127.0.0.1:9102".to_string(),
        "127.0.0.1:9103".to_string(),
    ];
    let peers_of = |i: usize| {
        addrs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, a)| a.clone())
            .collect::<Vec<_>>()
    };

    let (a, a_tasks) = Node::spawn("broker-a", &addrs[0], peers_of(0), cognito.clone()).await;
    let (b, _b_tasks) = Node::spawn("broker-b", &addrs[1], peers_of(1), cognito.clone()).await;
    let (c, _c_tasks) = Node::spawn("broker-c", &addrs[2], peers_of(2), cognito.clone()).await;

    let key = Key::new(
        "payments-client",
        vec!["payments/read".into(), "payments/write".into()],
    );

    // --- 1. Singleflight: 50 concurrent requests on broker-a, same key ----
    println!("== 50 concurrent requests hit broker-a for the same key ==");
    let mut joins = Vec::new();
    for _ in 0..50 {
        let a = a.clone();
        let k = key.clone();
        joins.push(tokio::spawn(async move { a.get_token(k).await }));
    }
    for j in joins {
        j.await.unwrap();
    }
    println!(
        "Cognito calls so far: {}   (singleflight collapsed 50 -> 1)\n",
        cognito.calls.load(Ordering::SeqCst)
    );

    // --- 2. Delta gossip: peers are warm without ever fetching ------------
    tokio::time::sleep(Duration::from_millis(200)).await;
    println!("== After the fill, one gossip round later ==");
    println!("broker-b warm: {}", b.has_fresh(&key));
    println!("broker-c warm: {}", c.has_fresh(&key));
    println!(
        "Cognito calls still: {}\n",
        cognito.calls.load(Ordering::SeqCst)
    );

    // --- 3. Kill the shard owner; successor serves from gossiped state ----
    println!("== broker-a (the shard owner) dies ==");
    for t in a_tasks {
        t.abort();
    }
    drop(a);

    let tok = b.get_token(key.clone()).await;
    println!(
        "broker-b served {} with NO new Cognito call (calls: {})",
        tok.access_token,
        cognito.calls.load(Ordering::SeqCst)
    );
    println!("blast radius of the dead shard: zero cold misses\n");

    // --- 4. Idempotence: re-merging the same state changes nothing --------
    let snapshot: Vec<(Key, Token)> = {
        let cache = b.cache.lock().unwrap();
        cache
            .map
            .iter()
            .map(|(k, t)| (k.clone(), t.clone()))
            .collect()
    };
    let changed: bool = {
        let mut cache = b.cache.lock().unwrap();
        // Deliberately not `.any()`: that would stop at the first entry that
        // reported a change, and the point here is to re-merge every entry.
        let mut changed = false;
        for (k, t) in snapshot {
            changed |= cache.merge_entry(k, t);
        }
        changed
    };
    println!("== Re-merge broker-b's own state into itself ==");
    println!("anything changed: {changed}   (idempotent join — duplicates are free)");
}
