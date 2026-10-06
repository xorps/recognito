//! The peer fabric (ADR-5, ADR-20), end to end: several broker replicas in one
//! process, each with its own caches, real mTLS peer listeners on localhost,
//! real gossip, and one fake Cognito that counts every call.
//!
//! The counters are the point. A fabric that "works" but does not reduce
//! Cognito traffic has not done its job, so most tests assert an exact number
//! of token-endpoint calls or `DescribeUserPoolClient`s.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::routing::post;
use hyper_util::client::legacy::connect::HttpConnector;
use recognito_api::RateLimiter;
use recognito_api::metrics::Metrics;
use recognito_broker::cluster::peer::{self, PeerState, WireToken};
use recognito_broker::cluster::{ClusterFetcher, Gossip, Membership, PeerClient, PeerTls};
use recognito_broker::cognito::CognitoFetcher;
use recognito_broker::secrets::{ClientSecret, SecretCache, SecretError, SecretSource};
use recognito_broker::server::serve_tls;
use recognito_cache::{CacheConfig, CacheKey, TokenCache, ring};
use rustls_pki_types::pem::PemObject;

// ---- fake Cognito ------------------------------------------------------------

#[derive(Clone, Default)]
struct Cognito {
    token_calls: Arc<AtomicUsize>,
    describes: Arc<AtomicUsize>,
    /// Slows the token endpoint so concurrent callers really overlap.
    delay: Arc<Mutex<Duration>>,
}

impl SecretSource for Cognito {
    async fn describe_secret(&self, client_id: &str) -> Result<ClientSecret, SecretError> {
        self.describes.fetch_add(1, Ordering::SeqCst);
        Ok(ClientSecret::new(format!("{client_id}-secret")))
    }
}

async fn token_endpoint(State(c): State<Cognito>, body: String) -> axum::Json<serde_json::Value> {
    let n = c.token_calls.fetch_add(1, Ordering::SeqCst) + 1;
    let delay = *c.delay.lock().unwrap();
    tokio::time::sleep(delay).await;
    axum::Json(serde_json::json!({
        "access_token": format!("token-{n}-{}", body.len()),
        "expires_in": 900,
        "token_type": "Bearer",
    }))
}

async fn start_cognito() -> (Cognito, String) {
    let cognito = Cognito::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/oauth2/token", post(token_endpoint))
        .with_state(cognito.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (cognito, format!("http://{addr}/oauth2/token"))
}

// ---- replicas ------------------------------------------------------------------

type Local = CognitoFetcher<Cognito, HttpConnector>;
type Tokens = TokenCache<ClusterFetcher<Local>>;

struct Replica {
    addr: SocketAddr,
    tokens: Arc<Tokens>,
    secrets: Arc<SecretCache<Cognito>>,
    membership: Arc<Membership>,
    gossip: Arc<Gossip<ClusterFetcher<Local>, Cognito>>,
    metrics: Arc<Metrics>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Replica {
    fn routes(&self, route: &str) -> u64 {
        let needle = format!("recognito_cold_fetch_total{{route=\"{route}\"}} ");
        self.metrics
            .render()
            .lines()
            .find_map(|l| l.strip_prefix(&needle).map(|n| n.parse().unwrap()))
            .unwrap_or(0)
    }

    fn kill(&mut self) {
        let _ = self.stop.take().map(|s| s.send(()));
    }
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn peer_tls(cert: &str) -> PeerTls {
    PeerTls {
        cert: fixture(&format!("{cert}.crt")),
        key: fixture(&format!("{cert}.key")),
        ca: fixture("peer-ca.crt"),
        server_name: "recognito-broker-peer".into(),
    }
}

fn free_addr() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

async fn replica(cognito: &Cognito, token_url: &str) -> Replica {
    let addr = free_addr();
    let metrics = Arc::new(Metrics::new());
    let secrets = Arc::new(SecretCache::new(
        cognito.clone(),
        RateLimiter::new(1000.0, 1000),
    ));
    let local = CognitoFetcher::with_connector(
        secrets.clone(),
        token_url.to_owned(),
        HttpConnector::new(),
        Duration::from_secs(5),
    );
    let membership = Arc::new(Membership::new(addr));
    let client = PeerClient::new(&peer_tls("peer"), Duration::from_secs(5)).unwrap();
    let fetcher = ClusterFetcher::new(
        local,
        membership.clone(),
        client.clone(),
        Duration::from_millis(500),
        metrics.clone(),
    );
    let tokens = TokenCache::new(fetcher, CacheConfig::default(), rand::random());
    let gossip = Arc::new(Gossip {
        tokens: tokens.clone(),
        secrets: secrets.clone(),
        membership: membership.clone(),
        client,
        metrics: metrics.clone(),
    });
    tokio::spawn(gossip.clone().token_deltas());
    tokio::spawn(gossip.clone().secret_deltas());

    let app = peer::router(Arc::new(PeerState {
        tokens: tokens.clone(),
        secrets: secrets.clone(),
        metrics: metrics.clone(),
    }));
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(serve_tls(
        addr,
        app,
        peer_tls("peer").server_config().unwrap(),
        async {
            let _ = stopped.await;
        },
        Duration::from_millis(100),
    ));
    Replica {
        addr,
        tokens,
        secrets,
        membership,
        gossip,
        metrics,
        stop: Some(stop),
    }
}

/// `n` replicas that all see each other.
async fn fleet(n: usize) -> (Cognito, Vec<Replica>) {
    let (cognito, url) = start_cognito().await;
    let mut replicas = Vec::new();
    for _ in 0..n {
        replicas.push(replica(&cognito, &url).await);
    }
    let addrs: Vec<SocketAddr> = replicas.iter().map(|r| r.addr).collect();
    for r in &replicas {
        r.membership.set(addrs.iter().copied());
    }
    tokio::time::sleep(Duration::from_millis(100)).await; // listeners up
    (cognito, replicas)
}

fn key(scope: &str) -> CacheKey {
    CacheKey::new("client-payments", scope)
}

/// Index of the replica the ring says owns `key`.
fn owner_of(replicas: &[Replica], key: &CacheKey) -> usize {
    let ids: Vec<String> = replicas.iter().map(|r| r.addr.to_string()).collect();
    let owner = ring::owner(key, &ids).unwrap();
    ids.iter().position(|i| i == owner).unwrap()
}

async fn eventually(what: &str, mut check: impl FnMut() -> bool) {
    for _ in 0..100 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for: {what}");
}

// ---- tests -----------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_burst_across_the_fleet_costs_one_cognito_call() {
    // The stampede ADR-5 exists for: every replica, many callers each, the
    // same cold key. Ring ownership plus singleflight makes it one fetch.
    let (cognito, fleet) = fleet(3).await;
    *cognito.delay.lock().unwrap() = Duration::from_millis(100);
    let k = key("payments/read");

    let mut calls = Vec::new();
    for r in &fleet {
        for _ in 0..10 {
            let (tokens, k) = (r.tokens.clone(), k.clone());
            calls.push(tokio::spawn(async move { tokens.get_or_fetch(k).await }));
        }
    }
    let mut values = std::collections::HashSet::new();
    for c in calls {
        values.insert(c.await.unwrap().unwrap().value.expose().to_owned());
    }

    assert_eq!(
        cognito.token_calls.load(Ordering::SeqCst),
        1,
        "one fetch for the whole fleet"
    );
    assert_eq!(
        cognito.describes.load(Ordering::SeqCst),
        1,
        "one Describe for the whole fleet"
    );
    assert_eq!(values.len(), 1, "everyone got the same token");
    let owner = owner_of(&fleet, &k);
    assert_eq!(fleet[owner].routes("owner"), 1);
    for (i, r) in fleet.iter().enumerate().filter(|(i, _)| *i != owner) {
        assert_eq!(r.routes("forwarded"), 1, "replica {i} forwarded once");
        assert_eq!(r.routes("fail_open"), 0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fill_reaches_every_replica_so_their_next_request_is_a_hit() {
    let (cognito, fleet) = fleet(3).await;
    let k = key("payments/read");
    let owner = owner_of(&fleet, &k);
    fleet[owner].tokens.get_or_fetch(k.clone()).await.unwrap();

    for r in &fleet {
        eventually("delta gossip", || r.tokens.get_entry(&k).is_some()).await;
    }
    for r in &fleet {
        r.tokens.get_or_fetch(k.clone()).await.unwrap();
        assert_eq!(r.routes("forwarded"), 0, "a hit never touches the ring");
    }
    assert_eq!(cognito.token_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn secrets_ride_the_mesh_so_one_describe_serves_the_fleet() {
    let (cognito, fleet) = fleet(3).await;
    let first = key("payments/read");
    fleet[owner_of(&fleet, &first)]
        .tokens
        .get_or_fetch(first)
        .await
        .unwrap();
    for r in &fleet {
        eventually("secret gossip", || {
            r.secrets.get_entry("client-payments").is_some()
        })
        .await;
    }

    // Other scopes, owned by other replicas: each fetches with the secret it
    // was gossiped, not one it described itself.
    for scope in [
        "payments/write",
        "payments/admin",
        "payments/refund",
        "payments/audit",
    ] {
        let k = key(scope);
        fleet[owner_of(&fleet, &k)]
            .tokens
            .get_or_fetch(k)
            .await
            .unwrap();
    }
    assert_eq!(cognito.describes.load(Ordering::SeqCst), 1);
    assert_eq!(cognito.token_calls.load(Ordering::SeqCst), 5);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn anti_entropy_repairs_a_replica_that_missed_the_delta() {
    let (cognito, fleet) = fleet(3).await;
    let k = key("payments/read");
    let owner = owner_of(&fleet, &k);
    let isolated = (owner + 1) % 3;

    // Partition: the owner cannot see `isolated` when it fills.
    let visible: Vec<SocketAddr> = fleet
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != isolated)
        .map(|(_, r)| r.addr)
        .collect();
    fleet[owner].membership.set(visible);
    fleet[owner].tokens.get_or_fetch(k.clone()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        fleet[isolated].tokens.get_entry(&k).is_none(),
        "missed the delta"
    );

    // One anti-entropy round with any healthy peer heals it.
    let peer = fleet[isolated]
        .membership
        .peer(&fleet[owner].addr.to_string())
        .unwrap();
    let merged = fleet[isolated].gossip.sync_with(&peer).await.unwrap();
    assert!(merged >= 2, "token and secret");
    assert!(fleet[isolated].tokens.get_entry(&k).is_some());
    assert!(
        fleet[isolated]
            .secrets
            .get_entry("client-payments")
            .is_some()
    );
    assert_eq!(cognito.token_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn anti_entropy_is_push_pull() {
    // The asker is ahead: the answerer names what it lacks and the asker
    // pushes it in the same round.
    let (_, fleet) = fleet(2).await;
    let k = key("payments/read");
    fleet[0].membership.set([]);
    fleet[0].tokens.get_or_fetch(k.clone()).await.unwrap();
    fleet[0].membership.set([fleet[0].addr, fleet[1].addr]);
    assert!(fleet[1].tokens.get_entry(&k).is_none());

    let peer = fleet[0]
        .membership
        .peer(&fleet[1].addr.to_string())
        .unwrap();
    fleet[0].gossip.sync_with(&peer).await.unwrap();
    assert!(fleet[1].tokens.get_entry(&k).is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreachable_owner_fails_open_within_the_deadline() {
    let (cognito, mut fleet) = fleet(3).await;
    let k = key("payments/read");
    let owner = owner_of(&fleet, &k);
    fleet[owner].kill();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let asker = (owner + 1) % 3;
    let started = std::time::Instant::now();
    let token = fleet[asker].tokens.get_or_fetch(k).await.unwrap();
    assert!(token.value.expose().starts_with("token-"));
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(fleet[asker].routes("fail_open"), 1);
    assert_eq!(cognito.token_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forwarded_request_is_never_forwarded_again() {
    // Views disagree: the asker thinks B owns the key; B thinks C does. B must
    // fetch itself rather than bounce the request on.
    let (cognito, fleet) = fleet(3).await;
    let k = (0..)
        .map(|i| key(&format!("scope/{i}")))
        .find(|k| owner_of(&fleet, k) == 2)
        .unwrap(); // C (index 2) owns it in the full view
    let (a, b, c) = (&fleet[0], &fleet[1], &fleet[2]);
    // A sees only B (and itself): pick a key B wins against A.
    a.membership.set([b.addr]);
    let ids = [a.addr.to_string(), b.addr.to_string()];
    let k = if ring::owner(&k, &ids).unwrap() == &ids[1] {
        k
    } else {
        (0..)
            .map(|i| key(&format!("other/{i}")))
            .find(|k| owner_of(&fleet, k) == 2 && ring::owner(k, &ids).unwrap() == &ids[1])
            .unwrap()
    };

    a.tokens.get_or_fetch(k).await.unwrap();
    assert_eq!(a.routes("forwarded"), 1);
    assert_eq!(b.routes("served_for_peer"), 1);
    assert_eq!(c.routes("served_for_peer"), 0, "B must not re-forward to C");
    assert_eq!(cognito.token_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_replica_warms_up_from_the_fleet_before_it_is_ready() {
    let (cognito, url) = start_cognito().await;
    let fleet: Vec<Replica> = vec![replica(&cognito, &url).await, replica(&cognito, &url).await];
    let addrs = [fleet[0].addr, fleet[1].addr];
    for r in &fleet {
        r.membership.set(addrs);
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    for scope in ["a/read", "b/read", "c/read"] {
        let k = key(scope);
        fleet[owner_of(&fleet, &k)]
            .tokens
            .get_or_fetch(k)
            .await
            .unwrap();
    }

    let newcomer = replica(&cognito, &url).await;
    newcomer.membership.set(addrs);
    let warmed = AtomicBool::new(false);
    newcomer
        .gossip
        .warm_up(Duration::from_secs(1), &warmed)
        .await;

    assert!(warmed.load(Ordering::SeqCst));
    assert_eq!(newcomer.tokens.len(), 3, "arrives with the fleet's tokens");
    assert!(newcomer.secrets.get_entry("client-payments").is_some());
    assert_eq!(
        cognito.token_calls.load(Ordering::SeqCst),
        3,
        "and fetched none itself"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_first_replica_of_a_fleet_still_becomes_ready() {
    let (cognito, url) = start_cognito().await;
    let alone = replica(&cognito, &url).await;
    let warmed = AtomicBool::new(false);
    let started = std::time::Instant::now();
    alone
        .gossip
        .warm_up(Duration::from_millis(300), &warmed)
        .await;
    assert!(warmed.load(Ordering::SeqCst));
    assert!(started.elapsed() < Duration::from_secs(2));
}

// ---- trust -------------------------------------------------------------------------

fn bogus_token() -> Vec<WireToken> {
    vec![WireToken {
        client_id: "client-payments".into(),
        scope: "payments/read".into(),
        token: "injected".into(),
        issued_at: recognito_cache::now(),
        expires_at: recognito_cache::now() + 900,
    }]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_certificate_from_another_ca_cannot_inject_tokens() {
    // Same DNS name, wrong issuer: the name alone buys nothing.
    let (_, fleet) = fleet(1).await;
    let rogue = PeerClient::new(&peer_tls("rogue-peer"), Duration::from_secs(2)).unwrap();
    let target = recognito_broker::cluster::Peer {
        id: fleet[0].addr.to_string(),
        addr: fleet[0].addr,
    };
    assert!(rogue.push_tokens(&target, &bogus_token()).await.is_err());
    assert!(fleet[0].tokens.get_entry(&key("payments/read")).is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_without_a_certificate_is_refused_at_the_handshake() {
    let (_, fleet) = fleet(1).await;
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pki_types::CertificateDer::pem_file_iter(fixture("peer-ca.crt")).unwrap() {
        roots.add(c.unwrap()).unwrap();
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let tcp = tokio::net::TcpStream::connect(fleet[0].addr).await.unwrap();
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(
            rustls_pki_types::ServerName::try_from("recognito-broker-peer").unwrap(),
            tcp,
        )
        .await;
    // TLS 1.3 may complete the client side before the server's alert lands;
    // either way, no request gets through.
    if let Ok(mut stream) = tls {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _ = stream
            .write_all(b"POST /peer/v1/tokens HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n[]")
            .await;
        let mut buf = Vec::new();
        let read = stream.read_to_end(&mut buf).await;
        assert!(read.is_err() || !String::from_utf8_lossy(&buf).contains("204"));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_with_the_wrong_name_is_not_trusted() {
    let (_, fleet) = fleet(1).await;
    let mut tls = peer_tls("peer");
    tls.server_name = "someone-else".into();
    let client = PeerClient::new(&tls, Duration::from_secs(2)).unwrap();
    let target = recognito_broker::cluster::Peer {
        id: fleet[0].addr.to_string(),
        addr: fleet[0].addr,
    };
    assert!(client.push_tokens(&target, &bogus_token()).await.is_err());
}

#[test]
fn peer_wire_types_do_not_print_credentials() {
    let t = &bogus_token()[0];
    assert!(!format!("{t:?}").contains("injected"));
}
