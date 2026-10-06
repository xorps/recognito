//! The peer channel: mTLS over HTTP/1.1 between broker replicas (ADR-20).
//!
//! Four calls, all `POST`, all JSON:
//!
//! - `/peer/v1/tokens` — delta gossip: tokens a peer just fetched.
//! - `/peer/v1/secrets` — the same for client secrets, keyed by generation.
//! - `/peer/v1/sync` — anti-entropy: "here is what I have, by expiry and
//!   generation"; the answer carries what the asker is missing and names what
//!   the answerer is missing, which the asker then pushes.
//! - `/peer/v1/fetch` — the ring's cold path: "you own this key; fetch it".
//!
//! # Trust
//!
//! These bodies are bearer tokens and client secrets, so the channel is mTLS
//! both ways against a **dedicated peer CA**: any certificate that CA signed
//! is a broker peer, and nothing else is. Peers are anonymous and
//! interchangeable by design (CLAUDE.md), so all replicas share one peer
//! certificate whose DNS name is checked on dial; pod IPs are what we connect
//! to, never what we verify. Anyone holding the peer key can inject tokens
//! into every replica's cache — guard it like the broker's IAM role.

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{DefaultBodyLimit, Json, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use bytes::Bytes;
use http_body_util::Full;
use hyper_rustls::{FixedServerNameResolver, HttpsConnector};
use hyper_util::client::legacy::connect::HttpConnector;
use recognito_cache::{CacheKey, CachedToken, TokenCache, TokenFetcher, TokenValue};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::http::HttpClient;
use crate::metrics::Metrics;
use crate::secrets::{ClientSecret, SecretCache, SecretSource};
use crate::server::{CertError, ReloadingCert};

tokio::task_local! {
    /// Set while serving a forwarded fetch. The cluster fetcher never
    /// forwards from inside one: forwarded requests are never re-forwarded,
    /// so two replicas with different views of the ring cannot bounce a key
    /// between them (ADR-5).
    pub(crate) static FORWARDED: bool;
}

/// Whole-state sync bodies grow with the number of live keys.
const MAX_PEER_BODY: usize = 8 * 1024 * 1024;

/// A broker replica, addressed by pod IP.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Peer {
    pub id: String,
    pub addr: SocketAddr,
}

impl fmt::Display for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.addr.fmt(f)
    }
}

// ---- wire ------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireKey {
    pub client_id: String,
    pub scope: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireToken {
    pub client_id: String,
    pub scope: String,
    pub token: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl fmt::Debug for WireToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "WireToken({}[{}], exp {})",
            self.client_id, self.scope, self.expires_at
        )
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireSecret {
    pub client_id: String,
    pub generation: Option<u64>,
    pub secret: String,
}

impl fmt::Debug for WireSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "WireSecret({}, gen {:?})",
            self.client_id, self.generation
        )
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SyncRequest {
    /// `(client_id, scope, expires_at)` for every live token the asker holds.
    pub tokens: Vec<(String, String, u64)>,
    /// `(client_id, generation)` for every secret the asker holds.
    pub secrets: Vec<(String, Option<u64>)>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SyncResponse {
    /// Entries the answerer has that are newer than, or absent from, the
    /// asker's digest.
    pub tokens: Vec<WireToken>,
    pub secrets: Vec<WireSecret>,
    /// Keys where the asker is ahead: push these back.
    pub want_tokens: Vec<WireKey>,
    pub want_secrets: Vec<String>,
}

impl WireKey {
    pub fn from_key(key: &CacheKey) -> Self {
        WireKey {
            client_id: key.client_id.clone(),
            scope: key.scope.clone(),
        }
    }

    pub fn to_key(&self) -> CacheKey {
        CacheKey::new(self.client_id.clone(), self.scope.clone())
    }
}

impl WireToken {
    pub fn from_entry(key: &CacheKey, token: &CachedToken) -> Self {
        WireToken {
            client_id: key.client_id.clone(),
            scope: key.scope.clone(),
            token: token.value.expose().to_owned(),
            issued_at: token.issued_at,
            expires_at: token.expires_at,
        }
    }

    pub fn into_entry(self) -> (CacheKey, CachedToken) {
        (
            CacheKey::new(self.client_id, self.scope),
            CachedToken {
                value: TokenValue::new(self.token),
                issued_at: self.issued_at,
                expires_at: self.expires_at,
            },
        )
    }
}

// ---- TLS -------------------------------------------------------------------

/// Paths to the shared peer certificate, its key, and the dedicated peer CA.
#[derive(Clone, Debug)]
pub struct PeerTls {
    pub cert: PathBuf,
    pub key: PathBuf,
    pub ca: PathBuf,
    /// DNS name in the peer certificate, verified on every dial.
    pub server_name: String,
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn roots(ca: &PathBuf) -> Result<Arc<rustls::RootCertStore>, CertError> {
    let mut roots = rustls::RootCertStore::empty();
    let certs = CertificateDer::pem_file_iter(ca)
        .and_then(|it| it.collect::<Result<Vec<_>, _>>())
        .map_err(|e| CertError::new(format!("{}: {e}", ca.display())))?;
    for cert in certs {
        roots
            .add(cert)
            .map_err(|e| CertError::new(format!("{}: {e}", ca.display())))?;
    }
    if roots.is_empty() {
        return Err(CertError::new(format!(
            "{}: no CA certificates",
            ca.display()
        )));
    }
    Ok(Arc::new(roots))
}

impl PeerTls {
    /// Server side: require a client certificate from the peer CA.
    pub fn server_config(&self) -> Result<Arc<rustls::ServerConfig>, CertError> {
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            roots(&self.ca)?,
            provider(),
        )
        .build()
        .map_err(|e| CertError::new(e.to_string()))?;
        let resolver = ReloadingCert::load(
            self.cert.clone(),
            self.key.clone(),
            ReloadingCert::CHECK_EVERY,
        )?;
        let mut config = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| CertError::new(e.to_string()))?
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(Arc::new(resolver));
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }

    /// Client side: trust only the peer CA, present our peer certificate.
    pub fn client_config(&self) -> Result<rustls::ClientConfig, CertError> {
        let resolver = ReloadingCert::load(
            self.cert.clone(),
            self.key.clone(),
            ReloadingCert::CHECK_EVERY,
        )?;
        let config = rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| CertError::new(e.to_string()))?
            .with_root_certificates(roots(&self.ca)?)
            .with_client_cert_resolver(Arc::new(resolver));
        // No ALPN here: hyper-rustls sets it from `enable_http1()` and panics
        // if the config already carries one.
        Ok(config)
    }
}

// ---- client ----------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum PeerError {
    #[error("peer request failed: {0}")]
    Transport(String),
    #[error("peer answered HTTP {0}")]
    Status(u16),
    #[error("peer answered with an unreadable body")]
    Body,
}

#[derive(Clone)]
pub struct PeerClient {
    http: HttpClient<HttpsConnector<HttpConnector>>,
}

impl PeerClient {
    pub fn new(tls: &PeerTls, timeout: Duration) -> Result<Self, CertError> {
        let name = ServerName::try_from(tls.server_name.clone())
            .map_err(|e| CertError::new(format!("peer server name: {e}")))?;
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls.client_config()?)
            .https_only()
            .with_server_name_resolver(FixedServerNameResolver::new(name))
            .enable_http1()
            .build();
        Ok(PeerClient {
            http: HttpClient::with_connector(connector, timeout, MAX_PEER_BODY),
        })
    }

    async fn post<T: Serialize, R: DeserializeOwned>(
        &self,
        peer: &Peer,
        path: &str,
        body: &T,
    ) -> Result<Option<R>, PeerError> {
        let bytes = serde_json::to_vec(body).map_err(|_| PeerError::Body)?;
        let request = http::Request::post(format!("https://{}{path}", peer.addr))
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(bytes)))
            .map_err(|e| PeerError::Transport(e.to_string()))?;
        let response = self
            .http
            .send(request)
            .await
            .map_err(|e| PeerError::Transport(e.to_string()))?;
        match response.status {
            204 => Ok(None),
            200 => serde_json::from_slice(&response.body)
                .map(Some)
                .map_err(|_| PeerError::Body),
            status => Err(PeerError::Status(status)),
        }
    }

    pub async fn push_tokens(&self, peer: &Peer, tokens: &[WireToken]) -> Result<(), PeerError> {
        self.post::<_, ()>(peer, "/peer/v1/tokens", &tokens)
            .await
            .map(|_| ())
    }

    pub async fn push_secrets(&self, peer: &Peer, secrets: &[WireSecret]) -> Result<(), PeerError> {
        self.post::<_, ()>(peer, "/peer/v1/secrets", &secrets)
            .await
            .map(|_| ())
    }

    pub async fn sync(
        &self,
        peer: &Peer,
        request: &SyncRequest,
    ) -> Result<SyncResponse, PeerError> {
        self.post(peer, "/peer/v1/sync", request)
            .await?
            .ok_or(PeerError::Body)
    }

    pub async fn fetch(&self, peer: &Peer, key: &WireKey) -> Result<WireToken, PeerError> {
        self.post(peer, "/peer/v1/fetch", key)
            .await?
            .ok_or(PeerError::Body)
    }
}

// ---- server ----------------------------------------------------------------

pub struct PeerState<F, S> {
    pub tokens: Arc<TokenCache<F>>,
    pub secrets: Arc<SecretCache<S>>,
    pub metrics: Arc<Metrics>,
}

/// The peer API. Serve it only behind [`PeerTls::server_config`].
pub fn router<F: TokenFetcher, S: SecretSource>(state: Arc<PeerState<F, S>>) -> Router {
    Router::new()
        .route("/peer/v1/tokens", post(push_tokens::<F, S>))
        .route("/peer/v1/secrets", post(push_secrets::<F, S>))
        .route("/peer/v1/sync", post(sync::<F, S>))
        .route("/peer/v1/fetch", post(fetch::<F, S>))
        .layer(DefaultBodyLimit::max(MAX_PEER_BODY))
        .with_state(state)
}

async fn push_tokens<F: TokenFetcher, S: SecretSource>(
    State(state): State<Arc<PeerState<F, S>>>,
    Json(tokens): Json<Vec<WireToken>>,
) -> StatusCode {
    let mut merged = 0;
    for t in tokens {
        let (key, token) = t.into_entry();
        merged += usize::from(state.tokens.merge_remote(key, token));
    }
    for _ in 0..merged {
        state.metrics.inc(
            "recognito_gossip_merged_total",
            &[("kind", "token"), ("via", "delta")],
        );
    }
    StatusCode::NO_CONTENT
}

async fn push_secrets<F: TokenFetcher, S: SecretSource>(
    State(state): State<Arc<PeerState<F, S>>>,
    Json(secrets): Json<Vec<WireSecret>>,
) -> StatusCode {
    for s in secrets {
        if state
            .secrets
            .merge_remote(&s.client_id, s.generation, ClientSecret::new(s.secret))
        {
            state.metrics.inc(
                "recognito_gossip_merged_total",
                &[("kind", "secret"), ("via", "delta")],
            );
        }
    }
    StatusCode::NO_CONTENT
}

/// Push-pull anti-entropy, answerer side. The asker's digest is compared to
/// ours: we return what we hold that is newer or that they lack, and name
/// what they hold that is newer or that we lack.
async fn sync<F: TokenFetcher, S: SecretSource>(
    State(state): State<Arc<PeerState<F, S>>>,
    Json(request): Json<SyncRequest>,
) -> Json<SyncResponse> {
    use std::collections::HashMap;
    let theirs: HashMap<(String, String), u64> = request
        .tokens
        .into_iter()
        .map(|(c, s, e)| ((c, s), e))
        .collect();
    let mut response = SyncResponse::default();
    let mut ours_keys = std::collections::HashSet::new();
    for (key, expires_at) in state.tokens.digest() {
        let id = (key.client_id.clone(), key.scope.clone());
        match theirs.get(&id) {
            Some(t) if *t >= expires_at => {}
            _ => {
                if let Some(token) = state.tokens.get_entry(&key) {
                    response.tokens.push(WireToken::from_entry(&key, &token));
                }
            }
        }
        ours_keys.insert(id.clone());
        if theirs.get(&id).is_some_and(|t| *t > expires_at) {
            response.want_tokens.push(WireKey::from_key(&key));
        }
    }
    for (client_id, scope) in theirs.keys().filter(|k| !ours_keys.contains(*k)) {
        response.want_tokens.push(WireKey {
            client_id: client_id.clone(),
            scope: scope.clone(),
        });
    }

    let their_secrets: HashMap<String, Option<u64>> = request.secrets.into_iter().collect();
    let mut ours_secrets = std::collections::HashSet::new();
    for (client_id, generation) in state.secrets.digest() {
        match their_secrets.get(&client_id) {
            Some(g) if *g >= generation => {}
            _ => {
                if let Some((generation, secret)) = state.secrets.get_entry(&client_id) {
                    response.secrets.push(WireSecret {
                        client_id: client_id.clone(),
                        generation,
                        secret: secret.expose().to_owned(),
                    });
                }
            }
        }
        if their_secrets
            .get(&client_id)
            .is_some_and(|g| *g > generation)
        {
            response.want_secrets.push(client_id.clone());
        }
        ours_secrets.insert(client_id);
    }
    response.want_secrets.extend(
        their_secrets
            .into_keys()
            .filter(|c| !ours_secrets.contains(c)),
    );
    Json(response)
}

/// The ring's cold path, owner side. Runs flagged as forwarded so this
/// replica fetches itself rather than forwarding again.
async fn fetch<F: TokenFetcher, S: SecretSource>(
    State(state): State<Arc<PeerState<F, S>>>,
    Json(key): Json<WireKey>,
) -> Response {
    state.metrics.inc(
        "recognito_cold_fetch_total",
        &[("route", "served_for_peer")],
    );
    let k = key.to_key();
    match FORWARDED
        .scope(true, state.tokens.get_or_fetch(k.clone()))
        .await
    {
        Ok(token) => Json(WireToken::from_entry(&k, &token)).into_response(),
        // The asker falls back to fetching itself; it needs no detail.
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}
