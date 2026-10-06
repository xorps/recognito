//! HTTP surface: the exchange listener and the ops listener.
//!
//! - `POST /token` — RFC 8693 token exchange (ADR-13).
//! - `POST /whoami` — same authentication, answers with identity and mapping,
//!   never a token. The "GetCallerIdentity-style" debug endpoint.
//! - ops (separate port, never exposed through the Service): `/healthz`,
//!   `/readyz` (gated on the mapping index's first full sync), `/metrics`.
//!
//! TLS is terminated here when a certificate is configured, with the
//! certificate re-read when its files change so cert-manager renewals need no
//! restart.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime};

use axum::Router;
use axum::extract::rejection::FormRejection;
use axum::extract::{DefaultBodyLimit, Form, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use hyper_util::rt::TokioIo;
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use recognito_cache::TokenFetcher;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;

use crate::exchange::{ErrorCode, ExchangeError, TokenExchangeForm};
use crate::index::MappingIndex;
use crate::jwt::TokenReviewer;
use crate::metrics::Metrics;
use crate::secrets::SecretSource;
use crate::service::Broker;
use crate::sts::StsTransport;

/// Form bodies are a few KiB at most (a presigned URL with a session token).
const MAX_BODY_BYTES: usize = 32 * 1024;

pub fn router<R, T, S, F>(broker: Arc<Broker<R, T, S, F>>) -> Router
where
    R: TokenReviewer,
    T: StsTransport,
    S: SecretSource,
    F: TokenFetcher,
{
    Router::new()
        .route("/token", post(token::<R, T, S, F>))
        .route("/whoami", post(whoami::<R, T, S, F>))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(broker)
}

async fn token<R, T, S, F>(
    State(broker): State<Arc<Broker<R, T, S, F>>>,
    form: Result<Form<TokenExchangeForm>, FormRejection>,
) -> Response
where
    R: TokenReviewer,
    T: StsTransport,
    S: SecretSource,
    F: TokenFetcher,
{
    let result = match form {
        Ok(Form(form)) => broker.exchange(form, SystemTime::now()).await,
        Err(rejection) => Err(form_rejection(rejection)),
    };
    match result {
        Ok(body) => no_store((StatusCode::OK, axum::Json(body)).into_response()),
        Err(e) => error_response(&e),
    }
}

async fn whoami<R, T, S, F>(
    State(broker): State<Arc<Broker<R, T, S, F>>>,
    form: Result<Form<TokenExchangeForm>, FormRejection>,
) -> Response
where
    R: TokenReviewer,
    T: StsTransport,
    S: SecretSource,
    F: TokenFetcher,
{
    let result = match form {
        Ok(Form(form)) => broker.whoami(form, SystemTime::now()).await,
        Err(rejection) => Err(form_rejection(rejection)),
    };
    match result {
        Ok(body) => no_store((StatusCode::OK, axum::Json(body)).into_response()),
        Err(e) => error_response(&e),
    }
}

/// A body we could not read as a form — wrong content type, bad encoding, a
/// duplicated parameter — is `invalid_request`, in the RFC 6749 shape, not
/// the framework's plain-text 4xx.
fn form_rejection(rejection: FormRejection) -> ExchangeError {
    let what = match rejection {
        FormRejection::InvalidFormContentType(_) => {
            "body must be application/x-www-form-urlencoded"
        }
        _ => "body is not a valid token exchange form (duplicated or malformed parameters)",
    };
    ExchangeError::new(ErrorCode::InvalidRequest, what)
}

fn error_response(error: &ExchangeError) -> Response {
    let status = StatusCode::from_u16(error.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    no_store((status, axum::Json(error.body())).into_response())
}

/// RFC 6749 §5.1: token responses must not be cached.
fn no_store(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

/// What `/readyz` reports.
pub struct Readiness {
    pub index: Arc<MappingIndex>,
    /// With the peer fabric on: warm-up has pulled from the fleet.
    pub warmed: Arc<std::sync::atomic::AtomicBool>,
    /// Set on SIGTERM, so endpoints drop this replica while it still serves.
    pub draining: Arc<std::sync::atomic::AtomicBool>,
}

/// `/readyz` is ready when the mapping index has its first full list, warm-up
/// is done, and the replica is not shutting down.
pub fn ops_router(readiness: Readiness, metrics: Arc<Metrics>) -> Router {
    let Readiness {
        index,
        warmed,
        draining,
    } = readiness;
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route(
            "/readyz",
            get(move || {
                use std::sync::atomic::Ordering::Acquire;
                let state = if draining.load(Acquire) {
                    Err("shutting down")
                } else if !index.is_synced() {
                    Err("mapping index not synced")
                } else if !warmed.load(Acquire) {
                    Err("warming up from peers")
                } else {
                    Ok("ready")
                };
                async move {
                    match state {
                        Ok(s) => (StatusCode::OK, s),
                        Err(s) => (StatusCode::SERVICE_UNAVAILABLE, s),
                    }
                }
            }),
        )
        .route(
            "/metrics",
            get(move || {
                let text = metrics.render();
                async move { ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], text) }
            }),
        )
}

/// Serve plain HTTP until `shutdown` resolves, then drain.
pub async fn serve_plain(
    addr: SocketAddr,
    app: Router,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
}

/// Serve HTTPS until `shutdown` resolves, then drain open connections for up
/// to `drain`.
pub async fn serve_tls(
    addr: SocketAddr,
    app: Router,
    tls: Arc<rustls::ServerConfig>,
    shutdown: impl Future<Output = ()> + Send + 'static,
    drain: Duration,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    let graceful = GracefulShutdown::new();
    let builder = hyper::server::conn::http1::Builder::new();
    tokio::pin!(shutdown);

    loop {
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    continue;
                }
            },
            () = &mut shutdown => break,
        };
        let acceptor = acceptor.clone();
        let service = TowerToHyperService::new(app.clone());
        let builder = builder.clone();
        let watcher = graceful.watcher();
        tokio::spawn(async move {
            // Bound the handshake: an idle TCP connection must not hold a task
            // forever.
            let tls = match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream))
                .await
            {
                Ok(Ok(tls)) => tls,
                Ok(Err(e)) => {
                    tracing::debug!(%peer, error = %e, "TLS handshake failed");
                    return;
                }
                Err(_) => return,
            };
            let conn = builder.serve_connection(TokioIo::new(tls), service);
            if let Err(e) = watcher.watch(conn).await {
                tracing::debug!(%peer, error = %e, "connection error");
            }
        });
    }

    if tokio::time::timeout(drain, graceful.shutdown())
        .await
        .is_err()
    {
        tracing::warn!("drain timed out; closing remaining connections");
    }
    Ok(())
}

/// TLS server config: rustls/ring, TLS 1.2+, HTTP/1.1, reloading certificate.
pub fn tls_config(cert: PathBuf, key: PathBuf) -> Result<Arc<rustls::ServerConfig>, CertError> {
    tls_config_with_reload(cert, key, ReloadingCert::CHECK_EVERY)
}

/// [`tls_config`] with an explicit reload-check interval (tests).
pub fn tls_config_with_reload(
    cert: PathBuf,
    key: PathBuf,
    check_every: Duration,
) -> Result<Arc<rustls::ServerConfig>, CertError> {
    let resolver = ReloadingCert::load(cert, key, check_every)?;
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| CertError(e.to_string()))?
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(resolver));
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

#[derive(Debug, thiserror::Error)]
#[error("TLS certificate: {0}")]
pub struct CertError(String);

impl CertError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        CertError(message.into())
    }
}

/// Serves the current certificate, and re-reads the files at most every
/// `check_every` (default [`Self::CHECK_EVERY`]) when their modification time changes. A bad
/// replacement is logged and the previous certificate kept.
#[derive(Debug)]
pub(crate) struct ReloadingCert {
    cert_path: PathBuf,
    key_path: PathBuf,
    check_every: Duration,
    state: RwLock<CertState>,
}

#[derive(Debug)]
struct CertState {
    key: Arc<CertifiedKey>,
    mtimes: (Option<SystemTime>, Option<SystemTime>),
    checked: Instant,
}

impl ReloadingCert {
    pub(crate) const CHECK_EVERY: Duration = Duration::from_secs(30);

    pub(crate) fn load(
        cert_path: PathBuf,
        key_path: PathBuf,
        check_every: Duration,
    ) -> Result<Self, CertError> {
        let key = read_certified_key(&cert_path, &key_path)?;
        let mtimes = (mtime(&cert_path), mtime(&key_path));
        Ok(ReloadingCert {
            cert_path,
            key_path,
            check_every,
            state: RwLock::new(CertState {
                key: Arc::new(key),
                mtimes,
                checked: Instant::now(),
            }),
        })
    }

    fn maybe_reload(&self) {
        {
            let state = self.state.read().unwrap_or_else(|p| p.into_inner());
            if state.checked.elapsed() < self.check_every {
                return;
            }
        }
        let mut state = self.state.write().unwrap_or_else(|p| p.into_inner());
        if state.checked.elapsed() < self.check_every {
            return;
        }
        state.checked = Instant::now();
        let mtimes = (mtime(&self.cert_path), mtime(&self.key_path));
        if mtimes == state.mtimes {
            return;
        }
        match read_certified_key(&self.cert_path, &self.key_path) {
            Ok(key) => {
                state.key = Arc::new(key);
                state.mtimes = mtimes;
                tracing::info!("TLS certificate reloaded");
            }
            Err(e) => {
                tracing::warn!(error = %e, "TLS certificate changed but did not load; keeping the previous one")
            }
        }
    }
}

impl ReloadingCert {
    fn current(&self) -> Arc<CertifiedKey> {
        self.maybe_reload();
        self.state
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .key
            .clone()
    }
}

impl ResolvesServerCert for ReloadingCert {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current())
    }
}

/// The same certificate presented as a client certificate: peers are
/// symmetric, each both dials and accepts (ADR-5).
impl rustls::client::ResolvesClientCert for ReloadingCert {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        Some(self.current())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

fn mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

fn read_certified_key(cert: &Path, key: &Path) -> Result<CertifiedKey, CertError> {
    let chain = CertificateDer::pem_file_iter(cert)
        .and_then(|it| it.collect::<Result<Vec<_>, _>>())
        .map_err(|e| CertError(format!("{}: {e}", cert.display())))?;
    if chain.is_empty() {
        return Err(CertError(format!("{}: no certificates", cert.display())));
    }
    let key_der = PrivateKeyDer::from_pem_file(key)
        .map_err(|e| CertError(format!("{}: {e}", key.display())))?;
    let signing = rustls::crypto::ring::sign::any_supported_type(&key_der)
        .map_err(|e| CertError(format!("{}: {e}", key.display())))?;
    let certified = CertifiedKey::new(chain, signing);
    certified
        .keys_match()
        .map_err(|e| CertError(format!("certificate and key do not match: {e}")))?;
    Ok(certified)
}
