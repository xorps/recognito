//! Broker entrypoint: configuration, wiring, and lifecycle. Everything that
//! decides anything lives in the library.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use anyhow::Context;
use recognito_api::RateLimiter;
use recognito_broker::audience::AudienceValidator;
use recognito_broker::aws::{CognitoSecretSource, sdk_config};
use recognito_broker::cluster::peer::{self, PeerState};
use recognito_broker::cluster::{ClusterConfig, ClusterFetcher, Gossip, Membership, PeerClient};
use recognito_broker::cognito::{CognitoFetcher, DEFAULT_TOKEN_TIMEOUT};
use recognito_broker::config::BrokerConfig;
use recognito_broker::index::MappingIndex;
use recognito_broker::jwt::{JwtAuthenticator, KubeTokenReviewer};
use recognito_broker::metrics::Metrics;
use recognito_broker::secrets::SecretCache;
use recognito_broker::server;
use recognito_broker::service::Broker;
use recognito_broker::sts::{DEFAULT_STS_TIMEOUT, HyperStsTransport, SigV4Authenticator};
use recognito_broker::{SigV4Validator, StsEndpoint};
use recognito_cache::{CacheConfig, TokenCache, TokenFetcher};
use tokio::sync::watch;

/// How long in-flight exchanges get to finish after SIGTERM. Kept under the
/// pod's terminationGracePeriodSeconds.
const DRAIN: Duration = Duration::from_secs(20);

/// How long a new replica keeps trying to pull from the fleet before becoming
/// ready cold (the first replica of a fleet has nobody to pull from).
const WARM_UP_SETTLE: Duration = Duration::from_secs(10);

/// After SIGTERM, how long to keep serving while reporting not-ready, so the
/// Service's endpoints drop this pod before its listeners close. Without it,
/// kube-proxy keeps routing to a pod that is gone for a few seconds and those
/// connections hang until the client times out.
const SHUTDOWN_DELAY: Duration = Duration::from_secs(5);

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    // CLAUDE.md runtime decision: multi-thread, workers = cgroup CPU limit.
    let workers = cgroup_cpu_limit().unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    });
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()?
        .block_on(run(workers))
}

type Secrets = SecretCache<CognitoSecretSource>;
type Local = CognitoFetcher<
    CognitoSecretSource,
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
>;

async fn run(workers: usize) -> anyhow::Result<()> {
    let config = BrokerConfig::from_env().context("invalid broker configuration")?;
    tracing::info!(
        audience = %config.audience,
        user_pool_id = %config.user_pool_id,
        token_url = %config.token_url,
        workers,
        tls = config.tls.is_some(),
        sigv4 = config.sigv4.is_some(),
        peer_fabric = config.cluster.is_some(),
        "recognito-broker starting"
    );
    if config.tls.is_none() {
        tracing::warn!(
            "no TLS certificate configured: serving plain HTTP. Only safe behind a TLS-terminating proxy or mesh."
        );
    }

    let metrics = Arc::new(Metrics::new());
    let kube = kube::Client::try_default()
        .await
        .context("cannot build a Kubernetes client")?;

    let aws = sdk_config(&config.region).await;
    let secrets: Arc<Secrets> = Arc::new(SecretCache::new(
        CognitoSecretSource::new(&aws, config.user_pool_id.clone()),
        RateLimiter::new(config.describe_rps, 1),
    ));
    let local: Local = CognitoFetcher::https(
        secrets.clone(),
        config.token_url.clone(),
        DEFAULT_TOKEN_TIMEOUT,
    )?;

    match config.cluster.clone() {
        None => serve(config, kube, metrics, secrets, local, None).await,
        Some(cluster) => {
            let membership = Arc::new(Membership::new(std::net::SocketAddr::new(
                cluster.pod_ip,
                cluster.listen.port(),
            )));
            let client = PeerClient::new(&cluster.tls, Duration::from_secs(5))
                .context("peer TLS is misconfigured")?;
            let fetcher = ClusterFetcher::new(
                local,
                membership.clone(),
                client.clone(),
                cluster.forward_deadline,
                metrics.clone(),
            );
            let fabric = Fabric {
                config: cluster,
                membership,
                client,
            };
            serve(config, kube, metrics, secrets, fetcher, Some(fabric)).await
        }
    }
}

struct Fabric {
    config: ClusterConfig,
    membership: Arc<Membership>,
    client: PeerClient,
}

async fn serve<F: TokenFetcher>(
    config: BrokerConfig,
    kube: kube::Client,
    metrics: Arc<Metrics>,
    secrets: Arc<Secrets>,
    fetcher: F,
    fabric: Option<Fabric>,
) -> anyhow::Result<()> {
    // Mapping index, fed by the CRD watch.
    let index = Arc::new(MappingIndex::new());
    tokio::spawn(index.clone().run(kube.clone()));

    // In-cluster door.
    let audience = AudienceValidator::new(config.audience.clone())
        .with_apiserver_audiences(config.apiserver_audiences.iter().cloned());
    let jwt = JwtAuthenticator::new(audience, KubeTokenReviewer::new(kube.clone()));

    // Off-cluster door, if opened.
    let sigv4 = match &config.sigv4 {
        Some(s) => {
            let validator = SigV4Validator::new(
                config.audience.clone(),
                s.endpoints.clone(),
                s.trusted_accounts.clone(),
            )
            .context("SigV4 is enabled but misconfigured")?;
            tracing::info!(
                sts_hosts = ?s.endpoints.iter().map(StsEndpoint::host).collect::<Vec<_>>(),
                trusted_accounts = ?s.trusted_accounts,
                "SigV4 door open"
            );
            Some(SigV4Authenticator::new(
                validator,
                HyperStsTransport::https(DEFAULT_STS_TIMEOUT)?,
            ))
        }
        None => None,
    };

    let tokens = TokenCache::new(fetcher, CacheConfig::default(), rand::random());
    register_gauges(&metrics, &index, &secrets, &tokens);

    // Memory hygiene only: expired tokens are never served, this just frees
    // them. Not a refresh timer — refresh stays lazy.
    {
        let tokens = tokens.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(300));
            loop {
                tick.tick().await;
                tokens.sweep_expired();
            }
        });
    }

    let (stop_tx, stop_rx) = watch::channel(false);
    let stopped = move || {
        let mut rx = stop_rx.clone();
        async move {
            let _ = rx.wait_for(|s| *s).await;
        }
    };

    // Peer fabric: membership, peer listener, gossip, warm-up.
    let warmed = Arc::new(AtomicBool::new(fabric.is_none()));
    let peer_server = match fabric {
        None => None,
        Some(Fabric {
            config: cluster,
            membership,
            client,
        }) => {
            let peer_port = cluster.listen.port();
            tokio::spawn(membership.clone().watch(
                kube.clone(),
                cluster.namespace.clone(),
                cluster.service.clone(),
                peer_port,
            ));
            {
                let m = membership.clone();
                metrics.gauge("recognito_peers", "Ready peer replicas.", move || {
                    m.peers().len() as f64
                });
            }
            let gossip = Arc::new(Gossip {
                tokens: tokens.clone(),
                secrets: secrets.clone(),
                membership,
                client,
                metrics: metrics.clone(),
            });
            tokio::spawn(gossip.clone().token_deltas());
            tokio::spawn(gossip.clone().secret_deltas());
            tokio::spawn(gossip.clone().anti_entropy(cluster.anti_entropy_interval));
            {
                let (gossip, warmed) = (gossip.clone(), warmed.clone());
                tokio::spawn(async move { gossip.warm_up(WARM_UP_SETTLE, &warmed).await });
            }

            let tls = cluster
                .tls
                .server_config()
                .context("peer TLS is misconfigured")?;
            let app = peer::router(Arc::new(PeerState {
                tokens: tokens.clone(),
                secrets: secrets.clone(),
                metrics: metrics.clone(),
            }));
            tracing::info!(listen = %cluster.listen, service = %cluster.service, "peer fabric on");
            Some(tokio::spawn(server::serve_tls(
                cluster.listen,
                app,
                tls,
                stopped(),
                DRAIN,
            )))
        }
    };

    let broker = Arc::new(Broker::new(
        jwt,
        sigv4,
        index.clone(),
        config.user_pool_id.clone(),
        secrets,
        tokens,
        metrics.clone(),
    ));

    let draining = Arc::new(AtomicBool::new(false));
    let ops = tokio::spawn(server::serve_plain(
        config.ops_listen,
        server::ops_router(
            server::Readiness {
                index,
                warmed,
                draining: draining.clone(),
            },
            metrics,
        ),
        stopped(),
    ));
    let app = server::router(broker);
    let main_server = match config.tls {
        Some((cert, key)) => {
            let tls = server::tls_config(cert, key)?;
            tokio::spawn(server::serve_tls(config.listen, app, tls, stopped(), DRAIN))
        }
        None => tokio::spawn(server::serve_plain(config.listen, app, stopped())),
    };
    tracing::info!(listen = %config.listen, ops = %config.ops_listen, "serving");

    shutdown_signal().await;
    tracing::info!(delay = ?SHUTDOWN_DELAY, "SIGTERM: not ready, still serving while endpoints converge");
    draining.store(true, std::sync::atomic::Ordering::Release);
    tokio::time::sleep(SHUTDOWN_DELAY).await;
    tracing::info!("shutting down; draining connections");
    let _ = stop_tx.send(true);
    main_server.await??;
    ops.await??;
    if let Some(peer_server) = peer_server {
        peer_server.await??;
    }
    Ok(())
}

fn register_gauges<F: TokenFetcher>(
    metrics: &Metrics,
    index: &Arc<MappingIndex>,
    secrets: &Arc<Secrets>,
    tokens: &Arc<TokenCache<F>>,
) {
    let (idx, sec) = (index.clone(), secrets.clone());
    metrics.gauge("recognito_mappings", "Mappings in the index.", move || {
        idx.len() as f64
    });
    metrics.gauge(
        "recognito_cached_secrets",
        "Client secrets held in memory.",
        move || sec.len() as f64,
    );
    let tok = tokens.clone();
    metrics.gauge(
        "recognito_cached_tokens",
        "Access tokens held in memory.",
        move || tok.len() as f64,
    );
    let tok = tokens.clone();
    metrics.gauge(
        "recognito_token_cache_hits",
        "Token cache hits.",
        move || tok.metrics().snapshot().hits as f64,
    );
    let tok = tokens.clone();
    metrics.gauge(
        "recognito_token_cache_misses",
        "Token cache misses.",
        move || tok.metrics().snapshot().misses as f64,
    );
    let tok = tokens.clone();
    metrics.gauge(
        "recognito_token_remote_merges",
        "Tokens learned from peers that changed this replica's cache.",
        move || tok.metrics().snapshot().remote_merges as f64,
    );
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = ctrl_c.await;
}

/// cgroup v2 `cpu.max` ("<quota> <period>" or "max <period>"), rounded up.
fn cgroup_cpu_limit() -> Option<usize> {
    let raw = std::fs::read_to_string("/sys/fs/cgroup/cpu.max").ok()?;
    let mut parts = raw.split_whitespace();
    let quota: f64 = parts.next()?.parse().ok()?;
    let period: f64 = parts.next()?.parse().ok()?;
    (period > 0.0).then(|| ((quota / period).ceil() as usize).max(1))
}
