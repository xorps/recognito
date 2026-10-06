//! Controller entrypoint: configuration, wiring, lifecycle.
//!
//! Single replica (Deployment, `Recreate`): one writer per mapping is what
//! keeps rotation and generation numbering simple. No leader election in v1;
//! a crash costs a pod restart, during which brokers keep serving from their
//! caches and nothing is rotated.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Context as _;
use axum::Router;
use axum::http::{StatusCode, header};
use axum::routing::get;
use recognito_api::RateLimiter;
use recognito_api::metrics::Metrics;
use recognito_controller::aws::{AwsCognitoAdmin, sdk_config};
use recognito_controller::config::ControllerConfig;
use recognito_controller::controller::{self, Context};
use recognito_controller::reconcile::Budgets;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config = ControllerConfig::from_env().context("invalid controller configuration")?;
    tracing::info!(
        allowed_pools = ?config.settings.allowed_pools,
        rotation_grace = ?config.settings.rotation_grace,
        read_rps = config.read_rps,
        write_rps = config.write_rps,
        "recognito-controller starting"
    );

    let client = kube::Client::try_default()
        .await
        .context("cannot build a Kubernetes client")?;
    let metrics = Arc::new(Metrics::new());
    let ready = Arc::new(AtomicBool::new(false));

    let ops = {
        let ready = ready.clone();
        let metrics = metrics.clone();
        Router::new()
            .route("/healthz", get(|| async { "ok" }))
            .route(
                "/readyz",
                get(move || {
                    let ok = ready.load(Ordering::Acquire);
                    async move {
                        if ok {
                            (StatusCode::OK, "ready")
                        } else {
                            (StatusCode::SERVICE_UNAVAILABLE, "informer not synced")
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
    };
    let listener = tokio::net::TcpListener::bind(config.ops_listen).await?;
    tokio::spawn(async move { axum::serve(listener, ops).await });

    let ctx = Arc::new(Context {
        client,
        admin: AwsCognitoAdmin::new(sdk_config().await),
        budgets: Budgets {
            reads: RateLimiter::new(config.read_rps, 1),
            writes: RateLimiter::new(config.write_rps, 2),
        },
        settings: config.settings,
        metrics,
    });

    // Returns on SIGTERM/SIGINT once in-flight reconciles finish.
    controller::run(ctx, ready).await;
    tracing::info!("recognito-controller stopped");
    Ok(())
}
