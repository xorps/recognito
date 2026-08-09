//! Controller entrypoint.
//!
//! The reconcile loop lands next. What exists today is the resync-discipline
//! decision function it will be built around, kept here with its tests because
//! CLAUDE.md invariant 4 — no AWS calls on resync — is a property of *this*
//! function and nothing else.

use anyhow::Result;
use recognito_api::{CognitoClientMapping, CognitoClientMappingStatus};

pub mod resync;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    tracing::info!("recognito-controller starting");
    anyhow::bail!("controller reconcile loop is not implemented yet")
}

/// Convenience for the reconciler and its tests.
pub fn status_of(mapping: &CognitoClientMapping) -> CognitoClientMappingStatus {
    mapping.status.clone().unwrap_or_default()
}
