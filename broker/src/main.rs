//! Broker entrypoint.
//!
//! Not yet a server: the layers below it (authn, authz, fetch) land next. What
//! it does today is prove that the audience configuration is well-formed
//! before anything else starts, because a broker that comes up with a
//! mis-normalized audience is a broker that is silently not enforcing the
//! invariant it exists to enforce.

use anyhow::Context;
use recognito_broker::{AudienceValidator, CanonicalAudience};

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let raw = std::env::var("RECOGNITO_BROKER_AUDIENCE")
        .context("RECOGNITO_BROKER_AUDIENCE must be set to the broker's canonical HTTPS URL")?;

    // Fail fast and loudly. Starting with an audience we could not canonicalize
    // would mean every token is rejected, or worse, that operators "fix" it by
    // loosening the check.
    let audience = CanonicalAudience::parse(&raw).with_context(|| {
        format!("RECOGNITO_BROKER_AUDIENCE={raw:?} is not a canonical broker audience")
    })?;

    if audience.as_str() != raw {
        tracing::warn!(
            configured = %raw,
            canonical = %audience,
            "broker audience was normalized; the pod-spec generator must emit the canonical form \
             or projected tokens will be rejected byte-exact"
        );
    }

    let validator = AudienceValidator::new(audience);
    tracing::info!(
        audience = %validator.expected(),
        "audience binding configured; TokenReview will request exactly this audience"
    );

    anyhow::bail!("broker request path is not implemented yet (authn/authz/fetch layers pending)")
}
