//! Emits the CognitoClientMapping CRD YAML to stdout.
//!
//! `cargo run --bin recognito-crdgen > deploy/crd.yaml`. Generating rather than
//! hand-maintaining the manifest keeps the OpenAPI validation the apiserver
//! enforces in lockstep with the Rust types the controller validates against —
//! two copies of the same rules is how a field ends up checked in one place
//! and not the other.

use kube::CustomResourceExt;
use recognito_api::CognitoClientMapping;

fn main() -> anyhow::Result<()> {
    let crd = CognitoClientMapping::crd();
    print!("{}", serde_yaml_ng::to_string(&crd)?);
    Ok(())
}
