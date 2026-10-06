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
    let mut crd = serde_json::to_value(CognitoClientMapping::crd())?;
    strip_integer_formats(&mut crd);
    print!("{}", serde_yaml_ng::to_string(&crd)?);
    Ok(())
}

/// schemars annotates integers with `format: int64` / `uint64`, which the
/// apiserver does not recognize and warns about on every `kubectl apply`.
/// The format is advisory only — the `type` and any `minimum` still apply —
/// so drop it rather than teach operators to ignore warnings.
fn strip_integer_formats(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            if map.get("type").and_then(|t| t.as_str()) == Some("integer") {
                map.remove("format");
            }
            map.values_mut().for_each(strip_integer_formats);
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(strip_integer_formats),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_emitted_crd_carries_no_integer_formats_but_keeps_date_times() {
        let mut crd = serde_json::to_value(CognitoClientMapping::crd()).unwrap();
        strip_integer_formats(&mut crd);
        let text = crd.to_string();
        assert!(!text.contains("\"int64\"") && !text.contains("\"uint64\""));
        assert!(text.contains("\"date-time\""));
    }
}
