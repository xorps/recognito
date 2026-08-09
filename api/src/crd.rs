//! The `CognitoClientMapping` custom resource.
//!
//! One mapping = one Kubernetes ServiceAccount authorized to obtain tokens for
//! one Cognito app client. The controller owns the `status` block; nothing
//! else writes it.

use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::duration::Duration;
use crate::scope::{ScopeError, ScopeProfile, ScopeProfiles};

/// Cognito's own bounds on access-token validity.
pub const TOKEN_VALIDITY_MIN: Duration = Duration::from_secs(5 * 60);
pub const TOKEN_VALIDITY_MAX: Duration = Duration::from_secs(24 * 60 * 60);

/// Push mode refreshes at ~50% of TTL and kubelet takes up to ~2 minutes to
/// propagate a Secret update to a mounted volume (ADR-12). Below a 10-minute
/// validity the refresh interval closes on the propagation lag and mounted
/// tokens can be expired by the time a workload reads them.
pub const PUSH_MODE_TOKEN_VALIDITY_MIN: Duration = Duration::from_secs(10 * 60);

pub const ROTATE_AFTER_MIN: Duration = Duration::from_secs(60 * 60);
pub const ROTATE_AFTER_MAX: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// `<region>_<alphanumeric>`, e.g. `us-east-1_aBcDeFgHi`.
pub const USER_POOL_ID_PATTERN: &str = r"^[a-z]{2}(-[a-z]+)+-[0-9]+_[0-9a-zA-Z]+$";

#[derive(CustomResource, Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "recognito.io",
    version = "v1alpha1",
    kind = "CognitoClientMapping",
    plural = "cognitoclientmappings",
    shortname = "ccm",
    namespaced,
    status = "CognitoClientMappingStatus",
    printcolumn = r#"{"name":"Client ID","type":"string","jsonPath":".status.clientId"}"#,
    printcolumn = r#"{"name":"ServiceAccount","type":"string","jsonPath":".spec.serviceAccountRef.name"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type==\"Ready\")].status"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct CognitoClientMappingSpec {
    /// The ServiceAccount authorized by this mapping. **Always resolved in the
    /// mapping's own namespace** — there is deliberately no `namespace` field.
    ///
    /// A cross-namespace reference would let anyone who can create a mapping in
    /// a namespace they control grant themselves the identity of a
    /// ServiceAccount in a namespace they do not, which turns namespaced RBAC
    /// into a suggestion.
    pub service_account_ref: ServiceAccountRef,

    /// Cognito user pool that owns the generated app client.
    #[schemars(regex(pattern = r"^[a-z]{2}(-[a-z]+)+-[0-9]+_[0-9a-zA-Z]+$"))]
    pub user_pool_id: String,

    /// Named scope profiles this mapping may mint. Callers downscope by naming
    /// a narrower profile; see [`crate::scope`] for why this is a bounded list
    /// rather than an arbitrary scope set.
    #[schemars(length(min = 1))]
    pub allowed_scopes: Vec<ScopeProfile>,

    /// Access-token lifetime requested from Cognito.
    #[serde(default = "default_token_validity")]
    pub token_validity: Duration,

    /// How long a client secret may live before the controller rotates it.
    #[serde(default = "default_rotate_after")]
    pub rotate_after: Duration,

    /// Opt-in push mode: the broker writes *tokens* (never client secrets) to
    /// a Secret in this namespace for workloads that cannot call the broker.
    /// Weaker audit posture; the pull endpoint remains primary (ADR-12).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deliver_to: Option<DeliverTo>,
}

fn default_token_validity() -> Duration {
    Duration::from_secs(15 * 60)
}

fn default_rotate_after() -> Duration {
    Duration::from_secs(90 * 24 * 60 * 60)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceAccountRef {
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeliverTo {
    pub secret_ref: SecretRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretRef {
    pub name: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CognitoClientMappingStatus {
    /// Cognito app client ID. Stable across secret rotations — rotation
    /// replaces the secret, never the client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,

    /// Hash of the spec the controller last applied to Cognito. Equality with
    /// the live spec's hash is what lets a resync short-circuit without an AWS
    /// call (CLAUDE.md invariant 4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec_hash: Option<String>,

    /// When the slow audit loop last confirmed Cognito matches this spec.
    /// Distinct from `spec_hash`: the hash says "we applied it", this says
    /// "we have since seen that it is still true".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_verified: Option<Time>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_created_at: Option<Time>,

    /// Bumped on every rotation. The broker's secret cache evicts on a
    /// generation change (ADR-10) — this is the informer's version signal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_generation: Option<u64>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum SpecError {
    #[error("serviceAccountRef.name must be a DNS subdomain")]
    InvalidServiceAccountName(String),
    #[error("userPoolId {0:?} is not a Cognito user pool ID (<region>_<id>)")]
    InvalidUserPoolId(String),
    #[error("deliverTo.secretRef.name must be a DNS subdomain")]
    InvalidSecretName(String),
    #[error("tokenValidity {0} is outside Cognito's supported range {1}..={2}")]
    TokenValidityOutOfRange(Duration, Duration, Duration),
    #[error("tokenValidity {0} is below the {1} floor required for push mode (deliverTo)")]
    TokenValidityTooShortForPushMode(Duration, Duration),
    #[error("rotateAfter {0} is outside the supported range {1}..={2}")]
    RotateAfterOutOfRange(Duration, Duration, Duration),
    #[error(transparent)]
    Scope(#[from] ScopeError),
}

/// A spec that has passed every check, with scope profiles already resolved.
///
/// The broker's index and the controller's reconciler both hold this rather
/// than the raw spec, so neither can forget to validate.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedSpec {
    pub service_account_name: String,
    pub user_pool_id: String,
    pub scope_profiles: ScopeProfiles,
    pub token_validity: Duration,
    pub rotate_after: Duration,
    pub deliver_to_secret: Option<String>,
}

impl CognitoClientMappingSpec {
    pub fn validate(&self) -> Result<ValidatedSpec, SpecError> {
        if !is_dns_subdomain(&self.service_account_ref.name) {
            return Err(SpecError::InvalidServiceAccountName(
                self.service_account_ref.name.clone(),
            ));
        }
        if !is_user_pool_id(&self.user_pool_id) {
            return Err(SpecError::InvalidUserPoolId(self.user_pool_id.clone()));
        }
        if self.token_validity < TOKEN_VALIDITY_MIN || self.token_validity > TOKEN_VALIDITY_MAX {
            return Err(SpecError::TokenValidityOutOfRange(
                self.token_validity,
                TOKEN_VALIDITY_MIN,
                TOKEN_VALIDITY_MAX,
            ));
        }
        if self.rotate_after < ROTATE_AFTER_MIN || self.rotate_after > ROTATE_AFTER_MAX {
            return Err(SpecError::RotateAfterOutOfRange(
                self.rotate_after,
                ROTATE_AFTER_MIN,
                ROTATE_AFTER_MAX,
            ));
        }

        let deliver_to_secret = match &self.deliver_to {
            Some(deliver_to) => {
                if !is_dns_subdomain(&deliver_to.secret_ref.name) {
                    return Err(SpecError::InvalidSecretName(
                        deliver_to.secret_ref.name.clone(),
                    ));
                }
                if self.token_validity < PUSH_MODE_TOKEN_VALIDITY_MIN {
                    return Err(SpecError::TokenValidityTooShortForPushMode(
                        self.token_validity,
                        PUSH_MODE_TOKEN_VALIDITY_MIN,
                    ));
                }
                Some(deliver_to.secret_ref.name.clone())
            }
            None => None,
        };

        Ok(ValidatedSpec {
            service_account_name: self.service_account_ref.name.clone(),
            user_pool_id: self.user_pool_id.clone(),
            scope_profiles: ScopeProfiles::validate(&self.allowed_scopes)?,
            token_validity: self.token_validity,
            rotate_after: self.rotate_after,
            deliver_to_secret,
        })
    }

    /// Hash of the spec, for the resync short-circuit.
    ///
    /// Hashing the `serde_json::Value` rather than the struct's field order is
    /// what makes this stable: `serde_json::Map` is a `BTreeMap` here, so keys
    /// serialize sorted and adding a field to the struct in a different
    /// position does not invalidate every mapping's cached hash.
    pub fn spec_hash(&self) -> String {
        let canonical = serde_json::to_vec(
            &serde_json::to_value(self).expect("CognitoClientMappingSpec is always serializable"),
        )
        .expect("serde_json::Value is always serializable");
        let digest = Sha256::digest(&canonical);
        format!("sha256:{}", hex(&digest))
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

fn is_dns_subdomain(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

/// Hand-checked rather than regex-matched so the crate carries no regex
/// dependency; the OpenAPI schema still ships [`USER_POOL_ID_PATTERN`] so the
/// apiserver rejects bad values before the controller sees them.
fn is_user_pool_id(id: &str) -> bool {
    let Some((region, suffix)) = id.split_once('_') else {
        return false;
    };
    let region_ok = region.split('-').count() >= 3
        && region
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !region.starts_with('-')
        && !region.ends_with('-');
    let suffix_ok = !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_alphanumeric());
    region_ok && suffix_ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::ScopeProfile;

    fn spec() -> CognitoClientMappingSpec {
        CognitoClientMappingSpec {
            service_account_ref: ServiceAccountRef {
                name: "payments".into(),
            },
            user_pool_id: "us-east-1_aBcDeFgHi".into(),
            allowed_scopes: vec![ScopeProfile {
                name: "read".into(),
                scopes: vec!["payments/read".into()],
            }],
            token_validity: default_token_validity(),
            rotate_after: default_rotate_after(),
            deliver_to: None,
        }
    }

    #[test]
    fn valid_spec_validates() {
        let validated = spec().validate().unwrap();
        assert_eq!(validated.service_account_name, "payments");
        assert_eq!(validated.scope_profiles.len(), 1);
    }

    #[test]
    fn token_validity_floor_and_ceiling_match_cognito() {
        let mut s = spec();
        s.token_validity = Duration::from_secs(60);
        assert!(matches!(
            s.validate(),
            Err(SpecError::TokenValidityOutOfRange(..))
        ));
        s.token_validity = Duration::from_secs(25 * 60 * 60);
        assert!(matches!(
            s.validate(),
            Err(SpecError::TokenValidityOutOfRange(..))
        ));
        s.token_validity = TOKEN_VALIDITY_MIN;
        assert!(s.validate().is_ok(), "the floor itself must be accepted");
    }

    #[test]
    fn push_mode_raises_the_token_validity_floor() {
        let mut s = spec();
        s.token_validity = Duration::from_secs(5 * 60);
        // Fine for pull mode...
        assert!(s.validate().is_ok());
        // ...but not once a Secret is mounted, where kubelet propagation lag
        // can exceed the refresh interval (ADR-12).
        s.deliver_to = Some(DeliverTo {
            secret_ref: SecretRef {
                name: "payments-token".into(),
            },
        });
        assert!(matches!(
            s.validate(),
            Err(SpecError::TokenValidityTooShortForPushMode(..))
        ));
    }

    #[test]
    fn service_account_ref_has_no_namespace_escape_hatch() {
        // Compile-time property, asserted here so a future field addition
        // trips a test rather than sliding through review: the serialized
        // reference carries a name and nothing else.
        let json = serde_json::to_value(&ServiceAccountRef {
            name: "payments".into(),
        })
        .unwrap();
        assert_eq!(json, serde_json::json!({ "name": "payments" }));
        // And an attempt to smuggle one in is rejected by deny_unknown_fields.
        let smuggled = serde_json::json!({ "name": "payments", "namespace": "kube-system" });
        assert!(serde_json::from_value::<ServiceAccountRef>(smuggled).is_err());
    }

    #[test]
    fn user_pool_id_shape_is_enforced() {
        let mut s = spec();
        for bad in [
            "aBcDeFgHi",
            "us-east-1",
            "useast1_abc",
            "us-east-1_",
            "_abc",
        ] {
            s.user_pool_id = bad.into();
            assert!(
                matches!(s.validate(), Err(SpecError::InvalidUserPoolId(_))),
                "{bad:?} should be rejected"
            );
        }
        s.user_pool_id = "eu-west-2_Ab0".into();
        assert!(s.validate().is_ok());
    }

    #[test]
    fn spec_hash_is_stable_and_sensitive() {
        let a = spec();
        let mut b = spec();
        assert_eq!(a.spec_hash(), b.spec_hash(), "same spec, same hash");

        b.token_validity = Duration::from_secs(30 * 60);
        assert_ne!(
            a.spec_hash(),
            b.spec_hash(),
            "a changed field must invalidate"
        );
    }

    #[test]
    fn spec_hash_ignores_cosmetic_duration_spellings() {
        // "15m" and "900s" are the same mapping; hashing them differently would
        // make the resync short-circuit miss and cost an AWS call per resync.
        let mut a = spec();
        let mut b = spec();
        a.token_validity = "15m".parse().unwrap();
        b.token_validity = "900s".parse().unwrap();
        assert_eq!(a.spec_hash(), b.spec_hash());
    }
}
