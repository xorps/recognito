//! The `CognitoClientMapping` custom resource.
//!
//! One mapping = one Kubernetes ServiceAccount authorized to obtain tokens for
//! one Cognito app client. The controller owns the `status` block; nothing
//! else writes it.

use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use kube::{CustomResource, KubeSchema};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::aws::{AwsArnError, AwsRoleIdentity};
use crate::duration::Duration;
use crate::scope::{ScopeError, ScopeProfile, ScopeProfiles};
use crate::{ServiceAccountIdentity, WorkloadIdentity};

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

/// Admission-time shape check for `awsRole.arn`. The authoritative parse is
/// [`AwsRoleIdentity::from_role_arn`]; this only keeps obvious garbage out of
/// etcd.
pub const AWS_ROLE_ARN_PATTERN: &str =
    r"^arn:aws(-[a-z]+)*:iam::[0-9]{12}:role/([!-~]+/)*[A-Za-z0-9+=,.@_-]{1,64}$";

#[derive(CustomResource, Clone, Debug, PartialEq, Serialize, Deserialize, KubeSchema)]
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
    printcolumn = r#"{"name":"AWS Role","type":"string","jsonPath":".spec.awsRole.arn","priority":1}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type==\"Ready\")].status"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[x_kube(validation = Rule::new("has(self.serviceAccountRef) != has(self.awsRole)")
    .message("exactly one of serviceAccountRef or awsRole must be set"))]
#[serde(rename_all = "camelCase")]
pub struct CognitoClientMappingSpec {
    /// The ServiceAccount authorized by this mapping. **Always resolved in the
    /// mapping's own namespace** — there is deliberately no `namespace` field.
    ///
    /// A cross-namespace reference would let anyone who can create a mapping in
    /// a namespace they control grant themselves the identity of a
    /// ServiceAccount in a namespace they do not, which turns namespaced RBAC
    /// into a suggestion.
    ///
    /// Exactly one of this and `awsRole` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account_ref: Option<ServiceAccountRef>,

    /// An IAM role authorized by this mapping, for workloads outside the
    /// cluster that authenticate with SigV4 (ADR-15). Exactly one of this and
    /// `serviceAccountRef` is set.
    ///
    /// Unlike a ServiceAccount, a role is not confined by the mapping's
    /// namespace — any namespace can name any role. Restrict who may set this
    /// field with admission policy; the broker refuses a role that more than one
    /// mapping claims rather than picking between them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aws_role: Option<AwsRoleRef>,

    /// Cognito user pool that owns the generated app client. Immutable: an
    /// app client cannot move between pools, so changing this would orphan
    /// the old client. Replace the mapping instead.
    #[schemars(regex(pattern = r"^[a-z]{2}(-[a-z]+)+-[0-9]+_[0-9a-zA-Z]+$"))]
    #[x_kube(validation = Rule::new("self == oldSelf").message("userPoolId is immutable; create a new mapping instead"))]
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
pub struct AwsRoleRef {
    /// `arn:<partition>:iam::<account>:role/[<path>/]<name>`. Matched against
    /// callers by partition, account, and role name; see [`crate::aws`] for why
    /// the path takes no part.
    #[schemars(regex(
        pattern = r"^arn:aws(-[a-z]+)*:iam::[0-9]{12}:role/([!-~]+/)*[A-Za-z0-9+=,.@_-]{1,64}$"
    ))]
    pub arn: String,
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

    /// The previous secret during a rotation's grace window. Cognito holds at
    /// most two secrets per client; while this is set the controller will not
    /// start another rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retiring_secret_id: Option<String>,

    /// When `retiringSecretId` may be deleted: rotation time plus a grace
    /// period longer than the broker's generation-propagation lag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retire_after: Option<Time>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum SpecError {
    #[error("exactly one of serviceAccountRef or awsRole must be set; neither is")]
    NoPrincipal,
    #[error("exactly one of serviceAccountRef or awsRole must be set; both are")]
    AmbiguousPrincipal,
    #[error("awsRole.arn {0:?} is not a usable IAM role ARN: {1}")]
    InvalidAwsRoleArn(String, AwsArnError),
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
    pub principal: MappedPrincipal,
    pub user_pool_id: String,
    pub scope_profiles: ScopeProfiles,
    pub token_validity: Duration,
    pub rotate_after: Duration,
    pub deliver_to_secret: Option<String>,
}

/// Who a validated mapping authorizes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MappedPrincipal {
    /// A ServiceAccount *name*. The namespace is not part of the spec; it is
    /// always the mapping's own, supplied by [`ValidatedSpec::identity`].
    ServiceAccount {
        name: String,
    },
    AwsRole(AwsRoleIdentity),
}

impl ValidatedSpec {
    /// The identity this mapping authorizes, i.e. its key in the broker index.
    ///
    /// Taking the namespace here, rather than storing one in the spec, is what
    /// holds ServiceAccount mappings to their own namespace. An IAM role
    /// ignores it: roles live outside the cluster's namespacing entirely.
    pub fn identity(&self, mapping_namespace: &str) -> WorkloadIdentity {
        match &self.principal {
            MappedPrincipal::ServiceAccount { name } => {
                WorkloadIdentity::ServiceAccount(ServiceAccountIdentity {
                    namespace: mapping_namespace.to_owned(),
                    name: name.clone(),
                })
            }
            MappedPrincipal::AwsRole(role) => WorkloadIdentity::AwsRole(role.clone()),
        }
    }
}

impl CognitoClientMappingSpec {
    pub fn validate(&self) -> Result<ValidatedSpec, SpecError> {
        let principal = match (&self.service_account_ref, &self.aws_role) {
            (None, None) => return Err(SpecError::NoPrincipal),
            (Some(_), Some(_)) => return Err(SpecError::AmbiguousPrincipal),
            (Some(sa), None) => {
                if !is_dns_subdomain(&sa.name) {
                    return Err(SpecError::InvalidServiceAccountName(sa.name.clone()));
                }
                MappedPrincipal::ServiceAccount {
                    name: sa.name.clone(),
                }
            }
            (None, Some(role)) => MappedPrincipal::AwsRole(
                AwsRoleIdentity::from_role_arn(&role.arn)
                    .map_err(|e| SpecError::InvalidAwsRoleArn(role.arn.clone(), e))?,
            ),
        };
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
            principal,
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
            service_account_ref: Some(ServiceAccountRef {
                name: "payments".into(),
            }),
            aws_role: None,
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
        assert_eq!(
            validated.principal,
            MappedPrincipal::ServiceAccount {
                name: "payments".into()
            }
        );
        assert_eq!(validated.scope_profiles.len(), 1);
    }

    fn role_spec() -> CognitoClientMappingSpec {
        CognitoClientMappingSpec {
            service_account_ref: None,
            aws_role: Some(AwsRoleRef {
                arn: "arn:aws:iam::111122223333:role/batch/payments-reconciler".into(),
            }),
            ..spec()
        }
    }

    #[test]
    fn an_aws_role_mapping_validates_to_a_role_identity() {
        let validated = role_spec().validate().unwrap();
        let WorkloadIdentity::AwsRole(role) = validated.identity("payments") else {
            panic!("expected a role identity");
        };
        assert_eq!(role.account_id, "111122223333");
        assert_eq!(role.role_name, "payments-reconciler");
    }

    #[test]
    fn a_service_account_mapping_is_confined_to_its_own_namespace() {
        let validated = spec().validate().unwrap();
        assert_eq!(
            validated.identity("payments"),
            WorkloadIdentity::ServiceAccount(ServiceAccountIdentity {
                namespace: "payments".into(),
                name: "payments".into(),
            })
        );
        assert_ne!(validated.identity("payments"), validated.identity("other"));
    }

    #[test]
    fn exactly_one_principal_must_be_declared() {
        let neither = CognitoClientMappingSpec {
            service_account_ref: None,
            ..spec()
        };
        assert_eq!(neither.validate(), Err(SpecError::NoPrincipal));

        let both = CognitoClientMappingSpec {
            aws_role: role_spec().aws_role,
            ..spec()
        };
        assert_eq!(both.validate(), Err(SpecError::AmbiguousPrincipal));
    }

    #[test]
    fn exactly_one_principal_is_also_enforced_at_admission() {
        // The apiserver must refuse the same specs `validate` does, or a
        // mapping can sit in etcd that the controller will never reconcile.
        use kube::CustomResourceExt;
        let crd = serde_json::to_value(CognitoClientMapping::crd()).unwrap();
        let spec_schema =
            &crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"];
        assert_eq!(
            spec_schema["x-kubernetes-validations"][0]["rule"],
            "has(self.serviceAccountRef) != has(self.awsRole)"
        );
        assert_eq!(
            spec_schema["properties"]["userPoolId"]["x-kubernetes-validations"][0]["rule"],
            "self == oldSelf",
            "userPoolId must be immutable at admission"
        );
        let required = spec_schema["required"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(
            !required.contains(&"serviceAccountRef".into()),
            "serviceAccountRef must no longer be schema-required"
        );
    }

    #[test]
    fn an_unusable_role_arn_is_refused() {
        let s = CognitoClientMappingSpec {
            aws_role: Some(AwsRoleRef {
                arn: "arn:aws:iam::111122223333:user/payments".into(),
            }),
            ..role_spec()
        };
        assert!(matches!(
            s.validate(),
            Err(SpecError::InvalidAwsRoleArn(_, AwsArnError::NotARoleArn))
        ));
    }

    #[test]
    fn adding_aws_role_did_not_change_existing_spec_hashes() {
        // Pinned from before `awsRole` existed. If this moves, every existing
        // mapping misses the resync short-circuit once and costs an AWS call
        // (CLAUDE.md invariant 4).
        assert_eq!(
            spec().spec_hash(),
            "sha256:30a57e16e31aca5fbd8edbf7f7964268b85abb886db6ad9ec20396602c59bb86"
        );
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
