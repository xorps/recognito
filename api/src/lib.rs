//! Shared API surface for the Cognito workload identity broker.
//!
//! Both binaries depend on this crate and neither depends on the other: the
//! controller writes `CognitoClientMapping` status, the broker reads mappings
//! into its in-memory index, and this crate is the single definition of what
//! a valid mapping is.

pub mod crd;
pub mod duration;
pub mod scope;

pub use crd::{
    CognitoClientMapping, CognitoClientMappingSpec, CognitoClientMappingStatus, DeliverTo,
    SecretRef, ServiceAccountRef, SpecError, ValidatedSpec,
};
pub use duration::{Duration, DurationError};
pub use scope::{CanonicalScopeSet, ScopeError, ScopeProfile, ScopeProfiles};

/// Identity of a workload as the broker knows it: a ServiceAccount in a
/// namespace. Derived from the `sub` claim of a projected SA token
/// (`system:serviceaccount:<namespace>:<name>`) and used as the index key
/// against which mappings are looked up.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ServiceAccountIdentity {
    pub namespace: String,
    pub name: String,
}

impl ServiceAccountIdentity {
    pub const SUB_PREFIX: &'static str = "system:serviceaccount:";

    /// Parse the `sub` claim of a projected ServiceAccount token.
    ///
    /// Strict on purpose: a `sub` with an unexpected shape means the token is
    /// not a ServiceAccount token, and guessing at the identity of a token we
    /// do not understand is how confused-deputy bugs start.
    pub fn from_sub(sub: &str) -> Option<Self> {
        let rest = sub.strip_prefix(Self::SUB_PREFIX)?;
        let (namespace, name) = rest.split_once(':')?;
        if namespace.is_empty() || name.is_empty() || name.contains(':') {
            return None;
        }
        Some(ServiceAccountIdentity {
            namespace: namespace.to_owned(),
            name: name.to_owned(),
        })
    }
}

impl std::fmt::Display for ServiceAccountIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}:{}", Self::SUB_PREFIX, self.namespace, self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_service_account_sub() {
        let id = ServiceAccountIdentity::from_sub("system:serviceaccount:payments:api").unwrap();
        assert_eq!(id.namespace, "payments");
        assert_eq!(id.name, "api");
        assert_eq!(id.to_string(), "system:serviceaccount:payments:api");
    }

    #[test]
    fn rejects_subs_that_are_not_service_accounts() {
        for bad in [
            "system:node:worker-1",
            "kubernetes-admin",
            "system:serviceaccount:payments",
            "system:serviceaccount::api",
            "system:serviceaccount:payments:",
            "system:serviceaccount:payments:api:extra",
            "",
        ] {
            assert!(
                ServiceAccountIdentity::from_sub(bad).is_none(),
                "{bad:?} should not parse as a ServiceAccount identity"
            );
        }
    }
}
