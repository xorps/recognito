//! Canonical scope sets and the bounded-profile model.
//!
//! # Why profiles instead of arbitrary scope subsets
//!
//! The cache key is `(client_id, canonical scope set)` and the fleet is sized
//! against a hard 150 RPS `ClientAuthentication` quota (docs/DESIGN.md §Quota
//! model). If callers could request any subset of a mapping's scopes, the key
//! space per client would be the *powerset* of its scopes — 2^n cache entries,
//! each with its own refresh cycle, each a separate Cognito exchange. Ten
//! scopes would be 1023 keys for one app client, and the quota arithmetic that
//! justifies the whole design stops holding.
//!
//! So `allowedScopes` is a list of *named profiles*, and a caller downscopes by
//! naming a narrower profile rather than by enumerating scopes. Cache
//! cardinality per client is then `|profiles|` — a number a human wrote down
//! in a manifest and can reason about. This is the concrete meaning of
//! "canonicalize scopes to bounded profiles from allowedScopes" in CLAUDE.md.
//!
//! Downscoping is still allowed and up-scoping is still impossible: the set a
//! caller receives is always one of the sets the mapping author authorized.

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A named, authorized scope set. The `name` is what a caller asks for; the
/// `scopes` are what it gets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScopeProfile {
    /// Caller-facing profile name, unique within a mapping.
    pub name: String,
    /// Cognito resource-server scopes, e.g. `payments/read`.
    pub scopes: Vec<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ScopeError {
    #[error("profile name must be non-empty and match [a-z0-9]([-a-z0-9]*[a-z0-9])?")]
    InvalidProfileName(String),
    #[error("profile {0:?} has no scopes")]
    EmptyProfile(String),
    #[error("scope {0:?} contains a character not permitted by RFC 6749 scope-token")]
    InvalidScopeToken(String),
    #[error("duplicate profile name {0:?}")]
    DuplicateProfile(String),
    #[error("mapping declares no scope profiles")]
    NoProfiles,
    #[error("no scope profile named {0:?}")]
    UnknownProfile(String),
    #[error("caller must name a scope profile: mapping declares {0} of them")]
    AmbiguousProfile(usize),
    #[error(
        "requested scope {requested:?} does not match any declared profile; this mapping declares {available:?}"
    )]
    NoMatchingProfile {
        requested: String,
        available: Vec<String>,
    },
}

/// A scope set in the one spelling this system uses: sorted, deduplicated,
/// non-empty. Constructing it is the only way to get one, so anything holding
/// a `CanonicalScopeSet` is holding a valid cache key component.
///
/// Scopes are **case-sensitive** (RFC 6749 §3.3 defines scope-token as an
/// opaque byte string). Lowercasing them here would silently merge two
/// distinct Cognito scopes into one cache entry.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalScopeSet(Vec<String>);

impl CanonicalScopeSet {
    pub fn new(scopes: impl IntoIterator<Item = String>) -> Result<Self, ScopeError> {
        let mut scopes: Vec<String> = scopes.into_iter().collect();
        for scope in &scopes {
            if !is_valid_scope_token(scope) {
                return Err(ScopeError::InvalidScopeToken(scope.clone()));
            }
        }
        scopes.sort();
        scopes.dedup();
        Ok(CanonicalScopeSet(scopes))
    }

    pub fn as_slice(&self) -> &[String] {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The `scope` parameter value for the Cognito token request, and the
    /// scope component of the cache key. Space-delimited per RFC 6749 §3.3.
    pub fn to_scope_parameter(&self) -> String {
        self.0.join(" ")
    }
}

impl fmt::Display for CanonicalScopeSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_scope_parameter())
    }
}

/// RFC 6749 §3.3 scope-token = 1*( %x21 / %x23-5B / %x5D-7E ).
///
/// Excludes space (the delimiter), double quote, and backslash. Enforcing this
/// keeps a scope from smuggling a delimiter and turning one requested scope
/// into two in the outbound form body.
fn is_valid_scope_token(scope: &str) -> bool {
    !scope.is_empty()
        && scope
            .bytes()
            .all(|b| b == 0x21 || (0x23..=0x5B).contains(&b) || (0x5D..=0x7E).contains(&b))
}

/// Profile names go into log lines and request parameters; keep them to the
/// DNS-label shape Kubernetes users already expect.
fn is_valid_profile_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-')
}

/// The validated, resolved profile table for one mapping. Built once when a
/// mapping enters the broker's index so the request path is a lookup, never a
/// validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeProfiles {
    profiles: Vec<(String, CanonicalScopeSet)>,
}

impl ScopeProfiles {
    pub fn validate(declared: &[ScopeProfile]) -> Result<Self, ScopeError> {
        if declared.is_empty() {
            return Err(ScopeError::NoProfiles);
        }
        let mut profiles: Vec<(String, CanonicalScopeSet)> = Vec::with_capacity(declared.len());
        for profile in declared {
            if !is_valid_profile_name(&profile.name) {
                return Err(ScopeError::InvalidProfileName(profile.name.clone()));
            }
            if profiles.iter().any(|(name, _)| name == &profile.name) {
                return Err(ScopeError::DuplicateProfile(profile.name.clone()));
            }
            let set = CanonicalScopeSet::new(profile.scopes.iter().cloned())?;
            if set.is_empty() {
                return Err(ScopeError::EmptyProfile(profile.name.clone()));
            }
            profiles.push((profile.name.clone(), set));
        }
        Ok(ScopeProfiles { profiles })
    }

    /// Resolve a caller's request to an authorized scope set.
    ///
    /// A caller that names nothing gets the sole profile if there is exactly
    /// one, and an error otherwise. Defaulting to "the first" or "the union"
    /// when several exist would hand out more scope than the caller asked for,
    /// which is the up-scoping the authz layer exists to prevent.
    pub fn resolve(&self, requested: Option<&str>) -> Result<&CanonicalScopeSet, ScopeError> {
        match requested {
            Some(name) => self
                .profiles
                .iter()
                .find(|(profile, _)| profile == name)
                .map(|(_, set)| set)
                .ok_or_else(|| ScopeError::UnknownProfile(name.to_owned())),
            None if self.profiles.len() == 1 => Ok(&self.profiles[0].1),
            None => Err(ScopeError::AmbiguousProfile(self.profiles.len())),
        }
    }

    /// Resolve an RFC 8693 `scope` parameter to an authorized scope set.
    ///
    /// This is the request-path entry point (ADR-13). The wire carries real
    /// scope strings, as the standard requires, but they must canonicalize to
    /// a set some profile declares **exactly**. An arbitrary subset is refused
    /// rather than served, because serving it would reintroduce the powerset
    /// of cache keys this module exists to bound — see the module docs.
    ///
    /// Order and duplicates do not matter: `"b a"`, `"a b"`, and `"a b a"` all
    /// resolve to the same profile and therefore the same cache key.
    pub fn resolve_requested_scopes(
        &self,
        requested: Option<&str>,
    ) -> Result<&CanonicalScopeSet, ScopeError> {
        let Some(raw) = requested.map(str::trim).filter(|s| !s.is_empty()) else {
            return self.resolve(None);
        };
        let wanted =
            CanonicalScopeSet::new(raw.split(' ').filter(|s| !s.is_empty()).map(str::to_owned))?;
        self.profiles
            .iter()
            .find(|(_, set)| *set == wanted)
            .map(|(_, set)| set)
            .ok_or(ScopeError::NoMatchingProfile {
                requested: wanted.to_scope_parameter(),
                available: self
                    .profiles
                    .iter()
                    .map(|(_, s)| s.to_scope_parameter())
                    .collect(),
            })
    }

    /// The profile name for a resolved set, for audit logs and the debug
    /// endpoint. Callers never send this; it exists so a log line says
    /// `profile=read` rather than repeating the scope string.
    pub fn name_of(&self, set: &CanonicalScopeSet) -> Option<&str> {
        self.profiles
            .iter()
            .find(|(_, declared)| declared == set)
            .map(|(name, _)| name.as_str())
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.profiles.iter().map(|(name, _)| name.as_str())
    }

    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(name: &str, scopes: &[&str]) -> ScopeProfile {
        ScopeProfile {
            name: name.into(),
            scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    #[test]
    fn canonical_set_sorts_and_dedupes_so_key_is_order_independent() {
        let a = CanonicalScopeSet::new(["b/write".into(), "a/read".into()]).unwrap();
        let b =
            CanonicalScopeSet::new(["a/read".into(), "b/write".into(), "a/read".into()]).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.to_scope_parameter(), "a/read b/write");
    }

    #[test]
    fn scopes_stay_case_sensitive() {
        let lower = CanonicalScopeSet::new(["payments/read".into()]).unwrap();
        let upper = CanonicalScopeSet::new(["payments/Read".into()]).unwrap();
        assert_ne!(
            lower, upper,
            "case folding would merge distinct Cognito scopes"
        );
    }

    #[test]
    fn scope_cannot_smuggle_the_space_delimiter() {
        let err = CanonicalScopeSet::new(["payments/read admin/write".into()]).unwrap_err();
        assert!(matches!(err, ScopeError::InvalidScopeToken(_)));
    }

    #[test]
    fn resolve_defaults_only_when_there_is_exactly_one_profile() {
        let one = ScopeProfiles::validate(&[profile("read", &["a/read"])]).unwrap();
        assert_eq!(one.resolve(None).unwrap().to_scope_parameter(), "a/read");

        let two = ScopeProfiles::validate(&[
            profile("read", &["a/read"]),
            profile("write", &["a/read", "a/write"]),
        ])
        .unwrap();
        assert_eq!(two.resolve(None), Err(ScopeError::AmbiguousProfile(2)));
        assert_eq!(
            two.resolve(Some("read")).unwrap().to_scope_parameter(),
            "a/read"
        );
    }

    #[test]
    fn unknown_profile_is_refused_rather_than_approximated() {
        let profiles = ScopeProfiles::validate(&[profile("read", &["a/read"])]).unwrap();
        assert_eq!(
            profiles.resolve(Some("write")),
            Err(ScopeError::UnknownProfile("write".into()))
        );
    }

    #[test]
    fn duplicate_profile_names_are_rejected_at_admission() {
        let err =
            ScopeProfiles::validate(&[profile("read", &["a/read"]), profile("read", &["a/write"])])
                .unwrap_err();
        assert_eq!(err, ScopeError::DuplicateProfile("read".into()));
    }

    #[test]
    fn requested_scopes_resolve_regardless_of_order_or_duplication() {
        // The RFC 8693 `scope` parameter is a set written as a string. Three
        // spellings of one set must land on one profile and one cache key.
        let profiles = ScopeProfiles::validate(&[profile("full", &["a/read", "b/write"])]).unwrap();
        for spelling in ["a/read b/write", "b/write a/read", "a/read  b/write a/read"] {
            assert_eq!(
                profiles
                    .resolve_requested_scopes(Some(spelling))
                    .unwrap()
                    .to_scope_parameter(),
                "a/read b/write",
                "{spelling:?} should resolve to the declared profile"
            );
        }
    }

    #[test]
    fn an_arbitrary_subset_is_refused_rather_than_served() {
        // The bounded-cardinality rule on the request path: `a/read` alone is
        // a subset of the `full` profile, and there is no profile declaring
        // it, so it is refused. Serving it would create a cache key nobody
        // budgeted for.
        let profiles = ScopeProfiles::validate(&[profile("full", &["a/read", "b/write"])]).unwrap();
        let err = profiles
            .resolve_requested_scopes(Some("a/read"))
            .unwrap_err();
        assert!(matches!(err, ScopeError::NoMatchingProfile { .. }));
    }

    #[test]
    fn requesting_more_than_a_profile_declares_is_refused() {
        let profiles = ScopeProfiles::validate(&[profile("read", &["a/read"])]).unwrap();
        let err = profiles
            .resolve_requested_scopes(Some("a/read admin/write"))
            .unwrap_err();
        assert!(matches!(err, ScopeError::NoMatchingProfile { .. }));
    }

    #[test]
    fn an_omitted_scope_parameter_falls_back_to_the_sole_profile() {
        let one = ScopeProfiles::validate(&[profile("read", &["a/read"])]).unwrap();
        for omitted in [None, Some(""), Some("   ")] {
            assert_eq!(
                one.resolve_requested_scopes(omitted)
                    .unwrap()
                    .to_scope_parameter(),
                "a/read"
            );
        }

        let two = ScopeProfiles::validate(&[
            profile("read", &["a/read"]),
            profile("write", &["a/write"]),
        ])
        .unwrap();
        assert_eq!(
            two.resolve_requested_scopes(None),
            Err(ScopeError::AmbiguousProfile(2))
        );
    }

    #[test]
    fn resolved_sets_carry_a_profile_name_for_audit_logs() {
        let profiles = ScopeProfiles::validate(&[
            profile("read", &["a/read"]),
            profile("full", &["a/read", "a/write"]),
        ])
        .unwrap();
        let resolved = profiles
            .resolve_requested_scopes(Some("a/write a/read"))
            .unwrap();
        assert_eq!(profiles.name_of(resolved), Some("full"));
    }

    #[test]
    fn cache_cardinality_per_client_equals_profile_count() {
        // The property the quota model depends on: N profiles, N keys — not 2^N.
        let profiles = ScopeProfiles::validate(&[
            profile("read", &["a/read"]),
            profile("write", &["a/write"]),
            profile("full", &["a/read", "a/write"]),
        ])
        .unwrap();
        let distinct: std::collections::HashSet<_> = profiles
            .names()
            .map(|n| profiles.resolve(Some(n)).unwrap().clone())
            .collect();
        assert_eq!(distinct.len(), profiles.len());
    }
}
