//! Audience binding (ADR-9, CLAUDE.md invariant 2).
//!
//! # The attack this module exists to stop
//!
//! Every pod in a Kubernetes cluster automatically mounts a ServiceAccount
//! token at `/var/run/secrets/kubernetes.io/serviceaccount/token`, minted for
//! the *apiserver's* audience. If a token-exchange service accepts that token,
//! then possession of any pod in the cluster is possession of every identity
//! that service brokers — the pod does not have to be the mapped one, because
//! the exchange service, not the apiserver, is the thing being confused.
//!
//! This is CVE-2025-32963 in MinIO Operator STS, and it is the failure mode
//! this design is most exposed to, since we are structurally the same kind of
//! component. See `broker/tests/audience_cve_2025_32963.rs`.
//!
//! # The two rules
//!
//! 1. **Normalize on the way in; compare byte-exact on the way out.** A
//!    [`CanonicalAudience`] can only be built by [`CanonicalAudience::parse`],
//!    which is used for *our own configuration* and for the pod-spec
//!    generator. The value inside is then compared to a token's `aud` claim
//!    with `==` and nothing else. Normalizing an incoming claim before
//!    comparing would silently widen the accepted set to every spelling an
//!    attacker can think of, and would make the accepted set impossible to
//!    state in a review.
//!
//! 2. **A token is for us or it is for someone else.** The `aud` claim must
//!    hold exactly one audience, and it must be ours. A token that is
//!    simultaneously valid at the broker and somewhere else is a token whose
//!    other holder can replay it here.
//!
//! Because a pod may request *any* audience it likes in a projected volume,
//! this check is not what stops an unauthorized workload — the
//! ServiceAccount-to-mapping lookup in the authz layer does that. What this
//! check stops is **replay of a token minted for a different relying party**,
//! which is the strictly harder problem to retrofit.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Audiences that a *default* projected ServiceAccount token carries. Tokens
/// bearing these are the CVE-2025-32963 payload; they get their own rejection
/// reason because their arrival is an active-exploitation signal worth paging
/// on, not the routine misconfiguration that a plain mismatch usually is.
pub const DEFAULT_APISERVER_AUDIENCES: &[&str] = &[
    "https://kubernetes.default.svc",
    "https://kubernetes.default.svc.cluster.local",
    "kubernetes.default.svc",
    "kubernetes.default.svc.cluster.local",
    "api",
    "kubernetes",
];

/// A broker audience in the one spelling this system accepts.
///
/// Construction is the only normalization point in the codebase. There is no
/// `From<String>`, no `Deserialize`, and no public constructor that skips
/// [`CanonicalAudience::parse`] — the type is the enforcement.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CanonicalAudience(String);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AudienceConfigError {
    #[error("audience is empty")]
    Empty,
    #[error("audience {0:?} must use the https scheme")]
    NotHttps(String),
    #[error("audience {0:?} must not carry userinfo (user@host)")]
    HasUserinfo(String),
    #[error("audience {0:?} must not carry a path, query, or fragment")]
    HasPathQueryOrFragment(String),
    #[error("audience {0:?} has an empty or malformed host")]
    MalformedHost(String),
    #[error("audience {0:?} must not carry an explicit port other than 443")]
    NonDefaultPort(String),
}

impl CanonicalAudience {
    /// Parse and normalize a broker audience from **trusted configuration**.
    ///
    /// Normalization is deliberately narrow — lowercase the scheme and host,
    /// drop an explicit `:443`, drop a bare trailing slash — because every
    /// transformation here is one more spelling that the pod-spec generator
    /// and the validator have to agree on. The paired tests in this module
    /// assert that agreement.
    ///
    /// Never call this on a value taken from a token. See the module docs.
    pub fn parse(raw: &str) -> Result<Self, AudienceConfigError> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(AudienceConfigError::Empty);
        }

        let rest = strip_scheme_ci(raw, "https://")
            .ok_or_else(|| AudienceConfigError::NotHttps(raw.to_owned()))?;

        // Split off a single trailing slash before looking for a path, so that
        // "https://host/" normalizes but "https://host/x" is refused.
        let authority = rest.strip_suffix('/').unwrap_or(rest);
        if authority.contains('/') {
            return Err(AudienceConfigError::HasPathQueryOrFragment(raw.to_owned()));
        }
        if authority.contains('?') || authority.contains('#') {
            return Err(AudienceConfigError::HasPathQueryOrFragment(raw.to_owned()));
        }
        if authority.contains('@') {
            return Err(AudienceConfigError::HasUserinfo(raw.to_owned()));
        }

        let host = match authority.rsplit_once(':') {
            Some((host, "443")) => host,
            Some(_) => return Err(AudienceConfigError::NonDefaultPort(raw.to_owned())),
            None => authority,
        };

        if !is_valid_host(host) {
            return Err(AudienceConfigError::MalformedHost(raw.to_owned()));
        }

        Ok(CanonicalAudience(format!(
            "https://{}",
            host.to_ascii_lowercase()
        )))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CanonicalAudience {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Serializes to the canonical string. There is intentionally **no**
/// `Deserialize`: reading one of these straight out of a config file would
/// bypass [`CanonicalAudience::parse`]. Config carries a `String` and calls
/// `parse` explicitly.
impl Serialize for CanonicalAudience {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

/// The JWT `aud` claim, which RFC 7519 §4.1.3 allows to be either a single
/// string or an array of strings. Both spellings are parsed; neither is
/// normalized.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum AudienceClaim {
    One(String),
    Many(Vec<String>),
}

impl AudienceClaim {
    fn as_slice(&self) -> &[String] {
        match self {
            AudienceClaim::One(value) => std::slice::from_ref(value),
            AudienceClaim::Many(values) => values,
        }
    }
}

/// Why a token's audience was refused.
///
/// Each variant is a separate counter. `ApiserverAudience` in particular
/// should alert: legitimate traffic never produces it.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AudienceRejection {
    #[error("token has no aud claim")]
    Missing,
    #[error("token carries the apiserver audience {got:?}: a default ServiceAccount token was replayed at the broker (CVE-2025-32963 class)")]
    ApiserverAudience { got: String },
    #[error("token is valid for {count} audiences; a token for the broker must be valid for the broker alone")]
    MultipleAudiences { count: usize },
    #[error("token audience {got:?} differs from {expected:?} only by normalization; the broker compares byte-exact and the pod spec must carry the canonical form")]
    NotCanonical { got: String, expected: String },
    #[error("token audience {got:?} is not {expected:?}")]
    Mismatch { got: String, expected: String },
    #[error("TokenReview did not authenticate the token")]
    NotAuthenticated,
    #[error("TokenReview returned no validated audiences: the apiserver did not confirm this token is for {expected:?} (CVE-2025-32963 class)")]
    NoValidatedAudiences { expected: String },
    #[error("TokenReview validated audiences {got:?}, which is not exactly [{expected:?}]")]
    UnexpectedValidatedAudiences { got: Vec<String>, expected: String },
}

impl AudienceRejection {
    /// Stable, low-cardinality label for metrics. Never includes the
    /// attacker-controlled value.
    pub fn reason(&self) -> &'static str {
        match self {
            AudienceRejection::Missing => "missing",
            AudienceRejection::ApiserverAudience { .. } => "apiserver_audience",
            AudienceRejection::MultipleAudiences { .. } => "multiple_audiences",
            AudienceRejection::NotCanonical { .. } => "not_canonical",
            AudienceRejection::Mismatch { .. } => "mismatch",
            AudienceRejection::NotAuthenticated => "not_authenticated",
            AudienceRejection::NoValidatedAudiences { .. } => "no_validated_audiences",
            AudienceRejection::UnexpectedValidatedAudiences { .. } => {
                "unexpected_validated_audiences"
            }
        }
    }

    /// Whether this rejection indicates someone is probing us rather than
    /// mis-deploying. Drives alert routing.
    pub fn is_attack_signal(&self) -> bool {
        matches!(
            self,
            AudienceRejection::ApiserverAudience { .. }
                | AudienceRejection::NoValidatedAudiences { .. }
                | AudienceRejection::UnexpectedValidatedAudiences { .. }
        )
    }
}

/// The audience policy: our canonical audience plus the apiserver audiences we
/// name explicitly so their replay is reported as such.
#[derive(Clone, Debug)]
pub struct AudienceValidator {
    expected: CanonicalAudience,
    apiserver_audiences: BTreeSet<String>,
}

impl AudienceValidator {
    pub fn new(expected: CanonicalAudience) -> Self {
        AudienceValidator {
            expected,
            apiserver_audiences: DEFAULT_APISERVER_AUDIENCES
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
        }
    }

    /// Add cluster-specific apiserver audiences (an EKS OIDC issuer URL, a
    /// custom `--api-audiences`). Purely for classification: these are already
    /// refused by the byte-exact comparison.
    pub fn with_apiserver_audiences<I, S>(mut self, audiences: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.apiserver_audiences
            .extend(audiences.into_iter().map(Into::into));
        self
    }

    pub fn expected(&self) -> &CanonicalAudience {
        &self.expected
    }

    /// Validate a token's `aud` claim.
    ///
    /// The accept path is a single byte-exact comparison against the
    /// configured audience. Everything else in this function runs only after
    /// that comparison has already failed, and exists to say *why*.
    pub fn validate_claim(&self, claim: Option<&AudienceClaim>) -> Result<(), AudienceRejection> {
        let Some(claim) = claim else {
            return Err(AudienceRejection::Missing);
        };
        let audiences = claim.as_slice();

        match audiences {
            [] => Err(AudienceRejection::Missing),
            [only] if only == self.expected.as_str() => Ok(()),
            [only] => Err(self.classify(only)),
            many => {
                // Report the apiserver audience if it is in there, since that
                // is the more actionable finding, then fall back to the count.
                if let Some(apiserver) = many.iter().find(|a| self.apiserver_audiences.contains(*a))
                {
                    return Err(AudienceRejection::ApiserverAudience {
                        got: apiserver.clone(),
                    });
                }
                Err(AudienceRejection::MultipleAudiences { count: many.len() })
            }
        }
    }

    /// Explain a single-audience mismatch. Reached only from the `Err` path of
    /// [`Self::validate_claim`], so nothing it computes can widen acceptance.
    fn classify(&self, got: &str) -> AudienceRejection {
        if self.apiserver_audiences.contains(got) {
            return AudienceRejection::ApiserverAudience {
                got: got.to_owned(),
            };
        }
        // Parsing attacker input *here* is safe and useful: the answer only
        // ever selects between two rejections.
        if CanonicalAudience::parse(got).is_ok_and(|c| c == self.expected) {
            return AudienceRejection::NotCanonical {
                got: got.to_owned(),
                expected: self.expected.0.clone(),
            };
        }
        AudienceRejection::Mismatch {
            got: got.to_owned(),
            expected: self.expected.0.clone(),
        }
    }

    /// Validate a `TokenReview` response.
    ///
    /// `status.audiences` is the apiserver's statement of *which of the
    /// audiences we asked about* this token is actually valid for. Checking
    /// `status.authenticated` alone is precisely the CVE: a default token
    /// authenticates perfectly well — it is simply not for us. An empty or
    /// absent `audiences` means the apiserver declined to confirm our
    /// audience, and must be a rejection.
    ///
    /// The caller is responsible for having set `spec.audiences` to
    /// `[expected]`; [`token_review_spec_audiences`] is the only supported way
    /// to build it.
    pub fn validate_token_review(
        &self,
        authenticated: Option<bool>,
        validated_audiences: Option<&[String]>,
    ) -> Result<(), AudienceRejection> {
        if authenticated != Some(true) {
            return Err(AudienceRejection::NotAuthenticated);
        }
        match validated_audiences {
            None | Some([]) => Err(AudienceRejection::NoValidatedAudiences {
                expected: self.expected.0.clone(),
            }),
            Some([only]) if only == self.expected.as_str() => Ok(()),
            Some(other) => Err(AudienceRejection::UnexpectedValidatedAudiences {
                got: other.to_vec(),
                expected: self.expected.0.clone(),
            }),
        }
    }

    /// The `spec.audiences` to send with a `TokenReview`. Sending this is not
    /// optional: a `TokenReview` with no audiences validates against the
    /// apiserver's own audience, which is the bug.
    pub fn token_review_spec_audiences(&self) -> Vec<String> {
        vec![self.expected.0.clone()]
    }
}

/// The `serviceAccountToken` projected-volume source a mapped workload needs.
///
/// This is the generator half of ADR-9's "normalization enforced in pod-spec
/// generator AND validator". It emits `audience` from the same
/// [`CanonicalAudience`] the validator compares against, so the two cannot
/// drift; the paired test below is what holds that property down.
pub fn projected_token_volume_source(
    audience: &CanonicalAudience,
    expiration_seconds: i64,
    path: &str,
) -> serde_json::Value {
    serde_json::json!({
        "serviceAccountToken": {
            "audience": audience.as_str(),
            "expirationSeconds": expiration_seconds,
            "path": path,
        }
    })
}

fn strip_scheme_ci<'a>(raw: &'a str, scheme: &str) -> Option<&'a str> {
    (raw.len() >= scheme.len() && raw[..scheme.len()].eq_ignore_ascii_case(scheme))
        .then(|| &raw[scheme.len()..])
}

/// Hostname check: ASCII DNS labels only.
///
/// Rejecting non-ASCII rather than punycoding it is intentional — an
/// internationalized host has more than one valid encoding, and "byte-exact"
/// stops meaning anything the moment two spellings both work.
fn is_valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host.starts_with('.')
        && !host.ends_with('.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const BROKER: &str = "https://cognito-broker.example.com";

    fn validator() -> AudienceValidator {
        AudienceValidator::new(CanonicalAudience::parse(BROKER).unwrap())
    }

    #[test]
    fn parse_normalizes_the_documented_variations() {
        for variant in [
            "https://cognito-broker.example.com",
            "https://cognito-broker.example.com/",
            "https://COGNITO-BROKER.EXAMPLE.COM",
            "HTTPS://Cognito-Broker.Example.Com/",
            "https://cognito-broker.example.com:443",
            "  https://cognito-broker.example.com  ",
        ] {
            assert_eq!(
                CanonicalAudience::parse(variant).unwrap().as_str(),
                BROKER,
                "{variant:?} should normalize to the canonical form"
            );
        }
    }

    #[test]
    fn parse_rejects_shapes_that_are_not_a_broker_url() {
        use AudienceConfigError::*;
        /// An input paired with the variant it should produce.
        type Case = (&'static str, fn(&AudienceConfigError) -> bool);
        let cases: &[Case] = &[
            ("", |e| matches!(e, Empty)),
            ("http://cognito-broker.example.com", |e| {
                matches!(e, NotHttps(_))
            }),
            ("cognito-broker.example.com", |e| matches!(e, NotHttps(_))),
            ("https://user@cognito-broker.example.com", |e| {
                matches!(e, HasUserinfo(_))
            }),
            ("https://cognito-broker.example.com/token", |e| {
                matches!(e, HasPathQueryOrFragment(_))
            }),
            ("https://cognito-broker.example.com?a=1", |e| {
                matches!(e, HasPathQueryOrFragment(_))
            }),
            ("https://cognito-broker.example.com:8443", |e| {
                matches!(e, NonDefaultPort(_))
            }),
            ("https://", |e| matches!(e, MalformedHost(_))),
            ("https://-bad.example.com", |e| {
                matches!(e, MalformedHost(_))
            }),
            ("https://cognito-bröker.example.com", |e| {
                matches!(e, MalformedHost(_))
            }),
        ];
        for (input, matches_variant) in cases {
            let err = CanonicalAudience::parse(input)
                .expect_err(&format!("{input:?} should be rejected"));
            assert!(
                matches_variant(&err),
                "{input:?} produced unexpected {err:?}"
            );
        }
    }

    // ---- The rule that makes the whole thing work ------------------------

    #[test]
    fn incoming_claims_are_compared_byte_exact_and_never_normalized() {
        let validator = validator();
        // Each of these *parses* to the canonical audience. None of them is
        // accepted, because the claim path does not parse.
        for probe in [
            "https://cognito-broker.example.com/",
            "https://COGNITO-BROKER.EXAMPLE.COM",
            "HTTPS://cognito-broker.example.com",
            "https://cognito-broker.example.com:443",
        ] {
            assert_eq!(
                CanonicalAudience::parse(probe).unwrap().as_str(),
                BROKER,
                "precondition: {probe:?} normalizes to the canonical audience"
            );
            let rejection = validator
                .validate_claim(Some(&AudienceClaim::One(probe.into())))
                .expect_err(&format!("{probe:?} must not be accepted"));
            assert_eq!(rejection.reason(), "not_canonical");
        }
    }

    #[test]
    fn the_canonical_audience_is_accepted_as_string_and_as_array() {
        let validator = validator();
        assert!(validator
            .validate_claim(Some(&AudienceClaim::One(BROKER.into())))
            .is_ok());
        assert!(validator
            .validate_claim(Some(&AudienceClaim::Many(vec![BROKER.into()])))
            .is_ok());
    }

    #[test]
    fn a_token_valid_for_us_and_someone_else_is_refused() {
        let validator = validator();
        let rejection = validator
            .validate_claim(Some(&AudienceClaim::Many(vec![
                BROKER.into(),
                "https://other.example.com".into(),
            ])))
            .unwrap_err();
        assert_eq!(rejection, AudienceRejection::MultipleAudiences { count: 2 });
    }

    #[test]
    fn a_missing_or_empty_aud_is_refused() {
        let validator = validator();
        assert_eq!(
            validator.validate_claim(None),
            Err(AudienceRejection::Missing)
        );
        assert_eq!(
            validator.validate_claim(Some(&AudienceClaim::Many(vec![]))),
            Err(AudienceRejection::Missing)
        );
    }

    #[test]
    fn apiserver_audiences_get_their_own_alertable_reason() {
        let validator = validator();
        for apiserver in DEFAULT_APISERVER_AUDIENCES {
            let rejection = validator
                .validate_claim(Some(&AudienceClaim::One((*apiserver).into())))
                .unwrap_err();
            assert_eq!(rejection.reason(), "apiserver_audience");
            assert!(rejection.is_attack_signal());
        }
    }

    #[test]
    fn cluster_specific_apiserver_audiences_can_be_registered() {
        let eks = "https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE";
        let validator = validator().with_apiserver_audiences([eks]);
        let rejection = validator
            .validate_claim(Some(&AudienceClaim::One(eks.into())))
            .unwrap_err();
        assert_eq!(rejection.reason(), "apiserver_audience");
    }

    #[test]
    fn an_apiserver_audience_hidden_among_others_is_still_named() {
        let validator = validator();
        let rejection = validator
            .validate_claim(Some(&AudienceClaim::Many(vec![
                "https://kubernetes.default.svc".into(),
                BROKER.into(),
            ])))
            .unwrap_err();
        assert_eq!(rejection.reason(), "apiserver_audience");
    }

    #[test]
    fn an_unrelated_audience_is_a_plain_mismatch_not_an_alert() {
        let validator = validator();
        let rejection = validator
            .validate_claim(Some(&AudienceClaim::One(
                "https://vault.example.com".into(),
            )))
            .unwrap_err();
        assert_eq!(rejection.reason(), "mismatch");
        assert!(!rejection.is_attack_signal());
    }

    // ---- TokenReview ------------------------------------------------------

    #[test]
    fn token_review_requires_the_apiserver_to_confirm_our_audience() {
        let validator = validator();
        assert!(validator
            .validate_token_review(Some(true), Some(&[BROKER.to_owned()]))
            .is_ok());
    }

    #[test]
    fn authenticated_with_no_validated_audiences_is_the_cve() {
        // A default ServiceAccount token authenticates perfectly well. The
        // apiserver simply returns no audiences, because none of the ones we
        // asked about apply. Trusting `authenticated` alone is the bug.
        let validator = validator();
        for audiences in [None, Some(&[][..])] {
            let rejection = validator
                .validate_token_review(Some(true), audiences)
                .unwrap_err();
            assert_eq!(rejection.reason(), "no_validated_audiences");
            assert!(rejection.is_attack_signal());
        }
    }

    #[test]
    fn token_review_validated_audiences_must_match_byte_exact() {
        let validator = validator();
        let rejection = validator
            .validate_token_review(
                Some(true),
                Some(&["https://cognito-broker.example.com/".to_owned()]),
            )
            .unwrap_err();
        assert_eq!(rejection.reason(), "unexpected_validated_audiences");
    }

    #[test]
    fn unauthenticated_is_refused_before_audiences_are_considered() {
        let validator = validator();
        for authenticated in [None, Some(false)] {
            assert_eq!(
                validator.validate_token_review(authenticated, Some(&[BROKER.to_owned()])),
                Err(AudienceRejection::NotAuthenticated)
            );
        }
    }

    #[test]
    fn token_review_spec_always_carries_exactly_our_audience() {
        assert_eq!(
            validator().token_review_spec_audiences(),
            vec![BROKER.to_owned()]
        );
    }

    // ---- Generator/validator pairing (ADR-9) ------------------------------

    #[test]
    fn generated_pod_spec_audience_is_accepted_by_the_validator() {
        // The pairing ADR-9 requires: whatever the generator writes into a pod
        // spec is, byte for byte, what the validator accepts. If either side
        // changes its normalization, this fails.
        let audience = CanonicalAudience::parse("HTTPS://Cognito-Broker.Example.Com/").unwrap();
        let volume = projected_token_volume_source(&audience, 3600, "broker-token");

        let emitted = volume["serviceAccountToken"]["audience"].as_str().unwrap();
        let validator = AudienceValidator::new(CanonicalAudience::parse(BROKER).unwrap());
        assert!(
            validator
                .validate_claim(Some(&AudienceClaim::One(emitted.to_owned())))
                .is_ok(),
            "generator emitted {emitted:?}, which the validator refuses"
        );
    }

    #[test]
    fn parse_is_idempotent() {
        // Required for the generator/validator pairing to hold under repeated
        // config round-trips.
        let once = CanonicalAudience::parse("HTTPS://Cognito-Broker.Example.Com:443/").unwrap();
        let twice = CanonicalAudience::parse(once.as_str()).unwrap();
        assert_eq!(once, twice);
    }
}
