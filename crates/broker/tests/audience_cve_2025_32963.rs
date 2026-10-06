//! Regression tests for the CVE-2025-32963 class: audience confusion in a
//! ServiceAccount-token exchange service.
//!
//! # The original
//!
//! MinIO Operator's STS endpoint accepted a projected ServiceAccount token and
//! exchanged it for credentials, but validated the token without binding it to
//! the STS service's own audience. Because *every* pod in a cluster mounts a
//! default ServiceAccount token, any pod could present its own default token
//! and be issued credentials for whichever identity it named. The token was
//! genuine and the apiserver authenticated it happily — it was simply minted
//! for the apiserver, not for the exchange service.
//!
//! We are structurally the same component, so the same mistake is available to
//! us in the same two places: the `aud` claim check, and the `TokenReview`
//! call. Each test below is one way to make it.
//!
//! Every test here is written from the attacker's side: it constructs the
//! thing an attacker would send and asserts we refuse it. A test that starts
//! passing for the wrong reason (say, because the validator began normalizing
//! incoming claims) is caught by the paired positive assertions — each test
//! also proves the legitimate token still works.

use recognito_broker::{
    AudienceClaim, AudienceRejection, AudienceValidator, CanonicalAudience, ErrorCode,
    ExchangeError,
};

const BROKER_AUDIENCE: &str = "https://cognito-broker.example.com";

/// The audience a default projected ServiceAccount token carries in-cluster.
const DEFAULT_SA_TOKEN_AUDIENCE: &str = "https://kubernetes.default.svc";

fn broker() -> AudienceValidator {
    AudienceValidator::new(CanonicalAudience::parse(BROKER_AUDIENCE).unwrap())
}

/// The token a correctly-configured workload projects for the broker.
fn broker_bound_token() -> AudienceClaim {
    AudienceClaim::Many(vec![BROKER_AUDIENCE.to_owned()])
}

/// The token every pod gets for free at
/// `/var/run/secrets/kubernetes.io/serviceaccount/token`.
fn default_service_account_token() -> AudienceClaim {
    AudienceClaim::Many(vec![DEFAULT_SA_TOKEN_AUDIENCE.to_owned()])
}

#[test]
fn default_apiserver_audience_token_from_a_mapped_sa_is_rejected() {
    // The headline case from CLAUDE.md invariant 2. The caller here is the
    // *legitimately mapped* ServiceAccount — it is authorized to get tokens.
    // It still may not use its default token to do so, because accepting that
    // token means accepting one from every other pod too.
    let broker = broker();

    let rejection = broker
        .validate_claim(Some(&default_service_account_token()))
        .expect_err("a default ServiceAccount token must never be accepted");

    assert_eq!(rejection.reason(), "apiserver_audience");
    assert!(
        rejection.is_attack_signal(),
        "arrival of a default SA token should page, not just count"
    );

    // ...and the correctly-projected token from the same workload still works.
    assert!(broker.validate_claim(Some(&broker_bound_token())).is_ok());
}

#[test]
fn token_review_reporting_authenticated_without_audiences_is_rejected() {
    // The second, subtler place to make the mistake. A default SA token
    // presented to `TokenReview` comes back `authenticated: true` — it is a
    // real token for a real identity. What it does *not* come back with is our
    // audience in `status.audiences`, because we asked about ours and the
    // token does not carry it. Checking only `authenticated` is the CVE.
    let broker = broker();

    let rejection = broker
        .validate_token_review(Some(true), Some(&[]))
        .expect_err("authenticated-but-no-audiences must be refused");

    assert_eq!(rejection.reason(), "no_validated_audiences");
    assert!(rejection.is_attack_signal());

    // The same call for a properly-bound token returns our audience, and passes.
    assert!(
        broker
            .validate_token_review(Some(true), Some(&[BROKER_AUDIENCE.to_owned()]))
            .is_ok()
    );
}

#[test]
fn token_review_omitting_the_audiences_field_entirely_is_rejected() {
    // An older or non-conformant apiserver may omit `status.audiences` rather
    // than send an empty list. Absent must mean "not confirmed", never
    // "confirmed by default".
    let rejection = broker()
        .validate_token_review(Some(true), None)
        .expect_err("absent status.audiences must be refused");
    assert_eq!(rejection.reason(), "no_validated_audiences");
}

#[test]
fn the_token_review_request_always_names_the_broker_audience() {
    // The check above only works if we asked the right question. A TokenReview
    // sent without `spec.audiences` is validated against the apiserver's own
    // audience, which reintroduces the vulnerability at the request side.
    assert_eq!(
        broker().token_review_spec_audiences(),
        vec![BROKER_AUDIENCE.to_owned()],
        "TokenReview must request exactly the broker audience"
    );
}

#[test]
fn a_token_for_the_broker_and_the_apiserver_at_once_is_rejected() {
    // A workload can project a token with several audiences. One that is valid
    // at both the apiserver and the broker is replayable from anything that
    // can read it as an apiserver token.
    let rejection = broker()
        .validate_claim(Some(&AudienceClaim::Many(vec![
            DEFAULT_SA_TOKEN_AUDIENCE.to_owned(),
            BROKER_AUDIENCE.to_owned(),
        ])))
        .expect_err("a dual-audience token must be refused");
    assert_eq!(rejection.reason(), "apiserver_audience");
}

#[test]
fn a_token_for_another_relying_party_is_rejected() {
    // The generalization: the broker is not a clearing house for tokens minted
    // for other services. Vault, Consul, and a sibling broker in another
    // environment are all "someone else".
    let broker = broker();
    for other in [
        "https://vault.example.com",
        "https://cognito-broker.staging.example.com",
        "https://cognito-broker.example.org",
        "sts.amazonaws.com",
    ] {
        let rejection = broker
            .validate_claim(Some(&AudienceClaim::One(other.to_owned())))
            .unwrap_err();
        assert_eq!(
            rejection.reason(),
            "mismatch",
            "{other:?} should be a plain mismatch"
        );
    }
}

#[test]
fn near_miss_spellings_of_the_broker_audience_are_rejected() {
    // Byte-exact means byte-exact. Each of these canonicalizes *to* our
    // audience, and each is refused, because the comparison happens before any
    // normalization could be applied to attacker-controlled input. If someone
    // ever "helpfully" normalizes the incoming claim, this test fails.
    let broker = broker();
    for near_miss in [
        "https://cognito-broker.example.com/",
        "https://COGNITO-BROKER.EXAMPLE.COM",
        "HTTPS://cognito-broker.example.com",
        "https://cognito-broker.example.com:443",
    ] {
        let rejection = broker
            .validate_claim(Some(&AudienceClaim::One(near_miss.to_owned())))
            .unwrap_err();
        assert_eq!(
            rejection.reason(),
            "not_canonical",
            "{near_miss:?} must be refused, not normalized into acceptance"
        );
    }
}

#[test]
fn a_token_with_no_audience_is_rejected() {
    let broker = broker();
    assert_eq!(broker.validate_claim(None), Err(AudienceRejection::Missing));
    assert_eq!(
        broker.validate_claim(Some(&AudienceClaim::Many(vec![]))),
        Err(AudienceRejection::Missing)
    );
}

#[test]
fn a_replayed_default_token_is_answered_with_403_invalid_grant() {
    // CLAUDE.md invariant 2 specifies 403 for this case. The status is decided
    // by the RFC 8693 error mapping in ADR-13, so assert it end to end rather
    // than trusting the two halves to agree.
    let rejection = broker()
        .validate_claim(Some(&default_service_account_token()))
        .unwrap_err();

    let error = ExchangeError::from(rejection);
    assert_eq!(error.status(), 403);
    assert_eq!(error.code, ErrorCode::InvalidGrant);
}

#[test]
fn a_rejection_response_does_not_echo_the_audience_the_caller_sent() {
    // The error body is the one part of a refused request the caller
    // definitely sees. It must not become a reflection channel for whatever
    // string they put in `aud`.
    let hostile = "https://evil.example.com/<script>alert(1)</script>";
    let rejection = broker()
        .validate_claim(Some(&AudienceClaim::One(hostile.to_owned())))
        .unwrap_err();

    let body = serde_json::to_string(&ExchangeError::from(rejection).body()).unwrap();
    assert!(
        !body.contains("evil.example.com"),
        "response echoed caller input: {body}"
    );
    assert!(
        body.contains("mismatch"),
        "response should carry the stable reason"
    );
}

#[test]
fn an_unauthenticated_token_review_is_rejected_regardless_of_audiences() {
    // Belt and braces: even if a malformed or hostile apiserver response
    // carried our audience, `authenticated != true` ends it.
    assert_eq!(
        broker().validate_token_review(Some(false), Some(&[BROKER_AUDIENCE.to_owned()])),
        Err(AudienceRejection::NotAuthenticated)
    );
}
