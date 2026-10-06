//! Regression tests for the SigV4 door (ADR-15): one test per way a
//! presigned-`GetCallerIdentity` verifier has been, or could be, fooled.
//!
//! The pattern follows `audience_cve_2025_32963.rs`: every test builds the
//! request an attacker would send and asserts we refuse it, and every test
//! also proves that the legitimate request next to it still passes, so a test
//! cannot start passing because the validator started refusing everything.
//!
//! Signatures are not computed here. The broker never verifies them — STS
//! does, over a header value *we* supply — so what these tests pin down is
//! everything the broker must refuse *before* forwarding, and everything it
//! must refuse in STS's answer *after*.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use recognito_broker::sigv4::{AUDIENCE_HEADER, MAX_PRESIGN_EXPIRES_SECS};
use recognito_broker::{
    CanonicalAudience, ErrorCode, ExchangeError, SigV4Rejection, SigV4Validator, StsEndpoint,
    StsError,
};

const BROKER_AUDIENCE: &str = "https://cognito-broker.example.com";
const TRUSTED_ACCOUNT: &str = "111122223333";
const STS_HOST: &str = "sts.us-east-1.amazonaws.com";

/// 2026-10-05T12:00:00Z, the `X-Amz-Date` of every URL below.
const SIGNED_AT: u64 = 1_791_201_600;

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(SIGNED_AT + 30)
}

fn broker() -> SigV4Validator {
    SigV4Validator::new(
        CanonicalAudience::parse(BROKER_AUDIENCE).unwrap(),
        vec![StsEndpoint::regional("us-east-1").unwrap()],
        [TRUSTED_ACCOUNT],
    )
    .unwrap()
}

/// The query of a correctly presigned, broker-bound URL, in the order and
/// encoding the AWS SDKs emit.
fn params() -> Vec<(String, String)> {
    [
        ("Action", "GetCallerIdentity"),
        ("Version", "2011-06-15"),
        ("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
        (
            "X-Amz-Credential",
            "ASIAEXAMPLEKEYID%2F20261005%2Fus-east-1%2Fsts%2Faws4_request",
        ),
        ("X-Amz-Date", "20261005T120000Z"),
        ("X-Amz-Expires", "60"),
        ("X-Amz-SignedHeaders", "host%3Bx-recognito-audience"),
        (
            "X-Amz-Security-Token",
            "IQoJb3JpZ2luX2VjEXAMPLE%2Bsession%2Ftoken%3D",
        ),
        (
            "X-Amz-Signature",
            "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7",
        ),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect()
}

fn url_with(host: &str, params: &[(String, String)]) -> String {
    let query: Vec<String> = params.iter().map(|(k, v)| format!("{k}={v}")).collect();
    format!("https://{host}/?{}", query.join("&"))
}

fn legit_url() -> String {
    url_with(STS_HOST, &params())
}

/// The legit URL with one parameter's value replaced.
fn with_param(key: &str, value: &str) -> String {
    let mut p = params();
    p.iter_mut().find(|(k, _)| k == key).unwrap().1 = value.to_owned();
    url_with(STS_HOST, &p)
}

fn reject(url: &str) -> SigV4Rejection {
    broker()
        .validate_presigned(url, now())
        .expect_err("this URL must be refused")
}

fn sts_ok(arn: &str, account: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "GetCallerIdentityResponse": {
            "GetCallerIdentityResult": {
                "Account": account,
                "Arn": arn,
                "UserId": "AROAEXAMPLEROLEID:i-0abc123",
            },
            "ResponseMetadata": { "RequestId": "c6104cbe-af31-11e0-8154-cbc7ccf896c7" },
        }
    }))
    .unwrap()
}

fn legit_sts_answer() -> Vec<u8> {
    sts_ok(
        "arn:aws:sts::111122223333:assumed-role/payments/i-0abc123",
        TRUSTED_ACCOUNT,
    )
}

#[test]
fn the_legitimate_request_passes_end_to_end() {
    let broker = broker();
    let presigned = broker.validate_presigned(&legit_url(), now()).unwrap();
    assert_eq!(presigned.access_key_id, "ASIAEXAMPLEKEYID");
    assert_eq!(presigned.expires_at, SIGNED_AT + 60);

    let forward = broker.forward_request(&presigned);
    assert_eq!(forward.method, "GET");
    assert_eq!(
        forward.url,
        legit_url(),
        "the URL must be forwarded verbatim"
    );

    let caller = broker
        .validate_sts_response(200, &legit_sts_answer())
        .unwrap();
    assert_eq!(caller.identity.role_name, "payments");
    assert_eq!(caller.identity.account_id, TRUSTED_ACCOUNT);
}

// ---- Audience binding: the CVE-2025-32963 analogue -------------------------

#[test]
fn the_forwarded_audience_is_ours_and_never_the_callers() {
    // This is the binding. STS checks the caller's signature over the header
    // value we send; a URL signed for any other audience fails at STS.
    let broker = broker();
    let presigned = broker.validate_presigned(&legit_url(), now()).unwrap();
    let forward = broker.forward_request(&presigned);
    let audience: Vec<_> = forward
        .headers
        .iter()
        .filter(|(name, _)| *name == AUDIENCE_HEADER)
        .collect();
    assert_eq!(audience.len(), 1);
    assert_eq!(
        audience[0].1, BROKER_AUDIENCE,
        "must be byte-exact canonical"
    );
}

#[test]
fn a_url_that_does_not_sign_the_audience_header_is_rejected() {
    // An unbound URL proves identity to anyone. Accepting it means accepting
    // URLs presigned for every other service that uses this trick.
    let rejection = reject(&with_param("X-Amz-SignedHeaders", "host"));
    assert_eq!(rejection, SigV4Rejection::AudienceNotSigned);
    assert!(broker().validate_presigned(&legit_url(), now()).is_ok());
}

#[test]
fn an_eks_cluster_token_replayed_at_the_broker_is_rejected() {
    // `aws eks get-token` output, i.e. the SigV4 equivalent of a default
    // apiserver-audience ServiceAccount token.
    let rejection = reject(&with_param("X-Amz-SignedHeaders", "host%3Bx-k8s-aws-id"));
    assert_eq!(rejection.reason(), "foreign_verifier");
    assert!(rejection.is_attack_signal());
}

#[test]
fn a_vault_iam_login_replayed_at_the_broker_is_rejected() {
    let rejection = reject(&with_param(
        "X-Amz-SignedHeaders",
        "host%3Bx-vault-aws-iam-server-id",
    ));
    assert_eq!(rejection.reason(), "foreign_verifier");
}

#[test]
fn a_url_bound_to_us_and_to_another_verifier_is_rejected() {
    // Same rule as a JWT with two audiences: valid here and elsewhere means
    // replayable here from elsewhere.
    let rejection = reject(&with_param(
        "X-Amz-SignedHeaders",
        "host%3Bx-k8s-aws-id%3Bx-recognito-audience",
    ));
    assert_eq!(rejection.reason(), "foreign_verifier");
}

#[test]
fn extra_signed_headers_are_rejected_before_spending_an_sts_call() {
    // We forward exactly two headers; a URL that signed a third can never
    // verify, and accepting it would make STS do our input validation.
    let rejection = reject(&with_param(
        "X-Amz-SignedHeaders",
        "host%3Bx-amz-foo%3Bx-recognito-audience",
    ));
    assert_eq!(rejection, SigV4Rejection::UnexpectedSignedHeaders);
}

// ---- We choose the host (SSRF / forged STS) -------------------------------

#[test]
fn a_caller_chosen_host_is_never_forwarded_to() {
    // If we forwarded here, the attacker's server would answer
    // GetCallerIdentity with any ARN it liked.
    for host in [
        "evil.example.com",
        "sts.us-east-1.amazonaws.com.evil.example.com",
        "sts.us-east-1.amazonaws.com@evil.example.com",
        "evil.example.com#@sts.us-east-1.amazonaws.com",
        "sts.us-east-1.amazonaws.com:8443",
        "STS.US-EAST-1.AMAZONAWS.COM",
        "sts.us-east-1.amazonaws.com.",
        "sts.amazonaws.com",
        "sts.eu-west-1.amazonaws.com",
        "169.254.169.254",
    ] {
        let rejection = reject(&url_with(host, &params()));
        assert_eq!(
            rejection,
            SigV4Rejection::UntrustedHost,
            "{host:?} must not be forwarded to"
        );
        assert!(rejection.is_attack_signal());
    }
}

#[test]
fn only_https_to_the_root_path_is_accepted() {
    let legit = legit_url();
    for url in [
        legit.replacen("https://", "http://", 1),
        legit.replacen("/?", "/sts/?", 1),
        legit.replacen("/?", "?", 1),
        format!("{legit}#fragment"),
    ] {
        assert!(
            broker().validate_presigned(&url, now()).is_err(),
            "{url:?} must be refused"
        );
    }
}

#[test]
fn the_credential_region_must_match_the_endpoint() {
    let rejection = reject(&with_param(
        "X-Amz-Credential",
        "ASIAEXAMPLEKEYID%2F20261005%2Feu-west-1%2Fsts%2Faws4_request",
    ));
    assert_eq!(rejection, SigV4Rejection::CredentialScope);
}

#[test]
fn a_credential_scoped_to_another_service_is_rejected() {
    let rejection = reject(&with_param(
        "X-Amz-Credential",
        "ASIAEXAMPLEKEYID%2F20261005%2Fus-east-1%2Fs3%2Faws4_request",
    ));
    assert_eq!(rejection, SigV4Rejection::CredentialScope);
}

// ---- We choose the action (CVE-2020-16250 class) --------------------------

#[test]
fn any_action_other_than_get_caller_identity_is_rejected() {
    // Vault's IAM auth forwarded caller-chosen STS actions and then parsed the
    // response leniently enough to find an identity in it.
    for action in ["AssumeRole", "GetSessionToken", "getcalleridentity"] {
        let rejection = reject(&with_param("Action", action));
        assert_eq!(rejection, SigV4Rejection::WrongAction, "{action}");
        assert!(rejection.is_attack_signal());
    }
}

#[test]
fn a_response_that_is_not_a_get_caller_identity_result_is_never_read_as_one() {
    let broker = broker();
    for body in [
        // XML: what STS returns without Accept: application/json, and what a
        // lenient parser could be tricked into reading.
        br#"<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:sts::111122223333:assumed-role/payments/x</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>"#.to_vec(),
        // The right fields at the wrong depth.
        serde_json::to_vec(&serde_json::json!({
            "AssumeRoleResponse": { "Arn": "arn:aws:sts::111122223333:assumed-role/payments/x" }
        })).unwrap(),
        // Duplicate keys: which Arn would we have read?
        br#"{"GetCallerIdentityResponse":{"GetCallerIdentityResult":{"Account":"111122223333","Arn":"arn:aws:sts::999999999999:assumed-role/x/y","Arn":"arn:aws:sts::111122223333:assumed-role/payments/x","UserId":"u"}}}"#.to_vec(),
        b"".to_vec(),
    ] {
        let err = broker.validate_sts_response(200, &body).unwrap_err();
        assert!(
            matches!(err, StsError::InvalidResponse(_)),
            "body {:?} produced {err:?}",
            String::from_utf8_lossy(&body)
        );
        assert_eq!(ExchangeError::from(err).code, ErrorCode::ServerError);
    }
    assert!(
        broker
            .validate_sts_response(200, &legit_sts_answer())
            .is_ok()
    );
}

#[test]
fn an_account_field_disagreeing_with_the_arn_is_not_trusted() {
    let err = broker()
        .validate_sts_response(
            200,
            &sts_ok(
                "arn:aws:sts::999999999999:assumed-role/payments/x",
                TRUSTED_ACCOUNT,
            ),
        )
        .unwrap_err();
    assert!(matches!(err, StsError::InvalidResponse(_)));
}

#[test]
fn redirects_from_sts_are_not_followed() {
    let err = broker().validate_sts_response(302, b"").unwrap_err();
    assert!(matches!(err, StsError::InvalidResponse(_)));
}

// ---- One spelling per parameter (CVE-2022-2385 class) ---------------------

#[test]
fn a_duplicated_parameter_is_rejected_not_resolved() {
    // If we read the first copy and STS reads the last (or vice versa), the
    // checks above are checking a request STS never sees.
    for (key, value) in [
        ("X-Amz-SignedHeaders", "host"),
        (
            "X-Amz-Credential",
            "AKIAOTHER%2F20261005%2Fus-east-1%2Fsts%2Faws4_request",
        ),
        ("Action", "AssumeRole"),
    ] {
        let mut p = params();
        p.push((key.to_owned(), value.to_owned()));
        let rejection = reject(&url_with(STS_HOST, &p));
        assert_eq!(rejection.reason(), "duplicate_parameter", "{key}");
        assert!(rejection.is_attack_signal());
    }
}

#[test]
fn case_variant_and_percent_encoded_keys_are_rejected_not_folded() {
    // Each of these might be the same parameter to STS. None of them is the
    // same parameter to a byte-exact allowlist, so none of them gets in.
    for key in [
        "x-amz-signedheaders",
        "X-AMZ-SIGNEDHEADERS",
        "X%2DAmz%2DSignedHeaders",
        "action",
    ] {
        let mut p = params();
        p.push((key.to_owned(), "host".to_owned()));
        let rejection = reject(&url_with(STS_HOST, &p));
        assert_eq!(rejection.reason(), "unknown_parameter", "{key}");
    }
}

#[test]
fn values_with_characters_parsers_disagree_on_are_rejected() {
    // '+' is a space to a form decoder and a plus to a SigV4 one; a raw ';'
    // is a separator to some query parsers.
    for value in ["host;x-recognito-audience", "host+x-recognito-audience"] {
        let rejection = reject(&with_param("X-Amz-SignedHeaders", value));
        assert_eq!(rejection.reason(), "bad_encoding", "{value}");
    }
    let rejection = reject(&with_param("X-Amz-Security-Token", "abc+def"));
    assert_eq!(rejection.reason(), "bad_encoding");
}

#[test]
fn a_missing_required_parameter_is_rejected() {
    for key in [
        "Action",
        "X-Amz-SignedHeaders",
        "X-Amz-Credential",
        "X-Amz-Date",
        "X-Amz-Expires",
        "X-Amz-Signature",
    ] {
        let p: Vec<_> = params().into_iter().filter(|(k, _)| k != key).collect();
        assert!(
            broker()
                .validate_presigned(&url_with(STS_HOST, &p), now())
                .is_err(),
            "missing {key} must be refused"
        );
    }
}

#[test]
fn a_security_token_is_optional() {
    // Long-lived keys have none; the principal check after STS is what refuses
    // IAM users, so this stage must not.
    let p: Vec<_> = params()
        .into_iter()
        .filter(|(k, _)| k != "X-Amz-Security-Token")
        .collect();
    assert!(
        broker()
            .validate_presigned(&url_with(STS_HOST, &p), now())
            .is_ok()
    );
}

// ---- Freshness -------------------------------------------------------------

#[test]
fn an_expired_url_is_rejected() {
    let broker = broker();
    let at_expiry = UNIX_EPOCH + Duration::from_secs(SIGNED_AT + 60);
    assert_eq!(
        broker.validate_presigned(&legit_url(), at_expiry),
        Err(SigV4Rejection::Expired)
    );
    let just_before = UNIX_EPOCH + Duration::from_secs(SIGNED_AT + 59);
    assert!(broker.validate_presigned(&legit_url(), just_before).is_ok());
}

#[test]
fn a_long_lived_presigned_url_is_rejected() {
    // A presigned URL is a bearer credential. Fifteen minutes is the most
    // replay window we will accept, however long the caller asked for.
    let too_long = (MAX_PRESIGN_EXPIRES_SECS + 1).to_string();
    assert_eq!(
        reject(&with_param("X-Amz-Expires", &too_long)),
        SigV4Rejection::LifetimeTooLong
    );
    assert_eq!(
        reject(&with_param("X-Amz-Expires", "604800")),
        SigV4Rejection::LifetimeTooLong
    );
    assert!(
        broker()
            .validate_presigned(
                &with_param("X-Amz-Expires", &MAX_PRESIGN_EXPIRES_SECS.to_string()),
                now()
            )
            .is_ok()
    );
}

#[test]
fn a_url_dated_in_the_future_is_rejected() {
    let rejection = reject(&with_param("X-Amz-Date", "20261005T130000Z"));
    assert_eq!(rejection, SigV4Rejection::NotYetValid);
}

#[test]
fn credential_date_and_signing_date_must_agree() {
    let rejection = reject(&with_param(
        "X-Amz-Credential",
        "ASIAEXAMPLEKEYID%2F20261004%2Fus-east-1%2Fsts%2Faws4_request",
    ));
    assert_eq!(rejection, SigV4Rejection::CredentialScope);
}

#[test]
fn an_oversized_url_is_rejected_before_parsing() {
    let huge = with_param("X-Amz-Security-Token", &"A".repeat(16 * 1024));
    assert_eq!(reject(&huge), SigV4Rejection::TooLarge);
}

// ---- Principal and account policy, after STS ------------------------------

#[test]
fn a_role_from_an_untrusted_account_is_rejected() {
    // STS vouches for the signature, not for the account being one of ours.
    let err = broker()
        .validate_sts_response(
            200,
            &sts_ok(
                "arn:aws:sts::999999999999:assumed-role/payments/x",
                "999999999999",
            ),
        )
        .unwrap_err();
    let StsError::Rejected(rejection) = err else {
        panic!("expected a rejection, got {err:?}");
    };
    assert_eq!(rejection.reason(), "untrusted_account");
    assert_eq!(ExchangeError::from(rejection).status(), 403);
}

#[test]
fn iam_users_and_root_are_rejected_even_from_a_trusted_account() {
    // Long-lived access keys are the distributed-secret problem this system
    // exists to remove; root is root.
    for arn in [
        "arn:aws:iam::111122223333:user/deploy-bot",
        "arn:aws:iam::111122223333:root",
        "arn:aws:sts::111122223333:federated-user/bob",
    ] {
        let err = broker()
            .validate_sts_response(200, &sts_ok(arn, TRUSTED_ACCOUNT))
            .unwrap_err();
        let StsError::Rejected(rejection) = err else {
            panic!("{arn}: expected a rejection, got {err:?}");
        };
        assert_eq!(rejection.reason(), "unsupported_principal", "{arn}");
    }
}

#[test]
fn sts_refusing_the_signature_is_a_403_for_the_caller() {
    // Includes a URL that signed a *different* audience value: STS computes
    // the signature over the value we sent, and it does not match.
    for status in [400, 403] {
        let err = broker().validate_sts_response(status, b"").unwrap_err();
        assert_eq!(
            err,
            StsError::Rejected(SigV4Rejection::StsRejected { status })
        );
        assert_eq!(ExchangeError::from(err).status(), 403);
    }
}

#[test]
fn sts_throttling_is_retryable_and_not_the_callers_fault() {
    for status in [429, 500, 503] {
        let err = broker().validate_sts_response(status, b"").unwrap_err();
        assert_eq!(ExchangeError::from(err).status(), 503, "{status}");
    }
}

// ---- Nothing sensitive leaks -----------------------------------------------

#[test]
fn rejections_never_echo_the_url_or_session_token() {
    let url = with_param("X-Amz-SignedHeaders", "host");
    let rejection = reject(&url);
    let body = serde_json::to_string(&ExchangeError::from(rejection).body()).unwrap();
    assert!(
        !body.contains("IQoJb3JpZ2lu"),
        "leaked session token: {body}"
    );
    assert!(!body.contains("ASIAEXAMPLEKEYID"), "leaked key id: {body}");

    let presigned = broker().validate_presigned(&legit_url(), now()).unwrap();
    let debug = format!("{presigned:?}");
    assert!(
        !debug.contains("IQoJb3JpZ2lu"),
        "Debug leaked the URL: {debug}"
    );
    assert!(
        !debug.contains("X-Amz-Signature"),
        "Debug leaked the URL: {debug}"
    );
}

// ---- Real SDK output -------------------------------------------------------

/// Produced by the Python snippet in docs/CLIENTS.md (boto3/botocore
/// `SigV4QueryAuth`) with fake credentials. If a validator change rejects this,
/// it rejects real clients.
const BOTOCORE_URL: &str = "https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIAEXAMPLEKEYID0000%2F20261006%2Fus-east-1%2Fsts%2Faws4_request&X-Amz-Date=20261006T023637Z&X-Amz-Expires=60&X-Amz-SignedHeaders=host%3Bx-recognito-audience&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEXAMPLE%2Bsession%2Ftoken%3D%3D&X-Amz-Signature=0386566b8fce4b2afe5a4058b2de6a17483f8e508ca108fdd48c7da7537c111b";

#[test]
fn a_url_presigned_by_botocore_is_accepted() {
    // 2026-10-06T02:36:37Z + 10s.
    let at = UNIX_EPOCH + Duration::from_secs(1_791_254_197 + 10);
    let presigned = broker().validate_presigned(BOTOCORE_URL, at).unwrap();
    assert_eq!(presigned.access_key_id, "ASIAEXAMPLEKEYID0000");
}
