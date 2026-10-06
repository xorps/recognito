//! The whole broker request path, end to end, through the axum router.
//!
//! Real: the router, `Broker`, the mapping index, scope resolution, the secret
//! cache, the token cache, and the Cognito fetcher talking HTTP to a local fake
//! token endpoint. Faked: only the apiserver (TokenReview), STS, and
//! `DescribeUserPoolClient` — the three things that need a cluster or an AWS
//! account.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::routing::post;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use http_body_util::BodyExt;
use hyper_util::client::legacy::connect::HttpConnector;
use recognito_api::{
    AwsRoleRef, CognitoClientMapping, CognitoClientMappingSpec, CognitoClientMappingStatus,
    RateLimiter,
};
use recognito_broker::audience::{AudienceValidator, CanonicalAudience};
use recognito_broker::cognito::CognitoFetcher;
use recognito_broker::exchange::TOKEN_TYPE_AWS_SIGV4;
use recognito_broker::index::MappingIndex;
use recognito_broker::jwt::{JwtAuthenticator, ReviewError, ReviewResult, TokenReviewer};
use recognito_broker::metrics::Metrics;
use recognito_broker::secrets::{ClientSecret, SecretCache, SecretError, SecretSource};
use recognito_broker::server;
use recognito_broker::service::Broker;
use recognito_broker::sigv4::StsForwardRequest;
use recognito_broker::sts::{SigV4Authenticator, StsHttpResponse, StsTransport, TransportError};
use recognito_broker::{SigV4Validator, StsEndpoint};
use recognito_cache::{CacheConfig, TokenCache};
use tower::ServiceExt;

const AUDIENCE: &str = "https://cognito-broker.example.com";
const POOL: &str = "us-east-1_aBcDeFgHi";
const CLIENT: &str = "client-payments";

// ---- fakes -----------------------------------------------------------------

/// Authenticates any token whose payload carries `"sub"` as that ServiceAccount
/// and confirms our audience only if the payload's `aud` is ours — enough to
/// exercise both the pre-check and the TokenReview check.
struct FakeApiserver;

impl TokenReviewer for FakeApiserver {
    async fn review(
        &self,
        token: &str,
        audiences: Vec<String>,
    ) -> Result<ReviewResult, ReviewError> {
        assert_eq!(audiences, vec![AUDIENCE.to_owned()]);
        let payload = token.split('.').nth(1).unwrap();
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
        let ours = claims["aud"] == serde_json::json!([AUDIENCE]);
        Ok(ReviewResult {
            authenticated: Some(true),
            audiences: ours.then(|| vec![AUDIENCE.to_owned()]),
            username: claims["sub"].as_str().map(str::to_owned),
            pod_name: Some("payments-api-0".into()),
            pod_uid: None,
        })
    }
}

/// STS that vouches for one role.
struct FakeSts;

impl StsTransport for FakeSts {
    async fn send(&self, _: &StsForwardRequest<'_>) -> Result<StsHttpResponse, TransportError> {
        Ok(StsHttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "GetCallerIdentityResponse": { "GetCallerIdentityResult": {
                    "Account": "111122223333",
                    "Arn": "arn:aws:sts::111122223333:assumed-role/payments-batch/i-0abc",
                    "UserId": "AROAEXAMPLE:i-0abc",
                }}
            }))
            .unwrap()
            .into(),
        })
    }
}

/// `DescribeUserPoolClient`: returns whatever the "current" secret is.
#[derive(Clone)]
struct FakeCognitoAdmin {
    secret: Arc<Mutex<String>>,
    describes: Arc<AtomicUsize>,
}

impl SecretSource for FakeCognitoAdmin {
    async fn describe_secret(&self, client_id: &str) -> Result<ClientSecret, SecretError> {
        assert_eq!(client_id, CLIENT);
        self.describes.fetch_add(1, Ordering::SeqCst);
        Ok(ClientSecret::new(self.secret.lock().unwrap().clone()))
    }
}

/// The user pool's `/oauth2/token`. Accepts only the secrets in `valid`.
#[derive(Clone)]
struct TokenEndpoint {
    valid: Arc<Mutex<Vec<String>>>,
    calls: Arc<AtomicUsize>,
}

async fn token_endpoint(
    State(ep): State<TokenEndpoint>,
    headers: HeaderMap,
    body: String,
) -> (StatusCode, axum::Json<serde_json::Value>) {
    ep.calls.fetch_add(1, Ordering::SeqCst);
    let basic = headers["authorization"].to_str().unwrap();
    let decoded = String::from_utf8(STANDARD.decode(&basic["Basic ".len()..]).unwrap()).unwrap();
    let (client, secret) = decoded.split_once(':').unwrap();
    assert_eq!(client, CLIENT);
    assert!(body.starts_with("grant_type=client_credentials&scope="));
    if !ep.valid.lock().unwrap().iter().any(|s| s == secret) {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({"error": "invalid_client"})),
        );
    }
    let n = ep.calls.load(Ordering::SeqCst);
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "access_token": format!("cognito-access-token-{n}"),
            "expires_in": 900,
            "token_type": "Bearer",
        })),
    )
}

// ---- harness ---------------------------------------------------------------

struct Harness {
    app: Router,
    index: Arc<MappingIndex>,
    admin: FakeCognitoAdmin,
    endpoint: TokenEndpoint,
    metrics: Arc<Metrics>,
}

async fn harness(sigv4: bool) -> Harness {
    let endpoint = TokenEndpoint {
        valid: Arc::new(Mutex::new(vec!["secret-1".into()])),
        calls: Arc::new(AtomicUsize::new(0)),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let ep_app = Router::new()
        .route("/oauth2/token", post(token_endpoint))
        .with_state(endpoint.clone());
    tokio::spawn(async move { axum::serve(listener, ep_app).await.unwrap() });

    let admin = FakeCognitoAdmin {
        secret: Arc::new(Mutex::new("secret-1".into())),
        describes: Arc::new(AtomicUsize::new(0)),
    };
    let secrets = Arc::new(SecretCache::new(
        admin.clone(),
        RateLimiter::new(100.0, 100),
    ));
    let fetcher = CognitoFetcher::with_connector(
        secrets.clone(),
        format!("http://{addr}/oauth2/token"),
        HttpConnector::new(),
        Duration::from_secs(2),
    );
    let tokens = TokenCache::new(fetcher, CacheConfig::default(), 7);
    let audience = CanonicalAudience::parse(AUDIENCE).unwrap();
    let sigv4 = sigv4.then(|| {
        SigV4Authenticator::new(
            SigV4Validator::new(
                audience.clone(),
                vec![StsEndpoint::regional("us-east-1").unwrap()],
                ["111122223333"],
            )
            .unwrap(),
            FakeSts,
        )
    });
    let index = Arc::new(MappingIndex::new());
    let metrics = Arc::new(Metrics::new());
    let broker = Arc::new(Broker::new(
        JwtAuthenticator::new(AudienceValidator::new(audience), FakeApiserver),
        sigv4,
        index.clone(),
        POOL.into(),
        secrets,
        tokens,
        metrics.clone(),
    ));
    Harness {
        app: server::router(broker),
        index,
        admin,
        endpoint,
        metrics,
    }
}

fn spec(json: serde_json::Value) -> CognitoClientMappingSpec {
    let mut base = serde_json::json!({
        "userPoolId": POOL,
        "allowedScopes": [
            { "name": "read", "scopes": ["payments/read"] },
            { "name": "write", "scopes": ["payments/read", "payments/write"] },
        ],
    });
    base.as_object_mut()
        .unwrap()
        .extend(json.as_object().unwrap().clone());
    serde_json::from_value(base).unwrap()
}

fn mapping(ns: &str, spec: CognitoClientMappingSpec, generation: u64) -> CognitoClientMapping {
    let mut m = CognitoClientMapping::new("payments", spec);
    m.metadata.namespace = Some(ns.into());
    m.status = Some(CognitoClientMappingStatus {
        client_id: Some(CLIENT.into()),
        secret_generation: Some(generation),
        ..Default::default()
    });
    m
}

fn sa_mapping(generation: u64) -> CognitoClientMapping {
    mapping(
        "payments",
        spec(serde_json::json!({"serviceAccountRef": {"name": "api"}})),
        generation,
    )
}

fn jwt(sub: &str, aud: &str) -> String {
    let enc = |v: serde_json::Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(&v).unwrap());
    format!(
        "{}.{}.sig",
        enc(serde_json::json!({"alg": "RS256"})),
        enc(serde_json::json!({"sub": sub, "aud": [aud]}))
    )
}

fn sa_token() -> String {
    jwt("system:serviceaccount:payments:api", AUDIENCE)
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| {
            let enc: String = v
                .bytes()
                .map(|b| match b {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' => {
                        (b as char).to_string()
                    }
                    _ => format!("%{b:02X}"),
                })
                .collect();
            format!("{k}={enc}")
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn exchange_form(token: &str, scope: Option<&str>) -> String {
    let mut pairs = vec![
        (
            "grant_type",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ),
        ("subject_token", token),
        ("subject_token_type", "urn:ietf:params:oauth:token-type:jwt"),
    ];
    if let Some(scope) = scope {
        pairs.push(("scope", scope));
    }
    form(&pairs)
}

async fn post_form(
    app: &Router,
    path: &str,
    body: String,
) -> (StatusCode, HeaderMap, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::post(path)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, headers, serde_json::from_slice(&bytes).unwrap())
}

// ---- tests -----------------------------------------------------------------

#[tokio::test]
async fn a_mapped_service_account_gets_a_cognito_token_and_the_second_call_is_cached() {
    let h = harness(false).await;
    h.index.apply(&sa_mapping(1)).unwrap();

    let (status, headers, body) = post_form(
        &h.app,
        "/token",
        exchange_form(&sa_token(), Some("payments/read")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["access_token"], "cognito-access-token-1");
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["scope"], "payments/read");
    assert_eq!(
        body["issued_token_type"],
        "urn:ietf:params:oauth:token-type:access_token"
    );
    let expires_in = body["expires_in"].as_u64().unwrap();
    assert!((899..=900).contains(&expires_in));
    assert_eq!(headers["cache-control"], "no-store");

    let (status, _, again) = post_form(
        &h.app,
        "/token",
        exchange_form(&sa_token(), Some("payments/read")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(again["access_token"], "cognito-access-token-1");
    assert_eq!(
        h.endpoint.calls.load(Ordering::SeqCst),
        1,
        "served from cache"
    );
    assert_eq!(h.admin.describes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn scopes_resolve_to_profiles_and_undeclared_subsets_are_refused() {
    let h = harness(false).await;
    h.index.apply(&sa_mapping(1)).unwrap();

    let (status, _, body) = post_form(
        &h.app,
        "/token",
        exchange_form(&sa_token(), Some("payments/write payments/read")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["scope"], "payments/read payments/write");

    let (status, _, body) = post_form(
        &h.app,
        "/token",
        exchange_form(&sa_token(), Some("payments/write")),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_scope");

    // Two profiles and no scope: refusing beats guessing (ADR-14).
    let (status, _, body) = post_form(&h.app, "/token", exchange_form(&sa_token(), None)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_scope");
}

#[tokio::test]
async fn a_default_service_account_token_is_refused_and_counted_as_an_attack() {
    let h = harness(false).await;
    h.index.apply(&sa_mapping(1)).unwrap();
    let default_token = jwt(
        "system:serviceaccount:payments:api",
        "https://kubernetes.default.svc",
    );
    let (status, _, body) = post_form(
        &h.app,
        "/token",
        exchange_form(&default_token, Some("payments/read")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "invalid_grant");
    assert!(
        h.metrics.render().contains(
            "recognito_attack_signals_total{door=\"jwt\",reason=\"apiserver_audience\"} 1"
        )
    );
    assert_eq!(h.endpoint.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn an_unmapped_service_account_is_refused() {
    let h = harness(false).await;
    h.index.apply(&sa_mapping(1)).unwrap();
    let other = jwt("system:serviceaccount:payments:other", AUDIENCE);
    let (status, _, body) = post_form(
        &h.app,
        "/token",
        exchange_form(&other, Some("payments/read")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        body["error_description"],
        "identity not authorized: not_mapped"
    );
}

#[tokio::test]
async fn a_mapping_for_another_pool_is_not_served() {
    let h = harness(false).await;
    let mut m = sa_mapping(1);
    m.spec.user_pool_id = "eu-west-1_Other123".into();
    h.index.apply(&m).unwrap();
    let (status, _, body) = post_form(
        &h.app,
        "/token",
        exchange_form(&sa_token(), Some("payments/read")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        body["error_description"],
        "identity not authorized: pool_not_served"
    );
}

#[tokio::test]
async fn invalid_client_evicts_the_secret_and_retries_once_invisibly() {
    // ADR-10's oracle: the controller rotated and deleted the old secret
    // before this replica saw the generation bump.
    let h = harness(false).await;
    h.index.apply(&sa_mapping(1)).unwrap();
    let ok = post_form(
        &h.app,
        "/token",
        exchange_form(&sa_token(), Some("payments/read")),
    )
    .await;
    assert_eq!(ok.0, StatusCode::OK);

    *h.admin.secret.lock().unwrap() = "secret-2".into();
    *h.endpoint.valid.lock().unwrap() = vec!["secret-2".into()];

    let (status, _, body) = post_form(
        &h.app,
        "/token",
        exchange_form(&sa_token(), Some("payments/read payments/write")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(h.admin.describes.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_secret_generation_bump_refetches_before_the_next_use() {
    let h = harness(false).await;
    h.index.apply(&sa_mapping(1)).unwrap();
    post_form(
        &h.app,
        "/token",
        exchange_form(&sa_token(), Some("payments/read")),
    )
    .await;

    // Rotation: both secrets valid during the grace window; the watch delivers
    // the new generation.
    *h.admin.secret.lock().unwrap() = "secret-2".into();
    h.endpoint.valid.lock().unwrap().push("secret-2".into());
    h.index.apply(&sa_mapping(2)).unwrap();

    let (status, _, _) = post_form(
        &h.app,
        "/token",
        exchange_form(&sa_token(), Some("payments/read payments/write")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        h.admin.describes.load(Ordering::SeqCst),
        2,
        "the generation change must evict the old secret"
    );
}

#[tokio::test]
async fn sigv4_is_refused_when_the_door_is_closed() {
    let h = harness(false).await;
    let body = form(&[
        (
            "grant_type",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ),
        (
            "subject_token",
            "https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity",
        ),
        ("subject_token_type", TOKEN_TYPE_AWS_SIGV4),
    ]);
    let (status, _, body) = post_form(&h.app, "/token", body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn an_aws_role_exchanges_through_the_sigv4_door() {
    let h = harness(true).await;
    h.index
        .apply(&mapping(
            "payments",
            spec(serde_json::json!({
                "awsRole": AwsRoleRef { arn: "arn:aws:iam::111122223333:role/batch/payments-batch".into() }
            })),
            1,
        ))
        .unwrap();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let date = amz_date(now);
    let url = format!(
        "https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15\
         &X-Amz-Algorithm=AWS4-HMAC-SHA256\
         &X-Amz-Credential=ASIAEXAMPLE%2F{}%2Fus-east-1%2Fsts%2Faws4_request\
         &X-Amz-Date={date}&X-Amz-Expires=60\
         &X-Amz-SignedHeaders=host%3Bx-recognito-audience&X-Amz-Signature=abc",
        &date[..8]
    );
    let body = form(&[
        (
            "grant_type",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ),
        ("subject_token", &url),
        ("subject_token_type", TOKEN_TYPE_AWS_SIGV4),
        ("scope", "payments/read"),
    ]);
    let (status, _, body) = post_form(&h.app, "/token", body).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["access_token"], "cognito-access-token-1");
}

#[tokio::test]
async fn whoami_names_the_caller_and_mapping_and_never_returns_a_token() {
    let h = harness(false).await;
    h.index.apply(&sa_mapping(1)).unwrap();
    let (status, _, body) = post_form(&h.app, "/whoami", exchange_form(&sa_token(), None)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["caller"]["identity"],
        "system:serviceaccount:payments:api"
    );
    assert_eq!(body["caller"]["door"], "jwt");
    assert_eq!(body["mapping"]["client_id"], CLIENT);
    assert_eq!(body["mapping"]["profiles"].as_array().unwrap().len(), 2);
    assert!(!body.to_string().contains("access_token"));
    assert_eq!(h.endpoint.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn non_form_bodies_get_an_oauth_error_not_a_framework_error() {
    let h = harness(false).await;
    let response = h
        .app
        .clone()
        .oneshot(
            Request::post("/token")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["error"], "invalid_request");

    // A duplicated parameter is refused, not resolved.
    let dup = format!("{}&subject_token=other", exchange_form(&sa_token(), None));
    let (status, _, body) = post_form(&h.app, "/token", dup).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}

fn amz_date(unix: u64) -> String {
    let days = (unix / 86_400) as i64;
    let secs = unix % 86_400;
    // civil_from_days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    )
}
