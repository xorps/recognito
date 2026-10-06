//! The STS round trip: transport rules over real HTTP against a local server,
//! and the authenticator's ordering against a fake transport.
//!
//! The local server speaks plain HTTP through
//! [`HyperStsTransport::with_connector`]. That is safe in production only
//! because the validator refuses every non-`https://` URL before a transport
//! sees it; the last test here pins that the production constructor refuses
//! plain HTTP on its own as well.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::get;
use hyper_util::client::legacy::connect::HttpConnector;
use recognito_broker::sigv4::{AUDIENCE_HEADER, StsForwardRequest};
use recognito_broker::sts::{
    HyperStsTransport, MAX_STS_BODY_BYTES, SigV4Authenticator, StsHttpResponse, StsTransport,
    TransportError,
};
use recognito_broker::{
    CanonicalAudience, ErrorCode, ExchangeError, SigV4Validator, StsEndpoint, StsError,
};

const AUDIENCE: &str = "https://cognito-broker.example.com";
const QUERY: &str = "Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Credential=ASIAEXAMPLE%2F20261005%2Fus-east-1%2Fsts%2Faws4_request";

#[derive(Default, Clone)]
struct Seen {
    headers: Arc<Mutex<Option<HeaderMap>>>,
    uri: Arc<Mutex<Option<Uri>>>,
}

async fn serve(seen: Seen) -> String {
    let record = seen.clone();
    let app = Router::new()
        .route(
            "/",
            get(move |headers: HeaderMap, uri: Uri| {
                let record = record.clone();
                async move {
                    *record.headers.lock().unwrap() = Some(headers);
                    *record.uri.lock().unwrap() = Some(uri);
                    r#"{"ok":true}"#
                }
            }),
        )
        .route(
            "/redirect",
            get(|| async { (StatusCode::FOUND, [("location", "/")]).into_response() }),
        )
        .route(
            "/huge",
            get(|| async { "x".repeat(MAX_STS_BODY_BYTES + 1) }),
        )
        .route(
            "/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(5)).await;
                "late"
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

fn plain_http(timeout: Duration) -> HyperStsTransport<HttpConnector> {
    HyperStsTransport::with_connector(HttpConnector::new(), timeout)
}

fn request(url: &str) -> StsForwardRequest<'_> {
    StsForwardRequest {
        method: "GET",
        url,
        headers: [
            (AUDIENCE_HEADER, AUDIENCE.to_owned()),
            ("accept", "application/json".to_owned()),
        ],
    }
}

#[tokio::test]
async fn the_audience_header_and_query_reach_sts_unaltered() {
    let seen = Seen::default();
    let base = serve(seen.clone()).await;
    let url = format!("{base}/?{QUERY}");

    let response = plain_http(Duration::from_secs(2))
        .send(&request(&url))
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(&response.body[..], br#"{"ok":true}"#);

    let headers = seen.headers.lock().unwrap().clone().unwrap();
    assert_eq!(headers[AUDIENCE_HEADER], AUDIENCE);
    assert_eq!(headers["accept"], "application/json");
    let host = headers["host"].to_str().unwrap();
    assert_eq!(
        format!("http://{host}"),
        base,
        "Host must be the URL's authority"
    );
    // Byte-exact: re-encoding %2F would break the caller's signature.
    let uri = seen.uri.lock().unwrap().clone().unwrap();
    assert_eq!(uri.query(), Some(QUERY));
}

#[tokio::test]
async fn redirects_are_returned_not_followed() {
    let seen = Seen::default();
    let base = serve(seen.clone()).await;
    let url = format!("{base}/redirect");
    let response = plain_http(Duration::from_secs(2))
        .send(&request(&url))
        .await
        .unwrap();
    assert_eq!(response.status, 302);
    assert!(
        seen.uri.lock().unwrap().is_none(),
        "the redirect target must never be requested"
    );
}

#[tokio::test]
async fn an_oversized_body_is_cut_off() {
    let base = serve(Seen::default()).await;
    let url = format!("{base}/huge");
    let err = plain_http(Duration::from_secs(2))
        .send(&request(&url))
        .await
        .unwrap_err();
    assert!(matches!(err, TransportError::BodyTooLarge(_)), "{err:?}");
}

#[tokio::test]
async fn a_slow_sts_costs_a_timeout_not_a_worker() {
    let base = serve(Seen::default()).await;
    let url = format!("{base}/slow");
    let err = plain_http(Duration::from_millis(200))
        .send(&request(&url))
        .await
        .unwrap_err();
    assert!(matches!(err, TransportError::Timeout(_)), "{err:?}");
}

#[tokio::test]
async fn the_production_transport_refuses_plain_http() {
    let base = serve(Seen::default()).await;
    let url = format!("{base}/");
    let transport = HyperStsTransport::https(Duration::from_secs(2)).unwrap();
    let err = transport.send(&request(&url)).await.unwrap_err();
    assert!(matches!(err, TransportError::Request(_)), "{err:?}");
}

// ---- Authenticator ---------------------------------------------------------

/// Counts calls and replays a canned answer.
struct FakeSts {
    calls: AtomicUsize,
    answer: Result<StsHttpResponse, ()>,
}

impl StsTransport for FakeSts {
    async fn send(
        &self,
        request: &StsForwardRequest<'_>,
    ) -> Result<StsHttpResponse, TransportError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert!(
            request
                .url
                .starts_with("https://sts.us-east-1.amazonaws.com/?")
        );
        self.answer
            .clone()
            .map_err(|()| TransportError::Request("connection refused".into()))
    }
}

fn authenticator(answer: Result<StsHttpResponse, ()>) -> SigV4Authenticator<FakeSts> {
    let validator = SigV4Validator::new(
        CanonicalAudience::parse(AUDIENCE).unwrap(),
        vec![StsEndpoint::regional("us-east-1").unwrap()],
        ["111122223333"],
    )
    .unwrap();
    SigV4Authenticator::new(
        validator,
        FakeSts {
            calls: AtomicUsize::new(0),
            answer,
        },
    )
}

const PRESIGNED: &str = "https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIAEXAMPLE%2F20261005%2Fus-east-1%2Fsts%2Faws4_request&X-Amz-Date=20261005T120000Z&X-Amz-Expires=60&X-Amz-SignedHeaders=host%3Bx-recognito-audience&X-Amz-Signature=abc123";

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_791_201_600 + 30)
}

fn ok_answer() -> StsHttpResponse {
    StsHttpResponse {
        status: 200,
        body: serde_json::to_vec(&serde_json::json!({
            "GetCallerIdentityResponse": { "GetCallerIdentityResult": {
                "Account": "111122223333",
                "Arn": "arn:aws:sts::111122223333:assumed-role/payments/i-0abc",
                "UserId": "AROAEXAMPLE:i-0abc",
            }}
        }))
        .unwrap()
        .into(),
    }
}

#[tokio::test]
async fn a_valid_url_is_forwarded_once_and_yields_the_role() {
    let auth = authenticator(Ok(ok_answer()));
    let caller = auth.authenticate(PRESIGNED, now()).await.unwrap();
    assert_eq!(caller.identity.role_name, "payments");
    assert_eq!(auth_calls(&auth), 1);
}

#[tokio::test]
async fn a_locally_refused_url_never_reaches_sts() {
    // An unbound URL: refusing it must not cost an STS call, or the door is
    // an amplifier for anyone who wants to burn our STS budget.
    let unbound = PRESIGNED.replace("host%3Bx-recognito-audience", "host");
    let auth = authenticator(Ok(ok_answer()));
    let err = auth.authenticate(&unbound, now()).await.unwrap_err();
    assert_eq!(ExchangeError::from(err).status(), 403);
    assert_eq!(auth_calls(&auth), 0);
}

#[tokio::test]
async fn an_unreachable_sts_is_retryable() {
    let auth = authenticator(Err(()));
    let err = auth.authenticate(PRESIGNED, now()).await.unwrap_err();
    assert_eq!(err, StsError::Unreachable);
    assert_eq!(
        ExchangeError::from(err).code,
        ErrorCode::TemporarilyUnavailable
    );
}

fn auth_calls(auth: &SigV4Authenticator<FakeSts>) -> usize {
    auth.transport().calls.load(Ordering::SeqCst)
}
