//! The STS round trip behind the SigV4 door (ADR-15).
//!
//! [`crate::sigv4`] decides what may be forwarded and what an answer means;
//! this module only carries the request there and the answer back. Kept
//! separate so the security decisions stay testable without a network, and so
//! the transport can be swapped for a fake in tests.
//!
//! Transport rules (HTTPS only, no redirects, bounded time and body) live in
//! [`crate::http`] and are shared with the Cognito token endpoint.

use std::future::Future;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use http_body_util::Full;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::{Connect, HttpConnector};

use crate::http::HttpClient;
pub use crate::http::{HttpResponse as StsHttpResponse, TransportError};
use crate::sigv4::{SigV4Validator, StsError, StsForwardRequest, VerifiedAwsCaller};

/// Default deadline for one STS round trip, connect through last body byte.
/// STS answers in tens of milliseconds; a caller waiting longer than this is
/// better served by a 503 and a retry with a fresh signature.
pub const DEFAULT_STS_TIMEOUT: Duration = Duration::from_secs(5);

/// A `GetCallerIdentity` answer is a few hundred bytes.
pub const MAX_STS_BODY_BYTES: usize = 64 * 1024;

/// Sends a forward request and returns STS's raw answer.
///
/// Implement with a plain `async fn send`; the future must be `Send` because
/// the broker serves on a multi-thread runtime.
pub trait StsTransport: Send + Sync + 'static {
    fn send(
        &self,
        request: &StsForwardRequest<'_>,
    ) -> impl Future<Output = Result<StsHttpResponse, TransportError>> + Send;
}

/// The production transport.
#[derive(Clone)]
pub struct HyperStsTransport<C> {
    http: HttpClient<C>,
}

impl HyperStsTransport<HttpsConnector<HttpConnector>> {
    pub fn https(timeout: Duration) -> std::io::Result<Self> {
        Ok(HyperStsTransport {
            http: HttpClient::https(timeout, MAX_STS_BODY_BYTES)?,
        })
    }
}

impl<C> HyperStsTransport<C>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    /// Any hyper connector. A plain [`HttpConnector`] is for tests against a
    /// local server, and is safe only because the validator never lets a
    /// non-https URL this far.
    pub fn with_connector(connector: C, timeout: Duration) -> Self {
        HyperStsTransport {
            http: HttpClient::with_connector(connector, timeout, MAX_STS_BODY_BYTES),
        }
    }
}

impl<C> StsTransport for HyperStsTransport<C>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    async fn send(
        &self,
        request: &StsForwardRequest<'_>,
    ) -> Result<StsHttpResponse, TransportError> {
        let mut builder = http::Request::builder()
            .method(request.method)
            // Parsed, not rebuilt: http::Uri keeps the query bytes as given,
            // which the signature depends on.
            .uri(request.url);
        for (name, value) in &request.headers {
            builder = builder.header(*name, value);
        }
        let http_request = builder
            .body(Full::new(Bytes::new()))
            .map_err(|e| TransportError::Request(e.to_string()))?;
        self.http.send(http_request).await
    }
}

/// The whole SigV4 door: validate locally, forward, interpret.
pub struct SigV4Authenticator<T> {
    validator: SigV4Validator,
    transport: T,
}

impl<T: StsTransport> SigV4Authenticator<T> {
    pub fn new(validator: SigV4Validator, transport: T) -> Self {
        SigV4Authenticator {
            validator,
            transport,
        }
    }

    pub fn validator(&self) -> &SigV4Validator {
        &self.validator
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Authenticate a presigned URL. Local checks run first, so a URL we
    /// would refuse never costs an STS call or reaches the network.
    pub async fn authenticate(
        &self,
        presigned_url: &str,
        now: SystemTime,
    ) -> Result<VerifiedAwsCaller, StsError> {
        let presigned = self.validator.validate_presigned(presigned_url, now)?;
        let request = self.validator.forward_request(&presigned);
        let response = self.transport.send(&request).await.map_err(|e| {
            tracing::warn!(error = %e, region = %presigned.region, "STS forward failed");
            StsError::Unreachable
        })?;
        self.validator
            .validate_sts_response(response.status, &response.body)
    }
}
