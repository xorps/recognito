//! Outbound HTTPS for the two upstreams the broker calls directly: STS (the
//! SigV4 door) and the Cognito token endpoint. AWS API calls go through the AWS
//! SDK, built on the same rustls/ring stack in [`crate::aws`].
//!
//! Rules every outbound call shares:
//!
//! - **HTTPS only**, platform trust roots, ring named explicitly as the
//!   crypto provider rather than relying on a process-wide default.
//! - **No redirects.** hyper never follows them; a 3xx is returned as a status
//!   and each caller refuses it.
//! - **Bounded**: one deadline over connect-through-last-body-byte, and a cap
//!   on how much body is read. A slow or enormous answer costs a timeout, not
//!   a worker.

use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::{Connect, HttpConnector};
use hyper_util::rt::TokioExecutor;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Bytes,
}

/// Why no answer came back. Never the caller's fault; always retryable.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("request timed out after {0:?}")]
    Timeout(Duration),
    #[error("request failed: {0}")]
    Request(String),
    #[error("response body exceeded {0} bytes")]
    BodyTooLarge(usize),
}

#[derive(Clone)]
pub struct HttpClient<C> {
    client: Client<C, Full<Bytes>>,
    timeout: Duration,
    max_body: usize,
}

impl HttpClient<HttpsConnector<HttpConnector>> {
    pub fn https(timeout: Duration, max_body: usize) -> std::io::Result<Self> {
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_provider_and_native_roots(rustls::crypto::ring::default_provider())?
            .https_only()
            .enable_http1()
            .build();
        Ok(Self::with_connector(connector, timeout, max_body))
    }
}

impl<C> HttpClient<C>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    /// Any hyper connector. Production uses [`HttpClient::https`]; a plain
    /// [`HttpConnector`] is for tests against a local server.
    pub fn with_connector(connector: C, timeout: Duration, max_body: usize) -> Self {
        HttpClient {
            client: Client::builder(TokioExecutor::new()).build(connector),
            timeout,
            max_body,
        }
    }

    pub async fn send(
        &self,
        request: http::Request<Full<Bytes>>,
    ) -> Result<HttpResponse, TransportError> {
        tokio::time::timeout(self.timeout, self.send_inner(request))
            .await
            .map_err(|_| TransportError::Timeout(self.timeout))?
    }

    async fn send_inner(
        &self,
        request: http::Request<Full<Bytes>>,
    ) -> Result<HttpResponse, TransportError> {
        let response = self
            .client
            .request(request)
            .await
            .map_err(|e| TransportError::Request(e.to_string()))?;
        let status = response.status().as_u16();
        let body = Limited::new(response.into_body(), self.max_body)
            .collect()
            .await
            .map_err(|e| {
                if e.is::<http_body_util::LengthLimitError>() {
                    TransportError::BodyTooLarge(self.max_body)
                } else {
                    TransportError::Request(e.to_string())
                }
            })?
            .to_bytes();
        Ok(HttpResponse { status, body })
    }
}
