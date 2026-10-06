//! The fetch layer: Cognito `client_credentials` at the user pool's token
//! endpoint, behind the token cache (DESIGN.md §Broker, layer 3).
//!
//! Pass-through only (invariant 6): Cognito issues and signs; we relay its
//! access token and never look inside it.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http_body_util::Full;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::{Connect, HttpConnector};
use recognito_cache::{CacheKey, CachedToken, FetchError, TokenFetcher, TokenValue};
use serde::Deserialize;

use crate::http::HttpClient;
use crate::secrets::{SecretCache, SecretError, SecretSource};

pub const DEFAULT_TOKEN_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_TOKEN_BODY_BYTES: usize = 64 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TokenEndpointError {
    #[error("Cognito domain must be an https:// origin with no path, query, or fragment")]
    NotHttpsOrigin,
}

/// `https://<domain>/oauth2/token` for a user pool domain — either the prefix
/// domain (`https://<prefix>.auth.<region>.amazoncognito.com`) or a custom
/// domain.
pub fn token_endpoint(domain: &str) -> Result<String, TokenEndpointError> {
    let host = domain
        .strip_prefix("https://")
        .map(|h| h.strip_suffix('/').unwrap_or(h))
        .filter(|h| {
            !h.is_empty()
                && h.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b':')
        })
        .ok_or(TokenEndpointError::NotHttpsOrigin)?;
    Ok(format!("https://{host}/oauth2/token"))
}

pub struct CognitoFetcher<S, C> {
    secrets: Arc<SecretCache<S>>,
    http: HttpClient<C>,
    token_url: String,
}

impl<S: SecretSource> CognitoFetcher<S, HttpsConnector<HttpConnector>> {
    pub fn https(
        secrets: Arc<SecretCache<S>>,
        token_url: String,
        timeout: Duration,
    ) -> std::io::Result<Self> {
        Ok(CognitoFetcher {
            secrets,
            http: HttpClient::https(timeout, MAX_TOKEN_BODY_BYTES)?,
            token_url,
        })
    }
}

impl<S, C> CognitoFetcher<S, C>
where
    S: SecretSource,
    C: Connect + Clone + Send + Sync + 'static,
{
    pub fn with_connector(
        secrets: Arc<SecretCache<S>>,
        token_url: String,
        connector: C,
        timeout: Duration,
    ) -> Self {
        CognitoFetcher {
            secrets,
            http: HttpClient::with_connector(connector, timeout, MAX_TOKEN_BODY_BYTES),
            token_url,
        }
    }

    async fn request(&self, key: &CacheKey, secret: &str) -> Result<CachedToken, FetchError> {
        // RFC 6749 §2.3.1: form-encode each half, then base64 the pair.
        let credentials = STANDARD.encode(format!(
            "{}:{}",
            form_encode(&key.client_id),
            form_encode(secret)
        ));
        let body = format!(
            "grant_type=client_credentials&scope={}",
            form_encode(&key.scope)
        );
        let request = http::Request::post(&self.token_url)
            .header("content-type", "application/x-www-form-urlencoded")
            .header("accept", "application/json")
            .header("authorization", format!("Basic {credentials}"))
            .body(Full::new(Bytes::from(body)))
            .map_err(|e| FetchError::Transport(e.to_string().into()))?;

        let issued_at = recognito_cache::now();
        let response = self
            .http
            .send(request)
            .await
            .map_err(|e| FetchError::Transport(e.to_string().into()))?;

        match response.status {
            200 => {
                #[derive(Deserialize)]
                struct Ok {
                    access_token: String,
                    expires_in: u64,
                }
                let ok: Ok = serde_json::from_slice(&response.body).map_err(|_| {
                    FetchError::Rejected("token endpoint returned an unreadable body".into())
                })?;
                Ok(CachedToken {
                    value: TokenValue::new(ok.access_token),
                    issued_at,
                    expires_at: issued_at + ok.expires_in,
                })
            }
            429 | 500..=599 => Err(FetchError::Transport(
                format!("token endpoint returned HTTP {}", response.status).into(),
            )),
            status => {
                #[derive(Deserialize)]
                struct Err {
                    error: String,
                }
                let code = serde_json::from_slice::<Err>(&response.body)
                    .map(|e| e.error)
                    .unwrap_or_default();
                if code == "invalid_client" {
                    Err(FetchError::InvalidClient)
                } else {
                    // Only the OAuth error code: Cognito's description can
                    // echo request values.
                    Err(FetchError::Rejected(
                        format!("token endpoint returned HTTP {status} {code}").into(),
                    ))
                }
            }
        }
    }
}

impl<S, C> TokenFetcher for CognitoFetcher<S, C>
where
    S: SecretSource,
    C: Connect + Clone + Send + Sync + 'static,
{
    /// `invalid_client` is the use-time oracle (ADR-10): evict the secret,
    /// refetch it, try exactly once more.
    async fn fetch(&self, key: &CacheKey) -> Result<CachedToken, FetchError> {
        for attempt in 0..2 {
            let secret = self
                .secrets
                .get(&key.client_id)
                .await
                .map_err(secret_to_fetch_error)?;
            match self.request(key, secret.expose()).await {
                Err(FetchError::InvalidClient) if attempt == 0 => {
                    tracing::info!(client_id = %key.client_id, "invalid_client; refetching secret once");
                    self.secrets.evict(&key.client_id);
                }
                other => return other,
            }
        }
        Err(FetchError::InvalidClient)
    }
}

fn secret_to_fetch_error(e: SecretError) -> FetchError {
    match e {
        SecretError::Throttled(_) | SecretError::Unavailable(_) => {
            FetchError::Transport(e.to_string().into())
        }
        SecretError::NotFound | SecretError::NoSecret => FetchError::Rejected(e.to_string().into()),
    }
}

/// `application/x-www-form-urlencoded` for one value: unreserved characters
/// literal, space as `+`, everything else `%XX`.
fn form_encode(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for b in raw.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'*' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_endpoint_accepts_prefix_and_custom_domains_only_over_https() {
        assert_eq!(
            token_endpoint("https://myapp.auth.us-east-1.amazoncognito.com").unwrap(),
            "https://myapp.auth.us-east-1.amazoncognito.com/oauth2/token"
        );
        assert_eq!(
            token_endpoint("https://auth.example.com/").unwrap(),
            "https://auth.example.com/oauth2/token"
        );
        for bad in [
            "http://auth.example.com",
            "auth.example.com",
            "https://auth.example.com/oauth2/token",
            "https://user@auth.example.com",
            "https://",
        ] {
            assert!(token_endpoint(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn scopes_and_credentials_are_form_encoded() {
        assert_eq!(
            form_encode("payments/read payments/write"),
            "payments%2Fread+payments%2Fwrite"
        );
        assert_eq!(form_encode("a+b=c"), "a%2Bb%3Dc");
    }
}
