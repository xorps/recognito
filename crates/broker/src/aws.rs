//! The broker's one AWS API call: `DescribeUserPoolClient`, to read a client
//! secret into memory (ADR-2). IAM: that action on one pool ARN, nothing else.

use std::time::Duration;

use aws_sdk_cognitoidentityprovider::Client;
use aws_smithy_http_client::tls::{Provider, rustls_provider::CryptoMode};

use crate::secrets::{ClientSecret, SecretError, SecretSource};

/// An SDK config on the same rustls/ring stack as the rest of the process.
/// Credentials come from the default chain — IRSA or Pod Identity in-cluster.
pub async fn sdk_config(region: &str) -> aws_config::SdkConfig {
    let http = aws_smithy_http_client::Builder::new()
        .tls_provider(Provider::Rustls(CryptoMode::Ring))
        .build_https();
    aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(region.to_owned()))
        .http_client(http)
        .load()
        .await
}

/// `us-east-1_aBcDeFgHi` → `us-east-1`.
pub fn region_of_pool(user_pool_id: &str) -> Option<&str> {
    user_pool_id.split_once('_').map(|(region, _)| region)
}

pub struct CognitoSecretSource {
    client: Client,
    user_pool_id: String,
}

impl CognitoSecretSource {
    pub fn new(config: &aws_config::SdkConfig, user_pool_id: String) -> Self {
        CognitoSecretSource {
            client: Client::new(config),
            user_pool_id,
        }
    }
}

impl SecretSource for CognitoSecretSource {
    async fn describe_secret(&self, client_id: &str) -> Result<ClientSecret, SecretError> {
        let out = self
            .client
            .describe_user_pool_client()
            .user_pool_id(&self.user_pool_id)
            .client_id(client_id)
            .send()
            .await
            .map_err(|e| {
                let service = e.as_service_error();
                if service.is_some_and(|s| s.is_resource_not_found_exception()) {
                    SecretError::NotFound
                } else if service.is_some_and(|s| s.is_too_many_requests_exception()) {
                    // Account-wide budget: yield for a while, not a moment.
                    SecretError::Throttled(Duration::from_secs(5))
                } else {
                    SecretError::Unavailable(
                        aws_sdk_cognitoidentityprovider::error::DisplayErrorContext(&e)
                            .to_string()
                            .into(),
                    )
                }
            })?;
        out.user_pool_client
            .and_then(|c| c.client_secret)
            .map(ClientSecret::new)
            .ok_or(SecretError::NoSecret)
    }
}
