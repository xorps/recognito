//! [`CognitoAdmin`] over the AWS SDK. IAM (the controller's own role, separate
//! from the broker's): Create/Update/Delete/Describe/ListUserPoolClients and
//! Add/Delete/ListUserPoolClientSecrets, on the allowed pools only.

use std::collections::HashMap;
use std::sync::Mutex;

use aws_sdk_cognitoidentityprovider::Client;
use aws_sdk_cognitoidentityprovider::error::{DisplayErrorContext, ProvideErrorMetadata, SdkError};
use aws_sdk_cognitoidentityprovider::types::{
    ExplicitAuthFlowsType, OAuthFlowType, PreventUserExistenceErrorTypes, TimeUnitsType,
    TokenValidityUnitsType,
};
use aws_smithy_http_client::tls::{Provider, rustls_provider::CryptoMode};

use crate::cognito::{AdminError, CognitoAdmin, DesiredClient, ObservedClient, SecretInfo};

/// SDK config on rustls/ring. The region here only seeds credentials; each
/// call uses a client for its pool's region.
pub async fn sdk_config() -> aws_config::SdkConfig {
    let http = aws_smithy_http_client::Builder::new()
        .tls_provider(Provider::Rustls(CryptoMode::Ring))
        .build_https();
    aws_config::defaults(aws_config::BehaviorVersion::latest())
        .http_client(http)
        .load()
        .await
}

/// One SDK client per region, built on first use: pools in different regions
/// need different endpoints, and the set of regions is small.
pub struct AwsCognitoAdmin {
    base: aws_config::SdkConfig,
    clients: Mutex<HashMap<String, Client>>,
}

impl AwsCognitoAdmin {
    pub fn new(base: aws_config::SdkConfig) -> Self {
        AwsCognitoAdmin {
            base,
            clients: Mutex::new(HashMap::new()),
        }
    }

    fn client(&self, pool: &str) -> Result<Client, AdminError> {
        let region = pool
            .split_once('_')
            .map(|(r, _)| r.to_owned())
            .ok_or_else(|| AdminError::Rejected(format!("{pool:?} is not a user pool ID")))?;
        let mut clients = self.clients.lock().unwrap_or_else(|p| p.into_inner());
        Ok(clients
            .entry(region.clone())
            .or_insert_with(|| {
                let config = aws_sdk_cognitoidentityprovider::config::Builder::from(&self.base)
                    .region(aws_config::Region::new(region))
                    .build();
                Client::from_conf(config)
            })
            .clone())
    }
}

fn classify<E, R>(e: SdkError<E, R>) -> AdminError
where
    E: ProvideErrorMetadata + std::error::Error + Send + Sync + 'static,
    R: std::fmt::Debug,
{
    match e.code() {
        Some("ResourceNotFoundException") => AdminError::NotFound,
        Some("TooManyRequestsException" | "LimitExceededException") => AdminError::Throttled,
        Some(
            "InvalidParameterException"
            | "ScopeDoesNotExistException"
            | "InvalidOAuthFlowException"
            | "NotAuthorizedException",
        ) => AdminError::Rejected(DisplayErrorContext(&e).to_string()),
        _ => AdminError::Unavailable(DisplayErrorContext(&e).to_string()),
    }
}

fn secret_info(
    d: aws_sdk_cognitoidentityprovider::types::ClientSecretDescriptorType,
) -> Option<SecretInfo> {
    Some(SecretInfo {
        id: d.client_secret_id?,
        created: d.client_secret_create_date.map(|t| t.secs()),
    })
}

fn units() -> TokenValidityUnitsType {
    TokenValidityUnitsType::builder()
        .access_token(TimeUnitsType::Minutes)
        .build()
}

impl CognitoAdmin for AwsCognitoAdmin {
    async fn find_client(&self, pool: &str, name: &str) -> Result<Option<String>, AdminError> {
        let client = self.client(pool)?;
        let mut next = None;
        loop {
            let page = client
                .list_user_pool_clients()
                .user_pool_id(pool)
                .max_results(60)
                .set_next_token(next)
                .send()
                .await
                .map_err(classify)?;
            if let Some(found) = page
                .user_pool_clients()
                .iter()
                .find(|c| c.client_name() == Some(name))
            {
                return Ok(found.client_id().map(str::to_owned));
            }
            match page.next_token {
                Some(token) => next = Some(token),
                None => return Ok(None),
            }
        }
    }

    async fn create_client(&self, pool: &str, d: &DesiredClient) -> Result<String, AdminError> {
        let out = self
            .client(pool)?
            .create_user_pool_client()
            .user_pool_id(pool)
            .client_name(&d.name)
            .generate_secret(true)
            .allowed_o_auth_flows(OAuthFlowType::ClientCredentials)
            .allowed_o_auth_flows_user_pool_client(true)
            .set_allowed_o_auth_scopes(Some(d.scopes.clone()))
            .access_token_validity(d.access_token_minutes)
            .token_validity_units(units())
            .explicit_auth_flows(ExplicitAuthFlowsType::AllowRefreshTokenAuth)
            .prevent_user_existence_errors(PreventUserExistenceErrorTypes::Enabled)
            .enable_token_revocation(true)
            .send()
            .await
            .map_err(classify)?;
        out.user_pool_client
            .and_then(|c| c.client_id)
            .ok_or_else(|| {
                AdminError::Unavailable("CreateUserPoolClient returned no client ID".into())
            })
    }

    async fn update_client(
        &self,
        pool: &str,
        client_id: &str,
        d: &DesiredClient,
    ) -> Result<(), AdminError> {
        self.client(pool)?
            .update_user_pool_client()
            .user_pool_id(pool)
            .client_id(client_id)
            .client_name(&d.name)
            .allowed_o_auth_flows(OAuthFlowType::ClientCredentials)
            .allowed_o_auth_flows_user_pool_client(true)
            .set_allowed_o_auth_scopes(Some(d.scopes.clone()))
            .access_token_validity(d.access_token_minutes)
            .token_validity_units(units())
            .explicit_auth_flows(ExplicitAuthFlowsType::AllowRefreshTokenAuth)
            .prevent_user_existence_errors(PreventUserExistenceErrorTypes::Enabled)
            .enable_token_revocation(true)
            .send()
            .await
            .map_err(classify)?;
        Ok(())
    }

    async fn describe_client(
        &self,
        pool: &str,
        client_id: &str,
    ) -> Result<ObservedClient, AdminError> {
        let out = self
            .client(pool)?
            .describe_user_pool_client()
            .user_pool_id(pool)
            .client_id(client_id)
            .send()
            .await
            .map_err(classify)?;
        let c = out.user_pool_client.ok_or(AdminError::NotFound)?;
        // The response carries the secret; it is dropped here, unread.
        Ok(ObservedClient {
            name: c.client_name.unwrap_or_default(),
            scopes: c.allowed_o_auth_scopes.unwrap_or_default(),
            flows: c
                .allowed_o_auth_flows
                .unwrap_or_default()
                .iter()
                .map(|f| f.as_str().to_owned())
                .collect(),
            flows_user_pool_client: c.allowed_o_auth_flows_user_pool_client.unwrap_or(false),
            access_token_validity: c.access_token_validity,
            access_token_units: c
                .token_validity_units
                .and_then(|u| u.access_token)
                .map(|u| u.as_str().to_owned()),
        })
    }

    async fn delete_client(&self, pool: &str, client_id: &str) -> Result<(), AdminError> {
        self.client(pool)?
            .delete_user_pool_client()
            .user_pool_id(pool)
            .client_id(client_id)
            .send()
            .await
            .map_err(classify)?;
        Ok(())
    }

    async fn list_secrets(
        &self,
        pool: &str,
        client_id: &str,
    ) -> Result<Vec<SecretInfo>, AdminError> {
        let client = self.client(pool)?;
        let mut out = Vec::new();
        let mut next = None;
        loop {
            let page = client
                .list_user_pool_client_secrets()
                .user_pool_id(pool)
                .client_id(client_id)
                .set_next_token(next)
                .send()
                .await
                .map_err(classify)?;
            out.extend(
                page.client_secrets
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(secret_info),
            );
            match page.next_token {
                Some(token) => next = Some(token),
                None => return Ok(out),
            }
        }
    }

    async fn add_secret(&self, pool: &str, client_id: &str) -> Result<SecretInfo, AdminError> {
        let out = self
            .client(pool)?
            .add_user_pool_client_secret()
            .user_pool_id(pool)
            .client_id(client_id)
            .send()
            .await
            .map_err(classify)?;
        // `client_secret_value` is in here; secret_info() never reads it.
        out.client_secret_descriptor
            .and_then(secret_info)
            .ok_or_else(|| {
                AdminError::Unavailable("AddUserPoolClientSecret returned no descriptor".into())
            })
    }

    async fn delete_secret(
        &self,
        pool: &str,
        client_id: &str,
        secret_id: &str,
    ) -> Result<(), AdminError> {
        self.client(pool)?
            .delete_user_pool_client_secret()
            .user_pool_id(pool)
            .client_id(client_id)
            .client_secret_id(secret_id)
            .send()
            .await
            .map_err(classify)?;
        Ok(())
    }
}
