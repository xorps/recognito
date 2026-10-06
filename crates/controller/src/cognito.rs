//! What the controller asks of Cognito, and what an app client should look
//! like.
//!
//! [`CognitoAdmin`] is the seam: [`crate::aws`] implements it over the AWS SDK,
//! tests implement it in memory. [`DesiredClient`] and [`drift`] are pure, so
//! "what would we send" and "does Cognito still match" are testable without
//! either.

use std::future::Future;

use recognito_api::ValidatedSpec;
use sha2::{Digest, Sha256};

/// The app client configuration a mapping implies. Sent in full on every
/// create and update: `UpdateUserPoolClient` resets any field it is not given.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DesiredClient {
    pub name: String,
    /// Union of every profile's scopes, sorted. The client may mint any of
    /// them; the broker decides which subset a caller gets (ADR-14).
    pub scopes: Vec<String>,
    pub access_token_minutes: i32,
}

/// What `DescribeUserPoolClient` says the client looks like, reduced to the
/// fields we own.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObservedClient {
    pub name: String,
    pub scopes: Vec<String>,
    pub flows: Vec<String>,
    pub flows_user_pool_client: bool,
    pub access_token_validity: Option<i32>,
    pub access_token_units: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretInfo {
    pub id: String,
    /// Unix seconds.
    pub created: Option<i64>,
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum AdminError {
    #[error("not found")]
    NotFound,
    /// Account-wide budget exhausted. Yield: someone else needs it.
    #[error("throttled by Cognito")]
    Throttled,
    /// Cognito refused the request as invalid. Retrying will not help until
    /// the spec changes.
    #[error("rejected by Cognito: {0}")]
    Rejected(String),
    #[error("Cognito unavailable: {0}")]
    Unavailable(String),
}

/// Implement with plain `async fn`s; futures must be `Send`.
pub trait CognitoAdmin: Send + Sync + 'static {
    /// Client ID of the client named `name`, if one exists. Create-path only:
    /// lets a create whose status write was lost adopt its client instead of
    /// minting a duplicate.
    fn find_client(
        &self,
        pool: &str,
        name: &str,
    ) -> impl Future<Output = Result<Option<String>, AdminError>> + Send;

    fn create_client(
        &self,
        pool: &str,
        desired: &DesiredClient,
    ) -> impl Future<Output = Result<String, AdminError>> + Send;

    fn update_client(
        &self,
        pool: &str,
        client_id: &str,
        desired: &DesiredClient,
    ) -> impl Future<Output = Result<(), AdminError>> + Send;

    fn describe_client(
        &self,
        pool: &str,
        client_id: &str,
    ) -> impl Future<Output = Result<ObservedClient, AdminError>> + Send;

    fn delete_client(
        &self,
        pool: &str,
        client_id: &str,
    ) -> impl Future<Output = Result<(), AdminError>> + Send;

    fn list_secrets(
        &self,
        pool: &str,
        client_id: &str,
    ) -> impl Future<Output = Result<Vec<SecretInfo>, AdminError>> + Send;

    /// Add a Cognito-generated secret. The value Cognito returns is dropped
    /// unread: the controller never holds a secret (invariant 1); the broker
    /// reads it with `DescribeUserPoolClient` when it needs it.
    fn add_secret(
        &self,
        pool: &str,
        client_id: &str,
    ) -> impl Future<Output = Result<SecretInfo, AdminError>> + Send;

    fn delete_secret(
        &self,
        pool: &str,
        client_id: &str,
        secret_id: &str,
    ) -> impl Future<Output = Result<(), AdminError>> + Send;
}

/// Cognito `ClientName`: `[\w\s+=,.@-]+`, at most 128 characters.
const MAX_CLIENT_NAME: usize = 128;

impl DesiredClient {
    pub fn for_mapping(namespace: &str, name: &str, uid: &str, spec: &ValidatedSpec) -> Self {
        let mut scopes: Vec<String> = spec
            .scope_profiles
            .names()
            .filter_map(|p| spec.scope_profiles.resolve(Some(p)).ok())
            .flat_map(|set| set.as_slice().iter().cloned())
            .collect();
        scopes.sort();
        scopes.dedup();
        DesiredClient {
            name: client_name(namespace, name, uid),
            scopes,
            access_token_minutes: (spec.token_validity.as_secs() / 60) as i32,
        }
    }
}

/// `recognito.<namespace>.<name>.<uid prefix>` — readable in the console, and
/// unique because of the UID even if a mapping is deleted and re-created
/// under the same name. Hashed when the readable form would not fit.
pub fn client_name(namespace: &str, name: &str, uid: &str) -> String {
    let uid8: String = uid
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(8)
        .collect();
    let readable = format!("recognito.{namespace}.{name}.{uid8}");
    if readable.len() <= MAX_CLIENT_NAME {
        return readable;
    }
    let digest = Sha256::digest(format!("{namespace}/{name}"));
    let short: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("recognito.{short}.{uid8}")
}

/// Fields where Cognito no longer matches the mapping. Empty means in sync.
pub fn drift(desired: &DesiredClient, observed: &ObservedClient) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if observed.name != desired.name {
        fields.push("clientName");
    }
    let mut scopes = observed.scopes.clone();
    scopes.sort();
    if scopes != desired.scopes {
        fields.push("allowedOAuthScopes");
    }
    if observed.flows != ["client_credentials"] || !observed.flows_user_pool_client {
        fields.push("allowedOAuthFlows");
    }
    if observed.access_token_validity != Some(desired.access_token_minutes)
        || observed.access_token_units.as_deref() != Some("minutes")
    {
        fields.push("accessTokenValidity");
    }
    fields
}

#[cfg(test)]
mod tests {
    use super::*;
    use recognito_api::CognitoClientMappingSpec;

    fn validated() -> ValidatedSpec {
        serde_json::from_value::<CognitoClientMappingSpec>(serde_json::json!({
            "serviceAccountRef": {"name": "api"},
            "userPoolId": "us-east-1_aBc",
            "allowedScopes": [
                {"name": "read", "scopes": ["payments/read"]},
                {"name": "write", "scopes": ["payments/write", "payments/read"]},
            ],
            "tokenValidity": "15m",
        }))
        .unwrap()
        .validate()
        .unwrap()
    }

    fn in_sync(d: &DesiredClient) -> ObservedClient {
        ObservedClient {
            name: d.name.clone(),
            scopes: d.scopes.iter().rev().cloned().collect(),
            flows: vec!["client_credentials".into()],
            flows_user_pool_client: true,
            access_token_validity: Some(d.access_token_minutes),
            access_token_units: Some("minutes".into()),
        }
    }

    #[test]
    fn desired_client_is_the_union_of_profiles() {
        let d = DesiredClient::for_mapping("payments", "api", "0b1c2d3e-aaaa", &validated());
        assert_eq!(d.scopes, vec!["payments/read", "payments/write"]);
        assert_eq!(d.access_token_minutes, 15);
        assert_eq!(d.name, "recognito.payments.api.0b1c2d3e");
    }

    #[test]
    fn long_names_are_hashed_to_fit_cognito() {
        let long = "x".repeat(200);
        let name = client_name("payments", &long, "0b1c2d3e");
        assert!(name.len() <= MAX_CLIENT_NAME);
        assert_eq!(name, client_name("payments", &long, "0b1c2d3e"));
        assert_ne!(name, client_name("other", &long, "0b1c2d3e"));
    }

    #[test]
    fn an_in_sync_client_has_no_drift_regardless_of_scope_order() {
        let d = DesiredClient::for_mapping("payments", "api", "u", &validated());
        assert!(drift(&d, &in_sync(&d)).is_empty());
    }

    #[test]
    fn each_owned_field_is_checked() {
        let d = DesiredClient::for_mapping("payments", "api", "u", &validated());
        let mut o = in_sync(&d);
        o.scopes.push("admin/everything".into());
        o.flows.push("code".into());
        o.access_token_validity = Some(60);
        assert_eq!(
            drift(&d, &o),
            vec![
                "allowedOAuthScopes",
                "allowedOAuthFlows",
                "accessTokenValidity"
            ]
        );
    }
}
