//! The broker's request path: authn → authz → fetch (DESIGN.md §Broker).
//!
//! HTTP-free on purpose, so the whole exchange — both doors, the index, scope
//! resolution, the secret and token caches — is testable end to end with fakes
//! at the edges. [`crate::server`] is a thin axum shell over this.

use std::sync::Arc;
use std::time::SystemTime;

use recognito_api::{ScopeError, WorkloadIdentity};
use recognito_cache::{CacheKey, FetchError, TokenCache, TokenFetcher};
use serde::Serialize;

use crate::exchange::{
    self, ErrorCode, ExchangeError, SubjectToken, TokenExchangeForm, TokenExchangeResponse,
};
use crate::index::{MappingEntry, MappingIndex};
use crate::jwt::{JwtAuthenticator, TokenReviewer};
use crate::metrics::Metrics;
use crate::secrets::{SecretCache, SecretSource};
use crate::sts::{SigV4Authenticator, StsTransport};

/// Who called, and how we know.
#[derive(Clone, Debug, Serialize)]
pub struct Caller {
    pub door: &'static str,
    pub identity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pod_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aws_caller_arn: Option<String>,
    #[serde(skip)]
    pub key: Option<WorkloadIdentity>,
}

/// The debug endpoint's answer: identity and mapping, never a token.
#[derive(Debug, Serialize)]
pub struct WhoAmI {
    pub caller: Caller,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mapping: Option<MappingSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mapping_error: Option<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct MappingSummary {
    pub namespace: String,
    pub name: String,
    pub user_pool_id: String,
    pub client_id: Option<String>,
    pub profiles: Vec<ProfileSummary>,
}

#[derive(Debug, Serialize)]
pub struct ProfileSummary {
    pub name: String,
    pub scope: String,
}

pub struct Broker<R, T, S, F> {
    jwt: JwtAuthenticator<R>,
    sigv4: Option<SigV4Authenticator<T>>,
    index: Arc<MappingIndex>,
    user_pool_id: String,
    secrets: Arc<SecretCache<S>>,
    tokens: Arc<TokenCache<F>>,
    metrics: Arc<Metrics>,
}

impl<R, T, S, F> Broker<R, T, S, F>
where
    R: TokenReviewer,
    T: StsTransport,
    S: SecretSource,
    F: TokenFetcher,
{
    pub fn new(
        jwt: JwtAuthenticator<R>,
        sigv4: Option<SigV4Authenticator<T>>,
        index: Arc<MappingIndex>,
        user_pool_id: String,
        secrets: Arc<SecretCache<S>>,
        tokens: Arc<TokenCache<F>>,
        metrics: Arc<Metrics>,
    ) -> Self {
        metrics.describe(
            "recognito_exchanges_total",
            "Token exchanges by door and outcome (ok, or the rejection reason).",
        );
        metrics.describe(
            "recognito_attack_signals_total",
            "Rejections that indicate probing rather than misconfiguration; alert on these.",
        );
        Broker {
            jwt,
            sigv4,
            index,
            user_pool_id,
            secrets,
            tokens,
            metrics,
        }
    }

    pub fn index(&self) -> &Arc<MappingIndex> {
        &self.index
    }

    pub fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    pub fn tokens(&self) -> &Arc<TokenCache<F>> {
        &self.tokens
    }

    /// RFC 8693 exchange. Emits exactly one audit line and one metric per call.
    pub async fn exchange(
        &self,
        form: TokenExchangeForm,
        now: SystemTime,
    ) -> Result<TokenExchangeResponse, ExchangeError> {
        let request_id = self.metrics.next_request_id();
        let mut audit = Audit::default();
        let result = self.exchange_inner(form, now, &mut audit).await;
        let outcome = match &result {
            Ok(_) => "ok",
            Err(_) => audit.reason.unwrap_or("error"),
        };
        self.metrics.inc(
            "recognito_exchanges_total",
            &[("door", audit.door), ("outcome", outcome)],
        );
        if audit.attack {
            self.metrics.inc(
                "recognito_attack_signals_total",
                &[("door", audit.door), ("reason", outcome)],
            );
        }
        let caller = audit.caller.as_ref();
        match &result {
            Ok(response) => tracing::info!(
                target: "recognito::audit",
                request_id,
                door = audit.door,
                identity = caller.map(|c| c.identity.as_str()),
                pod = caller.and_then(|c| c.pod_name.as_deref()),
                aws_caller = caller.and_then(|c| c.aws_caller_arn.as_deref()),
                mapping = audit.mapping.as_deref(),
                client_id = audit.client_id.as_deref(),
                profile = audit.profile.as_deref(),
                expires_in = response.expires_in,
                outcome,
                "token exchanged"
            ),
            Err(error) => tracing::warn!(
                target: "recognito::audit",
                request_id,
                door = audit.door,
                identity = caller.map(|c| c.identity.as_str()),
                pod = caller.and_then(|c| c.pod_name.as_deref()),
                aws_caller = caller.and_then(|c| c.aws_caller_arn.as_deref()),
                mapping = audit.mapping.as_deref(),
                outcome,
                attack_signal = audit.attack,
                detail = audit.detail.as_deref(),
                status = error.status(),
                "token exchange refused"
            ),
        }
        result
    }

    async fn exchange_inner(
        &self,
        form: TokenExchangeForm,
        now: SystemTime,
        audit: &mut Audit,
    ) -> Result<TokenExchangeResponse, ExchangeError> {
        let request = exchange::parse(form).inspect_err(|e| {
            audit.reason = Some(e.code.as_str());
        })?;
        let caller = self.authenticate(&request.subject, now, audit).await?;
        let key = caller
            .key
            .clone()
            .expect("authenticated callers carry a key");
        audit.caller = Some(caller);

        let entry = self.authorize(&key, audit)?;
        let profiles = &entry.spec.scope_profiles;
        let scopes = profiles
            .resolve_requested_scopes(request.requested_scope.as_deref())
            .map_err(|e: ScopeError| {
                audit.reason = Some("invalid_scope");
                ExchangeError::new(ErrorCode::InvalidScope, e.to_string())
            })?;
        audit.profile = profiles.name_of(scopes).map(str::to_owned);

        let client_id = entry
            .client_id
            .clone()
            .expect("lookup only returns provisioned mappings");
        audit.client_id = Some(client_id.clone());
        self.secrets.observe(&client_id, entry.secret_generation);

        let token = self
            .tokens
            .get_or_fetch(CacheKey::new(client_id, scopes.to_scope_parameter()))
            .await
            .map_err(|e| {
                audit.reason = Some(fetch_reason(&e));
                audit.detail = Some(e.to_string());
                fetch_error(e)
            })?;

        let now_secs = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Ok(TokenExchangeResponse::new(
            token.value.expose().to_owned(),
            token.remaining_secs_at(now_secs),
            Some(scopes.to_scope_parameter()),
        ))
    }

    /// Debug endpoint: who does the broker think you are, and which mapping
    /// would serve you. Authenticates exactly as `exchange` does.
    pub async fn whoami(
        &self,
        form: TokenExchangeForm,
        now: SystemTime,
    ) -> Result<WhoAmI, ExchangeError> {
        let mut audit = Audit::default();
        let request = exchange::parse(form)?;
        let caller = self.authenticate(&request.subject, now, &mut audit).await?;
        let key = caller
            .key
            .clone()
            .expect("authenticated callers carry a key");
        let (mapping, mapping_error) = match self.authorize(&key, &mut audit) {
            Ok(entry) => (Some(summary(&entry)), None),
            Err(_) => (None, audit.reason),
        };
        Ok(WhoAmI {
            caller,
            mapping,
            mapping_error,
        })
    }

    async fn authenticate(
        &self,
        subject: &SubjectToken,
        now: SystemTime,
        audit: &mut Audit,
    ) -> Result<Caller, ExchangeError> {
        match subject {
            SubjectToken::ServiceAccountJwt(token) => {
                audit.door = "jwt";
                let sa = self.jwt.authenticate(token).await.map_err(|e| {
                    audit.reason = Some(e.reason());
                    audit.attack = e.is_attack_signal();
                    audit.detail = Some(e.to_string());
                    ExchangeError::from(e)
                })?;
                Ok(Caller {
                    door: "jwt",
                    identity: sa.identity.to_string(),
                    pod_name: sa.pod_name,
                    aws_caller_arn: None,
                    key: Some(WorkloadIdentity::ServiceAccount(sa.identity)),
                })
            }
            SubjectToken::AwsSigV4PresignedUrl(url) => {
                audit.door = "sigv4";
                let Some(sigv4) = &self.sigv4 else {
                    audit.reason = Some("sigv4_disabled");
                    return Err(ExchangeError::new(
                        ErrorCode::InvalidRequest,
                        "this broker does not accept SigV4 subject tokens",
                    ));
                };
                let caller = sigv4.authenticate(url, now).await.map_err(|e| {
                    audit.reason = Some(sts_reason(&e));
                    audit.attack =
                        matches!(&e, crate::sigv4::StsError::Rejected(r) if r.is_attack_signal());
                    audit.detail = Some(e.to_string());
                    ExchangeError::from(e)
                })?;
                Ok(Caller {
                    door: "sigv4",
                    identity: caller.identity.to_string(),
                    pod_name: None,
                    aws_caller_arn: Some(caller.caller_arn),
                    key: Some(WorkloadIdentity::AwsRole(caller.identity)),
                })
            }
        }
    }

    fn authorize(
        &self,
        key: &WorkloadIdentity,
        audit: &mut Audit,
    ) -> Result<Arc<MappingEntry>, ExchangeError> {
        let entry = self.index.lookup(key).map_err(|e| {
            audit.reason = Some(e.reason());
            if let crate::index::LookupError::Ambiguous { .. } = e {
                audit.detail = Some(format!(
                    "claimed by {:?}",
                    self.index
                        .claimants(key)
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                ));
            }
            ExchangeError::from(e)
        })?;
        audit.mapping = Some(entry.key.to_string());
        if entry.spec.user_pool_id != self.user_pool_id {
            audit.reason = Some("pool_not_served");
            return Err(ExchangeError::new(
                ErrorCode::InvalidGrant,
                "identity not authorized: pool_not_served",
            ));
        }
        Ok(entry)
    }
}

struct Audit {
    door: &'static str,
    caller: Option<Caller>,
    mapping: Option<String>,
    client_id: Option<String>,
    profile: Option<String>,
    reason: Option<&'static str>,
    detail: Option<String>,
    attack: bool,
}

/// `door` is "none" until a subject token type is recognized, so a request
/// refused at the protocol layer still gets a meaningful metric label.
impl Default for Audit {
    fn default() -> Self {
        Audit {
            door: "none",
            caller: None,
            mapping: None,
            client_id: None,
            profile: None,
            reason: None,
            detail: None,
            attack: false,
        }
    }
}

fn summary(entry: &MappingEntry) -> MappingSummary {
    let profiles = &entry.spec.scope_profiles;
    MappingSummary {
        namespace: entry.key.namespace.clone(),
        name: entry.key.name.clone(),
        user_pool_id: entry.spec.user_pool_id.clone(),
        client_id: entry.client_id.clone(),
        profiles: profiles
            .names()
            .filter_map(|name| {
                profiles.resolve(Some(name)).ok().map(|set| ProfileSummary {
                    name: name.to_owned(),
                    scope: set.to_scope_parameter(),
                })
            })
            .collect(),
    }
}

fn sts_reason(e: &crate::sigv4::StsError) -> &'static str {
    use crate::sigv4::StsError;
    match e {
        StsError::Rejected(r) => r.reason(),
        StsError::Unavailable { .. } => "sts_unavailable",
        StsError::Unreachable => "sts_unreachable",
        StsError::InvalidResponse(_) => "sts_invalid_response",
    }
}

fn fetch_reason(e: &FetchError) -> &'static str {
    match e {
        FetchError::InvalidClient => "invalid_client",
        FetchError::Rejected(_) => "cognito_rejected",
        FetchError::Transport(_) => "cognito_unavailable",
        FetchError::ExpiredOnArrival { .. } => "expired_on_arrival",
    }
}

/// Fetch failures are never the caller's fault, so never 4xx. Details stay
/// in the audit log; the body says only what kind of failure it was.
fn fetch_error(e: FetchError) -> ExchangeError {
    match e {
        // Still invalid after evict-and-refetch: a rotation is mid-flight or
        // the client was deleted under us. Retrying shortly is right.
        FetchError::InvalidClient | FetchError::Transport(_) => ExchangeError::new(
            ErrorCode::TemporarilyUnavailable,
            "token issuance is temporarily unavailable",
        ),
        FetchError::Rejected(_) | FetchError::ExpiredOnArrival { .. } => {
            ExchangeError::new(ErrorCode::ServerError, "token issuance failed")
        }
    }
}
