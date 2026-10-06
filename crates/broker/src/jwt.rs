//! The in-cluster door: projected ServiceAccount JWTs, verified by TokenReview.
//!
//! # Why TokenReview rather than local JWKS verification
//!
//! TokenReview is the apiserver's own answer, so it covers what a signature
//! check cannot: a bound token whose pod has been deleted is refused, and so
//! is one whose ServiceAccount has been deleted and re-created. Local
//! verification would be faster and spare the apiserver, but it trades those
//! properties for latency the exchange path does not need — workloads hold
//! their Cognito token for most of its lifetime and exchange rarely. Deferred,
//! with a trigger, in ADR-16.
//!
//! # Two checks, in this order
//!
//! 1. **Unverified `aud` pre-check.** The payload is decoded *without* checking
//!    the signature and its `aud` run through
//!    [`AudienceValidator::validate_claim`]. This can only ever *refuse*: a
//!    token it passes still goes to the apiserver. What it buys is that a
//!    replayed apiserver-audience token is refused without an apiserver call
//!    and classified as the CVE-2025-32963 attack signal it is.
//! 2. **TokenReview** with `spec.audiences = [ours]`, then
//!    [`AudienceValidator::validate_token_review`] on `status.authenticated`
//!    *and* `status.audiences` (invariant 2), then the username must be a
//!    ServiceAccount.

use std::future::Future;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use k8s_openapi::api::authentication::v1::{TokenReview, TokenReviewSpec};
use recognito_api::ServiceAccountIdentity;
use serde::Deserialize;

use crate::audience::{AudienceClaim, AudienceRejection, AudienceValidator};
use crate::exchange::{ErrorCode, ExchangeError};

/// Projected tokens are around 1 KiB. Bounds the work an unauthenticated
/// caller can make us (and the apiserver) do.
pub const MAX_JWT_LEN: usize = 16 * 1024;

/// What the apiserver said about a token, reduced to the fields we use.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReviewResult {
    pub authenticated: Option<bool>,
    pub audiences: Option<Vec<String>>,
    pub username: Option<String>,
    /// `authentication.kubernetes.io/pod-name`, for the audit log.
    pub pod_name: Option<String>,
    pub pod_uid: Option<String>,
}

#[derive(Debug, thiserror::Error)]
#[error("TokenReview failed: {0}")]
pub struct ReviewError(pub String);

/// Asks the apiserver about a token. Implement with a plain `async fn`.
pub trait TokenReviewer: Send + Sync + 'static {
    fn review(
        &self,
        token: &str,
        audiences: Vec<String>,
    ) -> impl Future<Output = Result<ReviewResult, ReviewError>> + Send;
}

/// The production reviewer. Needs `create` on `tokenreviews` (the broker's
/// ClusterRole).
#[derive(Clone)]
pub struct KubeTokenReviewer {
    api: kube::Api<TokenReview>,
}

impl KubeTokenReviewer {
    pub fn new(client: kube::Client) -> Self {
        KubeTokenReviewer {
            api: kube::Api::all(client),
        }
    }
}

impl TokenReviewer for KubeTokenReviewer {
    async fn review(
        &self,
        token: &str,
        audiences: Vec<String>,
    ) -> Result<ReviewResult, ReviewError> {
        let review = TokenReview {
            spec: TokenReviewSpec {
                token: token.to_owned(),
                audiences: Some(audiences),
            },
            ..Default::default()
        };
        let created = self
            .api
            .create(&kube::api::PostParams::default(), &review)
            .await
            .map_err(|e| ReviewError(e.to_string()))?;
        let status = created.status.unwrap_or_default();
        let user = status.user.unwrap_or_default();
        let extra = user.extra.unwrap_or_default();
        let first = |key: &str| extra.get(key).and_then(|v| v.first().cloned());
        Ok(ReviewResult {
            authenticated: status.authenticated,
            audiences: status.audiences,
            username: user.username,
            pod_name: first("authentication.kubernetes.io/pod-name"),
            pod_uid: first("authentication.kubernetes.io/pod-uid"),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("subject token is not a JWT")]
    Malformed,
    #[error(transparent)]
    Audience(#[from] AudienceRejection),
    #[error("token authenticates a non-ServiceAccount user")]
    NotServiceAccount,
    #[error(transparent)]
    Unavailable(#[from] ReviewError),
}

impl JwtError {
    pub fn reason(&self) -> &'static str {
        match self {
            JwtError::Malformed => "malformed_jwt",
            JwtError::Audience(r) => r.reason(),
            JwtError::NotServiceAccount => "not_service_account",
            JwtError::Unavailable(_) => "token_review_unavailable",
        }
    }

    pub fn is_attack_signal(&self) -> bool {
        matches!(self, JwtError::Audience(r) if r.is_attack_signal())
    }
}

impl From<JwtError> for ExchangeError {
    fn from(error: JwtError) -> Self {
        match error {
            JwtError::Audience(rejection) => rejection.into(),
            JwtError::Unavailable(_) => ExchangeError::new(
                ErrorCode::TemporarilyUnavailable,
                "token verification is temporarily unavailable",
            ),
            other => ExchangeError::new(
                ErrorCode::InvalidGrant,
                format!("subject token rejected: {}", other.reason()),
            ),
        }
    }
}

/// A ServiceAccount the apiserver vouched for, bound to our audience.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedServiceAccount {
    pub identity: ServiceAccountIdentity,
    pub pod_name: Option<String>,
    pub pod_uid: Option<String>,
}

pub struct JwtAuthenticator<R> {
    audience: AudienceValidator,
    reviewer: R,
}

impl<R: TokenReviewer> JwtAuthenticator<R> {
    pub fn new(audience: AudienceValidator, reviewer: R) -> Self {
        JwtAuthenticator { audience, reviewer }
    }

    pub fn audience(&self) -> &AudienceValidator {
        &self.audience
    }

    pub fn reviewer(&self) -> &R {
        &self.reviewer
    }

    pub async fn authenticate(&self, token: &str) -> Result<VerifiedServiceAccount, JwtError> {
        if token.len() > MAX_JWT_LEN {
            return Err(JwtError::Malformed);
        }
        let claim = unverified_audience(token)?;
        self.audience.validate_claim(claim.as_ref())?;

        let review = self
            .reviewer
            .review(token, self.audience.token_review_spec_audiences())
            .await?;
        self.audience
            .validate_token_review(review.authenticated, review.audiences.as_deref())?;

        let identity = review
            .username
            .as_deref()
            .and_then(ServiceAccountIdentity::from_sub)
            .ok_or(JwtError::NotServiceAccount)?;
        Ok(VerifiedServiceAccount {
            identity,
            pod_name: review.pod_name,
            pod_uid: review.pod_uid,
        })
    }
}

/// The `aud` claim of a JWT whose signature has **not** been checked. Only fit
/// for refusing tokens early; see the module docs.
fn unverified_audience(token: &str) -> Result<Option<AudienceClaim>, JwtError> {
    #[derive(Deserialize)]
    struct Claims {
        aud: Option<AudienceClaim>,
    }
    let mut parts = token.split('.');
    let (Some(_header), Some(payload), Some(_sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(JwtError::Malformed);
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| JwtError::Malformed)?;
    let claims: Claims = serde_json::from_slice(&bytes).map_err(|_| JwtError::Malformed)?;
    Ok(claims.aud)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audience::CanonicalAudience;
    use std::sync::Mutex;

    const BROKER: &str = "https://cognito-broker.example.com";

    fn jwt(claims: serde_json::Value) -> String {
        let enc = |v: &serde_json::Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap());
        format!(
            "{}.{}.sig",
            enc(&serde_json::json!({"alg": "RS256"})),
            enc(&claims)
        )
    }

    /// Records the audiences it was asked about and replays a canned answer.
    struct FakeReviewer {
        answer: ReviewResult,
        asked: Mutex<Vec<Vec<String>>>,
    }

    impl TokenReviewer for FakeReviewer {
        async fn review(
            &self,
            _token: &str,
            audiences: Vec<String>,
        ) -> Result<ReviewResult, ReviewError> {
            self.asked.lock().unwrap().push(audiences);
            Ok(self.answer.clone())
        }
    }

    fn authenticator(answer: ReviewResult) -> JwtAuthenticator<FakeReviewer> {
        JwtAuthenticator::new(
            AudienceValidator::new(CanonicalAudience::parse(BROKER).unwrap()),
            FakeReviewer {
                answer,
                asked: Mutex::new(vec![]),
            },
        )
    }

    fn good_review() -> ReviewResult {
        ReviewResult {
            authenticated: Some(true),
            audiences: Some(vec![BROKER.into()]),
            username: Some("system:serviceaccount:payments:api".into()),
            pod_name: Some("api-7d9f".into()),
            pod_uid: None,
        }
    }

    #[tokio::test]
    async fn a_bound_token_the_apiserver_confirms_is_accepted() {
        let auth = authenticator(good_review());
        let sa = auth
            .authenticate(&jwt(serde_json::json!({"aud": [BROKER]})))
            .await
            .unwrap();
        assert_eq!(sa.identity.namespace, "payments");
        assert_eq!(sa.pod_name.as_deref(), Some("api-7d9f"));
        assert_eq!(
            *auth.reviewer.asked.lock().unwrap(),
            vec![vec![BROKER.to_owned()]],
            "TokenReview must ask about exactly our audience"
        );
    }

    #[tokio::test]
    async fn an_apiserver_audience_token_is_refused_without_calling_the_apiserver() {
        let auth = authenticator(good_review());
        let err = auth
            .authenticate(&jwt(
                serde_json::json!({"aud": ["https://kubernetes.default.svc"]}),
            ))
            .await
            .unwrap_err();
        assert_eq!(err.reason(), "apiserver_audience");
        assert!(err.is_attack_signal());
        assert!(auth.reviewer.asked.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_pre_check_never_replaces_token_review() {
        // `aud` in the payload says ours, but the apiserver does not confirm it
        // (e.g. a forged payload): refused.
        let auth = authenticator(ReviewResult {
            audiences: Some(vec![]),
            ..good_review()
        });
        let err = auth
            .authenticate(&jwt(serde_json::json!({"aud": [BROKER]})))
            .await
            .unwrap_err();
        assert_eq!(err.reason(), "no_validated_audiences");
    }

    #[tokio::test]
    async fn a_non_service_account_user_is_refused() {
        let auth = authenticator(ReviewResult {
            username: Some("system:node:worker-1".into()),
            ..good_review()
        });
        let err = auth
            .authenticate(&jwt(serde_json::json!({"aud": BROKER})))
            .await
            .unwrap_err();
        assert_eq!(err.reason(), "not_service_account");
    }

    #[tokio::test]
    async fn garbage_is_malformed_not_a_server_error() {
        let auth = authenticator(good_review());
        for token in [
            "",
            "a.b",
            "a.!!!.c",
            "a.b.c.d",
            &"x".repeat(MAX_JWT_LEN + 1),
        ] {
            let err = auth.authenticate(token).await.unwrap_err();
            assert_eq!(err.reason(), "malformed_jwt", "{token:.20}");
            assert_eq!(ExchangeError::from(err).status(), 403);
        }
    }

    #[tokio::test]
    async fn an_apiserver_outage_is_retryable() {
        struct Down;
        impl TokenReviewer for Down {
            async fn review(&self, _: &str, _: Vec<String>) -> Result<ReviewResult, ReviewError> {
                Err(ReviewError("connection refused".into()))
            }
        }
        let auth = JwtAuthenticator::new(
            AudienceValidator::new(CanonicalAudience::parse(BROKER).unwrap()),
            Down,
        );
        let err = auth
            .authenticate(&jwt(serde_json::json!({"aud": BROKER})))
            .await
            .unwrap_err();
        assert_eq!(ExchangeError::from(err).status(), 503);
    }
}
