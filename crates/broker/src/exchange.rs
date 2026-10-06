//! RFC 8693 token exchange: the broker's wire protocol (ADR-13).
//!
//! This module is the protocol surface and nothing else — it parses a request
//! into something the authn/authz/fetch layers can act on, and renders their
//! answer back. It performs no authentication and no authorization, so that
//! "did we validate the audience" is never a question about this file.
//!
//! The profile is narrow on purpose. Every RFC 8693 parameter we do not
//! support is *rejected* with the error the spec defines for it rather than
//! ignored, because a silently-dropped `resource` or `actor_token` is a caller
//! believing it constrained a token that we in fact issued unconstrained.

use serde::{Deserialize, Serialize};

pub const GRANT_TYPE_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
pub const TOKEN_TYPE_JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
pub const TOKEN_TYPE_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
/// A presigned STS `GetCallerIdentity` URL bound to the broker audience
/// (ADR-15). RFC 8693 §3 permits any URI as a token type; this one is ours.
pub const TOKEN_TYPE_AWS_SIGV4: &str =
    "urn:recognito:params:oauth:token-type:aws-sigv4-presigned-url";

/// The raw form body, exactly as RFC 8693 §2.1 spells it.
///
/// Every field is optional here even where the spec requires it, so that a
/// missing one produces our `invalid_request` with a useful message instead of
/// a framework-generated 422 that says nothing.
#[derive(Debug, Default, Deserialize)]
pub struct TokenExchangeForm {
    pub grant_type: Option<String>,
    pub subject_token: Option<String>,
    pub subject_token_type: Option<String>,
    pub scope: Option<String>,
    pub requested_token_type: Option<String>,
    pub actor_token: Option<String>,
    pub actor_token_type: Option<String>,
    pub resource: Option<String>,
    pub audience: Option<String>,
}

/// A request that is well-formed under our profile. Holding one means the
/// protocol layer is satisfied; nothing about the caller's identity has been
/// established yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenExchangeRequest {
    /// The subject token, still entirely unverified, tagged with the door it
    /// must go through.
    pub subject: SubjectToken,
    /// The `scope` parameter as sent, to be resolved against the mapping's
    /// declared profiles (ADR-14). `None` means the caller omitted it.
    pub requested_scope: Option<String>,
}

/// Which authentication door a subject token is for. `subject_token_type`
/// decides this, never the token's contents: sniffing would let a caller pick
/// the door with the weaker check by shaping their token.
///
/// `Debug` shows the variant and length only — both payloads are bearer
/// credentials.
#[derive(Clone, PartialEq, Eq)]
pub enum SubjectToken {
    /// A projected ServiceAccount JWT (`TOKEN_TYPE_JWT`).
    ServiceAccountJwt(String),
    /// A presigned STS `GetCallerIdentity` URL (`TOKEN_TYPE_AWS_SIGV4`).
    AwsSigV4PresignedUrl(String),
}

impl SubjectToken {
    pub fn as_str(&self) -> &str {
        match self {
            SubjectToken::ServiceAccountJwt(t) | SubjectToken::AwsSigV4PresignedUrl(t) => t,
        }
    }
}

impl std::fmt::Debug for SubjectToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self {
            SubjectToken::ServiceAccountJwt(_) => "ServiceAccountJwt",
            SubjectToken::AwsSigV4PresignedUrl(_) => "AwsSigV4PresignedUrl",
        };
        write!(f, "{kind}(<{} bytes redacted>)", self.as_str().len())
    }
}

#[derive(Debug, Serialize)]
pub struct TokenExchangeResponse {
    pub access_token: String,
    /// Required by RFC 8693 §2.2.1 even when it is the obvious value.
    pub issued_token_type: &'static str,
    pub token_type: &'static str,
    /// Seconds remaining on the token *now*, not the mapping's configured
    /// validity. A caller served from cache late in a token's life must not be
    /// told it has a full lifetime ahead of it.
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

impl TokenExchangeResponse {
    pub fn new(access_token: String, expires_in: u64, scope: Option<String>) -> Self {
        TokenExchangeResponse {
            access_token,
            issued_token_type: TOKEN_TYPE_ACCESS_TOKEN,
            token_type: "Bearer",
            expires_in,
            scope,
        }
    }
}

/// The RFC 6749 §5.2 error codes we emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    InvalidRequest,
    UnsupportedGrantType,
    InvalidScope,
    /// RFC 8693 §2.2.2: the requested target is unknown or unsupported.
    InvalidTarget,
    /// The subject token is not acceptable. Every audience rejection lands
    /// here.
    InvalidGrant,
    ServerError,
    TemporarilyUnavailable,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::InvalidRequest => "invalid_request",
            ErrorCode::UnsupportedGrantType => "unsupported_grant_type",
            ErrorCode::InvalidScope => "invalid_scope",
            ErrorCode::InvalidTarget => "invalid_target",
            ErrorCode::InvalidGrant => "invalid_grant",
            ErrorCode::ServerError => "server_error",
            ErrorCode::TemporarilyUnavailable => "temporarily_unavailable",
        }
    }

    /// HTTP status for this code.
    ///
    /// RFC 6749 §5.2 says 400 "unless specified otherwise". We specify
    /// otherwise for `invalid_grant`: a well-formed exchange whose subject
    /// token we refuse is an authorization outcome, and CLAUDE.md invariant 2
    /// requires 403 for a replayed apiserver-audience token. See ADR-13.
    pub fn status(self) -> u16 {
        match self {
            ErrorCode::InvalidRequest
            | ErrorCode::UnsupportedGrantType
            | ErrorCode::InvalidScope
            | ErrorCode::InvalidTarget => 400,
            ErrorCode::InvalidGrant => 403,
            ErrorCode::ServerError => 500,
            ErrorCode::TemporarilyUnavailable => 503,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErrorResponse {
    pub error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code:?}: {description}")]
pub struct ExchangeError {
    pub code: ErrorCode,
    pub description: String,
}

impl ExchangeError {
    pub fn new(code: ErrorCode, description: impl Into<String>) -> Self {
        ExchangeError {
            code,
            description: description.into(),
        }
    }

    pub fn status(&self) -> u16 {
        self.code.status()
    }

    /// The body to send. `error_description` is developer-facing text we
    /// wrote; it never echoes the subject token or any caller-supplied value
    /// that could carry a credential.
    pub fn body(&self) -> ErrorResponse {
        ErrorResponse {
            error: self.code.as_str(),
            error_description: Some(self.description.clone()),
        }
    }
}

/// Every audience rejection is an `invalid_grant`, and therefore a 403.
///
/// The description carries only the stable, low-cardinality reason — never the
/// audience the caller sent. Echoing attacker-controlled text into a response
/// body turns our error into their output channel, and the full detail is
/// already in the structured audit log where it belongs.
impl From<crate::audience::AudienceRejection> for ExchangeError {
    fn from(rejection: crate::audience::AudienceRejection) -> Self {
        ExchangeError::new(
            ErrorCode::InvalidGrant,
            format!("subject token rejected: {}", rejection.reason()),
        )
    }
}

/// Every SigV4 rejection is an `invalid_grant` (403), for the same reason and
/// with the same discipline as audience rejections: reason label only, never
/// the URL, which carries a session token.
impl From<crate::sigv4::SigV4Rejection> for ExchangeError {
    fn from(rejection: crate::sigv4::SigV4Rejection) -> Self {
        ExchangeError::new(
            ErrorCode::InvalidGrant,
            format!("subject token rejected: {}", rejection.reason()),
        )
    }
}

/// STS being down is ours to report as retryable, not the caller's to be
/// refused for. A malformed STS answer is a server error and is never
/// interpreted as an identity.
impl From<crate::sigv4::StsError> for ExchangeError {
    fn from(error: crate::sigv4::StsError) -> Self {
        use crate::sigv4::StsError;
        match error {
            StsError::Rejected(rejection) => rejection.into(),
            StsError::Unavailable { .. } | StsError::Unreachable => ExchangeError::new(
                ErrorCode::TemporarilyUnavailable,
                "identity verification is temporarily unavailable; retry with a fresh signature",
            ),
            StsError::InvalidResponse(_) => {
                ExchangeError::new(ErrorCode::ServerError, "identity verification failed")
            }
        }
    }
}

/// Validate a form body against our RFC 8693 profile.
///
/// Order matters: `grant_type` is checked first so that a client speaking a
/// different protocol entirely gets `unsupported_grant_type` rather than a
/// confusing complaint about a missing `subject_token`.
pub fn parse(form: TokenExchangeForm) -> Result<TokenExchangeRequest, ExchangeError> {
    match form.grant_type.as_deref() {
        Some(GRANT_TYPE_TOKEN_EXCHANGE) => {}
        Some(other) => {
            return Err(ExchangeError::new(
                ErrorCode::UnsupportedGrantType,
                format!("grant_type must be {GRANT_TYPE_TOKEN_EXCHANGE}, got {other:?}"),
            ));
        }
        None => {
            return Err(ExchangeError::new(
                ErrorCode::UnsupportedGrantType,
                format!("grant_type is required and must be {GRANT_TYPE_TOKEN_EXCHANGE}"),
            ));
        }
    }

    // Targeting parameters are refused before anything else is considered. A
    // caller that sent one is asking for a constraint we will not apply, and
    // issuing an unconstrained token in reply is the dangerous outcome.
    if form.resource.is_some() || form.audience.is_some() {
        return Err(ExchangeError::new(
            ErrorCode::InvalidTarget,
            "resource and audience are not supported: the target is fixed by the \
             CognitoClientMapping, not chosen per request",
        ));
    }

    if form.actor_token.is_some() || form.actor_token_type.is_some() {
        return Err(ExchangeError::new(
            ErrorCode::InvalidRequest,
            "delegation (actor_token) is not supported",
        ));
    }

    match form.requested_token_type.as_deref() {
        None | Some(TOKEN_TYPE_ACCESS_TOKEN) => {}
        Some(other) => {
            return Err(ExchangeError::new(
                ErrorCode::InvalidRequest,
                format!(
                    "requested_token_type must be {TOKEN_TYPE_ACCESS_TOKEN} or omitted, got \
                     {other:?}; the broker never issues refresh tokens (ADR-11)"
                ),
            ));
        }
    }

    let wrap: fn(String) -> SubjectToken = match form.subject_token_type.as_deref() {
        Some(TOKEN_TYPE_JWT) => SubjectToken::ServiceAccountJwt,
        Some(TOKEN_TYPE_AWS_SIGV4) => SubjectToken::AwsSigV4PresignedUrl,
        Some(other) => {
            return Err(ExchangeError::new(
                ErrorCode::InvalidRequest,
                format!(
                    "subject_token_type must be {TOKEN_TYPE_JWT} or {TOKEN_TYPE_AWS_SIGV4}, \
                     got {other:?}"
                ),
            ));
        }
        None => {
            return Err(ExchangeError::new(
                ErrorCode::InvalidRequest,
                format!(
                    "subject_token_type is required and must be {TOKEN_TYPE_JWT} or \
                     {TOKEN_TYPE_AWS_SIGV4}"
                ),
            ));
        }
    };

    let subject_token = form
        .subject_token
        .filter(|t| !t.is_empty())
        .ok_or_else(|| {
            ExchangeError::new(
                ErrorCode::InvalidRequest,
                "subject_token is required: send the projected ServiceAccount token, or a \
                 presigned STS GetCallerIdentity URL, in the form body",
            )
        })?;

    Ok(TokenExchangeRequest {
        subject: wrap(subject_token),
        requested_scope: form.scope.filter(|s| !s.trim().is_empty()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_form() -> TokenExchangeForm {
        TokenExchangeForm {
            grant_type: Some(GRANT_TYPE_TOKEN_EXCHANGE.into()),
            subject_token: Some("eyJhbGciOiJSUzI1NiJ9.body.sig".into()),
            subject_token_type: Some(TOKEN_TYPE_JWT.into()),
            ..Default::default()
        }
    }

    #[test]
    fn a_conforming_request_parses() {
        let request = parse(valid_form()).unwrap();
        assert_eq!(
            request.subject,
            SubjectToken::ServiceAccountJwt("eyJhbGciOiJSUzI1NiJ9.body.sig".into())
        );
        assert_eq!(request.requested_scope, None);
    }

    #[test]
    fn a_sigv4_subject_token_is_routed_to_the_sigv4_door() {
        let url = "https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity";
        let form = TokenExchangeForm {
            subject_token: Some(url.into()),
            subject_token_type: Some(TOKEN_TYPE_AWS_SIGV4.into()),
            ..valid_form()
        };
        assert_eq!(
            parse(form).unwrap().subject,
            SubjectToken::AwsSigV4PresignedUrl(url.into())
        );
    }

    #[test]
    fn the_door_is_chosen_by_token_type_never_by_token_shape() {
        // A JWT declared as SigV4 goes to the SigV4 door (where it will fail),
        // and vice versa. Nothing looks inside to "help".
        let form = TokenExchangeForm {
            subject_token_type: Some(TOKEN_TYPE_AWS_SIGV4.into()),
            ..valid_form()
        };
        assert!(matches!(
            parse(form).unwrap().subject,
            SubjectToken::AwsSigV4PresignedUrl(_)
        ));
    }

    #[test]
    fn subject_tokens_are_redacted_from_debug_output() {
        let request = parse(TokenExchangeForm {
            subject_token: Some("eyJhbGciOiJSUzI1NiJ9.sensitive.sig".into()),
            ..valid_form()
        })
        .unwrap();
        let debug = format!("{request:?}");
        assert!(!debug.contains("sensitive"), "{debug}");
        assert!(debug.contains("ServiceAccountJwt"));
    }

    #[test]
    fn sts_outages_are_retryable_not_refusals() {
        use crate::sigv4::{SigV4Rejection, StsError};
        let unavailable: ExchangeError = StsError::Unavailable { status: 503 }.into();
        assert_eq!(unavailable.code, ErrorCode::TemporarilyUnavailable);
        let rejected: ExchangeError =
            StsError::Rejected(SigV4Rejection::StsRejected { status: 403 }).into();
        assert_eq!(rejected.status(), 403);
        let garbage: ExchangeError = StsError::InvalidResponse("x").into();
        assert_eq!(garbage.code, ErrorCode::ServerError);
    }

    #[test]
    fn scope_is_carried_through_unresolved() {
        // Resolution against declared profiles belongs to the authz layer;
        // this module must not decide what a scope means.
        let form = TokenExchangeForm {
            scope: Some("payments/read payments/write".into()),
            ..valid_form()
        };
        assert_eq!(
            parse(form).unwrap().requested_scope,
            Some("payments/read payments/write".into())
        );
    }

    #[test]
    fn a_blank_scope_is_the_same_as_omitting_it() {
        for blank in ["", "   "] {
            let form = TokenExchangeForm {
                scope: Some(blank.into()),
                ..valid_form()
            };
            assert_eq!(parse(form).unwrap().requested_scope, None);
        }
    }

    #[test]
    fn a_wrong_grant_type_is_reported_before_anything_else() {
        let form = TokenExchangeForm {
            grant_type: Some("client_credentials".into()),
            subject_token: None,
            subject_token_type: None,
            ..Default::default()
        };
        let err = parse(form).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedGrantType);
        assert_eq!(err.status(), 400);
    }

    #[test]
    fn targeting_parameters_are_refused_not_ignored() {
        // The important half of ADR-13: a caller that thinks it scoped the
        // token to a resource must not receive an unscoped one with a 200.
        for form in [
            TokenExchangeForm {
                resource: Some("https://api.example.com".into()),
                ..valid_form()
            },
            TokenExchangeForm {
                audience: Some("https://api.example.com".into()),
                ..valid_form()
            },
        ] {
            let err = parse(form).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidTarget);
            assert_eq!(err.status(), 400);
        }
    }

    #[test]
    fn delegation_is_refused() {
        let form = TokenExchangeForm {
            actor_token: Some("another.jwt.here".into()),
            actor_token_type: Some(TOKEN_TYPE_JWT.into()),
            ..valid_form()
        };
        assert_eq!(parse(form).unwrap_err().code, ErrorCode::InvalidRequest);
    }

    #[test]
    fn asking_for_a_refresh_token_is_refused() {
        // ADR-11, enforced at the door rather than discovered later.
        let form = TokenExchangeForm {
            requested_token_type: Some("urn:ietf:params:oauth:token-type:refresh_token".into()),
            ..valid_form()
        };
        let err = parse(form).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidRequest);
        assert!(err.description.contains("refresh"));
    }

    #[test]
    fn asking_explicitly_for_an_access_token_is_fine() {
        let form = TokenExchangeForm {
            requested_token_type: Some(TOKEN_TYPE_ACCESS_TOKEN.into()),
            ..valid_form()
        };
        assert!(parse(form).is_ok());
    }

    #[test]
    fn a_missing_or_empty_subject_token_is_refused() {
        for subject_token in [None, Some(String::new())] {
            let form = TokenExchangeForm {
                subject_token,
                ..valid_form()
            };
            assert_eq!(parse(form).unwrap_err().code, ErrorCode::InvalidRequest);
        }
    }

    #[test]
    fn a_wrong_subject_token_type_is_refused() {
        let form = TokenExchangeForm {
            subject_token_type: Some("urn:ietf:params:oauth:token-type:saml2".into()),
            ..valid_form()
        };
        assert_eq!(parse(form).unwrap_err().code, ErrorCode::InvalidRequest);
    }

    // ---- status mapping (ADR-13's documented deviation) -------------------

    #[test]
    fn a_refused_subject_token_is_403_not_400() {
        // CLAUDE.md invariant 2's regression test asserts 403 for a replayed
        // apiserver-audience token; this is where that number is decided.
        assert_eq!(ErrorCode::InvalidGrant.status(), 403);
        assert_eq!(ErrorCode::InvalidGrant.as_str(), "invalid_grant");
    }

    #[test]
    fn protocol_errors_keep_the_oauth_default_of_400() {
        for code in [
            ErrorCode::InvalidRequest,
            ErrorCode::UnsupportedGrantType,
            ErrorCode::InvalidScope,
            ErrorCode::InvalidTarget,
        ] {
            assert_eq!(code.status(), 400, "{code:?} should be a 400");
        }
    }

    #[test]
    fn error_bodies_are_rfc6749_shaped() {
        let err = ExchangeError::new(ErrorCode::InvalidGrant, "audience mismatch");
        assert_eq!(
            serde_json::to_value(err.body()).unwrap(),
            serde_json::json!({
                "error": "invalid_grant",
                "error_description": "audience mismatch",
            })
        );
    }

    #[test]
    fn success_bodies_are_rfc8693_shaped() {
        let response = TokenExchangeResponse::new(
            "cognito.access.token".into(),
            842,
            Some("payments/read".into()),
        );
        assert_eq!(
            serde_json::to_value(&response).unwrap(),
            serde_json::json!({
                "access_token": "cognito.access.token",
                "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "token_type": "Bearer",
                "expires_in": 842,
                "scope": "payments/read",
            })
        );
    }

    #[test]
    fn error_descriptions_never_echo_the_subject_token() {
        // An error body is the one part of a rejected request most likely to
        // be logged by the caller. It must not carry the credential back.
        let token = "eyJhbGciOiJSUzI1NiJ9.sensitive.sig";
        let forms = [
            TokenExchangeForm {
                grant_type: Some("client_credentials".into()),
                ..valid_form()
            },
            TokenExchangeForm {
                subject_token_type: Some("wrong".into()),
                ..valid_form()
            },
            TokenExchangeForm {
                resource: Some("https://x".into()),
                ..valid_form()
            },
            TokenExchangeForm {
                actor_token: Some(token.into()),
                ..valid_form()
            },
        ];
        for form in forms {
            let err = parse(form).unwrap_err();
            let body = serde_json::to_string(&err.body()).unwrap();
            assert!(
                !body.contains("sensitive"),
                "error body leaked the subject token: {body}"
            );
        }
    }
}
