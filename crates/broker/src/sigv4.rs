//! SigV4 authentication for workloads outside Kubernetes (ADR-15).
//!
//! # The mechanism
//!
//! The caller presigns an STS `GetCallerIdentity` request with its own AWS
//! credentials — the same trick EKS authentication tokens and Vault's IAM auth
//! method use — and hands us the presigned URL as its subject token. We forward
//! it to STS. If STS answers, the signature was good, and STS has told us which
//! role signed it. We never see a secret key, never verify a signature
//! ourselves, and need no IAM permission of our own: `GetCallerIdentity` is
//! callable by any valid credential.
//!
//! # Audience binding, again
//!
//! A presigned `GetCallerIdentity` URL proves identity to *whoever receives
//! it*. Without a binding, a URL a workload presigned for some other verifier —
//! an EKS cluster, a Vault server, anything using this pattern — would be
//! accepted here too. That is CVE-2025-32963 in a different costume (see
//! [`crate::audience`]), so the cure is the same: the caller must sign an
//! [`AUDIENCE_HEADER`] carrying the broker audience, and we send exactly our
//! canonical audience in that header when forwarding. STS then verifies the
//! binding cryptographically — a URL signed for any other value fails the
//! signature check — and our only job is to insist the header was signed at
//! all. That check is [`SigV4Rejection::AudienceNotSigned`].
//!
//! # What else could go wrong, and did, elsewhere
//!
//! Everything below exists because a deployed system of this shape got it
//! wrong; each has a named test in `crates/broker/tests/sigv4_audience_binding.rs`.
//!
//! - **We pick the host, not the caller.** Forwarding to a caller-chosen host
//!   lets them answer `GetCallerIdentity` themselves with any ARN they like.
//!   The host must be byte-exact one of the configured regional STS endpoints.
//! - **We pick the action.** Forwarding any other STS action, whose response
//!   reflects caller-controlled data, then parsing that response leniently, is
//!   how Vault's IAM auth was bypassed (CVE-2020-16250). The query must say
//!   `Action=GetCallerIdentity` and we parse the answer as exactly the JSON
//!   shape of a `GetCallerIdentity` result, nothing more forgiving.
//! - **One spelling per parameter.** If the validator reads one copy of a
//!   duplicated parameter and STS reads another, every check here is checking
//!   the wrong thing (cf. aws-iam-authenticator CVE-2022-2385). Parameters are
//!   matched against a fixed allowlist byte-exact, so a duplicate, a
//!   case-variant, or a percent-encoded key is refused rather than
//!   interpreted.
//! - **Short-lived only.** A presigned URL is a bearer credential until it
//!   expires. We refuse lifetimes over [`MAX_PRESIGN_EXPIRES_SECS`] and check
//!   freshness before spending an STS call.

use std::collections::BTreeSet;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use recognito_api::{AwsArnError, AwsRoleIdentity};
use serde::Deserialize;

use crate::audience::CanonicalAudience;

/// The signed header that binds a presigned URL to this broker. Its value is
/// the broker's canonical audience — the same string projected ServiceAccount
/// tokens carry in `aud`.
pub const AUDIENCE_HEADER: &str = "x-recognito-audience";

/// Signed-header names other verifiers of this pattern use. A URL bound to one
/// of these was presigned for someone else and replayed at us: an attack
/// signal, like an apiserver-audience JWT.
pub const FOREIGN_BINDING_HEADERS: &[&str] = &[
    // EKS / aws-iam-authenticator cluster tokens.
    "x-k8s-aws-id",
    // HashiCorp Vault AWS IAM auth.
    "x-vault-aws-iam-server-id",
];

/// The longest presigned lifetime we accept. Matches the window
/// aws-iam-authenticator enforces; `aws eks get-token` presigns for 60s.
pub const MAX_PRESIGN_EXPIRES_SECS: u64 = 900;

/// How far in the future `X-Amz-Date` may be before the URL is refused as not
/// yet valid. Absorbs caller clock drift.
pub const MAX_CLOCK_SKEW_SECS: u64 = 300;

/// Session tokens make presigned URLs long, but not this long. Bounds the work
/// an unauthenticated caller can make us do.
pub const MAX_PRESIGNED_URL_LEN: usize = 8 * 1024;

const ALGORITHM: &str = "AWS4-HMAC-SHA256";
/// The only `X-Amz-SignedHeaders` value we accept: SigV4 requires the list
/// lowercase, sorted, and `;`-joined, and we will send exactly these two.
const REQUIRED_SIGNED_HEADERS: &str = "host;x-recognito-audience";

/// Every query parameter a conforming presigned `GetCallerIdentity` URL
/// carries. Nothing else is permitted.
const ALLOWED_PARAMS: &[&str] = &[
    "Action",
    "Version",
    "X-Amz-Algorithm",
    "X-Amz-Credential",
    "X-Amz-Date",
    "X-Amz-Expires",
    "X-Amz-SignedHeaders",
    "X-Amz-Signature",
    "X-Amz-Security-Token",
];

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SigV4ConfigError {
    #[error("region {0:?} is not an AWS region name")]
    InvalidRegion(String),
    #[error("SigV4 is enabled but no STS regions are configured")]
    NoRegions,
    #[error(
        "SigV4 is enabled but no trusted AWS accounts are configured; refusing to accept roles from every account in existence"
    )]
    NoTrustedAccounts,
    #[error("{0:?} is not a 12-digit AWS account ID")]
    InvalidAccountId(String),
}

/// A regional STS endpoint we are willing to forward to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StsEndpoint {
    region: String,
    host: String,
}

impl StsEndpoint {
    /// The regional endpoint for `region`. The global `sts.amazonaws.com` is
    /// deliberately not offered: it is a legacy alias for us-east-1, and every
    /// current SDK presigns against the regional endpoint.
    pub fn regional(region: &str) -> Result<Self, SigV4ConfigError> {
        if !is_region(region) {
            return Err(SigV4ConfigError::InvalidRegion(region.to_owned()));
        }
        let suffix = if region.starts_with("cn-") {
            "amazonaws.com.cn"
        } else {
            "amazonaws.com"
        };
        Ok(StsEndpoint {
            region: region.to_owned(),
            host: format!("sts.{region}.{suffix}"),
        })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn region(&self) -> &str {
        &self.region
    }
}

/// Why a SigV4 subject token was refused. Like [`crate::AudienceRejection`],
/// each variant is a separate counter and [`Self::reason`] never carries
/// caller-supplied text.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SigV4Rejection {
    #[error("presigned URL exceeds {MAX_PRESIGNED_URL_LEN} bytes")]
    TooLarge,
    #[error("presigned URL is not of the form https://<sts-host>/?<query>")]
    Malformed,
    #[error(
        "presigned URL targets a host that is not a configured STS endpoint; the broker chooses where to forward"
    )]
    UntrustedHost,
    #[error("query parameter {key:?} is not part of a presigned GetCallerIdentity request")]
    UnknownParameter { key: String },
    #[error(
        "query parameter {key:?} appears more than once; the broker and STS could disagree about which copy counts"
    )]
    DuplicateParameter { key: String },
    #[error("query parameter {key} is required")]
    MissingParameter { key: &'static str },
    #[error("query parameter {key} is not encoded as SigV4 requires")]
    BadEncoding { key: &'static str },
    #[error("presigned request is not Action=GetCallerIdentity")]
    WrongAction,
    #[error("presigned request is not Version=2011-06-15")]
    WrongVersion,
    #[error("X-Amz-Algorithm must be {ALGORITHM}")]
    UnsupportedAlgorithm,
    #[error(
        "presigned URL is bound to another verifier via {header:?}: a token minted for someone else was replayed at the broker"
    )]
    ForeignVerifier { header: &'static str },
    #[error(
        "the {AUDIENCE_HEADER} header is not signed, so the URL is not bound to this broker and could have been minted for anyone"
    )]
    AudienceNotSigned,
    #[error("X-Amz-SignedHeaders must be exactly {REQUIRED_SIGNED_HEADERS:?}")]
    UnexpectedSignedHeaders,
    #[error(
        "X-Amz-Credential scope is not <key>/<date>/<region>/sts/aws4_request for this endpoint"
    )]
    CredentialScope,
    #[error("X-Amz-Date is not a valid YYYYMMDD'T'HHMMSS'Z' timestamp")]
    MalformedDate,
    #[error("X-Amz-Expires must be between 1 and {MAX_PRESIGN_EXPIRES_SECS} seconds")]
    LifetimeTooLong,
    #[error("presigned URL is dated in the future beyond the permitted clock skew")]
    NotYetValid,
    #[error("presigned URL has expired")]
    Expired,
    #[error("STS refused the signed request (HTTP {status})")]
    StsRejected { status: u16 },
    #[error("caller principal is not acceptable: {0}")]
    Principal(AwsArnError),
    #[error("caller's AWS account {account:?} is not trusted by this broker")]
    UntrustedAccount { account: String },
}

impl SigV4Rejection {
    /// Stable, low-cardinality label for metrics and error bodies.
    pub fn reason(&self) -> &'static str {
        match self {
            SigV4Rejection::TooLarge => "too_large",
            SigV4Rejection::Malformed => "malformed",
            SigV4Rejection::UntrustedHost => "untrusted_host",
            SigV4Rejection::UnknownParameter { .. } => "unknown_parameter",
            SigV4Rejection::DuplicateParameter { .. } => "duplicate_parameter",
            SigV4Rejection::MissingParameter { .. } => "missing_parameter",
            SigV4Rejection::BadEncoding { .. } => "bad_encoding",
            SigV4Rejection::WrongAction => "wrong_action",
            SigV4Rejection::WrongVersion => "wrong_version",
            SigV4Rejection::UnsupportedAlgorithm => "unsupported_algorithm",
            SigV4Rejection::ForeignVerifier { .. } => "foreign_verifier",
            SigV4Rejection::AudienceNotSigned => "audience_not_signed",
            SigV4Rejection::UnexpectedSignedHeaders => "unexpected_signed_headers",
            SigV4Rejection::CredentialScope => "credential_scope",
            SigV4Rejection::MalformedDate => "malformed_date",
            SigV4Rejection::LifetimeTooLong => "lifetime_too_long",
            SigV4Rejection::NotYetValid => "not_yet_valid",
            SigV4Rejection::Expired => "expired",
            SigV4Rejection::StsRejected { .. } => "sts_rejected",
            SigV4Rejection::Principal(_) => "unsupported_principal",
            SigV4Rejection::UntrustedAccount { .. } => "untrusted_account",
        }
    }

    /// Whether this looks like probing rather than misconfiguration. No
    /// conforming SDK produces any of these by accident.
    pub fn is_attack_signal(&self) -> bool {
        matches!(
            self,
            SigV4Rejection::UntrustedHost
                | SigV4Rejection::UnknownParameter { .. }
                | SigV4Rejection::DuplicateParameter { .. }
                | SigV4Rejection::WrongAction
                | SigV4Rejection::ForeignVerifier { .. }
        )
    }
}

/// Outcome of forwarding to STS when it is not a clean answer.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StsError {
    /// The caller's request was refused. Their problem; 403.
    #[error(transparent)]
    Rejected(#[from] SigV4Rejection),
    /// STS throttled us or failed. Not the caller's fault; retryable.
    #[error("STS unavailable (HTTP {status})")]
    Unavailable { status: u16 },
    /// No answer at all: timeout, connection failure, oversized body.
    #[error("STS unreachable")]
    Unreachable,
    /// STS said 200 but the body is not a `GetCallerIdentity` result. Never
    /// interpreted further — see the CVE-2020-16250 note in the module docs.
    #[error("STS returned an unexpected response: {0}")]
    InvalidResponse(&'static str),
}

/// A presigned URL that passed every check we can make without STS. Still
/// entirely unauthenticated: only STS can say whether the signature is good.
///
/// `Debug` redacts the URL — it carries a session token and a signature, and
/// is a bearer credential until it expires.
#[derive(Clone, PartialEq, Eq)]
pub struct PresignedCallerIdentity {
    url: String,
    /// The access key ID, for the audit log. Key IDs are identifiers, not
    /// secrets, and correlate with CloudTrail.
    pub access_key_id: String,
    pub region: String,
    /// Unix seconds after which the URL is dead.
    pub expires_at: u64,
}

impl fmt::Debug for PresignedCallerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PresignedCallerIdentity")
            .field("url", &"<redacted>")
            .field("access_key_id", &self.access_key_id)
            .field("region", &self.region)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// The request to send to STS. The HTTP layer must send it as given and must
/// **not** follow redirects: a 3xx is reported as [`StsError::InvalidResponse`].
#[derive(Debug)]
pub struct StsForwardRequest<'a> {
    pub method: &'static str,
    /// The caller's URL, verbatim. Re-encoding it would break the signature.
    pub url: &'a str,
    pub headers: [(&'static str, String); 2],
}

/// A caller STS has vouched for, and who passed our account and principal
/// policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAwsCaller {
    pub identity: AwsRoleIdentity,
    /// The full assumed-role ARN, session name included, for the audit log.
    pub caller_arn: String,
    /// `AROA…:<session>`; the role's unique ID survives role re-creation under
    /// the same name, so it is worth logging even though we do not bind to it.
    pub user_id: String,
}

/// The SigV4 policy: our audience, where we forward, and whose roles we trust.
#[derive(Clone, Debug)]
pub struct SigV4Validator {
    audience: CanonicalAudience,
    endpoints: Vec<StsEndpoint>,
    trusted_accounts: BTreeSet<String>,
}

impl SigV4Validator {
    /// `trusted_accounts` is mandatory and non-empty.
    ///
    /// The account is already part of the identity key, so a stranger's role
    /// can only match a mapping that names the stranger's account. The point
    /// of the allowlist is *who* gets to decide that: mappings are written by
    /// namespace tenants, and a role mapping can name any account in
    /// existence. This list is the platform operator's boundary, set on the
    /// broker, that no mapping author can widen — and it turns a fat-fingered
    /// account ID in a mapping into a refusal rather than a grant.
    pub fn new<A, S>(
        audience: CanonicalAudience,
        endpoints: Vec<StsEndpoint>,
        trusted_accounts: A,
    ) -> Result<Self, SigV4ConfigError>
    where
        A: IntoIterator<Item = S>,
        S: Into<String>,
    {
        if endpoints.is_empty() {
            return Err(SigV4ConfigError::NoRegions);
        }
        let trusted_accounts: BTreeSet<String> =
            trusted_accounts.into_iter().map(Into::into).collect();
        if trusted_accounts.is_empty() {
            return Err(SigV4ConfigError::NoTrustedAccounts);
        }
        if let Some(bad) = trusted_accounts
            .iter()
            .find(|a| a.len() != 12 || !a.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err(SigV4ConfigError::InvalidAccountId(bad.clone()));
        }
        Ok(SigV4Validator {
            audience,
            endpoints,
            trusted_accounts,
        })
    }

    pub fn audience(&self) -> &CanonicalAudience {
        &self.audience
    }

    pub fn endpoints(&self) -> &[StsEndpoint] {
        &self.endpoints
    }

    /// Check everything about a presigned URL that can be checked without STS.
    ///
    /// Order is cheap-and-structural first, then policy, then time — so a
    /// replayed foreign token is reported as such even if it is also stale.
    pub fn validate_presigned(
        &self,
        url: &str,
        now: SystemTime,
    ) -> Result<PresignedCallerIdentity, SigV4Rejection> {
        if url.len() > MAX_PRESIGNED_URL_LEN {
            return Err(SigV4Rejection::TooLarge);
        }
        let rest = url
            .strip_prefix("https://")
            .ok_or(SigV4Rejection::Malformed)?;
        let (authority, query) = rest.split_once("/?").ok_or(SigV4Rejection::Malformed)?;
        // Byte-exact against configured hosts. This alone rules out userinfo,
        // ports, IP literals, case variants, and trailing-dot spellings, since
        // none of them is equal to a configured host.
        let endpoint = self
            .endpoints
            .iter()
            .find(|e| e.host == authority)
            .ok_or(SigV4Rejection::UntrustedHost)?;

        let params = Query::parse(query)?;

        if params.raw("Action")? != "GetCallerIdentity" {
            return Err(SigV4Rejection::WrongAction);
        }
        if params.raw("Version")? != "2011-06-15" {
            return Err(SigV4Rejection::WrongVersion);
        }
        if params.decoded("X-Amz-Algorithm")? != ALGORITHM {
            return Err(SigV4Rejection::UnsupportedAlgorithm);
        }

        let signed_headers = params.decoded("X-Amz-SignedHeaders")?;
        let signed: Vec<&str> = signed_headers.split(';').collect();
        if let Some(foreign) = FOREIGN_BINDING_HEADERS.iter().find(|h| signed.contains(h)) {
            return Err(SigV4Rejection::ForeignVerifier { header: foreign });
        }
        if !signed.contains(&AUDIENCE_HEADER) {
            return Err(SigV4Rejection::AudienceNotSigned);
        }
        if signed_headers != REQUIRED_SIGNED_HEADERS {
            return Err(SigV4Rejection::UnexpectedSignedHeaders);
        }

        let date = params.decoded("X-Amz-Date")?;
        let signed_at = parse_amz_date(&date).ok_or(SigV4Rejection::MalformedDate)?;

        let credential = params.decoded("X-Amz-Credential")?;
        let access_key_id = match credential.split('/').collect::<Vec<_>>()[..] {
            [key, scope_date, region, "sts", "aws4_request"]
                if !key.is_empty()
                    && key.bytes().all(|b| b.is_ascii_alphanumeric())
                    && scope_date == &date[..8]
                    && region == endpoint.region =>
            {
                key.to_owned()
            }
            _ => return Err(SigV4Rejection::CredentialScope),
        };

        // Required for the signature to mean anything; STS checks the value.
        params.raw("X-Amz-Signature")?;

        let expires = params.decoded("X-Amz-Expires")?;
        let expires: u64 = if !expires.is_empty() && expires.bytes().all(|b| b.is_ascii_digit()) {
            expires
                .parse()
                .map_err(|_| SigV4Rejection::LifetimeTooLong)?
        } else {
            return Err(SigV4Rejection::BadEncoding {
                key: "X-Amz-Expires",
            });
        };
        if !(1..=MAX_PRESIGN_EXPIRES_SECS).contains(&expires) {
            return Err(SigV4Rejection::LifetimeTooLong);
        }

        let now = now
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if signed_at > now + MAX_CLOCK_SKEW_SECS {
            return Err(SigV4Rejection::NotYetValid);
        }
        let expires_at = signed_at + expires;
        if now >= expires_at {
            return Err(SigV4Rejection::Expired);
        }

        Ok(PresignedCallerIdentity {
            url: url.to_owned(),
            access_key_id,
            region: endpoint.region.clone(),
            expires_at,
        })
    }

    /// The request that asks STS to verify `presigned`.
    ///
    /// The audience header carries *our* canonical audience, not anything the
    /// caller said. That is the whole binding: if they signed a different
    /// value, STS computes a different signature and refuses.
    ///
    /// `Accept: application/json` is unsigned (SigV4 permits extra headers)
    /// and makes STS answer in JSON, which we parse strictly instead of
    /// searching XML for an element with the right name.
    pub fn forward_request<'a>(
        &self,
        presigned: &'a PresignedCallerIdentity,
    ) -> StsForwardRequest<'a> {
        StsForwardRequest {
            method: "GET",
            url: &presigned.url,
            headers: [
                (AUDIENCE_HEADER, self.audience.as_str().to_owned()),
                ("accept", "application/json".to_owned()),
            ],
        }
    }

    /// Interpret STS's answer and apply principal and account policy.
    pub fn validate_sts_response(
        &self,
        status: u16,
        body: &[u8],
    ) -> Result<VerifiedAwsCaller, StsError> {
        match status {
            200 => {}
            // SignatureDoesNotMatch, ExpiredToken, InvalidClientTokenId, … —
            // including a URL signed for a different audience value.
            400 | 403 => return Err(SigV4Rejection::StsRejected { status }.into()),
            429 | 500..=599 => return Err(StsError::Unavailable { status }),
            300..=399 => {
                return Err(StsError::InvalidResponse(
                    "STS redirected; redirects are never followed",
                ));
            }
            _ => return Err(StsError::InvalidResponse("unexpected HTTP status")),
        }

        let parsed: GetCallerIdentityEnvelope = serde_json::from_slice(body)
            .map_err(|_| StsError::InvalidResponse("body is not a GetCallerIdentity result"))?;
        let result = parsed.response.result;

        let identity = AwsRoleIdentity::from_caller_arn(&result.arn).map_err(|e| match e {
            AwsArnError::UnsupportedPrincipal(_) => {
                StsError::Rejected(SigV4Rejection::Principal(e))
            }
            _ => StsError::InvalidResponse("Arn is not a well-formed ARN"),
        })?;
        if identity.account_id != result.account {
            return Err(StsError::InvalidResponse(
                "Account does not match the account in Arn",
            ));
        }
        if !self.trusted_accounts.contains(&identity.account_id) {
            return Err(SigV4Rejection::UntrustedAccount {
                account: identity.account_id,
            }
            .into());
        }

        Ok(VerifiedAwsCaller {
            identity,
            caller_arn: result.arn,
            user_id: result.user_id,
        })
    }
}

/// `{"GetCallerIdentityResponse": {"GetCallerIdentityResult": {...}}}`.
/// serde rejects duplicate keys at every level, so there is exactly one
/// `Arn` to read.
#[derive(Deserialize)]
struct GetCallerIdentityEnvelope {
    #[serde(rename = "GetCallerIdentityResponse")]
    response: GetCallerIdentityResponse,
}

#[derive(Deserialize)]
struct GetCallerIdentityResponse {
    #[serde(rename = "GetCallerIdentityResult")]
    result: GetCallerIdentityResult,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GetCallerIdentityResult {
    account: String,
    arn: String,
    user_id: String,
}

/// A query string in which every key is from [`ALLOWED_PARAMS`] and appears
/// once. Values are kept raw; decoding happens on read.
struct Query<'a> {
    pairs: Vec<(&'static str, &'a str)>,
}

impl<'a> Query<'a> {
    fn parse(query: &'a str) -> Result<Self, SigV4Rejection> {
        let mut pairs: Vec<(&'static str, &'a str)> = Vec::with_capacity(ALLOWED_PARAMS.len());
        for part in query.split('&') {
            let (key, value) = part.split_once('=').ok_or(SigV4Rejection::Malformed)?;
            let Some(known) = ALLOWED_PARAMS.iter().find(|k| **k == key) else {
                return Err(SigV4Rejection::UnknownParameter {
                    key: key.chars().take(64).collect(),
                });
            };
            if pairs.iter().any(|(k, _)| k == known) {
                return Err(SigV4Rejection::DuplicateParameter {
                    key: (*known).to_owned(),
                });
            }
            // Every value, not just the ones we read: an unchecked value is
            // still forwarded, and a stray '#' or '+' in it means STS and an
            // HTTP client may each see a different URL from the one we checked.
            if strict_percent_decode(value).is_none() {
                return Err(SigV4Rejection::BadEncoding { key: known });
            }
            pairs.push((known, value));
        }
        Ok(Query { pairs })
    }

    fn raw(&self, key: &'static str) -> Result<&'a str, SigV4Rejection> {
        self.pairs
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| *v)
            .ok_or(SigV4Rejection::MissingParameter { key })
    }

    fn decoded(&self, key: &'static str) -> Result<String, SigV4Rejection> {
        strict_percent_decode(self.raw(key)?).ok_or(SigV4Rejection::BadEncoding { key })
    }
}

/// Decode a value encoded the way SigV4 canonicalization requires: unreserved
/// characters literal, everything else `%XX`. Anything else — a raw `+`, `;`,
/// `/`, space, or a malformed escape — is refused, because each is a character
/// two parsers might read differently.
fn strict_percent_decode(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = bytes.get(i + 1..i + 3)?;
                let hex = std::str::from_utf8(hex).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            }
            b if b.is_ascii_alphanumeric() || b"-._~".contains(&b) => {
                out.push(b);
                i += 1;
            }
            _ => return None,
        }
    }
    String::from_utf8(out).ok()
}

/// `20261005T120000Z` → Unix seconds.
fn parse_amz_date(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() != 16 || b[8] != b'T' || b[15] != b'Z' {
        return None;
    }
    let digits = |r: std::ops::Range<usize>| -> Option<u64> {
        let part = s.get(r)?;
        part.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| part.parse().ok())?
    };
    let (y, mo, d) = (digits(0..4)?, digits(4..6)?, digits(6..8)?);
    let (h, mi, sec) = (digits(9..11)?, digits(11..13)?, digits(13..15)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 59 {
        return None;
    }
    let days = days_from_civil(y as i64, mo as i64, d as i64);
    u64::try_from(days)
        .ok()
        .map(|days| days * 86_400 + h * 3_600 + mi * 60 + sec)
}

/// Days since 1970-01-01 (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `us-east-1`, `ap-southeast-2`, `us-gov-west-1`, `cn-north-1`, ...
fn is_region(r: &str) -> bool {
    let mut parts = r.split('-').peekable();
    let mut count = 0;
    while let Some(p) = parts.next() {
        count += 1;
        let ok = if parts.peek().is_none() {
            !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())
        } else {
            !p.is_empty() && p.bytes().all(|b| b.is_ascii_lowercase())
        };
        if !ok {
            return false;
        }
    }
    count >= 3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amz_dates_parse_to_unix_seconds() {
        assert_eq!(parse_amz_date("19700101T000000Z"), Some(0));
        assert_eq!(parse_amz_date("20261005T120000Z"), Some(1_791_201_600));
        assert_eq!(parse_amz_date("20240229T000000Z"), Some(1_709_164_800));
        for bad in [
            "20261005T120000",
            "2026-10-05T12:00:00Z",
            "20261305T120000Z",
            "20261005T250000Z",
            "2026100+T120000Z",
        ] {
            assert_eq!(parse_amz_date(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn percent_decoding_refuses_ambiguous_characters() {
        assert_eq!(
            strict_percent_decode("host%3Bx-recognito-audience").as_deref(),
            Some("host;x-recognito-audience")
        );
        for bad in ["a+b", "a;b", "a/b", "a b", "%3", "%zz", "%"] {
            assert_eq!(strict_percent_decode(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn regional_endpoints_follow_the_partition_dns_suffix() {
        assert_eq!(
            StsEndpoint::regional("us-east-1").unwrap().host(),
            "sts.us-east-1.amazonaws.com"
        );
        assert_eq!(
            StsEndpoint::regional("cn-north-1").unwrap().host(),
            "sts.cn-north-1.amazonaws.com.cn"
        );
        assert_eq!(
            StsEndpoint::regional("us-gov-west-1").unwrap().host(),
            "sts.us-gov-west-1.amazonaws.com"
        );
        for bad in ["", "us-east", "US-EAST-1", "us-east-1.evil.com", "us--1"] {
            assert!(StsEndpoint::regional(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_validator_refuses_to_start_without_a_trust_boundary() {
        let audience = CanonicalAudience::parse("https://cognito-broker.example.com").unwrap();
        let endpoints = vec![StsEndpoint::regional("us-east-1").unwrap()];
        assert_eq!(
            SigV4Validator::new(audience.clone(), endpoints.clone(), Vec::<String>::new())
                .unwrap_err(),
            SigV4ConfigError::NoTrustedAccounts
        );
        assert_eq!(
            SigV4Validator::new(audience.clone(), vec![], ["111122223333"]).unwrap_err(),
            SigV4ConfigError::NoRegions
        );
        assert!(matches!(
            SigV4Validator::new(audience, endpoints, ["1111"]).unwrap_err(),
            SigV4ConfigError::InvalidAccountId(_)
        ));
    }
}
