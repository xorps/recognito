//! AWS IAM role principals: the identity behind the SigV4 door (ADR-15).
//!
//! A workload outside Kubernetes proves who it is by having STS answer
//! `GetCallerIdentity` for a request it signed. STS answers with an
//! *assumed-role* ARN; a mapping names a *role* ARN. This module is the one
//! place that turns both into the same key, [`AwsRoleIdentity`], so the
//! broker's index and the controller's validation cannot disagree about what
//! "the same role" means.
//!
//! # Why the key drops the role path
//!
//! `arn:aws:iam::111122223333:role/team/payments` assumes into
//! `arn:aws:sts::111122223333:assumed-role/payments/<session>` — STS omits the
//! path. Matching on `(partition, account, role name)` is still exact, because
//! IAM role names are unique within an account regardless of path.
//!
//! # Why only roles
//!
//! IAM users authenticate with long-lived access keys, which is precisely the
//! distributed-secret problem this system exists to remove; root is root; and
//! a `federated-user` is a GetFederationToken session minted from IAM-user
//! credentials. Every workload runtime worth supporting off-cluster — EC2
//! instance profiles, ECS task roles, Lambda execution roles, IAM Roles
//! Anywhere — presents an assumed role. Anything else is refused.

use std::fmt;

/// `(partition, account, role name)`: what a mapping authorizes and what a
/// verified SigV4 caller is looked up by.
///
/// Compared byte-exact. IAM treats role names case-insensitively for
/// uniqueness, but a spec spelling a role in a different case from the one it
/// was created with fails closed, which is the right direction to be wrong in.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AwsRoleIdentity {
    pub partition: String,
    pub account_id: String,
    pub role_name: String,
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum AwsArnError {
    #[error("not an ARN: expected arn:<partition>:<service>:<region>:<account>:<resource>")]
    NotAnArn,
    #[error("partition {0:?} is not an AWS partition")]
    InvalidPartition(String),
    #[error("account {0:?} is not a 12-digit AWS account ID")]
    InvalidAccountId(String),
    #[error("expected an IAM role ARN (arn:<partition>:iam::<account>:role/[<path>/]<name>)")]
    NotARoleArn,
    #[error("role path must be printable ASCII with no empty segments and at most 512 bytes")]
    InvalidRolePath,
    #[error("role name must be 1-64 characters from [A-Za-z0-9+=,.@_-]")]
    InvalidRoleName,
    #[error(
        "caller is an AWS {0}, not an assumed role; only role sessions may exchange for Cognito tokens"
    )]
    UnsupportedPrincipal(&'static str),
}

impl AwsArnError {
    /// Stable, low-cardinality label for metrics.
    pub fn reason(&self) -> &'static str {
        match self {
            AwsArnError::NotAnArn => "not_an_arn",
            AwsArnError::InvalidPartition(_) => "invalid_partition",
            AwsArnError::InvalidAccountId(_) => "invalid_account_id",
            AwsArnError::NotARoleArn => "not_a_role_arn",
            AwsArnError::InvalidRolePath => "invalid_role_path",
            AwsArnError::InvalidRoleName => "invalid_role_name",
            AwsArnError::UnsupportedPrincipal(_) => "unsupported_principal",
        }
    }
}

impl AwsRoleIdentity {
    /// Parse the role ARN a mapping declares (`spec.awsRole.arn`).
    pub fn from_role_arn(arn: &str) -> Result<Self, AwsArnError> {
        let parts = ArnParts::split(arn)?;
        if parts.service != "iam" || !parts.region.is_empty() {
            return Err(AwsArnError::NotARoleArn);
        }
        let path_and_name = parts
            .resource
            .strip_prefix("role/")
            .ok_or(AwsArnError::NotARoleArn)?;
        let (path, name) = match path_and_name.rsplit_once('/') {
            Some((path, name)) => (Some(path), name),
            None => (None, path_and_name),
        };
        if let Some(path) = path
            && !is_valid_role_path(path)
        {
            return Err(AwsArnError::InvalidRolePath);
        }
        if !is_valid_role_name(name) {
            return Err(AwsArnError::InvalidRoleName);
        }
        Ok(AwsRoleIdentity {
            partition: parts.partition.to_owned(),
            account_id: parts.account_id.to_owned(),
            role_name: name.to_owned(),
        })
    }

    /// Parse the `Arn` that STS `GetCallerIdentity` returned.
    ///
    /// Strict for the same reason as `ServiceAccountIdentity::from_sub`: a
    /// caller ARN of a shape we do not understand is refused, not guessed at.
    pub fn from_caller_arn(arn: &str) -> Result<Self, AwsArnError> {
        let parts = ArnParts::split(arn)?;
        if !parts.region.is_empty() {
            return Err(AwsArnError::NotAnArn);
        }
        match (parts.service, parts.resource) {
            ("sts", resource) if resource.starts_with("assumed-role/") => {}
            ("sts", resource) if resource.starts_with("federated-user/") => {
                return Err(AwsArnError::UnsupportedPrincipal("federated user"));
            }
            ("iam", "root") => return Err(AwsArnError::UnsupportedPrincipal("account root")),
            ("iam", resource) if resource.starts_with("user/") => {
                return Err(AwsArnError::UnsupportedPrincipal("IAM user"));
            }
            _ => return Err(AwsArnError::UnsupportedPrincipal("unrecognized principal")),
        }

        // assumed-role/<name>/<session>. Session names may not contain '/', so
        // exactly two segments follow the prefix.
        let rest = &parts.resource["assumed-role/".len()..];
        let (name, session) = rest.split_once('/').ok_or(AwsArnError::NotAnArn)?;
        if session.is_empty() || session.contains('/') {
            return Err(AwsArnError::NotAnArn);
        }
        if !is_valid_role_name(name) {
            return Err(AwsArnError::InvalidRoleName);
        }
        Ok(AwsRoleIdentity {
            partition: parts.partition.to_owned(),
            account_id: parts.account_id.to_owned(),
            role_name: name.to_owned(),
        })
    }
}

/// Path-less role ARN. Two role ARNs that differ only in path display the same
/// here because they *are* the same role.
impl fmt::Display for AwsRoleIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "arn:{}:iam::{}:role/{}",
            self.partition, self.account_id, self.role_name
        )
    }
}

struct ArnParts<'a> {
    partition: &'a str,
    service: &'a str,
    region: &'a str,
    account_id: &'a str,
    resource: &'a str,
}

impl<'a> ArnParts<'a> {
    fn split(arn: &'a str) -> Result<Self, AwsArnError> {
        let mut it = arn.splitn(6, ':');
        let (Some("arn"), Some(partition), Some(service), Some(region), Some(account), Some(rest)) = (
            it.next(),
            it.next(),
            it.next(),
            it.next(),
            it.next(),
            it.next(),
        ) else {
            return Err(AwsArnError::NotAnArn);
        };
        if !is_aws_partition(partition) {
            return Err(AwsArnError::InvalidPartition(partition.to_owned()));
        }
        if account.len() != 12 || !account.bytes().all(|b| b.is_ascii_digit()) {
            return Err(AwsArnError::InvalidAccountId(account.to_owned()));
        }
        Ok(ArnParts {
            partition,
            service,
            region,
            account_id: account,
            resource: rest,
        })
    }
}

/// `aws`, `aws-cn`, `aws-us-gov`, `aws-iso-b`, ...
fn is_aws_partition(p: &str) -> bool {
    p == "aws"
        || p.strip_prefix("aws-").is_some_and(|rest| {
            rest.split('-')
                .all(|seg| !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_lowercase()))
        })
}

/// IAM: `[\w+=,.@-]{1,64}`.
pub(crate) fn is_valid_role_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+=,.@_-".contains(&b))
}

/// The `<path>` between `role/` and the name, without its outer slashes:
/// `team/payments` for `role/team/payments/name`.
fn is_valid_role_path(path: &str) -> bool {
    path.len() <= 510
        && path
            .split('/')
            .all(|seg| !seg.is_empty() && seg.bytes().all(|b| (0x21..=0x7e).contains(&b)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn role(account: &str, name: &str) -> AwsRoleIdentity {
        AwsRoleIdentity {
            partition: "aws".into(),
            account_id: account.into(),
            role_name: name.into(),
        }
    }

    #[test]
    fn a_role_arn_and_its_assumed_role_session_are_the_same_identity() {
        let declared =
            AwsRoleIdentity::from_role_arn("arn:aws:iam::111122223333:role/payments").unwrap();
        let caller = AwsRoleIdentity::from_caller_arn(
            "arn:aws:sts::111122223333:assumed-role/payments/i-0abc123",
        )
        .unwrap();
        assert_eq!(declared, caller);
        assert_eq!(declared, role("111122223333", "payments"));
    }

    #[test]
    fn the_role_path_is_dropped_because_sts_drops_it() {
        let declared =
            AwsRoleIdentity::from_role_arn("arn:aws:iam::111122223333:role/team/svc/payments")
                .unwrap();
        let caller = AwsRoleIdentity::from_caller_arn(
            "arn:aws:sts::111122223333:assumed-role/payments/session",
        )
        .unwrap();
        assert_eq!(declared, caller);
        assert_eq!(
            declared.to_string(),
            "arn:aws:iam::111122223333:role/payments"
        );
    }

    #[test]
    fn non_commercial_partitions_are_kept_distinct() {
        let gov = AwsRoleIdentity::from_caller_arn(
            "arn:aws-us-gov:sts::111122223333:assumed-role/payments/s",
        )
        .unwrap();
        assert_eq!(gov.partition, "aws-us-gov");
        assert_ne!(gov, role("111122223333", "payments"));
    }

    #[test]
    fn principals_holding_long_lived_or_root_credentials_are_refused() {
        for (arn, reason) in [
            (
                "arn:aws:iam::111122223333:user/deploy-bot",
                "unsupported_principal",
            ),
            ("arn:aws:iam::111122223333:root", "unsupported_principal"),
            (
                "arn:aws:sts::111122223333:federated-user/bob",
                "unsupported_principal",
            ),
        ] {
            let err = AwsRoleIdentity::from_caller_arn(arn).unwrap_err();
            assert_eq!(err.reason(), reason, "{arn}");
        }
    }

    #[test]
    fn malformed_caller_arns_are_refused() {
        for arn in [
            "",
            "arn:aws:sts::111122223333:assumed-role/payments",
            "arn:aws:sts::111122223333:assumed-role/payments/",
            "arn:aws:sts::111122223333:assumed-role/payments/a/b",
            "arn:aws:sts:us-east-1:111122223333:assumed-role/payments/s",
            "arn:aws:sts::11112222333:assumed-role/payments/s",
            "arn:evil:sts::111122223333:assumed-role/payments/s",
            "arn:aws:sts::111122223333:assumed-role/pay ments/s",
        ] {
            assert!(
                AwsRoleIdentity::from_caller_arn(arn).is_err(),
                "{arn:?} should be refused"
            );
        }
    }

    #[test]
    fn malformed_role_arns_are_refused() {
        for (arn, reason) in [
            ("arn:aws:iam::111122223333:user/payments", "not_a_role_arn"),
            ("arn:aws:sts::111122223333:role/payments", "not_a_role_arn"),
            (
                "arn:aws:iam:us-east-1:111122223333:role/payments",
                "not_a_role_arn",
            ),
            ("arn:aws:iam::abc:role/payments", "invalid_account_id"),
            ("arn:aws:iam::111122223333:role/", "invalid_role_name"),
            (
                "arn:aws:iam::111122223333:role/team//payments",
                "invalid_role_path",
            ),
            (
                "arn:aws:iam::111122223333:role/pay*ments",
                "invalid_role_name",
            ),
            (
                "arn:AWS:iam::111122223333:role/payments",
                "invalid_partition",
            ),
        ] {
            let err = AwsRoleIdentity::from_role_arn(arn).unwrap_err();
            assert_eq!(err.reason(), reason, "{arn}");
        }
    }

    #[test]
    fn role_names_compare_byte_exact() {
        // IAM forbids two roles differing only by case, so this never splits one
        // real role into two identities — it only fails a mis-cased spec closed.
        let declared =
            AwsRoleIdentity::from_role_arn("arn:aws:iam::111122223333:role/Payments").unwrap();
        let caller =
            AwsRoleIdentity::from_caller_arn("arn:aws:sts::111122223333:assumed-role/payments/s")
                .unwrap();
        assert_ne!(declared, caller);
    }
}
