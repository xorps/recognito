//! Resync discipline (CLAUDE.md invariant 4).
//!
//! The controller is woken by every watch event and by the periodic relist,
//! which at fleet scale is a great many wakeups per mapping per hour. If each
//! of those consulted Cognito, the account-wide 15 RPS `UserPoolClientRead`
//! budget — and its tighter 5 RPS per-(operation, pool) sibling — would be
//! spent on discovering that nothing changed.
//!
//! So reconcile decides from CRD status alone. `specHash` says "we applied
//! this"; `lastVerified` says "we have since seen it is still true". When both
//! hold, reconcile does nothing at all. When only the hash holds, the mapping
//! is handed to the slow audit loop rather than verified inline — drift
//! detection is that loop's job, at 1-2 RPS, and it must never migrate onto
//! the reconcile path.

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use k8s_openapi::jiff::Timestamp;

use recognito_api::{CognitoClientMappingSpec, CognitoClientMappingStatus};

/// How long a verification stays good before the audit loop should revisit.
pub const DEFAULT_VERIFICATION_TTL_SECS: i64 = 24 * 60 * 60;

/// What reconcile should do, decided without talking to AWS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// No app client yet.
    CreateClient,
    /// The spec changed since we last applied it.
    ApplySpec { from: Option<String>, to: String },
    /// Secret is older than `rotateAfter`. Time-triggered, not resync-triggered.
    RotateSecret,
    /// A rotation's grace window has passed: delete the previous secret.
    RetireSecret { secret_id: String },
    /// Everything matches and verification is recent. The whole point.
    Skip,
    /// Applied state matches, but we have not confirmed it lately. Hand to the
    /// rate-limited audit loop; do **not** call Cognito from here.
    DeferToAudit { last_verified: Option<Time> },
}

impl Action {
    /// Whether taking this action costs a call against an AWS quota. The
    /// invariant is that a steady-state resync never returns one of these.
    pub fn costs_aws_call(&self) -> bool {
        match self {
            Action::CreateClient
            | Action::ApplySpec { .. }
            | Action::RotateSecret
            | Action::RetireSecret { .. } => true,
            Action::Skip | Action::DeferToAudit { .. } => false,
        }
    }
}

/// Age in whole seconds of `earlier` as of `now`. Negative if `earlier` is in
/// the future, which a clock skew between the apiserver and this process can
/// produce; the callers below treat that as "not yet due", which is the safe
/// direction for both rotation and verification.
fn age_secs(now: Timestamp, earlier: Timestamp) -> i64 {
    now.as_second() - earlier.as_second()
}

/// Decide what to do with one mapping.
///
/// Pure and total: every input is already in hand from the informer cache, so
/// this is a function of CRD state and the clock, and can be exhaustively
/// tested without a cluster or an AWS account.
pub fn decide(
    spec: &CognitoClientMappingSpec,
    status: &CognitoClientMappingStatus,
    now: Timestamp,
    verification_ttl_secs: i64,
) -> Action {
    if status.client_id.is_none() {
        return Action::CreateClient;
    }

    let desired = spec.spec_hash();
    if status.spec_hash.as_deref() != Some(desired.as_str()) {
        return Action::ApplySpec {
            from: status.spec_hash.clone(),
            to: desired,
        };
    }

    // Rotation is driven by the secret's age against the spec's policy, so it
    // is a legitimate scheduled write rather than a resync-induced read. Its
    // second half — retiring the old secret — is scheduled the same way, and
    // blocks the next rotation: Cognito holds at most two secrets per client.
    if let Some(retiring) = &status.retiring_secret_id {
        if status
            .retire_after
            .as_ref()
            .is_none_or(|t| age_secs(now, t.0) >= 0)
        {
            return Action::RetireSecret {
                secret_id: retiring.clone(),
            };
        }
    } else if let Some(created) = &status.secret_created_at
        && age_secs(now, created.0) >= spec.rotate_after.as_secs() as i64
    {
        return Action::RotateSecret;
    }

    match &status.last_verified {
        Some(verified) if age_secs(now, verified.0) < verification_ttl_secs => Action::Skip,
        other => Action::DeferToAudit {
            last_verified: other.clone(),
        },
    }
}

/// Seconds until the next time-triggered action (retirement or rotation) is
/// due, for requeueing. `None` when nothing is scheduled.
pub fn next_due_secs(
    spec: &CognitoClientMappingSpec,
    status: &CognitoClientMappingStatus,
    now: Timestamp,
) -> Option<i64> {
    let retire = status
        .retire_after
        .as_ref()
        .filter(|_| status.retiring_secret_id.is_some())
        .map(|t| -age_secs(now, t.0));
    // A pending retirement blocks rotation, so an overdue rotation must not
    // count as due — that would requeue in a hot loop until the grace ends.
    let rotate = status
        .secret_created_at
        .as_ref()
        .filter(|_| status.retiring_secret_id.is_none())
        .map(|t| spec.rotate_after.as_secs() as i64 - age_secs(now, t.0));
    retire.into_iter().chain(rotate).min().map(|s| s.max(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use recognito_api::crd::ServiceAccountRef;
    use recognito_api::{Duration, ScopeProfile};

    const HOUR: i64 = 3_600;
    const DAY: i64 = 24 * HOUR;

    /// 2026-08-08T12:00:00Z, chosen only so the arithmetic below reads easily.
    fn now() -> Timestamp {
        Timestamp::from_second(1_786_291_200).unwrap()
    }

    fn ago(seconds: i64) -> Time {
        Time(Timestamp::from_second(now().as_second() - seconds).unwrap())
    }

    fn spec() -> CognitoClientMappingSpec {
        CognitoClientMappingSpec {
            service_account_ref: Some(ServiceAccountRef {
                name: "payments".into(),
            }),
            aws_role: None,
            user_pool_id: "us-east-1_aBcDeFgHi".into(),
            allowed_scopes: vec![ScopeProfile {
                name: "read".into(),
                scopes: vec!["payments/read".into()],
            }],
            token_validity: Duration::from_secs(900),
            rotate_after: Duration::from_secs(90 * 24 * 60 * 60),
            deliver_to: None,
        }
    }

    /// Status of a mapping that is fully reconciled as of `verified_secs_ago`.
    fn settled(
        spec: &CognitoClientMappingSpec,
        verified_secs_ago: i64,
    ) -> CognitoClientMappingStatus {
        CognitoClientMappingStatus {
            client_id: Some("1example23client45id".into()),
            spec_hash: Some(spec.spec_hash()),
            last_verified: Some(ago(verified_secs_ago)),
            secret_created_at: Some(ago(DAY)),
            secret_generation: Some(1),
            ..Default::default()
        }
    }

    #[test]
    fn steady_state_resync_costs_nothing() {
        // The invariant, stated as a test: a mapping that is applied and
        // recently verified produces no AWS call, no matter how often the
        // informer wakes us.
        let spec = spec();
        let status = settled(&spec, HOUR);
        let action = decide(&spec, &status, now(), DEFAULT_VERIFICATION_TTL_SECS);
        assert_eq!(action, Action::Skip);
        assert!(!action.costs_aws_call());
    }

    #[test]
    fn a_mapping_with_no_client_is_created() {
        let spec = spec();
        let status = CognitoClientMappingStatus::default();
        assert_eq!(
            decide(&spec, &status, now(), DEFAULT_VERIFICATION_TTL_SECS),
            Action::CreateClient
        );
    }

    #[test]
    fn a_changed_spec_is_applied() {
        let spec = spec();
        let mut changed = spec.clone();
        changed.token_validity = Duration::from_secs(1800);
        let status = settled(&spec, HOUR);

        match decide(&changed, &status, now(), DEFAULT_VERIFICATION_TTL_SECS) {
            Action::ApplySpec { from, to } => {
                assert_eq!(from, Some(spec.spec_hash()));
                assert_eq!(to, changed.spec_hash());
            }
            other => panic!("expected ApplySpec, got {other:?}"),
        }
    }

    #[test]
    fn stale_verification_defers_to_the_audit_loop_instead_of_calling_aws() {
        // The distinction invariant 4 turns on: we are *not* confident the
        // mapping is still correct, and we still do not call Cognito here.
        // The rate-limited audit loop owns that call.
        let spec = spec();
        let status = settled(&spec, 3 * DAY);
        let action = decide(&spec, &status, now(), DEFAULT_VERIFICATION_TTL_SECS);

        assert!(matches!(action, Action::DeferToAudit { .. }));
        assert!(
            !action.costs_aws_call(),
            "drift detection must never run on the reconcile hot path"
        );
    }

    #[test]
    fn never_verified_also_defers_rather_than_verifying_inline() {
        let spec = spec();
        let mut status = settled(&spec, 0);
        status.last_verified = None;
        assert_eq!(
            decide(&spec, &status, now(), DEFAULT_VERIFICATION_TTL_SECS),
            Action::DeferToAudit {
                last_verified: None
            }
        );
    }

    #[test]
    fn rotation_fires_on_secret_age_not_on_resync() {
        let mut spec = spec();
        spec.rotate_after = Duration::from_secs(DAY as u64);
        let mut status = settled(&spec, HOUR);

        // One day old, rotateAfter one day: due.
        status.secret_created_at = Some(ago(DAY));
        assert_eq!(
            decide(&spec, &status, now(), DEFAULT_VERIFICATION_TTL_SECS),
            Action::RotateSecret
        );

        // An hour old: not due, and the resync still costs nothing.
        status.secret_created_at = Some(ago(HOUR));
        assert_eq!(
            decide(&spec, &status, now(), DEFAULT_VERIFICATION_TTL_SECS),
            Action::Skip
        );
    }

    #[test]
    fn spec_changes_outrank_rotation() {
        // Rotating a secret onto a client we are about to reconfigure wastes
        // an UpdateUserPoolClient call against a 15 RPS budget.
        let spec = spec();
        let mut changed = spec.clone();
        changed.rotate_after = Duration::from_secs(HOUR as u64);
        let mut status = settled(&spec, HOUR);
        status.secret_created_at = Some(ago(30 * DAY));

        assert!(matches!(
            decide(&changed, &status, now(), DEFAULT_VERIFICATION_TTL_SECS),
            Action::ApplySpec { .. }
        ));
    }

    #[test]
    fn a_secret_timestamp_in_the_future_does_not_trigger_rotation() {
        // Clock skew between the apiserver and this process must not cause a
        // rotation storm against the 15 RPS update budget.
        let mut spec = spec();
        spec.rotate_after = Duration::from_secs(DAY as u64);
        let mut status = settled(&spec, HOUR);
        status.secret_created_at = Some(ago(-HOUR));
        assert_eq!(
            decide(&spec, &status, now(), DEFAULT_VERIFICATION_TTL_SECS),
            Action::Skip
        );
    }

    #[test]
    fn repeated_resyncs_of_an_unchanged_mapping_are_all_free() {
        // The scale property: 1000 wakeups, zero AWS calls.
        let spec = spec();
        let status = settled(&spec, HOUR);
        for i in 0..1000 {
            let t = Timestamp::from_second(now().as_second() + i).unwrap();
            assert!(!decide(&spec, &status, t, DEFAULT_VERIFICATION_TTL_SECS).costs_aws_call());
        }
    }

    #[test]
    fn a_pending_retirement_waits_for_its_grace_window() {
        let spec = spec();
        let mut status = settled(&spec, HOUR);
        status.retiring_secret_id = Some("old".into());
        status.retire_after = Some(ago(-60));
        // Not due yet, and no new rotation may start meanwhile even though the
        // secret is old enough.
        status.secret_created_at = Some(ago(365 * DAY));
        assert_eq!(
            decide(&spec, &status, now(), DEFAULT_VERIFICATION_TTL_SECS),
            Action::Skip
        );
        assert_eq!(next_due_secs(&spec, &status, now()), Some(60));

        status.retire_after = Some(ago(1));
        assert_eq!(
            decide(&spec, &status, now(), DEFAULT_VERIFICATION_TTL_SECS),
            Action::RetireSecret {
                secret_id: "old".into()
            }
        );
    }

    #[test]
    fn next_due_is_the_rotation_time_when_nothing_is_retiring() {
        let spec = spec();
        let status = settled(&spec, HOUR);
        assert_eq!(
            next_due_secs(&spec, &status, now()),
            Some(spec.rotate_after.as_secs() as i64 - DAY)
        );
    }
}
