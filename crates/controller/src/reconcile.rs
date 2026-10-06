//! Reconcile, rotate, audit, delete — as functions of (spec, status, now) and a
//! [`CognitoAdmin`]. The kube plumbing in [`crate::controller`] only reads
//! objects in and patches status out, so everything here is testable against
//! an in-memory Cognito.
//!
//! Every AWS call spends from a [`Budgets`] limiter first (invariant 3), and
//! [`crate::resync::decide`] picks the action from CRD status alone, so a
//! steady-state resync makes no AWS call at all (invariant 4).

use std::collections::BTreeSet;
use std::time::Duration;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use k8s_openapi::jiff::Timestamp;
use recognito_api::{CognitoClientMappingSpec, CognitoClientMappingStatus, RateLimiter};

use crate::cognito::{AdminError, CognitoAdmin, DesiredClient, drift};
use crate::resync::{Action, decide, next_due_secs};

/// Controller-wide knobs.
#[derive(Clone, Debug)]
pub struct Settings {
    /// Pools this controller may manage. `None`: whatever IAM allows.
    pub allowed_pools: Option<BTreeSet<String>>,
    /// Old secret's lifetime after a rotation. Must exceed the time for a
    /// `secretGeneration` bump to reach every broker replica via the watch —
    /// seconds in practice; minutes for margin.
    pub rotation_grace: Duration,
    pub verification_ttl_secs: i64,
}

/// The controller's slices of the Cognito budgets. Reads (`Describe`/`List*`)
/// share the 5 RPS per-(operation, pool) `UserPoolClientRead` budget with the
/// broker; writes spend `UserPoolClientUpdate`, which the broker never uses.
pub struct Budgets {
    pub reads: RateLimiter,
    pub writes: RateLimiter,
}

impl Budgets {
    async fn read(&self) {
        acquire(&self.reads).await;
    }

    async fn write(&self) {
        acquire(&self.writes).await;
    }

    /// Account-wide budgets: on a throttle, yield (invariant 3).
    pub fn yield_after_throttle(&self) {
        self.reads.back_off(Duration::from_secs(30));
        self.writes.back_off(Duration::from_secs(30));
    }
}

async fn acquire(limiter: &RateLimiter) {
    while let Err(wait) = limiter.try_acquire() {
        tokio::time::sleep(wait).await;
    }
}

/// Identity of the object being reconciled.
#[derive(Clone, Debug)]
pub struct MappingRef {
    pub namespace: String,
    pub name: String,
    pub uid: String,
    pub generation: Option<i64>,
}

/// What reconcile decided: the status to write (written only if it differs),
/// when to look again, and a label for metrics.
#[derive(Debug)]
pub struct Plan {
    pub status: CognitoClientMappingStatus,
    pub requeue: Option<Duration>,
    pub action: &'static str,
}

/// One message for every healthy state, so a mapping that stays healthy
/// keeps a byte-identical status and costs no writes.
const PROVISIONED: &str = "app client provisioned";

/// How long to wait before retrying a spec Cognito refused as invalid.
/// Editing the mapping triggers an immediate reconcile regardless.
pub const REJECTED_RETRY: Duration = Duration::from_secs(300);

pub async fn reconcile<A: CognitoAdmin>(
    admin: &A,
    budgets: &Budgets,
    settings: &Settings,
    m: &MappingRef,
    spec: &CognitoClientMappingSpec,
    current: &CognitoClientMappingStatus,
    now: Timestamp,
) -> Result<Plan, AdminError> {
    match reconcile_inner(admin, budgets, settings, m, spec, current, now).await {
        // Cognito refused the configuration itself (a scope missing from the
        // resource server, say). Say so on the object; retrying fast won't help.
        Err(AdminError::Rejected(message)) => {
            let mut status = current.clone();
            set_ready(&mut status, m, false, "CognitoRejected", &message, now);
            Ok(Plan {
                status,
                requeue: Some(REJECTED_RETRY),
                action: "rejected",
            })
        }
        other => other,
    }
}

async fn reconcile_inner<A: CognitoAdmin>(
    admin: &A,
    budgets: &Budgets,
    settings: &Settings,
    m: &MappingRef,
    spec: &CognitoClientMappingSpec,
    current: &CognitoClientMappingStatus,
    now: Timestamp,
) -> Result<Plan, AdminError> {
    let mut status = current.clone();

    let validated = match spec.validate() {
        Ok(v) => v,
        Err(e) => {
            set_ready(&mut status, m, false, "InvalidSpec", &e.to_string(), now);
            return Ok(Plan {
                status,
                requeue: None,
                action: "invalid_spec",
            });
        }
    };
    // Push mode (ADR-12) is accepted but not built yet. Refuse it visibly:
    // provisioning a pull-only client for a mapping that asked for push would
    // leave the workload waiting on a Secret that never appears.
    if validated.deliver_to_secret.is_some() {
        set_ready(
            &mut status,
            m,
            false,
            "DeliverToUnsupported",
            "push-mode delivery (deliverTo) is not available in this release; remove deliverTo and call the broker instead",
            now,
        );
        return Ok(Plan {
            status,
            requeue: None,
            action: "unsupported",
        });
    }
    if let Some(allowed) = &settings.allowed_pools
        && !allowed.contains(&validated.user_pool_id)
    {
        set_ready(
            &mut status,
            m,
            false,
            "PoolNotAllowed",
            &format!(
                "user pool {} is not managed by this controller",
                validated.user_pool_id
            ),
            now,
        );
        return Ok(Plan {
            status,
            requeue: None,
            action: "pool_not_allowed",
        });
    }

    let pool = validated.user_pool_id.as_str();
    let desired = DesiredClient::for_mapping(&m.namespace, &m.name, &m.uid, &validated);
    let action = decide(spec, &status, now, settings.verification_ttl_secs);
    let label = match &action {
        Action::CreateClient => {
            create(admin, budgets, pool, &desired, &mut status, now).await?;
            status.spec_hash = Some(spec.spec_hash());
            status.last_verified = Some(Time(now));
            set_ready(&mut status, m, true, "Provisioned", PROVISIONED, now);
            "create"
        }
        Action::ApplySpec { .. } => {
            let client_id = status.client_id.clone().expect("decide checked client_id");
            budgets.write().await;
            match admin.update_client(pool, &client_id, &desired).await {
                Ok(()) => {
                    status.spec_hash = Some(spec.spec_hash());
                    status.last_verified = Some(Time(now));
                    set_ready(&mut status, m, true, "Provisioned", PROVISIONED, now);
                    "update"
                }
                Err(AdminError::NotFound) => {
                    forget_client(&mut status);
                    set_ready(
                        &mut status,
                        m,
                        false,
                        "ClientMissing",
                        "app client was deleted outside the controller; re-creating",
                        now,
                    );
                    return Ok(Plan {
                        status,
                        requeue: Some(Duration::ZERO),
                        action: "client_missing",
                    });
                }
                Err(e) => return Err(e),
            }
        }
        Action::RotateSecret => {
            rotate(admin, budgets, settings, pool, &mut status, now).await?;
            "rotate"
        }
        Action::RetireSecret { secret_id } => {
            let client_id = status.client_id.clone().expect("decide checked client_id");
            budgets.write().await;
            match admin.delete_secret(pool, &client_id, secret_id).await {
                Ok(()) | Err(AdminError::NotFound) => {}
                Err(e) => return Err(e),
            }
            status.retiring_secret_id = None;
            status.retire_after = None;
            "retire"
        }
        Action::Skip | Action::DeferToAudit { .. } => {
            set_ready(&mut status, m, true, "Provisioned", PROVISIONED, now);
            "none"
        }
    };

    let requeue = next_due_secs(spec, &status, now).map(|s| Duration::from_secs(s as u64));
    Ok(Plan {
        status,
        requeue,
        action: label,
    })
}

async fn create<A: CognitoAdmin>(
    admin: &A,
    budgets: &Budgets,
    pool: &str,
    desired: &DesiredClient,
    status: &mut CognitoClientMappingStatus,
    now: Timestamp,
) -> Result<(), AdminError> {
    // A previous create may have succeeded and its status write been lost.
    // The name embeds the object UID, so a match is ours to adopt.
    budgets.read().await;
    let client_id = match admin.find_client(pool, &desired.name).await? {
        Some(existing) => {
            budgets.write().await;
            admin.update_client(pool, &existing, desired).await?;
            existing
        }
        None => {
            budgets.write().await;
            admin.create_client(pool, desired).await?
        }
    };
    budgets.read().await;
    let newest = admin
        .list_secrets(pool, &client_id)
        .await?
        .into_iter()
        .filter_map(|s| s.created)
        .max();
    status.client_id = Some(client_id);
    status.secret_created_at = Some(Time(
        newest
            .and_then(|s| Timestamp::from_second(s).ok())
            .unwrap_or(now),
    ));
    status.secret_generation = Some(status.secret_generation.unwrap_or(0) + 1);
    status.retiring_secret_id = None;
    status.retire_after = None;
    Ok(())
}

/// Add a new secret, then schedule the old one's deletion after the grace
/// window. The generation bump is what tells brokers to drop the old secret.
async fn rotate<A: CognitoAdmin>(
    admin: &A,
    budgets: &Budgets,
    settings: &Settings,
    pool: &str,
    status: &mut CognitoClientMappingStatus,
    now: Timestamp,
) -> Result<(), AdminError> {
    let client_id = status.client_id.clone().expect("decide checked client_id");
    budgets.read().await;
    let mut existing = admin.list_secrets(pool, &client_id).await?;
    existing.sort_by_key(|s| s.created.unwrap_or(i64::MIN));

    let (newest, retiring) = if existing.len() >= 2 {
        // A previous rotation added its secret but lost the status write.
        // Finish that rotation rather than starting another (two is the max).
        let newest = existing.pop().expect("len >= 2");
        (newest, existing.into_iter().next())
    } else {
        budgets.write().await;
        let added = admin.add_secret(pool, &client_id).await?;
        (added, existing.into_iter().next())
    };

    status.secret_created_at = Some(Time(
        newest
            .created
            .and_then(|s| Timestamp::from_second(s).ok())
            .unwrap_or(now),
    ));
    status.secret_generation = Some(status.secret_generation.unwrap_or(0) + 1);
    status.retiring_secret_id = retiring.map(|s| s.id);
    status.retire_after = status
        .retiring_secret_id
        .as_ref()
        .map(|_| Time(now + jiff_secs(settings.rotation_grace)));
    Ok(())
}

/// The slow drift check (invariant 4: never on the reconcile path). Returns the
/// status to write, or `None` if the mapping is not due.
pub async fn audit<A: CognitoAdmin>(
    admin: &A,
    budgets: &Budgets,
    settings: &Settings,
    m: &MappingRef,
    spec: &CognitoClientMappingSpec,
    current: &CognitoClientMappingStatus,
    now: Timestamp,
) -> Result<Option<(CognitoClientMappingStatus, &'static str)>, AdminError> {
    if !matches!(
        decide(spec, current, now, settings.verification_ttl_secs),
        Action::DeferToAudit { .. }
    ) {
        return Ok(None);
    }
    let Ok(validated) = spec.validate() else {
        return Ok(None);
    };
    let Some(client_id) = current.client_id.clone() else {
        return Ok(None);
    };
    let pool = validated.user_pool_id.as_str();
    let desired = DesiredClient::for_mapping(&m.namespace, &m.name, &m.uid, &validated);
    let mut status = current.clone();

    budgets.read().await;
    let result = match admin.describe_client(pool, &client_id).await {
        Err(AdminError::NotFound) => {
            forget_client(&mut status);
            set_ready(
                &mut status,
                m,
                false,
                "ClientMissing",
                "app client was deleted outside the controller; re-creating",
                now,
            );
            "missing"
        }
        Err(e) => return Err(e),
        Ok(observed) => {
            let fields = drift(&desired, &observed);
            if fields.is_empty() {
                "in_sync"
            } else {
                tracing::warn!(
                    mapping = %format!("{}/{}", m.namespace, m.name),
                    client_id,
                    ?fields,
                    "app client drifted from its mapping; restoring"
                );
                budgets.write().await;
                admin.update_client(pool, &client_id, &desired).await?;
                "drift"
            }
        }
    };
    if result != "missing" {
        status.last_verified = Some(Time(now));
    }
    Ok(Some((status, result)))
}

/// Finalizer: delete the app client. Tokens already issued stay valid until
/// they expire — `client_credentials` tokens cannot be revoked (DESIGN.md
/// §Deprovisioning).
pub async fn cleanup<A: CognitoAdmin>(
    admin: &A,
    budgets: &Budgets,
    spec: &CognitoClientMappingSpec,
    status: &CognitoClientMappingStatus,
) -> Result<(), AdminError> {
    let Some(client_id) = &status.client_id else {
        return Ok(());
    };
    budgets.write().await;
    match admin.delete_client(&spec.user_pool_id, client_id).await {
        Ok(()) | Err(AdminError::NotFound) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Status that makes the next reconcile create a fresh client.
fn forget_client(status: &mut CognitoClientMappingStatus) {
    status.client_id = None;
    status.spec_hash = None;
    status.last_verified = None;
    status.retiring_secret_id = None;
    status.retire_after = None;
}

fn jiff_secs(d: Duration) -> k8s_openapi::jiff::SignedDuration {
    k8s_openapi::jiff::SignedDuration::from_secs(d.as_secs() as i64)
}

/// Set the `Ready` condition, keeping `lastTransitionTime` when the status
/// value does not change so an unchanged mapping produces an unchanged status
/// (and therefore no write).
fn set_ready(
    status: &mut CognitoClientMappingStatus,
    m: &MappingRef,
    ready: bool,
    reason: &str,
    message: &str,
    now: Timestamp,
) {
    let value = if ready { "True" } else { "False" };
    let previous = status.conditions.iter().find(|c| c.type_ == "Ready");
    let transition = match previous {
        Some(c) if c.status == value => c.last_transition_time.clone(),
        _ => Time(now),
    };
    status.conditions.retain(|c| c.type_ != "Ready");
    status.conditions.push(Condition {
        type_: "Ready".into(),
        status: value.into(),
        reason: reason.into(),
        message: message.into(),
        last_transition_time: transition,
        observed_generation: m.generation,
    });
}
