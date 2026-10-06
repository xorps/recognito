//! kube-rs plumbing: watch mappings, run [`crate::reconcile`] under a
//! finalizer, patch status, and drive the slow audit loop off the same
//! informer cache.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures::StreamExt;
use k8s_openapi::jiff::Timestamp;
use kube::api::{Patch, PatchParams};
use kube::runtime::controller::{Action, Controller};
use kube::runtime::finalizer::{Event, finalizer};
use kube::runtime::reflector::Store;
use kube::runtime::watcher;
use kube::{Api, ResourceExt};
use recognito_api::metrics::Metrics;
use recognito_api::{CognitoClientMapping, CognitoClientMappingStatus};

use crate::cognito::{AdminError, CognitoAdmin};
use crate::reconcile::{self, Budgets, MappingRef, Settings};

pub const FINALIZER: &str = "recognito.io/app-client";

/// Pause between audit passes. Within a pass, the read budget paces calls.
const AUDIT_PASS_INTERVAL: Duration = Duration::from_secs(60);

pub struct Context<A> {
    pub client: kube::Client,
    pub admin: A,
    pub budgets: Budgets,
    pub settings: Settings,
    pub metrics: Arc<Metrics>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Admin(#[from] AdminError),
    #[error(transparent)]
    Kube(#[from] kube::Error),
    #[error("mapping has no namespace")]
    NoNamespace,
    #[error(transparent)]
    Finalizer(#[from] Box<kube::runtime::finalizer::Error<Error>>),
}

impl Error {
    fn kind(&self) -> &'static str {
        match self {
            Error::Admin(AdminError::Throttled) => "throttled",
            Error::Admin(_) => "cognito",
            Error::Kube(_) => "kube",
            Error::NoNamespace => "no_namespace",
            Error::Finalizer(e) => match e.as_ref() {
                kube::runtime::finalizer::Error::ApplyFailed(inner)
                | kube::runtime::finalizer::Error::CleanupFailed(inner) => inner.kind(),
                _ => "finalizer",
            },
        }
    }
}

/// Run the controller and the audit loop until shutdown. `ready` flips once
/// the apiserver has answered a list of mappings.
///
/// Nothing here may call `Store::wait_until_ready`: in kube-runtime 4.2 it
/// sits on a oneshot that keeps a single waker, so a second waiter can steal
/// the wake-up from the controller's own runner and stall it. Readiness is a
/// direct list instead, and the audit loop reads whatever the store holds.
pub async fn run<A: CognitoAdmin>(ctx: Arc<Context<A>>, ready: Arc<AtomicBool>) {
    ctx.metrics
        .describe("recognito_reconciles_total", "Reconciles by action taken.");
    ctx.metrics.describe(
        "recognito_reconcile_errors_total",
        "Reconcile failures by kind.",
    );
    ctx.metrics.describe(
        "recognito_audits_total",
        "Drift audits by result (in_sync, drift, missing).",
    );

    let api = Api::<CognitoClientMapping>::all(ctx.client.clone());
    {
        let api = api.clone();
        tokio::spawn(async move {
            loop {
                match api.list(&kube::api::ListParams::default().limit(1)).await {
                    Ok(_) => {
                        ready.store(true, Ordering::Release);
                        return;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "cannot list mappings yet");
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
            }
        });
    }
    let controller = Controller::new(api, watcher::Config::default()).shutdown_on_signal();
    let store = controller.store();
    tokio::spawn(audit_loop(ctx.clone(), store));

    controller
        .run(reconcile_one, error_policy, ctx)
        .for_each(|result| async move {
            if let Err(e) = result {
                tracing::debug!(error = %e, "reconcile result");
            }
        })
        .await;
}

async fn reconcile_one<A: CognitoAdmin>(
    obj: Arc<CognitoClientMapping>,
    ctx: Arc<Context<A>>,
) -> Result<Action, Error> {
    let namespace = obj.namespace().ok_or(Error::NoNamespace)?;
    let api = Api::<CognitoClientMapping>::namespaced(ctx.client.clone(), &namespace);
    finalizer(&api, FINALIZER, obj, |event| async {
        match event {
            Event::Apply(m) => apply(&api, &m, &ctx).await,
            Event::Cleanup(m) => {
                reconcile::cleanup(
                    &ctx.admin,
                    &ctx.budgets,
                    &m.spec,
                    &m.status.clone().unwrap_or_default(),
                )
                .await?;
                ctx.metrics
                    .inc("recognito_reconciles_total", &[("action", "delete")]);
                tracing::info!(mapping = %key(&m), "app client deleted");
                Ok(Action::await_change())
            }
        }
    })
    .await
    .map_err(|e| Error::Finalizer(Box::new(e)))
}

async fn apply<A: CognitoAdmin>(
    api: &Api<CognitoClientMapping>,
    m: &CognitoClientMapping,
    ctx: &Context<A>,
) -> Result<Action, Error> {
    let current = m.status.clone().unwrap_or_default();
    let plan = reconcile::reconcile(
        &ctx.admin,
        &ctx.budgets,
        &ctx.settings,
        &mapping_ref(m),
        &m.spec,
        &current,
        Timestamp::now(),
    )
    .await?;
    ctx.metrics
        .inc("recognito_reconciles_total", &[("action", plan.action)]);
    if plan.action != "none" {
        tracing::info!(mapping = %key(m), action = plan.action, client_id = plan.status.client_id.as_deref(), "reconciled");
    }
    if plan.status != current {
        patch_status(api, &m.name_any(), &plan.status).await?;
    }
    Ok(match plan.requeue {
        Some(after) => Action::requeue(after.max(Duration::from_secs(1))),
        None => Action::await_change(),
    })
}

fn error_policy<A: CognitoAdmin>(
    obj: Arc<CognitoClientMapping>,
    error: &Error,
    ctx: Arc<Context<A>>,
) -> Action {
    let kind = error.kind();
    ctx.metrics
        .inc("recognito_reconcile_errors_total", &[("kind", kind)]);
    tracing::warn!(mapping = %key(&obj), error = %error, kind, "reconcile failed");
    if kind == "throttled" {
        ctx.budgets.yield_after_throttle();
        Action::requeue(Duration::from_secs(60))
    } else {
        Action::requeue(Duration::from_secs(15))
    }
}

/// Every pass, audit each mapping whose verification has lapsed, oldest first,
/// at the pace the read budget allows.
async fn audit_loop<A: CognitoAdmin>(ctx: Arc<Context<A>>, store: Store<CognitoClientMapping>) {
    // Before the first sync the store is empty and a pass does nothing; see
    // `run` for why this does not wait on the store.
    tokio::time::sleep(AUDIT_PASS_INTERVAL).await;
    loop {
        let mut due: Vec<Arc<CognitoClientMapping>> = store
            .state()
            .into_iter()
            .filter(|m| m.metadata.deletion_timestamp.is_none())
            .collect();
        due.sort_by_key(|m| {
            m.status
                .as_ref()
                .and_then(|s| s.last_verified.as_ref())
                .map(|t| t.0)
        });
        for m in due {
            let current = m.status.clone().unwrap_or_default();
            let result = reconcile::audit(
                &ctx.admin,
                &ctx.budgets,
                &ctx.settings,
                &mapping_ref(&m),
                &m.spec,
                &current,
                Timestamp::now(),
            )
            .await;
            match result {
                Ok(Some((status, outcome))) => {
                    ctx.metrics
                        .inc("recognito_audits_total", &[("result", outcome)]);
                    let Some(ns) = m.namespace() else { continue };
                    let api = Api::<CognitoClientMapping>::namespaced(ctx.client.clone(), &ns);
                    if let Err(e) = patch_status(&api, &m.name_any(), &status).await {
                        tracing::warn!(mapping = %key(&m), error = %e, "audit status write failed");
                    }
                }
                Ok(None) => {}
                Err(AdminError::Throttled) => {
                    ctx.budgets.yield_after_throttle();
                    ctx.metrics
                        .inc("recognito_audits_total", &[("result", "throttled")]);
                }
                Err(e) => {
                    ctx.metrics
                        .inc("recognito_audits_total", &[("result", "error")]);
                    tracing::warn!(mapping = %key(&m), error = %e, "audit failed");
                }
            }
        }
        tokio::time::sleep(AUDIT_PASS_INTERVAL).await;
    }
}

/// Merge-patch the whole status. Optional fields that are now `None` are sent
/// as explicit nulls — a merge patch that omits a key leaves the old value in
/// place, which would strand a completed rotation's `retiringSecretId`.
async fn patch_status(
    api: &Api<CognitoClientMapping>,
    name: &str,
    status: &CognitoClientMappingStatus,
) -> Result<(), kube::Error> {
    api.patch_status(
        name,
        &PatchParams::default(),
        &Patch::Merge(status_patch(status)),
    )
    .await?;
    Ok(())
}

pub fn status_patch(status: &CognitoClientMappingStatus) -> serde_json::Value {
    let mut value = serde_json::to_value(status).expect("status serializes");
    let obj = value.as_object_mut().expect("status is an object");
    for key in [
        "clientId",
        "specHash",
        "lastVerified",
        "secretCreatedAt",
        "secretGeneration",
        "retiringSecretId",
        "retireAfter",
    ] {
        obj.entry(key).or_insert(serde_json::Value::Null);
    }
    obj.entry("conditions").or_insert(serde_json::json!([]));
    serde_json::json!({ "status": value })
}

fn mapping_ref(m: &CognitoClientMapping) -> MappingRef {
    MappingRef {
        namespace: m.namespace().unwrap_or_default(),
        name: m.name_any(),
        uid: m.uid().unwrap_or_default(),
        generation: m.metadata.generation,
    }
}

fn key(m: &CognitoClientMapping) -> String {
    format!("{}/{}", m.namespace().unwrap_or_default(), m.name_any())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleared_fields_are_sent_as_explicit_nulls() {
        let status = CognitoClientMappingStatus {
            client_id: Some("c".into()),
            ..Default::default()
        };
        let patch = status_patch(&status);
        assert_eq!(patch["status"]["clientId"], "c");
        assert!(patch["status"]["retiringSecretId"].is_null());
        assert!(
            patch["status"]
                .as_object()
                .unwrap()
                .contains_key("retiringSecretId"),
            "omitting the key would leave the old value in place"
        );
    }
}
