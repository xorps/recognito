//! Mapping lifecycle against an in-memory Cognito: create, adopt, update,
//! rotate, retire, audit, delete — and, as importantly, every place where the
//! controller must make *no* call at all.

use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;
use std::time::Duration;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use k8s_openapi::jiff::{SignedDuration, Timestamp};
use recognito_api::{CognitoClientMappingSpec, CognitoClientMappingStatus, RateLimiter};
use recognito_controller::cognito::{
    AdminError, CognitoAdmin, DesiredClient, ObservedClient, SecretInfo,
};
use recognito_controller::reconcile::{self, Budgets, MappingRef, REJECTED_RETRY, Settings};

const POOL: &str = "us-east-1_aBcDeFgHi";
const GRACE: Duration = Duration::from_secs(600);

#[derive(Default)]
struct State {
    clients: HashMap<String, ObservedClient>,
    secrets: HashMap<String, Vec<SecretInfo>>,
    calls: Vec<String>,
    next_id: u32,
    next_secret: u32,
    fail_next: Option<AdminError>,
}

/// An in-memory Cognito that records every call.
#[derive(Default)]
struct FakeCognito(Mutex<State>);

impl FakeCognito {
    fn calls(&self) -> Vec<String> {
        self.0.lock().unwrap().calls.clone()
    }

    fn clear_calls(&self) {
        self.0.lock().unwrap().calls.clear();
    }

    fn fail_next(&self, e: AdminError) {
        self.0.lock().unwrap().fail_next = Some(e);
    }

    fn record(&self, call: &str) -> Result<std::sync::MutexGuard<'_, State>, AdminError> {
        let mut s = self.0.lock().unwrap();
        s.calls.push(call.to_owned());
        match s.fail_next.take() {
            Some(e) => Err(e),
            None => Ok(s),
        }
    }
}

fn observed(d: &DesiredClient) -> ObservedClient {
    ObservedClient {
        name: d.name.clone(),
        scopes: d.scopes.clone(),
        flows: vec!["client_credentials".into()],
        flows_user_pool_client: true,
        access_token_validity: Some(d.access_token_minutes),
        access_token_units: Some("minutes".into()),
    }
}

impl CognitoAdmin for FakeCognito {
    async fn find_client(&self, _: &str, name: &str) -> Result<Option<String>, AdminError> {
        let s = self.record("find")?;
        Ok(s.clients
            .iter()
            .find(|(_, c)| c.name == name)
            .map(|(id, _)| id.clone()))
    }

    async fn create_client(&self, _: &str, d: &DesiredClient) -> Result<String, AdminError> {
        let mut s = self.record("create")?;
        s.next_id += 1;
        s.next_secret += 1;
        let id = format!("client{}", s.next_id);
        let secret = SecretInfo {
            id: format!("{id}--{}", s.next_secret),
            created: Some(t0().as_second() + i64::from(s.next_secret)),
        };
        s.clients.insert(id.clone(), observed(d));
        s.secrets.insert(id.clone(), vec![secret]);
        Ok(id)
    }

    async fn update_client(&self, _: &str, id: &str, d: &DesiredClient) -> Result<(), AdminError> {
        let mut s = self.record("update")?;
        match s.clients.get_mut(id) {
            Some(c) => {
                *c = observed(d);
                Ok(())
            }
            None => Err(AdminError::NotFound),
        }
    }

    async fn describe_client(&self, _: &str, id: &str) -> Result<ObservedClient, AdminError> {
        let s = self.record("describe")?;
        s.clients.get(id).cloned().ok_or(AdminError::NotFound)
    }

    async fn delete_client(&self, _: &str, id: &str) -> Result<(), AdminError> {
        let mut s = self.record("delete")?;
        s.clients.remove(id).map(|_| ()).ok_or(AdminError::NotFound)
    }

    async fn list_secrets(&self, _: &str, id: &str) -> Result<Vec<SecretInfo>, AdminError> {
        let s = self.record("list_secrets")?;
        Ok(s.secrets.get(id).cloned().unwrap_or_default())
    }

    async fn add_secret(&self, _: &str, id: &str) -> Result<SecretInfo, AdminError> {
        let mut s = self.record("add_secret")?;
        s.next_secret += 1;
        // Cognito stamps a new secret with the time of the call; the tests
        // rotate thirty days in, which is close enough for ordering.
        let info = SecretInfo {
            id: format!("{id}--{}", s.next_secret),
            created: Some(t0().as_second() + 30 * 24 * 3600 + i64::from(s.next_secret)),
        };
        let list = s.secrets.entry(id.to_owned()).or_default();
        assert!(
            list.len() < 2,
            "Cognito allows at most two secrets per client"
        );
        list.push(info.clone());
        Ok(info)
    }

    async fn delete_secret(&self, _: &str, id: &str, secret: &str) -> Result<(), AdminError> {
        let mut s = self.record("delete_secret")?;
        let list = s.secrets.entry(id.to_owned()).or_default();
        let before = list.len();
        list.retain(|x| x.id != secret);
        if list.len() == before {
            Err(AdminError::NotFound)
        } else {
            Ok(())
        }
    }
}

// ---- harness ---------------------------------------------------------------

fn budgets() -> Budgets {
    Budgets {
        reads: RateLimiter::new(1000.0, 1000),
        writes: RateLimiter::new(1000.0, 1000),
    }
}

fn settings() -> Settings {
    Settings {
        allowed_pools: Some(BTreeSet::from([POOL.to_owned()])),
        rotation_grace: GRACE,
        verification_ttl_secs: 24 * 3600,
    }
}

fn mref() -> MappingRef {
    MappingRef {
        namespace: "payments".into(),
        name: "api".into(),
        uid: "0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0".into(),
        generation: Some(1),
    }
}

fn spec() -> CognitoClientMappingSpec {
    serde_json::from_value(serde_json::json!({
        "serviceAccountRef": {"name": "api"},
        "userPoolId": POOL,
        "allowedScopes": [{"name": "read", "scopes": ["payments/read"]}],
        "tokenValidity": "15m",
        "rotateAfter": "720h",
    }))
    .unwrap()
}

fn t0() -> Timestamp {
    Timestamp::from_second(1_791_201_600).unwrap()
}

fn after(secs: i64) -> Timestamp {
    t0() + SignedDuration::from_secs(secs)
}

fn ready(status: &CognitoClientMappingStatus) -> (String, String) {
    let c = status
        .conditions
        .iter()
        .find(|c| c.type_ == "Ready")
        .expect("Ready condition");
    (c.status.clone(), c.reason.clone())
}

async fn reconcile_at(
    cognito: &FakeCognito,
    spec: &CognitoClientMappingSpec,
    status: &CognitoClientMappingStatus,
    now: Timestamp,
) -> reconcile::Plan {
    reconcile::reconcile(cognito, &budgets(), &settings(), &mref(), spec, status, now)
        .await
        .unwrap()
}

async fn provisioned(cognito: &FakeCognito) -> CognitoClientMappingStatus {
    let plan = reconcile_at(cognito, &spec(), &Default::default(), t0()).await;
    cognito.clear_calls();
    plan.status
}

// ---- tests -----------------------------------------------------------------

#[tokio::test]
async fn a_new_mapping_creates_one_client_and_records_it() {
    let cognito = FakeCognito::default();
    let plan = reconcile_at(&cognito, &spec(), &Default::default(), t0()).await;
    assert_eq!(plan.action, "create");
    assert_eq!(cognito.calls(), ["find", "create", "list_secrets"]);
    let s = plan.status;
    assert_eq!(s.client_id.as_deref(), Some("client1"));
    assert_eq!(s.spec_hash, Some(spec().spec_hash()));
    assert_eq!(s.secret_generation, Some(1));
    assert!(s.secret_created_at.is_some() && s.last_verified.is_some());
    assert_eq!(ready(&s), ("True".into(), "Provisioned".into()));
    // Next wake-up is the rotation, not sooner.
    assert!(plan.requeue.unwrap() > Duration::from_secs(29 * 24 * 3600));
}

#[tokio::test]
async fn a_lost_status_write_adopts_the_client_instead_of_duplicating_it() {
    let cognito = FakeCognito::default();
    let _lost = provisioned(&cognito).await;
    let plan = reconcile_at(&cognito, &spec(), &Default::default(), t0()).await;
    assert_eq!(cognito.calls(), ["find", "update", "list_secrets"]);
    assert_eq!(plan.status.client_id.as_deref(), Some("client1"));
}

#[tokio::test]
async fn steady_state_reconcile_makes_no_cognito_calls() {
    let cognito = FakeCognito::default();
    let status = provisioned(&cognito).await;
    for _ in 0..100 {
        let plan = reconcile_at(&cognito, &spec(), &status, after(3600)).await;
        assert_eq!(
            plan.status, status,
            "nothing changed, so nothing is written"
        );
    }
    assert!(
        cognito.calls().is_empty(),
        "invariant 4: {:?}",
        cognito.calls()
    );
}

#[tokio::test]
async fn a_spec_change_updates_the_client_in_place() {
    let cognito = FakeCognito::default();
    let status = provisioned(&cognito).await;
    let mut changed = spec();
    changed.token_validity = "30m".parse().unwrap();
    let plan = reconcile_at(&cognito, &changed, &status, after(60)).await;
    assert_eq!(plan.action, "update");
    assert_eq!(cognito.calls(), ["update"]);
    assert_eq!(
        plan.status.client_id, status.client_id,
        "client ID never changes"
    );
    assert_eq!(plan.status.spec_hash, Some(changed.spec_hash()));
}

#[tokio::test]
async fn a_client_deleted_out_of_band_is_recreated() {
    let cognito = FakeCognito::default();
    let status = provisioned(&cognito).await;
    cognito.0.lock().unwrap().clients.clear();
    let mut changed = spec();
    changed.token_validity = "30m".parse().unwrap();

    let plan = reconcile_at(&cognito, &changed, &status, after(60)).await;
    assert_eq!(plan.action, "client_missing");
    assert_eq!(plan.status.client_id, None);
    assert_eq!(plan.requeue, Some(Duration::ZERO));

    let plan = reconcile_at(&cognito, &changed, &plan.status, after(61)).await;
    assert_eq!(plan.action, "create");
    assert_eq!(plan.status.client_id.as_deref(), Some("client2"));
    assert_eq!(
        plan.status.secret_generation,
        Some(2),
        "generation keeps rising so brokers drop the dead client's secret"
    );
}

#[tokio::test]
async fn rotation_adds_then_retires_after_the_grace_window() {
    let cognito = FakeCognito::default();
    let status = provisioned(&cognito).await;
    let rotate_at = after(30 * 24 * 3600 + 10);

    let plan = reconcile_at(&cognito, &spec(), &status, rotate_at).await;
    assert_eq!(plan.action, "rotate");
    assert_eq!(cognito.calls(), ["list_secrets", "add_secret"]);
    let rotated = plan.status;
    assert_eq!(rotated.secret_generation, Some(2));
    assert_eq!(rotated.retiring_secret_id.as_deref(), Some("client1--1"));
    assert_eq!(
        rotated.retire_after,
        Some(Time(
            rotate_at + SignedDuration::from_secs(GRACE.as_secs() as i64)
        ))
    );
    assert_eq!(
        plan.requeue,
        Some(GRACE),
        "wake exactly when the old secret may go"
    );
    assert_eq!(rotated.client_id, status.client_id);

    // During the grace window: both secrets live, no calls.
    cognito.clear_calls();
    let plan = reconcile_at(
        &cognito,
        &spec(),
        &rotated,
        rotate_at + SignedDuration::from_secs(60),
    )
    .await;
    assert!(cognito.calls().is_empty());
    assert_eq!(plan.status, rotated);

    // After it: the old secret is deleted.
    let plan = reconcile_at(
        &cognito,
        &spec(),
        &rotated,
        rotate_at + SignedDuration::from_secs(GRACE.as_secs() as i64),
    )
    .await;
    assert_eq!(plan.action, "retire");
    assert_eq!(cognito.calls(), ["delete_secret"]);
    assert_eq!(plan.status.retiring_secret_id, None);
    assert_eq!(plan.status.retire_after, None);
    assert_eq!(cognito.0.lock().unwrap().secrets["client1"].len(), 1);
}

#[tokio::test]
async fn a_rotation_whose_status_write_was_lost_is_finished_not_repeated() {
    let cognito = FakeCognito::default();
    let status = provisioned(&cognito).await;
    let rotate_at = after(30 * 24 * 3600 + 10);
    let _lost = reconcile_at(&cognito, &spec(), &status, rotate_at).await;
    cognito.clear_calls();

    // Same old status again: two secrets already exist.
    let plan = reconcile_at(&cognito, &spec(), &status, rotate_at).await;
    assert_eq!(
        cognito.calls(),
        ["list_secrets"],
        "must not add a third secret"
    );
    assert_eq!(
        plan.status.retiring_secret_id.as_deref(),
        Some("client1--1")
    );
    assert_eq!(plan.status.secret_generation, Some(2));
}

#[tokio::test]
async fn an_invalid_spec_or_foreign_pool_costs_no_calls() {
    let cognito = FakeCognito::default();
    let mut bad = spec();
    bad.allowed_scopes.clear();
    let plan = reconcile_at(&cognito, &bad, &Default::default(), t0()).await;
    assert_eq!(ready(&plan.status), ("False".into(), "InvalidSpec".into()));
    assert_eq!(plan.requeue, None);

    let mut foreign = spec();
    foreign.user_pool_id = "eu-west-1_Other".into();
    let plan = reconcile_at(&cognito, &foreign, &Default::default(), t0()).await;
    assert_eq!(
        ready(&plan.status),
        ("False".into(), "PoolNotAllowed".into())
    );
    assert!(cognito.calls().is_empty());
}

#[tokio::test]
async fn push_mode_is_refused_visibly_not_ignored() {
    let cognito = FakeCognito::default();
    let mut push = spec();
    push.deliver_to = Some(recognito_api::DeliverTo {
        secret_ref: recognito_api::SecretRef {
            name: "payments-token".into(),
        },
    });
    let plan = reconcile_at(&cognito, &push, &Default::default(), t0()).await;
    assert_eq!(
        ready(&plan.status),
        ("False".into(), "DeliverToUnsupported".into())
    );
    assert!(cognito.calls().is_empty());
}

#[tokio::test]
async fn a_spec_cognito_rejects_is_reported_on_the_object() {
    let cognito = FakeCognito::default();
    let status = provisioned(&cognito).await;
    cognito.fail_next(AdminError::Rejected(
        "ScopeDoesNotExistException: payments/admin".into(),
    ));
    let mut changed = spec();
    changed.allowed_scopes[0]
        .scopes
        .push("payments/admin".into());
    let plan = reconcile_at(&cognito, &changed, &status, after(60)).await;
    let (value, reason) = ready(&plan.status);
    assert_eq!(
        (value.as_str(), reason.as_str()),
        ("False", "CognitoRejected")
    );
    assert_eq!(plan.requeue, Some(REJECTED_RETRY));
    assert_eq!(
        plan.status.spec_hash, status.spec_hash,
        "not marked applied"
    );
}

#[tokio::test]
async fn throttling_is_an_error_so_the_controller_backs_off() {
    let cognito = FakeCognito::default();
    cognito.fail_next(AdminError::Throttled);
    let err = reconcile::reconcile(
        &cognito,
        &budgets(),
        &settings(),
        &mref(),
        &spec(),
        &Default::default(),
        t0(),
    )
    .await
    .unwrap_err();
    assert_eq!(err, AdminError::Throttled);
}

#[tokio::test]
async fn audit_only_touches_mappings_whose_verification_lapsed() {
    let cognito = FakeCognito::default();
    let status = provisioned(&cognito).await;
    let (b, st, m, sp) = (budgets(), settings(), mref(), spec());

    let not_due = reconcile::audit(&cognito, &b, &st, &m, &sp, &status, after(3600)).await;
    assert!(not_due.unwrap().is_none());
    assert!(cognito.calls().is_empty());

    let (verified, result) =
        reconcile::audit(&cognito, &b, &st, &m, &sp, &status, after(25 * 3600))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(result, "in_sync");
    assert_eq!(cognito.calls(), ["describe"]);
    assert_eq!(verified.last_verified, Some(Time(after(25 * 3600))));
}

#[tokio::test]
async fn audit_restores_a_drifted_client() {
    let cognito = FakeCognito::default();
    let status = provisioned(&cognito).await;
    cognito
        .0
        .lock()
        .unwrap()
        .clients
        .get_mut("client1")
        .unwrap()
        .scopes
        .push("admin/everything".into());

    let (_, result) = reconcile::audit(
        &cognito,
        &budgets(),
        &settings(),
        &mref(),
        &spec(),
        &status,
        after(25 * 3600),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(result, "drift");
    assert_eq!(cognito.calls(), ["describe", "update"]);
    assert_eq!(
        cognito.0.lock().unwrap().clients["client1"].scopes,
        vec!["payments/read"]
    );
}

#[tokio::test]
async fn audit_notices_a_deleted_client() {
    let cognito = FakeCognito::default();
    let status = provisioned(&cognito).await;
    cognito.0.lock().unwrap().clients.clear();
    let (forgotten, result) = reconcile::audit(
        &cognito,
        &budgets(),
        &settings(),
        &mref(),
        &spec(),
        &status,
        after(25 * 3600),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(result, "missing");
    assert_eq!(forgotten.client_id, None, "reconcile will re-create it");
}

#[tokio::test]
async fn deletion_removes_the_client_and_tolerates_it_being_gone() {
    let cognito = FakeCognito::default();
    let status = provisioned(&cognito).await;
    reconcile::cleanup(&cognito, &budgets(), &spec(), &status)
        .await
        .unwrap();
    assert!(cognito.0.lock().unwrap().clients.is_empty());
    reconcile::cleanup(&cognito, &budgets(), &spec(), &status)
        .await
        .unwrap();
    cognito.clear_calls();
    reconcile::cleanup(&cognito, &budgets(), &spec(), &Default::default())
        .await
        .unwrap();
    assert!(
        cognito.calls().is_empty(),
        "nothing to delete, nothing called"
    );
}
