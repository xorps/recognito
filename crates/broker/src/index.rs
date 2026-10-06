//! The CRD-fed mapping index: authenticated identity → the mapping that
//! authorizes it (docs/DESIGN.md §Broker, authz layer).
//!
//! # Fail closed on contested identities
//!
//! An identity claimed by two mappings is refused, not resolved. Any rule for
//! picking one — oldest, newest, alphabetical — hands the choice of which
//! Cognito client a workload gets to whoever can create the second mapping.
//! For ServiceAccounts that is only the SA's own namespace; for IAM roles it is
//! any namespace at all, since a role is not namespaced (ADR-15). Refusing
//! makes a duplicate claim a loud outage for one identity instead of a quiet
//! redirection of its tokens.
//!
//! # Fail closed on bad or departing specs
//!
//! A mapping whose spec no longer validates loses its claim rather than
//! keeping its last good one: the index never serves a spec the controller
//! would refuse. A mapping with a `deletionTimestamp` is dropped immediately,
//! not when its finalizer clears, so new issuance stops the moment someone
//! deletes it (DESIGN.md §Deprovisioning).
//!
//! # Consistency with the apiserver
//!
//! A watcher re-list (`Init` … `InitDone`) is built off to the side and swapped
//! in whole, so a mapping deleted while the watch was down disappears on the
//! swap and lookups never see a half-built index.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use futures::StreamExt;
use kube::ResourceExt;
use kube::runtime::{WatchStreamExt, watcher};
use recognito_api::{CognitoClientMapping, SpecError, ValidatedSpec, WorkloadIdentity};

use crate::exchange::{ErrorCode, ExchangeError};

/// `namespace/name` of a mapping.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MappingKey {
    pub namespace: String,
    pub name: String,
}

impl std::fmt::Display for MappingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.namespace, self.name)
    }
}

/// What the authz and fetch layers need from a mapping.
#[derive(Clone, Debug, PartialEq)]
pub struct MappingEntry {
    pub key: MappingKey,
    pub identity: WorkloadIdentity,
    pub spec: ValidatedSpec,
    /// Absent until the controller has created the app client.
    pub client_id: Option<String>,
    /// Drives secret-cache eviction (ADR-10).
    pub secret_generation: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LookupError {
    #[error("no mapping authorizes this identity")]
    NotMapped,
    #[error("{claimants} mappings claim this identity; refusing to choose between them")]
    Ambiguous { claimants: usize },
    #[error("the mapping for this identity has no app client yet")]
    NotReady,
}

impl LookupError {
    pub fn reason(&self) -> &'static str {
        match self {
            LookupError::NotMapped => "not_mapped",
            LookupError::Ambiguous { .. } => "ambiguous_mapping",
            LookupError::NotReady => "mapping_not_ready",
        }
    }
}

/// The description never names the competing mappings: the caller is not
/// entitled to learn what else exists in the cluster.
impl From<LookupError> for ExchangeError {
    fn from(error: LookupError) -> Self {
        match error {
            LookupError::NotMapped | LookupError::Ambiguous { .. } => ExchangeError::new(
                ErrorCode::InvalidGrant,
                format!("identity not authorized: {}", error.reason()),
            ),
            LookupError::NotReady => ExchangeError::new(
                ErrorCode::TemporarilyUnavailable,
                "the mapping for this identity is still being provisioned",
            ),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    #[error("mapping has no namespace")]
    NoNamespace,
    #[error("mapping {key} is invalid and has been dropped from the index: {source}")]
    InvalidSpec { key: MappingKey, source: SpecError },
}

#[derive(Default)]
struct Inner {
    /// Every claim on an identity. More than one entry means contested.
    by_identity: HashMap<WorkloadIdentity, BTreeMap<MappingKey, Arc<MappingEntry>>>,
    /// Reverse edge, so an edit that changes a mapping's identity releases the
    /// old claim.
    by_key: HashMap<MappingKey, WorkloadIdentity>,
}

impl Inner {
    fn remove(&mut self, key: &MappingKey) {
        if let Some(identity) = self.by_key.remove(key)
            && let Some(claims) = self.by_identity.get_mut(&identity)
        {
            claims.remove(key);
            if claims.is_empty() {
                self.by_identity.remove(&identity);
            }
        }
    }

    fn apply(&mut self, mapping: &CognitoClientMapping) -> Result<(), ApplyError> {
        let key = MappingKey {
            namespace: mapping.namespace().ok_or(ApplyError::NoNamespace)?,
            name: mapping.name_any(),
        };
        // Release the old claim first: whatever happens next, the previous
        // version of this mapping no longer authorizes anything.
        self.remove(&key);
        if mapping.metadata.deletion_timestamp.is_some() {
            return Ok(());
        }
        let spec = mapping
            .spec
            .validate()
            .map_err(|source| ApplyError::InvalidSpec {
                key: key.clone(),
                source,
            })?;
        let identity = spec.identity(&key.namespace);
        let status = mapping.status.as_ref();
        let entry = Arc::new(MappingEntry {
            key: key.clone(),
            identity: identity.clone(),
            spec,
            client_id: status.and_then(|s| s.client_id.clone()),
            secret_generation: status.and_then(|s| s.secret_generation),
        });
        self.by_identity
            .entry(identity.clone())
            .or_default()
            .insert(key.clone(), entry);
        self.by_key.insert(key, identity);
        Ok(())
    }
}

/// See the module docs.
///
/// A `RwLock` over plain maps rather than `DashMap`: writes are rare
/// (mapping edits), reads are one short lookup, and a re-list has to replace
/// both maps together, which per-shard locking cannot do atomically.
#[derive(Default)]
pub struct MappingIndex {
    live: RwLock<Inner>,
    /// The re-list in progress, if any.
    relist: Mutex<Option<Inner>>,
    /// Set once the first full list has landed. Readiness gates on it: a
    /// replica that has not seen every mapping would refuse valid callers
    /// with `not_mapped`.
    synced: AtomicBool,
}

impl MappingIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// The mapping that authorizes `identity`, if exactly one does.
    pub fn lookup(&self, identity: &WorkloadIdentity) -> Result<Arc<MappingEntry>, LookupError> {
        let live = self.live.read().unwrap_or_else(|p| p.into_inner());
        let claims = live
            .by_identity
            .get(identity)
            .ok_or(LookupError::NotMapped)?;
        let mut it = claims.values();
        let (Some(entry), None) = (it.next(), it.next()) else {
            return Err(LookupError::Ambiguous {
                claimants: claims.len(),
            });
        };
        if entry.client_id.is_none() {
            return Err(LookupError::NotReady);
        }
        Ok(entry.clone())
    }

    /// Every mapping claiming `identity`, for diagnostics and alerts.
    pub fn claimants(&self, identity: &WorkloadIdentity) -> Vec<MappingKey> {
        let live = self.live.read().unwrap_or_else(|p| p.into_inner());
        live.by_identity
            .get(identity)
            .map(|c| c.keys().cloned().collect())
            .unwrap_or_default()
    }

    pub fn is_synced(&self) -> bool {
        self.synced.load(Ordering::Acquire)
    }

    pub fn len(&self) -> usize {
        self.live
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .by_key
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Insert or replace one mapping.
    pub fn apply(&self, mapping: &CognitoClientMapping) -> Result<(), ApplyError> {
        let mut live = self.live.write().unwrap_or_else(|p| p.into_inner());
        live.apply(mapping)
    }

    pub fn delete(&self, mapping: &CognitoClientMapping) {
        let Some(namespace) = mapping.namespace() else {
            return;
        };
        let key = MappingKey {
            namespace,
            name: mapping.name_any(),
        };
        let mut live = self.live.write().unwrap_or_else(|p| p.into_inner());
        live.remove(&key);
    }

    /// Apply one watcher event. Errors are logged, never fatal: one bad
    /// mapping must not stop the index from tracking the rest.
    pub fn handle(&self, event: watcher::Event<CognitoClientMapping>) {
        let result = match event {
            watcher::Event::Apply(m) => self.apply(&m),
            watcher::Event::Delete(m) => {
                self.delete(&m);
                Ok(())
            }
            watcher::Event::Init => {
                *self.relist.lock().unwrap_or_else(|p| p.into_inner()) = Some(Inner::default());
                Ok(())
            }
            watcher::Event::InitApply(m) => {
                let mut relist = self.relist.lock().unwrap_or_else(|p| p.into_inner());
                relist.get_or_insert_with(Inner::default).apply(&m)
            }
            watcher::Event::InitDone => {
                let rebuilt = self
                    .relist
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .take()
                    .unwrap_or_default();
                *self.live.write().unwrap_or_else(|p| p.into_inner()) = rebuilt;
                self.synced.store(true, Ordering::Release);
                tracing::info!(mappings = self.len(), "mapping index synced");
                Ok(())
            }
        };
        if let Err(error) = result {
            tracing::warn!(%error, "mapping not indexed");
        }
    }

    /// Keep the index in sync with every `CognitoClientMapping` in the
    /// cluster. Runs until the process exits; the watcher reconnects with
    /// backoff on its own.
    pub async fn run(self: Arc<Self>, client: kube::Client) {
        let api = kube::Api::<CognitoClientMapping>::all(client);
        let stream = watcher(api, watcher::Config::default()).default_backoff();
        futures::pin_mut!(stream);
        while let Some(event) = stream.next().await {
            match event {
                Ok(event) => self.handle(event),
                Err(error) => tracing::warn!(%error, "mapping watch error; retrying"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
    use recognito_api::{
        AwsRoleIdentity, AwsRoleRef, CognitoClientMappingSpec, CognitoClientMappingStatus,
        ServiceAccountIdentity,
    };

    const ROLE_ARN: &str = "arn:aws:iam::111122223333:role/payments";

    fn spec() -> CognitoClientMappingSpec {
        serde_json::from_value(serde_json::json!({
            "serviceAccountRef": { "name": "api" },
            "userPoolId": "us-east-1_aBcDeFgHi",
            "allowedScopes": [{ "name": "read", "scopes": ["payments/read"] }],
        }))
        .unwrap()
    }

    fn mapping(ns: &str, name: &str, spec: CognitoClientMappingSpec) -> CognitoClientMapping {
        let mut m = CognitoClientMapping::new(name, spec);
        m.metadata.namespace = Some(ns.into());
        m.status = Some(CognitoClientMappingStatus {
            client_id: Some(format!("client-{ns}-{name}")),
            ..Default::default()
        });
        m
    }

    fn sa_mapping(ns: &str, name: &str) -> CognitoClientMapping {
        mapping(ns, name, spec())
    }

    fn role_mapping(ns: &str, name: &str) -> CognitoClientMapping {
        mapping(
            ns,
            name,
            CognitoClientMappingSpec {
                service_account_ref: None,
                aws_role: Some(AwsRoleRef {
                    arn: ROLE_ARN.into(),
                }),
                ..spec()
            },
        )
    }

    fn sa(ns: &str, name: &str) -> WorkloadIdentity {
        WorkloadIdentity::ServiceAccount(ServiceAccountIdentity {
            namespace: ns.into(),
            name: name.into(),
        })
    }

    fn role() -> WorkloadIdentity {
        WorkloadIdentity::AwsRole(AwsRoleIdentity::from_role_arn(ROLE_ARN).unwrap())
    }

    #[test]
    fn a_singly_claimed_identity_resolves_to_its_mapping() {
        let index = MappingIndex::new();
        index.apply(&sa_mapping("payments", "m")).unwrap();
        let entry = index.lookup(&sa("payments", "api")).unwrap();
        assert_eq!(entry.client_id.as_deref(), Some("client-payments-m"));
        assert_eq!(
            index.lookup(&sa("other", "api")),
            Err(LookupError::NotMapped)
        );
    }

    #[test]
    fn a_role_claimed_from_two_namespaces_is_refused_not_resolved() {
        // The cross-namespace case from ADR-15: a tenant in `attacker` claims a
        // role already mapped in `payments`. Neither mapping wins.
        let index = MappingIndex::new();
        index.apply(&role_mapping("payments", "m")).unwrap();
        assert!(index.lookup(&role()).is_ok());

        index.apply(&role_mapping("attacker", "m")).unwrap();
        assert_eq!(
            index.lookup(&role()),
            Err(LookupError::Ambiguous { claimants: 2 })
        );
        assert_eq!(index.claimants(&role()).len(), 2);

        // Removing the duplicate restores service.
        index.delete(&role_mapping("attacker", "m"));
        assert!(index.lookup(&role()).is_ok());
    }

    #[test]
    fn two_mappings_for_one_service_account_are_also_refused() {
        let index = MappingIndex::new();
        index.apply(&sa_mapping("payments", "a")).unwrap();
        index.apply(&sa_mapping("payments", "b")).unwrap();
        assert_eq!(
            index.lookup(&sa("payments", "api")).unwrap_err().reason(),
            "ambiguous_mapping"
        );
    }

    #[test]
    fn ambiguity_is_a_403_that_names_no_mappings() {
        let err = ExchangeError::from(LookupError::Ambiguous { claimants: 2 });
        assert_eq!(err.status(), 403);
        assert!(!err.description.contains("attacker"));
        assert!(!err.description.contains('/'));
    }

    #[test]
    fn an_edit_that_changes_the_identity_releases_the_old_claim() {
        let index = MappingIndex::new();
        index.apply(&sa_mapping("payments", "m")).unwrap();
        index.apply(&role_mapping("payments", "m")).unwrap();
        assert_eq!(
            index.lookup(&sa("payments", "api")),
            Err(LookupError::NotMapped)
        );
        assert!(index.lookup(&role()).is_ok());
        assert_eq!(index.len(), 1);
    }

    #[test]
    fn a_mapping_that_stops_validating_loses_its_claim() {
        let index = MappingIndex::new();
        index.apply(&sa_mapping("payments", "m")).unwrap();
        let mut broken = sa_mapping("payments", "m");
        broken.spec.user_pool_id = "not-a-pool".into();
        assert!(matches!(
            index.apply(&broken),
            Err(ApplyError::InvalidSpec { .. })
        ));
        assert_eq!(
            index.lookup(&sa("payments", "api")),
            Err(LookupError::NotMapped)
        );
    }

    #[test]
    fn a_mapping_being_deleted_stops_issuing_before_its_finalizer_clears() {
        let index = MappingIndex::new();
        index.apply(&sa_mapping("payments", "m")).unwrap();
        let mut deleting = sa_mapping("payments", "m");
        deleting.metadata.deletion_timestamp = Some(Time(k8s_openapi::jiff::Timestamp::now()));
        index.apply(&deleting).unwrap();
        assert_eq!(
            index.lookup(&sa("payments", "api")),
            Err(LookupError::NotMapped)
        );
    }

    #[test]
    fn an_unprovisioned_mapping_is_retryable_not_refused() {
        let index = MappingIndex::new();
        let mut m = sa_mapping("payments", "m");
        m.status = None;
        index.apply(&m).unwrap();
        let err = index.lookup(&sa("payments", "api")).unwrap_err();
        assert_eq!(err, LookupError::NotReady);
        assert_eq!(ExchangeError::from(err).status(), 503);
    }

    #[test]
    fn a_relist_replaces_the_index_wholesale() {
        // `gone` was deleted while the watch was disconnected: the re-list does
        // not mention it, and it must not survive the swap.
        let index = MappingIndex::new();
        index.handle(watcher::Event::Apply(sa_mapping("payments", "gone")));
        index.handle(watcher::Event::Init);
        index.handle(watcher::Event::InitApply(role_mapping("payments", "m")));
        // Mid-relist, lookups still see the old, complete index.
        assert!(index.lookup(&sa("payments", "api")).is_ok());
        assert_eq!(index.lookup(&role()), Err(LookupError::NotMapped));

        assert!(!index.is_synced());
        index.handle(watcher::Event::InitDone);
        assert!(index.is_synced());
        assert_eq!(
            index.lookup(&sa("payments", "api")),
            Err(LookupError::NotMapped)
        );
        assert!(index.lookup(&role()).is_ok());
    }

    #[test]
    fn watcher_deletes_remove_the_claim() {
        let index = MappingIndex::new();
        index.handle(watcher::Event::Apply(sa_mapping("payments", "m")));
        index.handle(watcher::Event::Delete(sa_mapping("payments", "m")));
        assert!(index.is_empty());
    }
}
