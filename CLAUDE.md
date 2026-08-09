# Project: Cognito Workload Identity Broker ("IRSA for Cognito")

K8s controller + broker that maps Kubernetes ServiceAccounts to Cognito app
clients and exchanges projected SA tokens for Cognito client_credentials
access tokens. Workloads never hold client secrets.

Two binaries and two libraries, one cargo workspace (split later if the cache
crate is extracted):
- **controller/**: reconciles `CognitoClientMapping` CRDs -> Cognito app
  clients (create/rotate/delete). Rust, kube-rs. Also ships `recognito-crdgen`,
  which emits `deploy/crd.yaml` — never hand-edit that file.
- **broker/**: validates SA JWTs, maps identity -> client, mints + caches
  tokens. Rust, tokio (multi-thread), axum, rustls.
- **api/**: `CognitoClientMapping` types, scope profiles, duration parsing,
  spec hashing. The single definition of a valid mapping; both binaries
  depend on it and neither depends on the other.
- **cache/**: token cache fabric. Depends on neither `api` nor kube nor any
  AWS SDK — the credential source is injected as a `TokenFetcher` trait, which
  is what keeps the crate extractable. Do not add those dependencies to it.

## Core invariants — do not violate without updating docs/ADRS.md
1. **Store nothing durable.** Cognito is the only durable home of client
   secrets. Broker state is memory-only, re-derivable. No PVCs, no Redis,
   no Secrets Manager copies. Broker runs as a Deployment, never StatefulSet.
2. **Audience binding is mandatory.** Broker accepts SA tokens ONLY with
   `aud == https://cognito-broker.<domain>` (byte-exact, canonical form).
   Default apiserver-audience tokens MUST be rejected (see CVE-2025-32963
   regression test). TokenReview calls must set spec.audiences AND check
   status.audiences.
3. **Quota budgets are architectural.** ClientAuthentication: 150 RPS
   account-wide. UserPoolClientRead/Update: 15 RPS account-wide AND 5 RPS
   per (operation, pool). Broker Describe limiter 3 RPS; controller audit
   loop 1-2 RPS; controller yields under contention. None are adjustable.
4. **Controller avoids AWS calls on resync.** Spec-hash + lastVerified in
   CRD status short-circuits reconcile; drift detection is a separate slow
   background audit loop (1-2 RPS/pool), never the reconcile hot path.
5. **Three credential shapes, three mechanisms** (docs/DESIGN.md §Shapes):
   - token-shaped (parallel-valid, self-expiring) -> CRDT cache + gossip
   - config-shaped (single-writer, re-derivable: client secrets) ->
     informer pattern: CRD-watch generation eviction + invalid_client
     oracle (evict-and-refetch-once on invalid_client)
   - vault-shaped (not re-derivable) -> out of scope; ESO/Vault behind the
     same authn door
6. **Pass-through STS.** Cognito stays the issuer. Never mint/sign our own
   tokens, never build a JWKS.

## Cache fabric (v1 vs drawer)
- v1: per-replica in-memory cache (DashMap), singleflight per key,
  jittered freshness thresholds (uniform ~60-80% of lifetime, per replica
  per key), lazy refresh only (no background timers).
- Drawer (designed, deferred — see ADRs for triggers): gossip mesh
  (LWW-by-expiry merge over mTLS UDP/QUIC), rendezvous-hash ring for
  cold-path fetch ownership (forwarded requests never re-forward; fail
  open to local fetch), secrets on gossip mesh keyed by rotation
  generation.
- Cache key = (client_id, canonical scope set). Canonicalize scopes to
  bounded profiles from allowedScopes: a request's `scope` must match a
  declared profile's set exactly, so cardinality per client is the profile
  count, not the powerset (ADR-14).

## Rotation (Cognito Feb 2026 APIs)
AddUserPoolClientSecret -> grace period (> propagation lag) ->
DeleteUserPoolClientSecret. Client ID never changes. CRD: rotateAfter;
status: secretCreatedAt, secretGeneration. Secrets never expire on their
own; rotation policy is entirely ours.

## Runtime decisions
tokio multi-thread (NOT thread-per-core — see ADRS), worker_threads pinned
to cgroup CPU limit, RS256 verify inline (no spawn_blocking), DashMap for
caches. Broker IAM: DescribeUserPoolClient on one pool ARN only.
Controller IAM (separate role): Create/Update/Delete + Add/Delete secret.

## Deployment shape
Deployment, >=3 replicas, topologySpreadConstraints on zone (minDomains 3),
PDB minAvailable 2, maxUnavailable 0 / maxSurge 1, readiness gated on
gossip warm-up (when gossip lands). Peer discovery: EndpointSlice watch on
own headless Service; peers are anonymous/interchangeable by design.

## Style
- Rust 2021. Errors: thiserror in libs, anyhow at binary edges.
- Every rejected design lives in docs/ADRS.md with the reasoning and, if
  deferred rather than rejected, an explicit metric trigger.
- Security-sensitive validation logic gets a named test per failure mode
  (see broker/tests/audience_cve_2025_32963.rs pattern).
