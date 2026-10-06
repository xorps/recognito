# Project: Cognito Workload Identity Broker ("STS for Cognito")

K8s controller + broker that maps Kubernetes ServiceAccounts to Cognito app
clients and exchanges projected SA tokens for Cognito client_credentials
access tokens. Workloads never hold client secrets.

Two binaries and two libraries, one cargo workspace under `crates/` (split
later if the cache crate is extracted):
- **crates/controller/**: reconciles `CognitoClientMapping` CRDs -> Cognito app
  clients (create/rotate/delete). Rust, kube-rs. Also ships `recognito-crdgen`,
  which emits `deploy/crd.yaml` — never hand-edit that file.
- **crates/broker/**: validates SA JWTs (in-cluster) and presigned STS
  GetCallerIdentity URLs (SigV4, off-cluster), maps identity -> client, mints
  + caches tokens. Rust, tokio (multi-thread), axum, rustls.
- **crates/api/**: `CognitoClientMapping` types, scope profiles, duration parsing,
  spec hashing. The single definition of a valid mapping; both binaries
  depend on it and neither depends on the other.
- **crates/cache/**: token cache fabric. Depends on neither `api` nor kube nor any
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
   status.audiences. SigV4 door: the presigned URL MUST sign
   `x-recognito-audience`, and the broker forwards that header with its own
   canonical audience so STS enforces the match; host, action, and query
   params are allowlisted byte-exact (ADR-15).
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
- v2 peer fabric (built, `crates/broker/src/cluster/`; ADR-5, ADR-20):
  gossip mesh (LWW-by-expiry merge over mTLS HTTP/1.1, dedicated peer CA),
  rendezvous-hash ring for cold-path fetch ownership (forwarded requests
  never re-forward; fail open to local fetch), secrets on the mesh keyed by
  rotation generation, readiness gated on a warm-up pull. Generic pieces
  (ring, merge_remote, fill feed, digest) live in `cache`; anything that
  knows about kube, TLS or Cognito stays in the broker. The ring hash is
  pinned by a test — changing it splits ownership during a rollout.
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
to cgroup CPU limit, DashMap for caches. JWTs are verified by TokenReview
(ADR-16); if local verification lands, RS256 verify inline (no
spawn_blocking). One rustls stack (ring) for every TLS connection, the AWS
SDK included — don't let aws-lc back in through default features. Broker IAM: DescribeUserPoolClient on one pool ARN only
(the SigV4 door needs none: GetCallerIdentity is signed with the caller's creds).
Controller IAM (separate role): Create/Update/Delete + Add/Delete secret.

## Deployment shape
Deployment, >=3 replicas, topologySpreadConstraints on zone (minDomains 3),
PDB minAvailable 2, maxUnavailable 0 / maxSurge 1, readiness gated on the
mapping index's first full sync (and on gossip warm-up, when gossip lands).
Controller: single replica, Recreate, no leader election (ADR-18). Install is
`kubectl apply -k deploy/`; docs/OPERATIONS.md and docs/CLIENTS.md are the
operator- and caller-facing docs — keep them in step with config and errors.
Peer discovery: EndpointSlice watch on own headless Service (`cognito-broker-peers`); peers are anonymous/interchangeable
by design and share one peer certificate. On SIGTERM the broker reports
not-ready and keeps serving 5s before draining (endpoint-propagation race).

## Style
- Rust 2024, toolchain pinned in `rust-toolchain.toml` (bump it and
  `rust-version` together). No `async-trait`: use native `async fn` in traits
  (declare `-> impl Future<Output = ..> + Send` in the trait) and generics
  rather than `dyn`. Errors: thiserror in libs, anyhow at binary edges.
- Every rejected design lives in docs/ADRS.md with the reasoning and, if
  deferred rather than rejected, an explicit metric trigger.
- Security-sensitive validation logic gets a named test per failure mode
  (see crates/broker/tests/audience_cve_2025_32963.rs and
  sigv4_audience_binding.rs).
