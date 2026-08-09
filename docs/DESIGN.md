# Design: Cognito Workload Identity Broker

## Problem
Cognito's token endpoint supports only client_id+secret (no client
assertions / private_key_jwt / mTLS), so K8s workloads calling
Cognito-protected APIs normally require distributed client secrets.
This system eliminates that: workloads present projected ServiceAccount
tokens; a broker exchanges them for Cognito access tokens. Analogous to
IRSA/Pod Identity, targeting Cognito's issuer instead of IAM.
Prior art: Curity/Keycloak solve this via RFC 7523 client assertions
(impossible on Cognito); MinIO Operator STS is the closest structural
cousin (and shipped CVE-2025-32963 — audience confusion — which we test
against explicitly).

## Components
**CognitoClientMapping CRD** (namespaced): serviceAccountRef, userPoolId,
allowedScopes (canonical profiles), tokenValidity (floor-validated),
rotateAfter, optional deliverTo.secretRef (push-mode opt-in, weaker
posture, documented). Status: clientId, specHash, lastVerified,
secretCreatedAt, secretGeneration.

**Controller**: reconciles CRD -> app client (CreateUserPoolClient, tag
with CRD UID, finalizer). Resync discipline: spec-hash short-circuit, no
AWS calls when hash matches + verification recent. Drift detection =
separate background audit loop at 1-2 RPS/pool. Rotation loop per
rotateAfter using Add/DeleteUserPoolClientSecret with grace window.

**Broker** (Deployment, >=3 replicas, zone-spread): layers in one binary —
1. authn: verify SA JWT (sig via cluster JWKS or TokenReview; iss, exp,
   sub; aud byte-exact = broker URL; reject apiserver audience).
2. authz: identity -> mapping via CRD-fed in-memory index; downscoping
   allowed, never up.
3. fetch: cache fabric get_or_fetch with Cognito client_credentials
   fetcher. Structured audit log per exchange (caller, mapping, scopes,
   ttl, request id). GetCallerIdentity-style debug endpoint.

## Credential shapes -> mechanisms
| Shape | Test | Example | Mechanism |
|---|---|---|---|
| token | parallel-valid + self-expiring + re-derivable | access tokens, STS sessions | LWW-by-expiry CRDT map, gossip-safe, no tombstones |
| config | single-writer + re-derivable + non-expiring | Cognito client secrets | informer: watch-driven eviction (secretGeneration) + resync + use-time oracle (invalid_client -> evict, refetch once) |
| vault | not re-derivable | 3rd-party static keys | durable store (ESO/Vault) behind same authn door; out of scope here |

Boundary: rotating refresh tokens are LINEAR (use invalidates siblings) —
explicitly unsupported by the cache; document loudly.

## Cache fabric
v1: per-replica DashMap + singleflight (Notify-based; waiters woken before
gossip send; wake loops back to fast path) + jittered lazy refresh
(threshold ~U(60%,80%) of lifetime per replica per key; no timers; idle
keys cost zero).
v2 (single "peer fabric" ship, trigger: before first at-scale cluster
restart): mTLS peer channel + EndpointSlice membership; delta gossip on
fill + 1s anti-entropy to random peer; rendezvous-hash ring for cold-path
fetch ownership (hit -> serve local; miss+owner -> fetch; miss+not-owner ->
forward once, deadline ~500ms, fail open; forwarded never re-forwarded).
Secrets ride the mesh keyed by generation. Metric: forward_rate ~0 is the
health signal for both mechanisms.

## Quota model (all non-adjustable; account/region unless noted)
- ClientAuthentication 150 RPS: sizes fleet (~90k mappings at 15-min TTL).
  Steady state ~1% utilized post-fabric. Watch account ThrottleCount
  (noisy-neighbor risk: budget is shared with the whole account).
- UserPoolClientRead 15 RPS, AND 5 RPS per (op, pool): shapes secret
  design. Steady-state Describes ~0 (event-driven eviction). Cold-start
  drain bounded 1/client via singleflight+ring; prioritized warming (hot
  mappings first). Split: broker 3 RPS, controller 1-2, controller yields.
- UserPoolClientUpdate 15 RPS + same 5 RPS footnote: controller only.
- Domain limits 300/IP, 300/client, 500/domain: NAT egress note; 150 trips
  first at one pool.
- jwks.json 50k RPS: consumer-side; enforce JWKS caching in resource
  servers; serve-stale on refresh failure.
- App clients/pool 1000 -> request 10k early (only adjustable quota).

## Failure posture
Static-stability gap acknowledged: total-fleet cold start drains secrets
through 5 RPS. Mitigations: ops never produce zero survivors (PDB, spread,
surge, readiness-gate on warm-up); workload-held tokens coast <=15 min;
prioritized warming; drawer option = single KMS-encrypted snapshot (S3),
trigger = RTO tighter than warm window. Failure mode is availability-only,
never disclosure.

## Deprovisioning
Finalizer deletes app client; cached/held tokens remain valid <= TTL
(client_credentials tokens are irrevocable). Zombie window = tokenValidity;
documented, security-review sign-off required. Broker evicts mapping on
CRD delete immediately (stops NEW issuance instantly).

## Wire protocol
RFC 8693 token exchange, narrow profile — ADR-13. `POST /token`, form-encoded,
`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, subject token in
the body (not the Authorization header). Response is RFC 8693 §2.2.1; errors
are RFC 6749 §5.2 with one documented status deviation: `invalid_grant` is 403,
not 400, because a refused subject token is an authorization outcome. Unsupported
parameters (`resource`, `audience`, `actor_token`, non-access `requested_token_type`)
are rejected with their spec-defined error, never ignored.

`scope` carries real scope strings per the standard, but must canonicalize to a
set some profile declares exactly (ADR-14) — that is what keeps cache
cardinality per client equal to the profile count rather than the powerset of
its scopes, which is the assumption the quota arithmetic above rests on.

## Open items
- Broker blast-radius containment (per-namespace pools? scope deny-list?).
- Audience migration plan if SPIRE lands (URL -> +SPIFFE ID dual-accept).
- Secret cache (config-shaped) implementation: informer wiring + invalid_client
  oracle. Cache crate covers token-shaped only today.
