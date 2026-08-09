# Architecture Decision Records

Format: decision, status (accepted / rejected / deferred+trigger), reasoning.

## ADR-1: Pass-through STS; Cognito remains sole issuer — ACCEPTED
Broker mediates but never mints/signs tokens. Issuing would require our own
JWKS, key rotation, revocation, and every resource server trusting us —
rebuilding Cognito. Revisit only if certificate-bound tokens become a hard
requirement.

## ADR-2: Store-nothing secrets — ACCEPTED
Cognito is the durable secret store; broker fetches via
DescribeUserPoolClient and caches in memory. No Secrets Manager/Parameter
Store/K8s Secret copies. Triggers to revisit: cross-account pools, or
policy denying broker Describe (over-disclosure of client config).

## ADR-3: Raft/consensus for shared cache — REJECTED
All broker state is derived and re-derivable (tokens from Cognito, secrets
from Describe, mappings from CRDs). Consensus buys durability/linearizability
for authoritative state we don't have; costs quorum availability under
partition and churn-heavy membership. CALM framing: state is monotone under
max-by-expiry join -> coordination-free implementation exists; use it.
Consensus returns only if broker ever owns non-re-derivable state (own
issuer, revocation lists, exactly-once) — and then rent it (etcd via CRDs,
DynamoDB), don't embed it.

## ADR-4: Shared external cache (Redis/ElastiCache) — REJECTED
Solves duplicate misses across ~3 replicas (worth ~nothing) at the cost of
bearer tokens at rest in another system + a hard dependency on the data
path. Gossip achieves replication with no infrastructure.

## ADR-5: Peer fabric (gossip + ring) — DEFERRED, single package
Trigger: before first at-scale cluster-wide restart (predictable stampede),
or deploy-time cold-miss spikes on dashboard.
Gossip: state-based LWW-by-expiry map; fire-and-forget deltas on fill +
periodic anti-entropy; loss/dup/reorder safe by merge algebra; no
tombstones (self-expiry). Ring: rendezvous hash over EndpointSlices, cold
path only (hits always served locally); forward once, never re-forward,
fail open on deadline. Both share one mTLS channel + one membership source.
Jitter (v1, free): thresholds ~U(60%,80%) desync refresh; gossip suppresses
followers; probabilistic ownership, no timers.

## ADR-6: Thread-per-core runtime — REJECTED
Load is ~100x below TPC payoff threshold (per-replica RPS bounded by
quota-derived fleet ceiling). TPC forces per-core state sharding —
reintroduces fetch amplification inside the pod that gossip/ring removed
across pods. Bimodal request costs (150us hits vs 300ms misses) favor work
stealing. Chosen: tokio multi-thread, worker_threads = cgroup CPU limit.

## ADR-7: StatefulSet for broker — REJECTED
Stable identity is load-bearing only when membership changes require state
transfer decisions (Cassandra). Our peers are anonymous: state is fully
replicated + re-derivable; membership = EndpointSlice watch; K8s is the
failure detector. Per-pod PVCs would be N durable secret copies AZ-locked
to failure domains — strictly worse than ADR-8's snapshot. Deployment +
headless Service.

## ADR-8: Persisted cache snapshot — DEFERRED
Trigger: DR RTO for token issuance tighter than prioritized-warm window
(~1 min for 300 clients at 3 RPS, hot-first). Design: single KMS-encrypted
blob to S3, written by jitter-elected replica, restored at boot, staleness
healed by invalid_client oracle + generation check. Note: breaks ADR-2
minimally (one ciphertext copy, CloudTrail'd decrypts).

## ADR-9: Audience = broker HTTPS URL — ACCEPTED
`https://cognito-broker.<domain>`, canonical form (lowercase, no trailing
slash), byte-exact match, normalization enforced in pod-spec generator AND
validator (paired tests). Rejected bare names (collision/squatting, no env
separation). SPIFFE ID deferred: if SPIRE lands, dual-accept during
migration, then decide. Every accepted audience traces to an ADR line.
Regression test: default apiserver-audience token from a mapped SA -> 403
(CVE-2025-32963 class).

## ADR-10: Secret cache is informer-shaped, not CRDT-shaped — ACCEPTED
Secrets fail the CRDT test (no self-expiry, single-writer). Mechanism:
CRD-watch generation eviction + Cognito as use-time validity oracle
(invalid_client -> evict + refetch once) + engineered dual-validity via
rotation grace window > propagation lag. Gossiping them is safe by
single-writer monotonicity (generation order), not by lattice join.
History: started as TTL cache; 5 RPS per-pool read quota forced the
event-driven redesign.

## ADR-11: Refresh tokens / linear credentials — OUT OF SCOPE, LOUDLY
Cache fabric requires parallel validity (concurrent mints all honored).
Rotating refresh tokens are linear (use invalidates siblings; reuse
detection can revoke families) — no local merge can be correct. Enforce in
docs and, where possible, types.

## ADR-12: Push-mode Secret delivery — ACCEPTED as per-mapping opt-in
For unmodifiable workloads: broker refresh loop writes TOKENS (never
client secrets) to a namespaced Secret. Constraints: volume mount only, no
subPath, no env vars; refresh at ~50% TTL (kubelet propagation lag up to
~2 min); never with TTLs < ~10 min; not immutable Secrets. Documented as
weaker-audit compatibility mode; pull endpoint remains primary.

## ADR-13: RFC 8693 token exchange as the wire protocol — ACCEPTED
The operation we perform *is* token exchange: present a subject token, receive
a different token for a different issuer. RFC 8693 already names every part of
that, so a bespoke JSON shape would be a second vocabulary for a solved
problem — one that every client library, every proxy, and every security
reviewer would have to learn from our docs alone. Adopted with a deliberately
narrow profile.

**Request** — `POST /token`, `application/x-www-form-urlencoded`:
- `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` (required)
- `subject_token=<projected SA JWT>` (required)
- `subject_token_type=urn:ietf:params:oauth:token-type:jwt` (required)
- `scope=<space-delimited scopes>` (optional; must canonicalize to exactly one
  declared profile — ADR-14)

The subject token rides in the body, not an `Authorization: Bearer` header.
Two different tokens would otherwise both be "the bearer token" on one request,
and the header is the one a proxy or access log is most likely to capture.

**Response** — `200`, JSON, per RFC 8693 §2.2.1: `access_token`,
`issued_token_type` (always `urn:ietf:params:oauth:token-type:access_token`),
`token_type: "Bearer"`, `expires_in`, `scope`. `expires_in` is computed from
the cached token's real expiry, so a caller that arrives late in a cached
token's life is told the truth about how long it has left.

**Errors** — RFC 6749 §5.2 body (`error`, `error_description`). Status codes
deviate knowingly from 6749's blanket 400: a malformed or unsupported request
is `400` (`invalid_request`, `unsupported_grant_type`, `invalid_scope`,
`invalid_target`), but a well-formed request whose subject token we refuse is
`403` (`invalid_grant`). The refusal is an authorization outcome, not a
protocol error, and CLAUDE.md invariant 2's regression test asserts 403 for a
replayed apiserver-audience token. Documented here so the deviation is a
decision rather than a bug.

**Explicitly not implemented**, each returning a spec-defined error rather than
being silently ignored — a security-relevant parameter we quietly drop is worse
than one we reject:
- `actor_token` / delegation → `invalid_request`. We have no delegation model.
- `requested_token_type` other than `access_token` → `invalid_request`.
- `resource` / `audience` → `invalid_target`. The target is implied by the
  mapping; honouring a caller-supplied target would be up-scoping by another
  name.
- refresh tokens in any position → `invalid_request` (ADR-11).
- No `/.well-known/oauth-authorization-server`. We are an exchange endpoint,
  not an authorization server, and advertising discovery invites clients to
  try grants we do not implement.

Does not weaken ADR-1: RFC 8693 describes a wire shape, not an issuer. Cognito
still mints and signs; we still have no keys and no JWKS. Revisit only if we
ever need a token type Cognito cannot issue.

## ADR-14: Scope profiles are named sets, not arbitrary subsets — ACCEPTED
`allowedScopes` is a list of named profiles; a request's `scope` must
canonicalize (sort + dedup) to a set some profile declares exactly. Downscoping
is choosing a narrower profile.

Reasoning is the quota model, not ergonomics. The cache key is
`(client_id, canonical scope set)`, and the 150 RPS `ClientAuthentication`
budget sizes the fleet against the number of live keys. Arbitrary subsets make
the key space the powerset of a mapping's scopes — ten scopes is 1023 keys for
one app client, each with its own refresh cycle and its own exchange — and the
arithmetic that justifies the architecture stops holding. With profiles,
cardinality per client is a number a human wrote in a manifest.

Rejected: accept any subset and cap cardinality with an LRU. That converts a
static bound into a runtime eviction policy, and the failure mode is thrashing
under exactly the load where the budget is tightest.

Cost, accepted: a caller wanting a subset nobody declared gets `invalid_scope`
and needs a manifest change. That is the intended friction — it puts scope
decisions in a reviewed artifact rather than in a caller's request.
