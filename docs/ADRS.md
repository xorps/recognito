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

## ADR-5: Peer fabric (gossip + ring) — ACCEPTED, implemented (was DEFERRED)
Built as one package in `crates/broker/src/cluster/` (generic pieces — ring,
remote merge, fill feed, digest — in `crates/cache`). Transport and trust in
ADR-20. Original trigger, for the record: before first at-scale cluster-wide
restart (predictable stampede), or deploy-time cold-miss spikes.
Gossip: state-based LWW-by-expiry map; fire-and-forget deltas on fill +
periodic anti-entropy; loss/dup/reorder safe by merge algebra; no
tombstones (self-expiry). Ring: rendezvous hash over EndpointSlices, cold
path only (hits always served locally); forward once, never re-forward,
fail open on deadline. Both share one mTLS channel + one membership source.
Jitter (v1, free): thresholds ~U(60%,80%) desync refresh; gossip suppresses
followers; probabilistic ownership, no timers.

As built: deltas batch for 20ms; anti-entropy is push-pull against a digest
(`(key, expires_at)` / `(client, generation)`), one random peer every ~1s;
a new replica pulls from two peers before `/readyz` passes, retrying across
peers for up to 10s and then becoming ready cold rather than never. Secrets
merge by generation (higher wins, older refused — single-writer monotone, not
a lattice; ADR-10). Ring hash is FNV-1a + SplitMix64, pinned by a test so two
builds in one rollout agree on owners. Peer identity is `pod-ip:port`.
Verified in kind: 60 exchanges over 3 replicas = 3 token calls and 1 Describe;
a full rolling restart under load = 0 failed requests and 0 new Cognito calls.

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

## ADR-15: SigV4 (presigned STS GetCallerIdentity) for workloads outside Kubernetes — ACCEPTED
Workloads off-cluster (EC2, ECS, Lambda, IAM Roles Anywhere) have no projected
ServiceAccount token, but they do have an IAM role. The caller presigns an STS
`GetCallerIdentity` request with its own credentials and sends the URL as an
RFC 8693 subject token (`subject_token_type =
urn:recognito:params:oauth:token-type:aws-sigv4-presigned-url`). The broker
forwards it to STS; STS verifying the signature *is* the authentication, and
its answer names the role. Same mechanism as EKS cluster tokens
(aws-iam-authenticator) and Vault's IAM auth method — chosen because it is the
one every AWS SDK can produce, and because it keeps ADR-1 intact: AWS verifies,
we hold no keys, and the broker needs no IAM permission for it.

**Audience binding carries over (invariant 2).** A presigned URL proves
identity to whoever holds it, so an unbound one is the CVE-2025-32963 shape
again. The caller must sign `x-recognito-audience`; the broker forwards with
that header set to its own canonical audience — the same value JWTs carry in
`aud` — so STS's signature check *is* the byte-exact comparison. The broker
refuses any URL that did not sign the header, and names URLs bound to known
foreign verifiers (`x-k8s-aws-id`, `x-vault-aws-iam-server-id`) as an attack
signal, like an apiserver-audience JWT.

**Hardening, each a named test** (`crates/broker/tests/sigv4_audience_binding.rs`):
- Host is byte-exact one of the configured regional STS endpoints. A
  caller-chosen host answers GetCallerIdentity with any ARN it likes.
- `Action=GetCallerIdentity`, `Version=2011-06-15`, raw-exact; the response is
  requested as JSON and parsed as exactly that result shape; redirects are not
  followed (CVE-2020-16250, Vault IAM auth: caller-chosen action + lenient
  response parsing).
- Query keys from a fixed allowlist, byte-exact, each at most once; values in
  strict SigV4 encoding. Duplicate, case-variant, or percent-encoded keys are
  refused rather than interpreted (CVE-2022-2385 class, aws-iam-authenticator:
  validator and STS reading different copies of a duplicated parameter).
- `X-Amz-SignedHeaders` exactly `host;x-recognito-audience`; credential scope
  `…/<endpoint region>/sts/aws4_request`; `X-Amz-Expires` ≤ 900s; date within
  skew. All checked before spending an STS call.

**Principals: assumed roles only.** IAM users (long-lived keys — the
distributed-secret problem this project removes), root, and federated users
are refused after STS answers. Identity key is `(partition, account, role
name)`: STS drops the role path from assumed-role ARNs, and role names are
unique per account regardless of path. Byte-exact; a mis-cased spec fails
closed.

**Trust boundary: `RECOGNITO_SIGV4_TRUSTED_ACCOUNTS`.** Mandatory once the door
is open (`RECOGNITO_SIGV4_REGIONS` set); the broker refuses to start without
it. Mapping authors are namespace tenants and can name any account's role; the
allowlist is the platform operator's boundary that no mapping can widen.

**CRD: `spec.awsRole.arn`**, exactly one of it and `serviceAccountRef`
(CEL rule at admission + `validate()`). A role is *not* namespace-confined the
way a ServiceAccount is, so the broker index (`crates/broker/src/index.rs`)
refuses an identity that more than one mapping claims rather than picking one —
fail closed. The cost: any tenant can deny service to a role by claiming it a
second time. Accepted for now; an admission policy restricting `awsRole` to
platform namespaces closes it if that ever matters.

**Transport** (`crates/broker/src/sts.rs`): hyper + rustls (ring), HTTPS only,
platform trust roots, no redirect following, 5s deadline over the whole round
trip, 64 KiB body cap. Timeouts and connection failures are 503, never 403.

**Cost.** One STS round trip per SigV4 exchange; uncacheable, since each
presigned URL is distinct. The request is signed with the caller's
credentials, so STS rate limits are charged to the caller's account, not
ours. Cognito-side cost is unchanged: the token cache key is client + scope
set, not the door a caller came through.

Rejected:
- *Signed request with headers + body forwarded (Vault's original shape).*
  More caller-controlled surface (method, headers, body) for no gain; the
  presigned-URL form is one opaque string that fits `subject_token`.
- *Verifying SigV4 ourselves.* Requires the caller's secret key. No.
- *IAM Roles Anywhere / X.509 directly.* Roles Anywhere already ends in an
  assumed role, so it arrives through this door for free.
- *Binding to the role's unique ID (`AROA…`).* Survives delete-and-recreate
  of a same-named role, which name binding does not. DEFERRED; trigger: a
  role-recreation incident, or a policy requiring it. Needs either an
  `iam:GetRole` permission on the broker or the ID written into the spec.

## ADR-16: JWT door verifies by TokenReview, not local JWKS — ACCEPTED (local verify DEFERRED)
The broker sends every projected token to `TokenReview` with
`spec.audiences=[ours]` and checks `authenticated` *and* `status.audiences`
(invariant 2). Before that, it decodes the payload **unverified** and runs
`aud` through the claim validator; that pre-check can only refuse, never
accept, and exists so a replayed apiserver-audience token is rejected without
an apiserver call and counted as an attack signal.

Why not verify RS256 locally against the cluster JWKS: TokenReview is the
apiserver's own answer, so a bound token whose pod is gone, or whose
ServiceAccount was deleted and re-created, is refused — a signature check
cannot know either. Local verification buys latency the exchange path does not
need: callers hold their Cognito token for most of its life and exchange
rarely, and the broker's token cache makes the Cognito leg cheap.

Deferred, trigger: TokenReview p99 > 50ms at steady state, or apiserver
request budget pressure attributable to the broker. Then: verify locally
(JWKS from the issuer discovery document, RS256 inline per CLAUDE.md runtime
decisions), keep TokenReview for tokens whose `kubernetes.io` claims name a pod
not in an informer cache. `jsonwebtoken` was removed from the workspace until
then.

## ADR-17: Secret rotation mechanics — ACCEPTED
Rotation is `AddUserPoolClientSecret` → bump `status.secretGeneration` and
record `retiringSecretId` / `retireAfter` → after `RECOGNITO_ROTATION_GRACE`,
`DeleteUserPoolClientSecret`. Cognito holds at most two secrets per client, so
no rotation starts while a retirement is pending. The controller drops the
secret value `AddUserPoolClientSecret` returns, unread; brokers read secrets
only through `DescribeUserPoolClient` (ADR-2).

**Assumption, not documented by AWS:** which of two live secrets
`DescribeUserPoolClient` returns. The design does not depend on the answer.
The generation bump evicts every broker's cached secret; whichever secret
Describe then returns is valid during the grace window; once the old one is
deleted, a broker still holding it gets `invalid_client` and the fetcher
evicts, re-describes and retries once inside the same request. Worst case is
one extra Describe and one extra token call per client per rotation, invisible
to callers. If AWS documents "newest", the retry path simply stops firing.

Crash safety: a rotation whose status write was lost is detected on the next
reconcile (two secrets exist, none recorded as retiring) and *finished* —
oldest marked retiring — rather than repeated. A create whose status write was
lost is adopted by name: client names embed the object UID, so a match is
ours.

`userPoolId` is immutable (CEL transition rule). An app client cannot move
between pools; allowing the edit would orphan the old client.

## ADR-18: Single controller replica, no leader election — ACCEPTED for v1, DEFERRED
One replica, `Recreate` strategy. Every Cognito write is idempotent or
crash-recoverable (ADR-17), and the broker serves from cache while the
controller is down, so controller downtime delays provisioning and rotation —
it never breaks issuance. Two concurrent writers, by contrast, would race
rotations and could add a third secret. Leader election (a `coordination.k8s.io`
Lease) is the fix when needed.

Trigger: an SLO on time-to-provision tighter than a pod restart (~30s plus
image pull), or node-failure recovery time for the controller pod becoming a
reported problem.

## ADR-19: Broker serves one user pool — ACCEPTED
`RECOGNITO_USER_POOL_ID` is a single pool; mappings for others are refused
(`pool_not_served`). This keeps the broker's IAM to `DescribeUserPoolClient` on
one ARN (CLAUDE.md runtime decisions) and its token endpoint to one domain.
Multiple pools = multiple broker Deployments with distinct audiences. The
controller, which has no request path, may manage several pools.

## ADR-20: Peer channel is mTLS over TCP (HTTP/1.1), not UDP/QUIC — ACCEPTED
ADR-5's sketch said "mTLS UDP/QUIC". Built instead on the stack the broker
already has: rustls (ring) + hyper HTTP/1.1, four JSON calls
(`/peer/v1/{tokens,secrets,sync,fetch}`) on a dedicated port.

Why: the merge algebra already makes loss, duplication and reordering
harmless, so UDP's one advantage — not paying for reliability we do not need
— is worth little at this volume (a few small messages per fill, one digest
per second). QUIC would add quinn and a second TLS integration to audit for no
measured gain; DTLS has no maintained Rust implementation. TCP connections are
pooled, so the handshake is paid once per peer pair, not per message.
Trigger to revisit: peer-channel CPU or p99 forward latency showing up in
profiles, or fleets large enough that full-mesh delta fan-out dominates (then
switch fan-out to a random subset before switching transport).

**Trust.** mTLS both ways against a **dedicated peer CA**; any certificate it
signs is a peer, nothing else is. All replicas share one peer certificate
(peers are anonymous and interchangeable — CLAUDE.md deployment shape), whose
DNS name (`recognito-broker-peer`) is verified on dial; pod IPs are where we
connect, never what we verify. A NetworkPolicy additionally limits the peer
port to broker pods. Holding the peer key = ability to inject tokens and
secrets into every replica's cache; it is as sensitive as the broker's IAM
role, which is why the CA must sign nothing else.

**Rejected: per-pod certificates.** Would let a peer be named in logs, but
cert-manager cannot mint per-pod certificates without a CSI driver, and naming
peers buys nothing when they are interchangeable by design.
