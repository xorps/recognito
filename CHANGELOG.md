# Changelog

## 0.1.0 — unreleased

First release.

### Broker
- RFC 8693 token exchange at `POST /token` (ADR-13), and `POST /whoami` for
  debugging identity and mapping resolution without issuing a token.
- In-cluster door: projected ServiceAccount tokens, verified by TokenReview with
  mandatory audience binding; default apiserver-audience tokens are refused and
  counted as attack signals (invariant 2, CVE-2025-32963 regression suite;
  ADR-16).
- Off-cluster door (opt-in): presigned STS `GetCallerIdentity` URLs bound to the
  broker by a signed `x-recognito-audience` header; regional STS endpoints and
  trusted accounts only; assumed roles only (ADR-15).
- Mapping index fed by a CRD watch; identities claimed by more than one mapping
  are refused rather than resolved.
- Scope profiles: a request's `scope` must equal one declared profile (ADR-14).
- In-memory token cache with singleflight and jittered lazy refresh; in-memory
  client-secret cache evicted by `secretGeneration` and by the `invalid_client`
  oracle, with a fail-fast Describe rate limit (ADR-10, ADR-17).
- TLS termination on rustls/ring with certificate hot-reload; `/healthz`,
  `/readyz` (gated on index sync) and Prometheus `/metrics`; one JSON audit line
  per exchange.

### Broker mesh (ADR-5, ADR-20)
- Replicas discover each other from the EndpointSlices of a headless Service
  and talk over mTLS against a dedicated peer CA.
- Delta gossip of tokens and client secrets on every fetch, plus push-pull
  anti-entropy with a random peer every second.
- Rendezvous-hash ownership of the cold path: one replica fetches each key;
  others forward once and fail open to a local fetch after 500ms.
- Readiness waits for a warm-up pull from two peers; SIGTERM keeps serving 5s
  while not-ready so endpoints converge before listeners close.
- NetworkPolicy limits the peer port to broker pods.

### Controller
- Creates, updates and deletes one Cognito app client per mapping, under a
  finalizer; adopts a client whose status write was lost.
- Secret rotation with Cognito's two-secret API and a grace window; crash-safe
  (ADR-17).
- Rate-limited drift audit that restores hand-edited clients and re-creates
  deleted ones; steady-state reconciles make no AWS calls (invariant 4).
- `Ready` condition with actionable reasons; `userPoolId` immutable at
  admission.

### Packaging
- Kustomize base (`kubectl apply -k deploy/`), generated CRD, least-privilege
  IAM policies and RBAC, distroless image, CI (fmt, clippy,
  tests, CRD drift, manifest validation).

### Not in this release
Push-mode Secret delivery (`deliverTo` mappings are refused with
`Ready=False/DeliverToUnsupported`), local JWKS verification, and controller
leader election. Each has an ADR with its trigger.
