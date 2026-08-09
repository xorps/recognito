# recognito

IRSA for Cognito.

Kubernetes workloads present their projected ServiceAccount token; a broker
exchanges it for a Cognito `client_credentials` access token. Workloads never
hold client secrets, and nothing durable is stored outside Cognito.

Cognito's token endpoint supports only `client_id` + secret — no client
assertions, no `private_key_jwt`, no mTLS — so the usual answer (RFC 7523, as
Curity and Keycloak do it) is unavailable. This is the workaround, shaped like
IRSA/Pod Identity but targeting Cognito's issuer instead of IAM.

## Layout

| Path | What it is |
|---|---|
| [api/](api/) | `CognitoClientMapping` CRD types, scope profiles, spec hashing |
| [cache/](cache/) | Token cache fabric — no kube, no AWS, no `api` dependency |
| [broker/](broker/) | Token exchange endpoint: audience binding, authz, fetch |
| [controller/](controller/) | CRD reconciler, rotation, and `recognito-crdgen` |
| [docs/DESIGN.md](docs/DESIGN.md) | Architecture, quota model, failure posture |
| [docs/ADRS.md](docs/ADRS.md) | Every decision, including the rejected ones |

## Status

Early. The contracts are in place and tested; the request path is not wired yet.

Built and tested:
- CRD types with admission-time validation, and a generated `deploy/crd.yaml`
- Audience binding (ADR-9) with the CVE-2025-32963 regression suite
- RFC 8693 wire protocol (ADR-13): parsing, error codes, status mapping
- v1 cache fabric: singleflight, jittered lazy refresh, LWW-by-expiry lattice
- Reconcile resync discipline (no AWS calls when nothing changed)

Not yet built: JWT signature verification and TokenReview plumbing, the CRD
mapping index, the Cognito fetcher, the HTTP server, controller reconcile and
rotation loops, and the config-shaped secret cache.

## Development

```sh
cargo test --workspace
cargo run --bin recognito-crdgen > deploy/crd.yaml   # regenerate the CRD
cargo run --example gossip_cache_demo -p recognito-cache
```

The gossip demo is a worked example of the **deferred** v2 peer fabric
(ADR-5) — it demonstrates singleflight collapsing a burst, delta gossip warming
peers with no extra upstream calls, and an idempotent merge. Nothing in `src/`
depends on it.

## Reading order

Start with the invariants in [CLAUDE.md](CLAUDE.md), then
[docs/DESIGN.md](docs/DESIGN.md). Every rejected design lives in
[docs/ADRS.md](docs/ADRS.md) with its reasoning and, where deferred rather than
rejected, an explicit metric trigger.
