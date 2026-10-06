# Operating recognito

## Install

Prerequisites: an EKS (or other) cluster with IRSA or Pod Identity, a Cognito
user pool with a domain and at least one resource server, and cert-manager (or
another way to put a TLS certificate in a Secret).

1. **IAM.** Create two roles — they are deliberately separate:
   - broker: `deploy/iam/broker-policy.json` — `DescribeUserPoolClient` on the
     one pool, nothing else.
   - controller: `deploy/iam/controller-policy.json` — create, update, delete,
     describe and list app clients and their secrets on the pool(s) it manages.

   Trust them to the `recognito-system/recognito-broker` and
   `recognito-system/recognito-controller` ServiceAccounts.

2. **Fill in the placeholders** with an overlay on `deploy/` (search for
   `REPLACE_WITH_`): role ARNs on both ServiceAccounts, the broker audience
   (`https://cognito-broker.<your domain>`), the pool ID, the Cognito domain
   (`https://<prefix>.auth.<region>.amazoncognito.com` or your custom domain),
   and the controller's allowed pools.

3. **TLS.** Issue a certificate for `cognito-broker.<your domain>` into Secret
   `recognito-system/recognito-broker-tls`
   (`deploy/examples/broker-certificate.yaml`), and make that name resolve
   to the `cognito-broker` Service for in-cluster callers. The broker reloads
   the certificate when the files change; no restart is needed on renewal.

   **Peer TLS** for the broker mesh: a dedicated CA and one shared peer
   certificate into Secret `recognito-system/recognito-broker-peer-tls`
   with `tls.crt`, `tls.key` and `ca.crt`
   (`deploy/examples/peer-certificates.yaml` does this with cert-manager).
   Never let that CA sign anything else: every certificate it signs can
   inject tokens into every replica.

4. **Apply:** `kubectl apply -k deploy/` (your overlay). This installs the CRD,
   namespace, RBAC, both Deployments, the Service and the PDB.

5. **Verify:** create `deploy/examples/mapping-serviceaccount.yaml`, wait for
   `kubectl get ccm -n payments` to show `Ready=True` and a client ID, then call
   `/whoami` and `/token` from a pod as in [CLIENTS.md](CLIENTS.md).

## Configuration

### Broker

| Variable | Default | |
|---|---|---|
| `RECOGNITO_BROKER_AUDIENCE` | required | Canonical `https://` URL. Projected tokens must carry exactly this `aud`; SigV4 URLs must sign it. |
| `RECOGNITO_USER_POOL_ID` | required | The one pool this broker serves. Mappings for other pools are refused (`pool_not_served`). |
| `RECOGNITO_COGNITO_DOMAIN` | required | `https://` origin of the pool's domain; the token endpoint is `<domain>/oauth2/token`. |
| `RECOGNITO_LISTEN_ADDR` | `0.0.0.0:8443` | Exchange listener. |
| `RECOGNITO_OPS_LISTEN_ADDR` | `0.0.0.0:9090` | `/healthz`, `/readyz`, `/metrics`. Not exposed by the Service. |
| `RECOGNITO_TLS_CERT_FILE`, `RECOGNITO_TLS_KEY_FILE` | unset | Set both to terminate TLS. Unset: plain HTTP, only behind a TLS-terminating proxy or mesh. |
| `RECOGNITO_DESCRIBE_RPS` | `1` | This replica's share of `DescribeUserPoolClient` calls. Fleet total (replicas × this) should stay ≤ 3. |
| `RECOGNITO_APISERVER_AUDIENCES` | unset | Extra apiserver audiences (e.g. your EKS OIDC issuer) so their replay is classified as an attack. |
| `RECOGNITO_SIGV4_REGIONS` | unset | Comma-separated. Setting it opens the SigV4 door. |
| `RECOGNITO_SIGV4_TRUSTED_ACCOUNTS` | required with SigV4 | Comma-separated 12-digit account IDs. Roles from other accounts are refused. |
| `RECOGNITO_PEER_SERVICE` | unset | Headless Service whose ready endpoints are the peers. Setting it turns the peer fabric on (the base manifests do). |
| `RECOGNITO_POD_IP`, `RECOGNITO_POD_NAMESPACE` | required with peers | From the downward API. |
| `RECOGNITO_PEER_LISTEN_ADDR` | `0.0.0.0:8444` | Peer mTLS listener. |
| `RECOGNITO_PEER_TLS_CERT_FILE`, `_KEY_FILE`, `_CA_FILE` | required with peers | Shared peer certificate and the dedicated peer CA. Certificate and key reload on change; a CA change needs a restart. |
| `RECOGNITO_PEER_SERVER_NAME` | `recognito-broker-peer` | DNS name in the peer certificate, verified on every dial. |
| `RECOGNITO_FORWARD_DEADLINE_MS` | `500` | How long to wait for a key's owner before fetching locally. |
| `RECOGNITO_ANTI_ENTROPY_INTERVAL_MS` | `1000` | Mean interval between anti-entropy rounds (jittered ±25%). |
| `RUST_LOG` | `info` | |

Worker threads follow the container's CPU limit; keep it a whole number.

### Controller

| Variable | Default | |
|---|---|---|
| `RECOGNITO_ALLOWED_USER_POOLS` | unset (IAM decides) | Comma-separated. Mappings for other pools go `Ready=False/PoolNotAllowed`. |
| `RECOGNITO_AUDIT_RPS` | `1` | Read budget: drift audits plus create-path lookups. Shares Cognito's 5 RPS per-(operation, pool) budget with the broker. |
| `RECOGNITO_WRITE_RPS` | `2` | Create/update/delete and secret calls. |
| `RECOGNITO_ROTATION_GRACE` | `10m` | How long the old secret lives after a rotation. Minimum `1m`. |
| `RECOGNITO_VERIFICATION_TTL` | `24h` | How often each client is audited for drift. |
| `RECOGNITO_OPS_LISTEN_ADDR` | `0.0.0.0:9090` | |

The controller runs as a single replica (`Recreate`). While it is down,
brokers keep serving; nothing is created, rotated or audited.

## Broker mesh

With the peer fabric on (the default), broker replicas share what they
fetch:

- A token or secret one replica fetches is pushed to the others within
  milliseconds, so their next request for it is a cache hit.
- On a miss, the replica that owns the key on a rendezvous-hash ring fetches
  it; the others forward to it (once, with a 500ms deadline) and fall back to
  fetching themselves if it does not answer. Hits are always local.
- Every second, each replica reconciles with one random peer, repairing any
  missed push.
- A new replica pulls state from two peers before `/readyz` passes, so a
  rolling restart costs no Cognito calls for keys the fleet already holds.
  After 10s without a reachable peer it becomes ready cold.

Peers are the ready endpoints of `cognito-broker-peers`. The peer port is
mTLS-only and NetworkPolicy-restricted to broker pods. On SIGTERM a broker
reports not-ready and keeps serving for 5s before draining, so the Service
stops routing to it before its listener closes.

Turning the fabric off (unset `RECOGNITO_PEER_SERVICE`) is safe at any time:
replicas fall back to fetching for themselves.

## Mapping status

```
kubectl get ccm -A
NAMESPACE  NAME  CLIENT ID             SERVICEACCOUNT  READY  AGE
payments   api   1example23client45id  api             True   3d
```

`kubectl get ccm -A -o wide` adds the AWS role column for SigV4 mappings.

`Ready=False` reasons: `InvalidSpec` (fix the spec), `PoolNotAllowed`,
`DeliverToUnsupported` (push mode is not in this release; remove `deliverTo`),
`CognitoRejected` (message carries Cognito's error — typically a scope that
does not exist on the resource server), `ClientMissing` (someone deleted the
app client in Cognito; it is re-created automatically, with a new client ID).

`userPoolId` is immutable. To move a mapping between pools, create a new one.

## Secret rotation

Every `rotateAfter` (default 90 days) the controller:

1. adds a second secret to the app client,
2. bumps `status.secretGeneration` — every broker drops its cached secret for
   that client on the next request,
3. after `RECOGNITO_ROTATION_GRACE`, deletes the old secret.

Callers notice nothing. Tokens already issued stay valid until they expire. If
a broker meets `invalid_client` it refetches the secret once and retries before
answering.

## Metrics and alerts

Broker (`:9090/metrics`):

| Metric | |
|---|---|
| `recognito_exchanges_total{door,outcome}` | Every exchange; `outcome` is `ok` or the refusal reason. |
| `recognito_attack_signals_total{door,reason}` | **Page on any increase.** Default ServiceAccount tokens replayed at the broker, SigV4 URLs aimed at other hosts or actions, tokens minted for EKS or Vault, parameter smuggling. Legitimate traffic never produces these. |
| `recognito_mappings`, `recognito_cached_secrets`, `recognito_cached_tokens` | Sizes. |
| `recognito_token_cache_hits`, `recognito_token_cache_misses` | Cache effectiveness; misses spend Cognito `ClientAuthentication` quota (150 RPS account-wide). |
| `recognito_peers` | Ready peers this replica sees. Should be replicas − 1. |
| `recognito_cold_fetch_total{route}` | Misses by route: `owner`, `forwarded`, `fail_open`, `served_for_peer`. `forwarded` near zero in steady state; **`fail_open` > 0 means a sick peer or diverged views.** |
| `recognito_gossip_sent_total{kind,result}`, `recognito_gossip_merged_total{kind,via}` | Mesh traffic. Sustained `result="failed"` means a peer is unreachable. |

Controller:

| Metric | |
|---|---|
| `recognito_reconciles_total{action}` | `create`, `update`, `rotate`, `retire`, `delete`, `none`, ... |
| `recognito_reconcile_errors_total{kind}` | `throttled` means Cognito quota contention — the controller backs off for 30s. |
| `recognito_audits_total{result}` | `drift` and `missing` mean someone changed Cognito by hand. |

Suggested alerts: any `recognito_attack_signals_total` increase; sustained
`recognito_exchanges_total{outcome=~"cognito_unavailable|invalid_client"}`;
`recognito_reconcile_errors_total{kind="throttled"}` for more than 15 minutes;
`recognito_peers` below replicas − 1 for more than 5 minutes; any sustained
`recognito_cold_fetch_total{route="fail_open"}`;
any `recognito_audits_total{result=~"drift|missing"}`.

Every exchange also writes one JSON audit line (`target: recognito::audit`)
with the door, identity, pod or AWS caller ARN, mapping, client ID, profile and
outcome. Tokens and secrets are never logged.

## Failure modes

| What fails | Effect |
|---|---|
| One broker replica | None: PDB keeps two, clients retry. |
| Every broker replica at once | No survivor to warm up from: tokens and secrets refill from Cognito, secrets at the Describe rate (ADR-8 territory). Workloads holding tokens keep working until they expire. Rolling restarts never hit this — new replicas pull from old ones. |
| Peer mesh (partition, bad peer cert) | Replicas fall back to fetching for themselves — the v1 behaviour. `fail_open` and failed-gossip metrics rise; serving continues. |
| apiserver | JWT exchanges return 503 (TokenReview). SigV4 exchanges continue. |
| STS | SigV4 exchanges return 503. |
| Cognito | Cache hits continue; misses return 503. |
| Controller | Nothing new is provisioned or rotated; serving continues. |

Deleting a mapping stops new issuance immediately. Tokens already issued
cannot be revoked and remain valid for up to `tokenValidity`.
