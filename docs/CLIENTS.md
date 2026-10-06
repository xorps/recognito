# Calling the broker

The broker turns a workload identity into a Cognito access token. You send
proof of who you are; you get back a token for the app client your
`CognitoClientMapping` names. You never see a client secret.

There is one endpoint, `POST https://cognito-broker.<domain>/token`, speaking
[RFC 8693 token exchange](https://www.rfc-editor.org/rfc/rfc8693). Two kinds of
proof are accepted:

| Where you run | Proof | `subject_token_type` |
|---|---|---|
| Kubernetes pod | Projected ServiceAccount token, audience = broker URL | `urn:ietf:params:oauth:token-type:jwt` |
| AWS outside the cluster (EC2, ECS, Lambda, Roles Anywhere) | Presigned STS `GetCallerIdentity` URL | `urn:recognito:params:oauth:token-type:aws-sigv4-presigned-url` |

Either way, the response is the same:

```json
{
  "access_token": "eyJraWQiOi...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 842,
  "scope": "payments/read"
}
```

`expires_in` is the real time left on this token, which may be less than the
mapping's `tokenValidity` if it came from the broker's cache. **Cache the token
yourself and reuse it until shortly before it expires** — that is what keeps
your service fast and the shared Cognito quota healthy.

## Choosing scopes

A mapping declares named profiles:

```yaml
allowedScopes:
  - name: read
    scopes: [payments/read]
  - name: write
    scopes: [payments/read, payments/write]
```

Send `scope` as the space-separated scopes of exactly one profile, in any
order: `scope=payments/read` or `scope=payments/write payments/read`. A subset
nobody declared (`scope=payments/write` here) is refused with `invalid_scope`;
add a profile to the mapping instead. If the mapping has a single profile you
may omit `scope`.

## From a Kubernetes pod

1. A `CognitoClientMapping` in your namespace names your ServiceAccount
   (`deploy/examples/mapping-serviceaccount.yaml`).
2. Your pod projects a token **for the broker's audience**. The default token
   at `/var/run/secrets/kubernetes.io/serviceaccount/token` is refused — it is
   minted for the apiserver, and accepting it would let any pod impersonate any
   other.

```yaml
volumes:
  - name: recognito
    projected:
      sources:
        - serviceAccountToken:
            audience: https://cognito-broker.example.com   # exactly this, byte for byte
            expirationSeconds: 3600
            path: broker-token
containers:
  - name: app
    volumeMounts:
      - name: recognito
        mountPath: /var/run/secrets/recognito
        readOnly: true
```

3. Exchange it. Re-read the file each time: the kubelet rotates it.

```sh
curl -sS https://cognito-broker.example.com/token \
  --data-urlencode grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  --data-urlencode subject_token_type=urn:ietf:params:oauth:token-type:jwt \
  --data-urlencode subject_token@/var/run/secrets/recognito/broker-token \
  --data-urlencode scope=payments/read
```

## From AWS, outside the cluster

1. A `CognitoClientMapping` names your IAM **role**
   (`deploy/examples/mapping-awsrole.yaml`). IAM users are not accepted: their
   long-lived keys are exactly the kind of distributed secret this system
   exists to remove.
2. Presign an STS `GetCallerIdentity` request with your role credentials,
   **signing the `x-recognito-audience` header** with the broker's URL. That
   header is what makes the URL good for this broker and nothing else.
3. Send the URL as the subject token.

Python (boto3 / botocore):

```python
import boto3
import requests
from botocore.auth import SigV4QueryAuth
from botocore.awsrequest import AWSRequest

BROKER = "https://cognito-broker.example.com"
REGION = "us-east-1"  # one of the broker's RECOGNITO_SIGV4_REGIONS


def presigned_caller_identity(session: boto3.Session) -> str:
    creds = session.get_credentials().get_frozen_credentials()
    request = AWSRequest(
        method="GET",
        url=f"https://sts.{REGION}.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
        headers={"x-recognito-audience": BROKER},
    )
    SigV4QueryAuth(creds, "sts", REGION, expires=60).add_auth(request)
    return request.url


response = requests.post(
    f"{BROKER}/token",
    data={
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token_type": "urn:recognito:params:oauth:token-type:aws-sigv4-presigned-url",
        "subject_token": presigned_caller_identity(boto3.Session()),
        "scope": "payments/read",
    },
    timeout=10,
)
response.raise_for_status()
access_token = response.json()["access_token"]
```

The output of exactly this function is pinned as a regression test in
`crates/broker/tests/sigv4_audience_binding.rs`.

Rules for any other language — each is enforced and each failure is a `403`:

- Regional endpoint only (`sts.<region>.amazonaws.com`, or `.amazonaws.com.cn`
  in China), and the region must be one the broker is configured for.
- Presigned (query-string) GET, not a signed POST.
- `X-Amz-SignedHeaders` exactly `host;x-recognito-audience`; the header value
  exactly the broker URL.
- `X-Amz-Expires` at most 900. Presign just before you exchange; a URL is a
  bearer credential until it expires.
- Standard SDK encoding. Hand-built URLs with unusual encodings, duplicated
  parameters or extra parameters are refused.

## Debugging: `/whoami`

`POST /whoami` takes the same form as `/token`, authenticates you the same way,
and tells you what the broker thinks — without issuing a token:

```json
{
  "caller": { "door": "jwt", "identity": "system:serviceaccount:payments:api", "pod_name": "api-7d9f" },
  "mapping": {
    "namespace": "payments", "name": "api", "user_pool_id": "us-east-1_aBc",
    "client_id": "1example23client45id",
    "profiles": [ { "name": "read", "scope": "payments/read" } ]
  }
}
```

If no mapping applies you get `mapping_error` instead (`not_mapped`,
`ambiguous_mapping`, `mapping_not_ready`, `pool_not_served`).

## Errors

Errors are [RFC 6749 §5.2](https://www.rfc-editor.org/rfc/rfc6749#section-5.2)
JSON: `{"error": "...", "error_description": "..."}`. The description never
echoes your token.

| Status | `error` | Meaning | Retry? |
|---|---|---|---|
| 400 | `invalid_request` | Malformed form, missing/duplicated parameter, unsupported `subject_token_type`, SigV4 not enabled on this broker | No — fix the request |
| 400 | `unsupported_grant_type` | `grant_type` is not token exchange | No |
| 400 | `invalid_scope` | `scope` matches no declared profile | No — add a profile |
| 400 | `invalid_target` | You sent `resource` or `audience` | No — the mapping decides |
| 403 | `invalid_grant` | Your proof was refused, or no single mapping authorizes you. The description carries a stable reason code. | No |
| 503 | `temporarily_unavailable` | Apiserver, STS or Cognito unreachable or throttled; mapping still provisioning | Yes, with backoff (and a fresh presigned URL) |
| 500 | `server_error` | Cognito rejected the client configuration | Tell the platform team |

Common `invalid_grant` reasons: `apiserver_audience` (you sent the default
ServiceAccount token), `mismatch` / `not_canonical` (wrong `audience` in the
projected volume), `audience_not_signed` (SigV4 URL without the header),
`expired`, `not_mapped`, `ambiguous_mapping` (two mappings claim you — ask the
platform team), `unsupported_principal` (IAM user or root).
