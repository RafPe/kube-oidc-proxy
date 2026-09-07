# Log-delivery lab: Kinesis to S3, locally

A one-command check of the recipe in
[docs/log-shipping.md](../../docs/log-shipping.md), run against a local AWS
emulator instead of an AWS account. It builds on the
[multi-issuer demo](../README.md): the demo gives you a kind cluster with two
issuers and the proxy; this lab turns on the proxy's audit log, installs the
node agent, and follows one request's records all the way into an S3 bucket.

```
                   ┌────────────────── kind: kube-oidc-proxy-demo ──────────────────┐
                   │                                                                │
 kubectl (alice) ──┼─► kube-oidc-proxy ──stdout──► aws-for-fluent-bit ──┐          │
                   │   audit Event + log record     DaemonSet            │ PutRecords
                   │                                                     ▼          │
                   │                    Floci (AWS emulator) ┌─ kube-oidc-proxy-audit ─┐   │
                   │                    Kinesis · Firehose · S3 └─ kube-oidc-proxy-logs ──┘   │
                   │                                  │ Firehose (Kinesis stream as source)   │
                   │                                  ▼                                       │
                   │                        s3://kube-oidc-proxy-logs/{audit,logs}/…          │
                   └────────────────────────────────────────────────────────────────┘
```

What it proves: the two record kinds the proxy writes are told apart by the
agent, land on their own Kinesis streams, and arrive in S3 as valid JSON with
the proxy's record under `data`, joined on `request_id == auditID`.

## Prerequisites

- The demo has been run and its cluster is up: `cd .. && ./run.sh`.
- `aws` (CLI v2), `kubectl`, `helm`, `kind`, `jq`, `openssl`.
- Internet access from the kind node to pull `floci/floci`, `nginx` and
  `public.ecr.aws/aws-observability/aws-for-fluent-bit`.

## Usage

```bash
cd demo && ./run.sh            # once: the base demo
cd lab-log-delivery && ./run.sh
```

The run takes a few minutes, most of it waiting for Firehose's 60-second
buffer. On success it prints the request's audit event and log record three
times: from the Kinesis streams, and from the two S3 objects. It is safe to
re-run; the agent's `dropped_records` and `retries_failed` counters then
include any earlier failed attempts, because they count over the agent pod's
lifetime.

Afterwards, look around with the emulator's endpoint:

```bash
kubectl --context kind-kube-oidc-proxy-demo -n floci port-forward svc/floci 4566:4566 &
export AWS_ACCESS_KEY_ID=lab AWS_SECRET_ACCESS_KEY=lab AWS_DEFAULT_REGION=eu-west-1
aws --endpoint-url http://127.0.0.1:4566 kinesis list-streams
aws --endpoint-url http://127.0.0.1:4566 s3 ls s3://kube-oidc-proxy-logs/ --recursive
aws --endpoint-url http://127.0.0.1:4566 s3 cp s3://kube-oidc-proxy-logs/audit/<key> - | jq .
kubectl --context kind-kube-oidc-proxy-demo -n aws-for-fluent-bit exec ds/aws-for-fluent-bit -- \
  curl -s localhost:2020/api/v1/metrics | jq .output
```

Tear down with `./cleanup.sh` (removes the agent and the emulator, keeps the
demo) or `../cleanup.sh` (deletes the cluster).

## What differs from the docs page

Everything in `values/` is the page's configuration, with the lines the
emulator needs marked `EMULATOR`:

| On the page | In the lab | Why |
| --- | --- | --- |
| IRSA annotation on the agent's ServiceAccount | static `AWS_*` env vars | the emulator has no IAM or STS; it accepts any credentials |
| outputs name only `region` and `stream` | plus `endpoint`, `port`, `tls.ca_file` | the `kinesis_streams` output always speaks TLS, so the emulator sits behind an nginx TLS front whose CA is mounted into the agent |
| SSE-KMS, retention, VPC endpoint | not created | the emulator does not evaluate them |

Nothing about the proxy differs: `values/proxy-audit.yaml` is the page's
"What you need" block, and `manifests/audit-policy.yaml` is the auditing
page's baseline policy.

## Layout

```
demo/lab-log-delivery/
├── run.sh                       # audit on, emulator, streams + bucket + Firehose, agent, verify
├── cleanup.sh                   # remove the agent and the emulator from the demo cluster
├── manifests/
│   ├── audit-policy.yaml        # the baseline policy from docs/auditing.md
│   └── floci.yaml               # Floci + nginx TLS front, one Service (4566 plain, 443 TLS)
├── values/
│   ├── proxy-audit.yaml         # audit flags from docs/log-shipping.md
│   └── fluent-bit.yaml          # the page's agent values, EMULATOR lines marked
└── .generated/                  # gitignored: CA and serving cert, synced S3 objects
```
