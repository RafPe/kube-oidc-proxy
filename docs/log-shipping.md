# Shipping logs and audit events

The proxy writes everything it has to say to stdout as JSON, one object per
line: the [structured log](./logging.md) and, when auditing is enabled with
`--audit-log-path=-`, the [audit events](./auditing.md). Shipping them anywhere
is therefore a job for a node-level log agent, not for the proxy. This page is
the recipe for one destination, AWS Kinesis Data Streams, using
[aws-for-fluent-bit](https://github.com/aws/eks-charts/tree/master/stable/aws-for-fluent-bit)
as the agent. It needs no change to the proxy and no change to its chart.

- [What leaves the proxy](#what-leaves-the-proxy)
- [What you need](#what-you-need)
- [AWS side](#aws-side)
- [Agent side](#agent-side)
- [Verify](#verify)
- [Sharp edges](#sharp-edges)
- [Reading the streams](#reading-the-streams)
- [Several clusters](#several-clusters)
- [When a node agent is not enough](#when-a-node-agent-is-not-enough)
- [See also](#see-also)

## What leaves the proxy

Two kinds of record share the container's stdout. They are told apart by one
field each:

| Record | Discriminator | Example |
| --- | --- | --- |
| Structured log | `event_type` present (or `component: k8s` for bridged library output) | `{"event_type":"request.access.decided","request_id":"7f1a…","decision":"allow",…}` |
| Audit event | `kind: Event`, `apiVersion: audit.k8s.io/v1` | `{"kind":"Event","apiVersion":"audit.k8s.io/v1","auditID":"7f1a…","stage":"ResponseComplete",…}` |

The same request carries the same ID in both: `request_id` on the log record,
`auditID` on the audit event, and `auditID` again in the kube-apiserver's own
audit log, because the proxy forwards it as `Audit-ID`
([correlation](./logging.md#correlation)).

Within one process the two writers cannot tear each other's lines: Go
serialises writes to one file descriptor and writes each line whole. The
container runtime may still split a very long line into several file entries,
which the agent's `cri` parser reassembles.

## What you need

On the proxy: nothing beyond the [documented audit setup](./auditing.md#enabling-it-with-the-chart),
which already writes audit events to stdout next to the structured log. The
chart's hardened defaults stay as they are. `logging.format` stays at its
default, `json`.

```yaml
# kube-oidc-proxy values.yaml (unchanged from the auditing page)
extraArgs:
  audit-policy-file: /audit/policy.yaml
  audit-log-path: "-"
  audit-log-format: json
extraVolumeMounts:
  - name: audit-policy
    mountPath: /audit
    readOnly: true
extraVolumes:
  - name: audit-policy
    configMap:
      name: kube-oidc-proxy-audit-policy
```

On the cluster: a node-level agent that can read `/var/log/containers` and
has an AWS identity. The rest of this page assumes EKS with IAM Roles for
Service Accounts (IRSA); on another platform substitute the credential
mechanism and keep everything else.

## AWS side

Two streams, so audit and operational logs get their own IAM scope, retention
and capacity. On-demand mode needs no shard arithmetic.

```bash
REGION=eu-west-1
for s in kube-oidc-proxy-audit kube-oidc-proxy-logs; do
  aws kinesis create-stream --region "$REGION" --stream-name "$s" \
    --stream-mode-details StreamMode=ON_DEMAND
  aws kinesis wait stream-exists --region "$REGION" --stream-name "$s"
  aws kinesis start-stream-encryption --region "$REGION" --stream-name "$s" \
    --encryption-type KMS --key-id alias/kube-oidc-proxy-logs
done
aws kinesis increase-stream-retention-period --region "$REGION" \
  --stream-name kube-oidc-proxy-audit --retention-period-hours 168
```

The agent's IAM role needs exactly this. Scope `Resource` to the two stream
ARNs; the plugin's own documentation shows `"*"`, and that is the one thing to
tighten.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["kinesis:PutRecords"],
      "Resource": [
        "arn:aws:kinesis:eu-west-1:123456789012:stream/kube-oidc-proxy-audit",
        "arn:aws:kinesis:eu-west-1:123456789012:stream/kube-oidc-proxy-logs"
      ]
    },
    {
      "Effect": "Allow",
      "Action": ["kms:GenerateDataKey"],
      "Resource": "arn:aws:kms:eu-west-1:123456789012:key/<key-id>"
    }
  ]
}
```

Bind that policy to a role whose trust policy is the cluster's OIDC provider
for `system:serviceaccount:aws-for-fluent-bit:aws-for-fluent-bit` (the
namespace and ServiceAccount the agent chart creates below). If the nodes have
no route to the public Kinesis endpoint, add an interface VPC endpoint for
`com.amazonaws.<region>.kinesis-streams`; an endpoint policy limited to the
two stream ARNs is the cheapest blast-radius reduction available.

## Agent side

Install the `aws-for-fluent-bit` chart with the chart's own input and
Kinesis outputs turned off and replaced by the blocks below. The replacement
input tails only the proxy's container files, the filters route audit events
to their own tag, and the two outputs send each tag to its stream. Pin the
chart and image versions you actually tested; the ones here are the chart's
defaults at the time of writing.

```bash
helm repo add eks https://aws.github.io/eks-charts
helm upgrade --install aws-for-fluent-bit eks/aws-for-fluent-bit \
  --namespace aws-for-fluent-bit --create-namespace \
  --version 0.2.0 -f fluent-bit-values.yaml
```

```yaml
# fluent-bit-values.yaml
serviceAccount:
  create: true
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/kube-oidc-proxy-log-shipper

# The chart's default input tails every container on the node. Replace it
# with one scoped to the proxy, with the line buffer and disk buffering the
# audit stream needs.
input:
  enabled: false
additionalInputs: |
  [INPUT]
      Name              tail
      Tag               kube.*
      Path              /var/log/containers/*_kube-oidc-proxy_kube-oidc-proxy-*.log
      multiline.parser  cri
      DB                /var/log/flb_kube_oidc_proxy.db
      Buffer_Max_Size   1M
      Skip_Long_Lines   On
      Refresh_Interval  5
      Rotate_Wait       30
      Mem_Buf_Limit     50MB
      storage.type      filesystem

# The chart's kubernetes filter stays on. It parses the JSON line into the
# `data` key (Merge_Log_Key) and adds pod metadata under `kubernetes`.
filter:
  enabled: true
  mergeLog: "On"
  mergeLogKey: "data"
  keepLog: "Off"

# Audit events get their own tag so they can go to their own stream. The
# emitted tag does not match `kube.*`, so the filter cannot loop.
additionalFilters: |
  [FILTER]
      Name                  rewrite_tag
      Match                 kube.*
      Rule                  $data['kind'] ^Event$ audit.$TAG false
      Emitter_Name          oidc_proxy_audit
      Emitter_Storage.type  filesystem

# The chart enables `cloudWatchLogs` by default. Left on, it adds a third
# output matching `*` that ships both record kinds to CloudWatch in
# `us-east-1` as well. Turn it off with the two kinesis outputs, which match
# `*` too and cannot split the two record kinds.
cloudWatchLogs:
  enabled: false
kinesis:
  enabled: false
kinesis_streams:
  enabled: false
additionalOutputs: |
  [OUTPUT]
      Name                      kinesis_streams
      Match                     audit.*
      region                    eu-west-1
      stream                    kube-oidc-proxy-audit
      storage.total_limit_size  1G

  [OUTPUT]
      Name                      kinesis_streams
      Match                     kube.*
      region                    eu-west-1
      stream                    kube-oidc-proxy-logs
      storage.total_limit_size  1G

# Filesystem buffering needs a path; /var/log is a hostPath the chart already
# mounts. Keep the chart's health-check settings above these lines.
service:
  extraService: |
    HTTP_Server      On
    HTTP_Listen      0.0.0.0
    HTTP_PORT        2020
    Health_Check     On
    HC_Errors_Count  5
    HC_Retry_Failure_Count 5
    HC_Period        5
    storage.path     /var/log/flb-storage/kube-oidc-proxy/
    storage.sync     normal
    storage.checksum off
    storage.backlog.mem_limit 20M
```

Each Kinesis record is one JSON object: the proxy's own record under `data`,
wrapped in what the agent knows about the pod. Do **not** reach for
`log_key data` to strip the wrapper. The `kinesis_streams` output serialises the
selected value and then drops its outer delimiter, so `log_key data` puts
`"kind":"Event",…` on the stream with no enclosing braces, and `log_key log`
puts an unquoted, still-escaped string there. Neither is parseable JSON.
Verified against aws-for-fluent-bit 3.2.1 (Fluent Bit 4.2.2).

The path glob relies on the kubelet's file naming,
`<pod>_<namespace>_<container>-<id>.log`, and on the proxy running in the
`kube-oidc-proxy` namespace with the chart's default container name. Adjust
both if yours differ.

## Verify

1. The agent is up and its outputs are healthy on every node:

   ```bash
   kubectl -n aws-for-fluent-bit get pods -o wide
   kubectl -n aws-for-fluent-bit exec ds/aws-for-fluent-bit -- \
     curl -s localhost:2020/api/v1/metrics | jq '.output'
   ```

   `kinesis_streams.0` and `.1` should show `proc_records` climbing, with
   `dropped_records` and `retries_failed` at zero. Watch those two, not
   `errors`: a misconfigured output drops every record while `errors` stays at
   `0`, and the chart's health check does not restart the pod for it. An
   `AccessDeniedException` in the agent's log is the IAM role or the trust
   policy.

2. Make one request through the proxy and read it back from the audit stream:

   ```bash
   kubectl --context oidc-proxy get pods -n default
   SHARD=$(aws kinesis list-shards --stream-name kube-oidc-proxy-audit \
     --query 'Shards[0].ShardId' --output text)
   IT=$(aws kinesis get-shard-iterator --stream-name kube-oidc-proxy-audit \
     --shard-id "$SHARD" --shard-iterator-type TRIM_HORIZON \
     --query ShardIterator --output text)
   aws kinesis get-records --shard-iterator "$IT" --output json \
     | jq -r '.Records[].Data | @base64d' \
     | jq -c 'select(.data.kind == "Event") | {auditID: .data.auditID, stage: .data.stage, verb: .data.verb, user: .data.user.username}'
   ```

   With `omitStages: ["RequestReceived"]` in the policy you get one
   `ResponseComplete` event per request; without it, two.

3. Read the matching log record from the other stream the same way and join
   on `.data.request_id == .data.auditID`.

## Sharp edges

- **`Buffer_Max_Size` is cheap insurance, not a fix for a problem you have.**
  Fluent Bit's tail input defaults it to 32768 bytes, and a physical line longer
  than that removes the whole file from monitoring unless `Skip_Long_Lines` is
  on. Two things stop that firing here. The container runtime writes CRI-format
  log files and splits long output into ~16 KB chunks that `multiline.parser
  cri` reassembles, so the tail input never sees an over-long physical line; and
  the proxy's audit events are small at every level, because a reverse proxy
  never records request or response bodies (see [auditing](./auditing.md)). The
  recipe still sets `1M` and `Skip_Long_Lines On` because they cost nothing.
  Note that Fluent Bit reads `k` and `M` as 1000 and 1000000, so `1M` is a
  million bytes — and `Buffer_Max_Size 32k` is 32000, below the default
  `Buffer_Chunk_Size` of 32768, which makes the tail input refuse to start.
- **The kubelet's rotated files are the only buffer before the agent.** With
  the upstream defaults (`containerLogMaxSize: 10Mi`, `containerLogMaxFiles: 5`)
  a container keeps about 50Mi of history on the node. A policy that records
  `RequestResponse` for list verbs can churn through that faster than the
  agent tails it. Keep read verbs at `Metadata` (the
  [baseline policy](./auditing.md#baseline) does), and raise the kubelet limits
  on the node group if audit volume is high. EKS AMIs ship their own kubelet
  configuration; check the actual values.
- **Records are lost on node loss and pod eviction.** The kubelet removes an
  evicted pod's log files, and a node that dies takes its files and the agent's
  filesystem buffer with it. That is acceptable for the structured log and
  must be a conscious decision for the audit trail; if it is not acceptable,
  see [below](#when-a-node-agent-is-not-enough).
- **The partition key is random.** The `kinesis_streams` plugin always uses a
  random key, so records for one request may land on different shards and
  Kinesis preserves no cross-shard order. Consumers sort by
  `(auditID, stage, stageTimestamp)` rather than by arrival.
- **Delivery is at-least-once.** A batch that partially succeeds is retried
  whole, so duplicates happen under throttling. Deduplicate audit events on
  `(auditID, stage)`, never on `auditID` alone: a long-running request
  legitimately emits `ResponseStarted` and `ResponseComplete` under one ID. If
  the same stream also receives the kube-apiserver's audit log, add the
  producer to the key, because the API server's event for the same request
  carries the same `auditID` and stage names.
- **The agent reads every file its path matches.** With the scoped path above
  that is only the proxy's containers; with the chart's default input it is
  every pod on the node. Either way the agent's hostPath grants it that
  access; that is the DaemonSet's blast radius, and it is the platform team's,
  not the proxy's.

## Reading the streams

Each record in `kube-oidc-proxy-logs` carries one proxy record as documented in
the [logging reference](./logging.md#record-shape) under `data`; each record in
`kube-oidc-proxy-audit` carries one `audit.k8s.io/v1` Event as documented in
[reading the events](./auditing.md#reading-the-events), also under `data`. The
agent adds the wrapper (`kubernetes`, `time`, `stream`, `_p`) but renames
nothing inside it, so the [worked queries](./logging.md#worked-queries) and the
[ECS mapping](./logging.md#ecs-mapping) apply to whatever consumes the stream
with a `data.` prefix.

## Several clusters

Nothing in either stream names the cluster it came from. The structured log
carries no cluster, environment, pod or node field; an audit event is a plain
`audit.k8s.io/v1 Event`, and the policy format cannot add one. The proxy does
not know its cluster's name, it only has a kubeconfig. What is safe across
clusters is the join key: `request_id` and `auditID` are UUIDs, so records
from two clusters never collide on it.

Add the distinction in the agent. The DaemonSet is already a per-cluster
deployment with a per-cluster values file, and it is where every other log on
that cluster gets its cluster tag. A `record_modifier` filter ahead of the
`rewrite_tag` filter stamps both record kinds:

```yaml
env:
  - name: CLUSTER_NAME
    value: prod-eu-1
additionalFilters: |
  [FILTER]
      Name    record_modifier
      Match   kube.*
      Record  cluster      ${CLUSTER_NAME}
      Record  environment  prod

  [FILTER]
      Name                  rewrite_tag
      Match                 kube.*
      Rule                  $data['kind'] ^Event$ audit.$TAG false
      Emitter_Name          oidc_proxy_audit
      Emitter_Storage.type  filesystem
```

`record_modifier` adds top-level keys, and the outputs above already ship the
whole record, so the two new keys travel with it. Kinesis receives the proxy
record under `data`, wrapped in what the agent knows:

```json
{"cluster":"prod-eu-1","environment":"prod",
 "time":"2026-01-01T00:00:00.000000000Z","stream":"stdout","_p":"F",
 "kubernetes":{"namespace_name":"kube-oidc-proxy","pod_name":"kube-oidc-proxy-7c9d…","host":"ip-10-42-1-3.eu-west-1.compute.internal"},
 "data":{"event_type":"request.access.decided","request_id":"7f1a9c1e-…","decision":"allow"}}
```

`time`, `stream` and `_p` come from the tail input and the CRI parser; ignore
them or drop them with a `record_modifier` `Remove_key`.

Consumers read the proxy fields under `data.` and get the pod and node for
free. Every query on the [logging reference](./logging.md#worked-queries)
applies with that prefix.

Streams: clusters in separate AWS accounts already have separate streams and
roles, so the stream ARN identifies the cluster and the field is a
convenience. Clusters that share an account are best served by one pair of
streams per environment tier (`prod`, `nonprod`) filtered on `cluster`, rather
than a pair per cluster; go per cluster only when IAM isolation or a
compliance boundary between clusters requires it.

## When a node agent is not enough

A node agent gives the audit trail the same guarantee as every other log on
the node. When the trail needs its own buffer, its own credentials, or must
fail closed, the proxy's audit backend already has a second exit that needs
no proxy change either: `--audit-webhook-config-file` posts batches of events
to an HTTP collector with retries and backoff, and `--audit-webhook-mode`
chooses between buffering (`batch`), waiting (`blocking`) and refusing the
request when the event cannot be stored (`blocking-strict`). A collector such
as Vector can receive that and write to Kinesis. The wiring and the mode
trade-offs are on the [auditing page](./auditing.md#how-it-is-wired); note
that `blocking-strict` only gates the `RequestReceived` stage, so failing
closed requires keeping that stage in the policy.

Building a Kinesis client into the proxy was considered and rejected: it would
put a write credential inside the process that terminates every user's TLS
and mints impersonation headers, for nothing the two paths above do not give.

## See also

- [Logging reference](./logging.md): record shape, event registry, worked
  queries, ECS mapping.
- [Auditing](./auditing.md): enabling audit, writing a policy, the webhook
  backend.
- [Operations: reading the request log](./operations.md#reading-the-request-log):
  the fields to grep first.
