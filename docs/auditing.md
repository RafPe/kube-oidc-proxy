# Auditing

The proxy can write a Kubernetes audit log of its own, using the same
machinery, flags and policy format as kube-apiserver. This page explains how
that is wired, how to turn it on with the Helm chart, which policies make sense
in front of a proxy, and how its events line up with the API server's audit log
on the other side.

- [Two audit trails, one ID](#two-audit-trails-one-id)
- [How it is wired](#how-it-is-wired)
- [Enabling it with the chart](#enabling-it-with-the-chart)
- [Writing a policy](#writing-a-policy)
  - [Baseline](#baseline)
  - [More detail for one class of caller](#more-detail-for-one-class-of-caller)
  - [Sensitive resources](#sensitive-resources)
  - [What a policy cannot do](#what-a-policy-cannot-do)
- [Reading the events](#reading-the-events)
- [Joining with the API server's audit log](#joining-with-the-api-servers-audit-log)
- [See also](#see-also)

## Two audit trails, one ID

Every request that passes through the proxy can leave two audit events:

| Trail | Written by | `user` in the event | Sees |
| --- | --- | --- | --- |
| Proxy audit log | the proxy, before impersonation | the identity your claim mappings produced, groups and extras included | every request that reached the proxy, including 401s the API server never saw |
| API server audit log | kube-apiserver, after impersonation | the proxy's ServiceAccount; the mapped identity is under `impersonatedUser` | every request the proxy forwarded, with the authorization decision |

The proxy mints a request ID for every request, sets it as the `Audit-ID`
header on the request it forwards, and uses it as `auditID` in its own events.
kube-apiserver adopts an inbound `Audit-ID`, so the same string is the
`auditID` in its event too. That ID is also the `request_id` on every record in
the proxy's structured log. One value therefore joins the proxy log, the proxy
audit event and the API server audit event — see
[correlation](./logging.md#correlation).

Which trail answers which question:

- **Was this identity allowed to do that?** The API server's log. Authorization
  happens there; the proxy only authenticates and impersonates.
- **Who tried and failed to authenticate?** The proxy's log. A rejected token
  never reaches the API server.
- **What did the token actually map to?** The proxy's log, whose `user` field
  is the mapped identity with its groups and extras, exactly as the proxy
  forwarded it.

## How it is wired

The proxy embeds the API server's audit stack rather than reimplementing it.

1. **Flags.** The proxy registers kube-apiserver's own audit options, so every
   `--audit-*` flag the API server accepts exists here, with one exception:
   dynamic configuration (`--audit-dynamic-configuration`) is not supported.
   Two backends are available. `--audit-log-path` writes one JSON object per
   line to a file, or to stdout when the path is `-`. `--audit-webhook-config-file`
   posts batches of events to an HTTP collector described by a kubeconfig.
   Either backend needs `--audit-policy-file`; without a policy nothing is
   recorded.
2. **Startup.** The options build two things the request path needs: the audit
   backend and a policy evaluator compiled from the policy file. A backend that
   fails to start is a startup failure, on the grounds that a proxy serving
   without its audit trail is worse than a proxy that is down.
3. **Position in the request path.** A request passes, in order, through:
   request ID assignment, request-info resolution (verb, resource, namespace),
   the lifecycle filter, forwarding-header sanitization, authentication,
   impersonation, and finally the audit filter, which sits directly in front of
   the reverse proxy. Because the audit filter runs after authentication, the
   event's `user` is the mapped identity. Because request info was resolved
   early, the event carries a proper `objectRef` and Kubernetes verb
   (`create`, not `post`) even for core-group paths under `/api`.
4. **Failed authentication.** A 401 never reaches the main audit filter, so the
   authentication handler wraps its error path in a second, shorter audit chain
   that records the failed attempt against the anonymous user. Both chains use
   the same policy.
5. **Long-running requests.** `exec`, `attach`, `portforward`, `log`, `proxy`
   and every watch are recorded twice, at `ResponseStarted` and
   `ResponseComplete`, using kube-apiserver's own definition of long-running.
   An hour-long `exec` therefore leaves a trace at its start, and still leaves
   one if the proxy is stopped before the session ends.
6. **Shutdown.** The backend is flushed as a pre-shutdown hook, and the result
   is logged as `audit.flush.completed` or `audit.flush.failed`. A failed flush
   means events for requests the process already served were dropped, so it is
   never silent.

## Enabling it with the chart

The chart has no dedicated audit values; it needs none. Each `extraArgs` entry
becomes a `--key=value` flag on the container, and `extraVolumes` plus
`extraVolumeMounts` are added to the pod spec verbatim. A ConfigMap with the
policy, a mount, and three flags are the whole setup.

Write to stdout. The chart runs the proxy with a read-only root filesystem, and
a stdout audit log needs no writable path, no sidecar and no extra collector:
it lands in the same stream as the structured log and reaches your log pipeline
the same way.

```yaml
# values.yaml
extraArgs:
  audit-policy-file: /audit/policy.yaml
  audit-log-path: "-"               # stdout, next to the structured log
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

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: kube-oidc-proxy-audit-policy
  namespace: kube-oidc-proxy
data:
  policy.yaml: |
    apiVersion: audit.k8s.io/v1
    kind: Policy
    omitStages: ["RequestReceived"]
    rules:
      - level: Metadata
```

Two operational notes:

- Changing `extraArgs` changes the pod spec, so `helm upgrade` rolls the
  Deployment. Changing the ConfigMap alone does not: the policy is read once at
  startup, so restart the pods after editing it
  (`kubectl -n kube-oidc-proxy rollout restart deploy/kube-oidc-proxy`).
- To write a file instead, add an `emptyDir` volume for the path, relax
  `securityContext.readOnlyRootFilesystem`, and ship the file with a sidecar.
  The webhook backend needs neither; it takes a kubeconfig pointing at the
  collector via `--audit-webhook-config-file`.

## Writing a policy

A policy is a list of rules evaluated top to bottom; the first rule that matches
decides the level, and a request that matches no rule is not audited. The
selectors are `users`, `userGroups`, `verbs`, `resources` (API group plus
resource, optionally with a subresource such as `pods/exec`), `namespaces`,
`nonResourceURLs`, and a per-rule `omitStages`.

The level sets how much of each request is kept:

| Level | Records |
| --- | --- |
| `None` | nothing |
| `Metadata` | who, verb, resource, namespace, source IP, status code, timestamps; no bodies |
| `Request` | Metadata plus the request body |
| `RequestResponse` | Metadata plus request and response bodies |

`Metadata` is the right default. It answers "who did what, when, and was it
allowed" without copying object manifests, and never a Secret's contents, into
the log.

`omitStages: ["RequestReceived"]` at the top level drops the event that is
written when a request arrives, before anything is known about the outcome.
Every request would otherwise produce two events; the completion event has the
status code, so the first adds only volume.

### Baseline

Quiet on probes and discovery, metadata for everything else. Self-checks such
as `kubectl auth whoami` and `kubectl auth can-i` are not actions and are
excluded too.

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: ["RequestReceived"]
rules:
  - level: None
    nonResourceURLs:
      - "/healthz*"
      - "/readyz*"
      - "/livez*"
      - "/version"
      - "/api"
      - "/api/*"
      - "/apis"
      - "/apis/*"
      - "/openapi/*"
  - level: None
    resources:
      - group: authentication.k8s.io
        resources: ["selfsubjectreviews"]
      - group: authorization.k8s.io
        resources: ["selfsubjectaccessreviews", "selfsubjectrulesreviews"]
  - level: Metadata
```

### More detail for one class of caller

Because the proxy's event carries the mapped identity, a policy can select on
the groups your claim mappings synthesize. That lets you keep request bodies
for writes made by CI systems, which are the ones you may need to reconstruct
after a bad deploy, while everything else stays at metadata.

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: ["RequestReceived"]
rules:
  - level: None
    nonResourceURLs: ["/healthz*", "/readyz*", "/livez*", "/api", "/api/*", "/apis", "/apis/*"]
  # Secrets first, whoever writes them: a Request-level rule below would copy
  # the value into the log on every create.
  - level: Metadata
    resources:
      - group: ""
        resources: ["secrets"]
  # Request bodies for every other write from CI. No response bodies: those
  # would echo data back into the log.
  - level: Request
    userGroups: ["gha:org:my-org", "gitlab:ns:my-group"]
    verbs: ["create", "update", "patch", "delete", "deletecollection"]
  # Reads from CI: who looked at what, no bodies.
  - level: Metadata
    userGroups: ["gha:org:my-org", "gitlab:ns:my-group"]
  # Everyone else, including issuers added later.
  - level: Metadata
```

The group names are whatever your mappings produce; see the
[multi-issuer recipes](./multi-issuer.md#examples).

### Sensitive resources

Secrets stay at `Metadata` regardless of who touches them, because even
`Request` level would copy the value into the log on a create. RBAC changes get
bodies, because the body is what you will want to read. `exec` and
`portforward` keep both stages so an open session is visible while it runs.

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: ["RequestReceived"]
rules:
  - level: Metadata
    resources:
      - group: ""
        resources: ["secrets", "configmaps", "serviceaccounts/token"]
  - level: Request
    verbs: ["create", "update", "patch", "delete"]
    resources:
      - group: rbac.authorization.k8s.io
  - level: Metadata
    resources:
      - group: ""
        resources: ["pods/exec", "pods/attach", "pods/portforward"]
    omitStages: []
  - level: Metadata
```

### What a policy cannot do

- **Select on the outcome.** There is no rule for "only denials"; the status
  code is not known when the rule is chosen. The proxy's structured log records
  every denial with a `reason` at the default verbosity, so use that for
  denials and the audit log for the full record — see
  [denials by reason](./logging.md#denials-by-reason-in-the-last-hour).
- **Match users by pattern.** `users` is exact. To cover everyone from one
  issuer or one repository, select on a group your mapping emits for them
  rather than listing usernames.

## Reading the events

On stdout, audit events are JSON objects with `kind: Event`, which separates
them from the proxy's own records in one `select`:

```bash
kubectl -n kube-oidc-proxy logs -l app.kubernetes.io/name=kube-oidc-proxy --since=15m --tail=-1 \
  | jq -r 'select(.kind == "Event")
           | [.stageTimestamp[11:19], .stage, .verb, (.objectRef.resource // .requestURI),
              (.objectRef.namespace // "-"), .user.username,
              ((.responseStatus.code // "-") | tostring), .auditID[0:8]] | @tsv' \
  | column -t
```

```text
17:45:10  ResponseComplete  list    namespaces  -        gha:my-org/my-repo:refs/heads/main  200  5c9d2e40
17:45:31  ResponseComplete  list    secrets     default  gha:my-org/my-repo:refs/heads/main  403  7e0f1a22
17:46:02  ResponseStarted   create  pods        payments google:alice@example.com            101  b7d1e0aa
```

The last column is the first eight characters of the `auditID`. It matches the
`request_id` of the proxy's own records for that request and the `auditID` in
the API server's audit log, so one grep follows a request across all three.

## Joining with the API server's audit log

Enable the API server audit log on your cluster if it is not already on. Where
it ends up is cluster-specific: a file on control-plane nodes for clusters you
run yourself, a log service for managed ones (CloudWatch Logs for EKS, Cloud
Logging for GKE, Log Analytics for AKS). Two things hold everywhere:

- The proxy's ServiceAccount is the `user` of the event. The identity you care
  about is `impersonatedUser`, including its `groups` and `extra`.
- `auditID` equals the proxy's `request_id`.

So a query for "everything one CI identity did" filters on the impersonated
user, and a query for "the upstream half of this proxy record" filters on the
ID. In CloudWatch Logs Insights against an EKS cluster's log group, for
example:

```text
fields @timestamp, verb, objectRef.resource, objectRef.namespace, objectRef.name,
       responseStatus.code, impersonatedUser.username, auditID
| filter @logStream like /kube-apiserver-audit/
| filter impersonatedUser.username like /^gha:/
| sort @timestamp desc
| limit 50
```

and for one request, `| filter auditID = "<request_id>"`.

The two events record different decisions. The proxy's `decision` says
whether the request was admitted and forwarded; the API server's
`authorization.k8s.io/decision` says whether the impersonated identity was
allowed to perform the action. A proxy `allow` followed by an API server
`forbid` is the normal shape of an RBAC denial, and a proxy `deny` has no
API server event at all. See [correlation](./logging.md#correlation).

## See also

- [Logging reference](./logging.md) — the structured log the audit events sit
  next to, and the `request_id` that joins them.
- [Operations: reading the request log](./operations.md#reading-the-request-log).
- [Configuration reference](./configuration.md) — every flag, including the
  audit flags the proxy inherits from kube-apiserver.
- [Kubernetes auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
  — the policy format in full.
