# Contributing

Thanks for your interest in `kube-oidc-proxy`!

## Reporting issues

Open an issue at https://github.com/RafPe/kube-oidc-proxy/issues with steps to
reproduce, your Kubernetes and OIDC provider details, and any relevant proxy
logs.

## Development

- Requires Go 1.26+, Docker, and [kind](https://kind.sigs.k8s.io/).
- Unit tests: `go test ./cmd/... ./pkg/...`
- Generated files (mocks, the event table): `make generate`.
- End-to-end suite on a local kind cluster: `make e2e` (see
  [docs/development.md](./docs/development.md#end-to-end-tests)).

## Pull requests

- Branch from `main`, keep changes focused, and include tests for behaviour changes.
- CI runs unit tests, the e2e gate, `govulncheck`, and the Helm checks — keep them green.
- Conventional-style commit messages (`fix:`, `feat:`, `docs:` …) are appreciated.

## Logging

The proxy has one structured log stream. `docs/logging.md` is the reference;
this section is what a contributor needs before touching it.

### Adding an event

Every record carries an `event_type` from a closed, registered set. No call site
builds one from a string. To add one:

1. **Add the constant** in `pkg/logging/events.go`. The value is exactly three
   lowercase segments, `<domain>.<object>.<action>`
   (`^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*){2}$`), with the domain from the closed
   set `proxy`, `request`, `authn`, `authz`, `cache`, `oidc`, `readiness`,
   `upstream`, `audit`, `log`, and the action from the closed verb list in
   `docs/logging.md`. The outcome never goes in the name — `decision`, `reason`,
   `termination` and `cache_result` carry it.
2. **Add the registry entry** in the same file: component, default level,
   required fields, static `msg`, and the one-line summary that becomes the doc
   row. The grammar and completeness tests fail if a constant has no entry.
3. **Run `make eventdoc`** and commit the regenerated table in
   `docs/logging.md`. `make verify` runs `verify_eventdoc`, which prints the
   unified diff and fails CI when the file is stale. Never hand-edit between the
   `events:begin` and `events:end` markers; hand-written prose lives outside
   them and survives regeneration.
4. **Add a changelog fragment** for the PR. A new event is append-only and does
   **not** bump `schema_version`; renaming one that has shipped does, and needs
   the migration described under
   [versioning](./docs/logging.md#versioning).

Emit through `logging.Emit(ctx, logger, logging.EventX, attrs...)`, which stamps
the level and `msg` from the registry, or `logging.EmitLevel` for the few events
whose severity depends on the outcome.

**Never bind `request_id` onto a logger with `.With()`.** The request id lives
on the context: the outermost filter calls `logging.WithRequestID(ctx, id)`, and
`Emit` appends `request_id` automatically for any event whose registry entry
requires it and whose caller did not pass it. A test that needs a request id
uses `logging.WithRequestID(ctx, "...")`, not `root.With("request_id", "...")` —
a bound attribute bypasses the registry check and duplicates the key.

### Level policy

ERROR means the process cannot serve correctly: the audit backend failed to
start or flush, the API server is unreachable for a review, an internal
invariant broke, a CA is unreadable. WARN means degraded state or an anomaly —
an issuer pending, a forwarded header dropped, a reserved-identity or header-cap
attempt — and anything attacker-triggerable at WARN goes through the token
bucket, which emits a `log.warning.suppressed` summary rather than a flood.
Everything a healthy process does routinely is INFO (lifecycle milestones and
the unsampled per-request access record) or DEBUG (per-request internals, cache
hits, live reviews); denials are INFO on the access record and are never
rate-limited, because a bad token must not be able to buy a warning line.

### Redaction

Never log a bearer token, an `Authorization` or `Cookie` value, any header off
the allowlist, a request or response body, a cache key, an arbitrary claim or
extra, a configured extra-header value, the `User-Agent` header, or a full
issuer URL — log the configured `issuer_name` instead. Run every
user-influenced string through `logging.Sanitize` (control characters stripped)
and bound it with `logging.Bound`: `request_id` 64, `error_message` 512,
identity strings 256. Cap group lists with `logging.BoundedList` at 32 and
report the drop as a `*_groups_omitted` count.
Prefer a classified `reason` from the closed set over raw error text at INFO and
WARN; a truncated `error_message` belongs on internal failures and at DEBUG
only.

## Upstream

This is a fork of [TremoloSecurity/kube-oidc-proxy](https://github.com/TremoloSecurity/kube-oidc-proxy)
(originally [jetstack/kube-oidc-proxy](https://github.com/jetstack/kube-oidc-proxy)).
See [MAINTAINING.md](./MAINTAINING.md) for how this fork tracks upstream security fixes.
