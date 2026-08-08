# Contributing

Thanks for your interest in `kube-oidc-proxy`!

## Reporting issues

Open an issue at https://github.com/RafPe/kube-oidc-proxy/issues with steps to
reproduce, your Kubernetes and OIDC provider details, and any relevant proxy
logs.

## Development

- Requires Go 1.26+, Docker, and [kind](https://kind.sigs.k8s.io/).
- Unit tests: `go test ./cmd/... ./pkg/...`
- End-to-end suite on a local kind cluster: `make e2e` (see
  [docs/operations.md](./docs/operations.md#development-and-testing)).

## Pull requests

- Branch from `main`, keep changes focused, and include tests for behaviour changes.
- CI runs unit tests, the e2e gate, `govulncheck`, and the Helm checks — keep them green.
- Conventional-style commit messages (`fix:`, `feat:`, `docs:` …) are appreciated.

## Upstream

This is a fork of [TremoloSecurity/kube-oidc-proxy](https://github.com/TremoloSecurity/kube-oidc-proxy)
(originally [jetstack/kube-oidc-proxy](https://github.com/jetstack/kube-oidc-proxy)).
See [MAINTAINING.md](./MAINTAINING.md) for how this fork tracks upstream security fixes.
