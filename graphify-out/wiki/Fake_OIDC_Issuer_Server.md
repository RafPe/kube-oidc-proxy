# Fake OIDC Issuer Server

> 26 nodes

## Key Concepts

- **Issuer** (7 connections) — `test/tools/issuer/pkg/issuer/issuer.go`
- **Sink** (6 connections) — `test/tools/audit-webhook/pkg/sink/sink.go`
- **.ServeHTTP()** (5 connections) — `test/tools/issuer/pkg/issuer/issuer.go`
- **Handler()** (5 connections) — `pkg/util/signals/signals.go`
- **Server** (4 connections) — `test/tools/fake-apiserver/pkg/server/server.go`
- **main()** (4 connections) — `test/tools/fake-apiserver/cmd/main.go`
- **main()** (3 connections) — `cmd/main.go`
- **crypto/rsa.PrivateKey** (3 connections)
- **main()** (3 connections) — `test/tools/audit-webhook/cmd/main.go`
- **New()** (3 connections) — `test/tools/audit-webhook/pkg/sink/sink.go`
- **server.go** (3 connections) — `test/tools/fake-apiserver/pkg/server/server.go`
- **New()** (3 connections) — `test/tools/fake-apiserver/pkg/server/server.go`
- **main()** (3 connections) — `test/tools/issuer/cmd/main.go`
- **New()** (3 connections) — `test/tools/issuer/pkg/issuer/issuer.go`
- **.certsDiscovery()** (2 connections) — `test/tools/issuer/pkg/issuer/issuer.go`
- **.wellKnownResponse()** (2 connections) — `test/tools/issuer/pkg/issuer/issuer.go`
- **.Run()** (2 connections) — `test/tools/fake-apiserver/pkg/server/server.go`
- **sink.go** (2 connections) — `test/tools/audit-webhook/pkg/sink/sink.go`
- **issuer.go** (2 connections) — `test/tools/issuer/pkg/issuer/issuer.go`
- **cmd/main.go** (1 connections) — `cmd/main.go`
- **.Run()** (1 connections) — `test/tools/issuer/pkg/issuer/issuer.go`
- **signals.go** (1 connections) — `pkg/util/signals/signals.go`
- **.Run()** (1 connections) — `test/tools/audit-webhook/pkg/sink/sink.go`
- **audit-webhook/cmd/main.go** (1 connections) — `test/tools/audit-webhook/cmd/main.go`
- **fake-apiserver/cmd/main.go** (1 connections) — `test/tools/fake-apiserver/cmd/main.go`
- *... and 1 more nodes in this community*

## Relationships

- [Proxy Handlers & Access Logging](Proxy_Handlers_&_Access_Logging.md) (5 shared connections)
- [Run Command & Authenticator Wiring](Run_Command_&_Authenticator_Wiring.md) (1 shared connections)
- [E2E Framework TLS & URLs](E2E_Framework_TLS_&_URLs.md) (1 shared connections)
- [Readiness Probe](Readiness_Probe.md) (1 shared connections)

## Source Files

- `cmd/main.go`
- `pkg/util/signals/signals.go`
- `test/tools/audit-webhook/cmd/main.go`
- `test/tools/audit-webhook/pkg/sink/sink.go`
- `test/tools/fake-apiserver/cmd/main.go`
- `test/tools/fake-apiserver/pkg/server/server.go`
- `test/tools/issuer/cmd/main.go`
- `test/tools/issuer/pkg/issuer/issuer.go`

## Audit Trail

- EXTRACTED: 40 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*