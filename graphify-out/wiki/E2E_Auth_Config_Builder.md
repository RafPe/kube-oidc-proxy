# E2E Auth Config Builder

> 6 nodes

## Key Concepts

- **authconfig.go** (3 connections) — `test/e2e/suite/cases/authconfig/authconfig.go`
- **authConfig()** (2 connections) — `test/e2e/suite/cases/authconfig/authconfig.go`
- **configMapVolume()** (2 connections) — `test/e2e/suite/cases/authconfig/authconfig.go`
- **jwtAuthenticator()** (2 connections) — `test/e2e/suite/cases/authconfig/authconfig.go`
- **k8s.io/apiserver/pkg/apis/apiserver/v1.AuthenticationConfiguration** (1 connections)
- **k8s.io/apiserver/pkg/apis/apiserver/v1.JWTAuthenticator** (1 connections)

## Relationships

- [E2E Proxy Deployment](E2E_Proxy_Deployment.md) (1 shared connections)

## Source Files

- `test/e2e/suite/cases/authconfig/authconfig.go`

## Audit Trail

- EXTRACTED: 6 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*