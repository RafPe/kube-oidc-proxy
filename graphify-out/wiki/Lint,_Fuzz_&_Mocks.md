# Lint, Fuzz & Mocks

> 13 nodes

## Key Concepts

- **FuzzParseTrustedProxies()** (5 connections) — `pkg/proxy/proxy_fuzz_test.go`
- **FuzzStringToStringSliceSet()** (5 connections) — `pkg/util/flags/string_to_string_slice_fuzz_test.go`
- **FuzzParseFromRequest()** (5 connections) — `pkg/util/token/token_fuzz_test.go`
- **fuzz workflow** (5 connections) — `.github/workflows/fuzz.yaml`
- **test workflow** (5 connections) — `.github/workflows/test.yaml`
- **testing.F** (3 connections)
- **lint:go job** (3 connections) — `.github/workflows/test.yaml`
- **pkg/mocks/authenticator.go (generated Token mock)** (3 connections) — `.github/workflows/test.yaml`
- **string_to_string_slice_fuzz_test.go** (2 connections) — `pkg/util/flags/string_to_string_slice_fuzz_test.go`
- **countFields()** (2 connections) — `pkg/util/flags/string_to_string_slice_fuzz_test.go`
- **proxy_fuzz_test.go** (1 connections) — `pkg/proxy/proxy_fuzz_test.go`
- **token_fuzz_test.go** (1 connections) — `pkg/util/token/token_fuzz_test.go`
- **golangci-lint Config** (1 connections) — `.golangci.yml`

## Relationships

- [E2E & Test Workflows](E2E_&_Test_Workflows.md) (3 shared connections)
- [Proxy Core: Audit & Serving](Proxy_Core-_Audit_&_Serving.md) (1 shared connections)
- [StringToStringSlice Flag](StringToStringSlice_Flag.md) (1 shared connections)
- [Token Parsing Utilities](Token_Parsing_Utilities.md) (1 shared connections)
- [Build, Sign & Publish Workflows](Build,_Sign_&_Publish_Workflows.md) (1 shared connections)

## Source Files

- `.github/workflows/fuzz.yaml`
- `.github/workflows/test.yaml`
- `.golangci.yml`
- `pkg/proxy/proxy_fuzz_test.go`
- `pkg/util/flags/string_to_string_slice_fuzz_test.go`
- `pkg/util/token/token_fuzz_test.go`

## Audit Trail

- EXTRACTED: 19 (79%)
- INFERRED: 5 (21%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*