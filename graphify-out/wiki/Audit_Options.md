# Audit Options

> 6 nodes

## Key Concepts

- **AuditOptions** (8 connections) — `cmd/app/options/audit.go`
- **k8s.io/component-base/cli/flag.NamedFlagSets** (8 connections)
- **NewAuditOptions()** (5 connections) — `cmd/app/options/audit.go`
- **.AddFlags()** (3 connections) — `cmd/app/options/audit.go`
- **options/audit.go** (2 connections) — `cmd/app/options/audit.go`
- **k8s.io/apiserver/pkg/server/options.AuditOptions** (1 connections)

## Relationships

- [Proxy Core: Audit & Serving](Proxy_Core-_Audit_&_Serving.md) (3 shared connections)
- [Command Options](Command_Options.md) (2 shared connections)
- [Misc Options & Version](Misc_Options_&_Version.md) (2 shared connections)
- [App Options & Flags](App_Options_&_Flags.md) (2 shared connections)
- [Authentication Config Options](Authentication_Config_Options.md) (1 shared connections)
- [Client Options](Client_Options.md) (1 shared connections)
- [OIDC Authentication Options](OIDC_Authentication_Options.md) (1 shared connections)
- [Secure Serving Options](Secure_Serving_Options.md) (1 shared connections)

## Source Files

- `cmd/app/options/audit.go`

## Audit Trail

- EXTRACTED: 19 (95%)
- INFERRED: 1 (5%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*