# Single-issuer existing Secret tests

The user requested externally supplied single-issuer OIDC environment variables
with configurable Secret keys. This builds on PR #163's structured configuration
Secret support.

User journey: an operator references an existing Secret without copying issuer
settings into Helm values, enables optional flags through key mappings, and
retains existing deployments' behavior.

## TDD evidence

- RED: `bash hack/verify-chart-authentication.sh` passed the existing cases,
  then failed with `external clientId reference missing`. Committed as
  `f226002e9` before implementation.
- GREEN: the same script passed after the environment source selection and
  validation were added (`173d559f9`). Additional boundary checks also pass.

## Guarantees

All cases are rendered-manifest integration checks in
`hack/verify-chart-authentication.sh`, already invoked by chart CI.

| Behavior | Evidence |
| --- | --- |
| Required fields reference the external Secret with default or custom keys | Each required environment reference and the CLI argument wiring are asserted |
| Optional mappings enable flags without inline placeholders | Prefixes, groups and signing algorithms are exercised individually |
| Defaults and unmapped optional values remain supported | RS256, inline groups, empty/null mappings and omitted optional flags are checked |
| CA, required claims and mTLS coexist | Arguments, inline environment source and CA volume projection are asserted |
| Conflicting sources fail at render time | Required/optional inline conflicts, signing default conflict and both structured configuration sources are rejected |
| Invalid mappings fail clearly | Missing Secret name, unknown fields, malformed keys, non-map and non-string inputs are rejected |
| The chart does not manage the external Secret | No external Secret resource is rendered; required fields are not copied into the generated Secret; chart-owned name collision is rejected |
| No Secret API grants are added | Full ClusterRole render matches the existing mode |
| Existing values remain compatible | Old stored values with null new fields render identically |

Validation passed:

- `bash hack/verify-chart-authentication.sh`
- `bash hack/verify-chart-logging.sh`
- `bash hack/verify-chart-rbac.sh`
- `bash hack/verify-chart-namespace.sh`
- `shellcheck hack/verify-chart-authentication.sh`
- Helm lint for the single-issuer and multi-issuer fixtures, and both external
  Secret modes.
- Full render comparisons against parent PR #163 for classic single-issuer,
  inline structured configuration and external structured configuration, using
  a fixed serving TLS Secret: all three are byte-identical, including checksums.
- `git diff --check`

No application code changed. Coverage is measured through rendered cases;
there is no Helm template line-coverage percentage. No live cluster test was
run: missing Secret/key startup failures and environment refresh after a Pod
restart rely on Kubernetes behavior, not a local cluster verification.
