# Unified release workflow — TDD evidence

## Journeys

- Contributors receive a required exact-label and changelog-fragment check.
- Maintainers explicitly prepare and review `release/next` before publication.
- All sharded Kind E2E jobs test the resolved release commit before tagging.
- Recovery can resume an immutable tag but cannot move or overwrite it.

## Evidence

| Guarantee | Type | RED | GREEN |
| --- | --- | --- | --- |
| Unified release files and README contract exist | Contract | `sh scripts/release-contract-check.sh` failed on missing `pr-release-metadata.yml` | Same command: `release-contract-check: ok` |
| Workflow syntax and embedded shell are valid | Integration/static | N/A | `GOENV_VERSION=1.26.2 actionlint ...`: PASS |
| Existing Go behavior is unchanged | Unit | N/A | `go test ./pkg/... ./cmd/...`: PASS |
| Release E2E tests the resolved SHA | Contract | Added after recovery-path review | Contract and actionlint: PASS; reusable E2E receives `target_ref` |

## Coverage and E2E

The repository does not expose one aggregate local coverage threshold. Its Go
unit packages passed. `make verify test` remains blocked by pre-existing missing
boilerplate headers in `demo/run.sh` and `demo/cleanup.sh`; the new release
contract script has the required header. The existing three-shard Kind suite is
now reusable and mandatory before release tagging; PR CI will execute it without
duplicating a resource-heavy local cluster run.
