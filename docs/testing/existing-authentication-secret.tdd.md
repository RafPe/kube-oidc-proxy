# Existing authentication Secret tests

Issue: #162. Test cases come from the requested existing Secret support and
backward compatibility requirement.

- RED: `bash hack/verify-chart-authentication.sh` passed the legacy cases, then
  failed with `external config or shared mTLS flags missing`.
- GREEN: the same command reports `chart authentication: ok` after the change.
- Compatibility: full renders of both existing CI fixtures were compared with
  the parent implementation using a fixed serving Secret. Both were identical,
  including configuration checksums.

The chart test covers single-issuer flags and Secret references, inline content,
old values without the new fields, external default and custom keys, empty/null
key fallback, read-only mounts, suppression of legacy flags and environment,
ignored legacy CA data, shared mTLS, readiness, explicit extra-claim RBAC,
absence of generated configuration Secrets, and conflicting sources. It also
checks that a custom external key does not change inline configuration.

Validation passed:

- `bash hack/verify-chart-authentication.sh`
- `bash hack/verify-chart-logging.sh`
- `bash hack/verify-chart-rbac.sh`
- `bash hack/verify-chart-namespace.sh`
- `helm lint chart/kube-oidc-proxy -f chart/kube-oidc-proxy/ci/single-issuer-values.yaml`
- `helm lint chart/kube-oidc-proxy -f chart/kube-oidc-proxy/ci/multi-issuer-values.yaml`
- `helm lint chart/kube-oidc-proxy --set authenticationConfig.existingSecret=external-auth`
- `git diff --check`

Coverage is checked through rendered Helm resources for all three configuration
modes and the error path. Helm templates have no line-coverage report in this
repository; no percentage is claimed. No application code changed. A live
cluster authentication or upgrade test was not run.
