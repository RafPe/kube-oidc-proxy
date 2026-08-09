# Upstream transport improvements

This proposal tracks two upstream requests that remain applicable to this fork:

- [#91](https://github.com/RafPe/kube-oidc-proxy/issues/91): reload rotated API-server client certificates;
- [#92](https://github.com/RafPe/kube-oidc-proxy/issues/92): support mTLS to OIDC issuers.

## Proposed implementation

1. Replace the reverse proxy's one-time TLS transport construction with the
   client-go transport path, preserving existing authentication wrappers and
   forcing HTTP/1.1 where required for SPDY streaming upgrades. Add a focused
   certificate-rotation test and exercise exec/port-forward in the kind e2e
   suite.
2. Add paired OIDC client-certificate and client-key options with startup
   validation. Inject a dedicated TLS transport into issuer discovery and JWKS
   retrieval without changing the default system-root or custom-CA paths.
3. Define the multi-issuer configuration shape before exposing the mTLS flags,
   then document certificate rotation behavior and update Helm values once the
   runtime contract is settled.

The changes should land separately: #91 is a correctness fix for an existing
configuration, while #92 is an opt-in feature with additional configuration
design and security review.
