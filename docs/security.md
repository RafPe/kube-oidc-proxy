# Security considerations

- **The proxy is a privileged component.** Its ServiceAccount can impersonate
  users, groups, and extras against the API server. Restrict who can modify its
  Deployment and RBAC, and run it with the hardened defaults the chart ships
  (non-root, read-only root filesystem, dropped capabilities, seccomp
  `RuntimeDefault`).
- **Impersonation replaces, but does not bypass, RBAC.** The API server still
  authorizes the impersonated identity. Keep API-server RBAC tight; the proxy
  only decides *who* the request is, not *what* they may do.
- **Terminate and verify TLS end to end.** Clients must trust the proxy's
  serving certificate, and each OIDC issuer's TLS must be verifiable
  (`oidc.caPEM` / inline `certificateAuthority` for private CAs).
- **Scope audiences and required claims.** Use `audiences` / `--oidc-client-id`
  and `requiredClaims` to ensure tokens minted for other systems can't be
  replayed against the cluster — especially important for machine issuers like
  GitHub Actions.
- **Mind username prefixes across issuers.** In multi-issuer mode, distinct
  `prefix` values prevent one issuer's `alice` from colliding with another's.
- **Use token passthrough deliberately.** `--token-passthrough` forwards
  non-OIDC tokens after a TokenReview; only enable it (and constrain
  `--token-passthrough-audiences`) when you understand the tokens involved.

## See also

- [Impersonation model](./impersonation.md)
- [Architecture](./architecture.md)
- [Token passthrough](./tasks/token-passthrough.md)
