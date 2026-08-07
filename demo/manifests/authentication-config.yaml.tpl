# kube-oidc-proxy multi-issuer AuthenticationConfiguration (template).
#
# run.sh replaces the __CA_A__ / __CA_B__ marker lines with each issuer's CA
# certificate (PEM), indented to sit under the `certificateAuthority: |` block
# scalar. The rendered file is passed to the Helm chart via
# `--set-file authenticationConfig.content=<rendered>`, which makes the proxy
# start with `--authentication-config` and accept tokens from BOTH issuers.
#
# Each issuer's `url` equals the Dex Service DNS, so it matches the `iss` claim
# in the minted tokens and the issuer in Dex's discovery document. The username
# is the token's `email` claim, prefixed per issuer to keep the two IdPs'
# identities distinct (oidc-a: / oidc-b:).
apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
jwt:
  - issuer:
      url: https://dex-a.dex.svc.cluster.local:5556/dex
      audiences:
        - demo
      certificateAuthority: |
__CA_A__
    claimMappings:
      username:
        claim: email
        prefix: "oidc-a:"
      groups:
        claim: groups
        prefix: "oidc-a:"
  - issuer:
      url: https://dex-b.dex.svc.cluster.local:5556/dex
      audiences:
        - demo
      certificateAuthority: |
__CA_B__
    claimMappings:
      username:
        claim: email
        prefix: "oidc-b:"
      groups:
        claim: groups
        prefix: "oidc-b:"
