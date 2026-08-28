# Copyright Jetstack Ltd. See LICENSE for details.
#
# Distroless static base: the proxy is a CGO_ENABLED=0 static binary, so it
# needs nothing from the OS except CA certificates (which distroless/static
# ships). This drops every Ubuntu base package — and with them the base-image
# CVEs that a static binary can never use — and runs as a non-root user.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
LABEL description="OIDC reverse proxy authenticator based on Kubernetes"

ARG TARGETARCH

COPY bin/${TARGETARCH}/kube-oidc-proxy /usr/bin/

ENTRYPOINT ["/usr/bin/kube-oidc-proxy"]
