# Copyright Jetstack Ltd. See LICENSE for details.
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

LABEL description="A basic OIDC issuer that prsents a well-known and certs endpoint."

RUN apk --no-cache add ca-certificates

COPY ./bin/oidc-issuer-linux /usr/bin/oidc-issuer

CMD ["/usr/bin/oidc-issuer"]
