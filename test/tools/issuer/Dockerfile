# Copyright Jetstack Ltd. See LICENSE for details.
FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d

LABEL description="A basic OIDC issuer that prsents a well-known and certs endpoint."

RUN apk --no-cache add ca-certificates

COPY ./bin/oidc-issuer-linux /usr/bin/oidc-issuer

CMD ["/usr/bin/oidc-issuer"]
