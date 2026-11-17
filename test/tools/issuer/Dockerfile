# Copyright Jetstack Ltd. See LICENSE for details.
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

LABEL description="A basic OIDC issuer that prsents a well-known and certs endpoint."

RUN apk --no-cache add ca-certificates

COPY ./bin/oidc-issuer-linux /usr/bin/oidc-issuer

CMD ["/usr/bin/oidc-issuer"]
