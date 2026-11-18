# Copyright Jetstack Ltd. See LICENSE for details.
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

LABEL description="An HTTP echo server the e2e upgrade cases exec and port-forward into."

# The exec case runs curl inside this container against the server itself.
RUN apk --no-cache add curl

COPY ./bin/echoserver /usr/bin/echoserver

CMD ["/usr/bin/echoserver"]
