# Copyright Jetstack Ltd. See LICENSE for details.
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

LABEL description="A fake API server that will respond to requests with the same body and headers."

RUN apk --no-cache add ca-certificates

COPY ./bin/fake-apiserver-linux /usr/bin/fake-apiserver

CMD ["/usr/bin/fake-apiserver"]
