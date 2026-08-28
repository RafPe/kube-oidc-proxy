# Copyright Jetstack Ltd. See LICENSE for details.
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

LABEL description="A fake API server that will respond to requests with the same body and headers."

RUN apk --no-cache add ca-certificates

COPY ./bin/fake-apiserver-linux /usr/bin/fake-apiserver

CMD ["/usr/bin/fake-apiserver"]
