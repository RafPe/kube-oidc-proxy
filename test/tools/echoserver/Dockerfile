# Copyright Jetstack Ltd. See LICENSE for details.
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

LABEL description="An HTTP echo server the e2e upgrade cases exec and port-forward into."

# The exec case runs curl inside this container against the server itself.
RUN apk --no-cache add curl

COPY ./bin/echoserver /usr/bin/echoserver

CMD ["/usr/bin/echoserver"]
