# Copyright Jetstack Ltd. See LICENSE for details.
FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d

LABEL description="A fake API server that will respond to requests with the same body and headers."

RUN apk --no-cache add ca-certificates

COPY ./bin/fake-apiserver-linux /usr/bin/fake-apiserver

CMD ["/usr/bin/fake-apiserver"]
