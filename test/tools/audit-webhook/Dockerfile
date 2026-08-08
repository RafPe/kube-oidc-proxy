# Copyright Jetstack Ltd. See LICENSE for details.
FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d

LABEL description="A audit webhook sink to read audit events and write to file."

RUN apk --no-cache add ca-certificates

COPY ./bin/audit-webhook /usr/bin/audit-webhook

CMD ["/usr/bin/audit-webhook"]
