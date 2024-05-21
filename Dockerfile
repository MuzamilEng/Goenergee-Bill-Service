FROM golang:1.19-alpine3.18 AS builder
WORKDIR /
ADD . .
RUN go build -o bin/goenergy /cmd/main.go

FROM registry.automatrix.et/library/python:1.0.1

WORKDIR /

COPY --from=builder /bin/goenergy .
COPY --from=builder /config/config.yaml /config/config.yaml


EXPOSE 8000
ENTRYPOINT [ "./goenergy" ]