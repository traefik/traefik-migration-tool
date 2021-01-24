FROM golang:1-alpine as builder

RUN apk --update upgrade \
    && apk --no-cache --no-progress add git make gcc musl-dev ca-certificates tzdata

WORKDIR /go/traefik-certs-dumper

ENV GO111MODULE on
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN GOARCH={{ .GoARCH }} GOARM={{ .GoARM }} make build

FROM {{ .RuntimeImage }}

# Not supported for multi-arch without Buildkit or QEMU
#RUN apk --update upgrade \
#    && apk --no-cache --no-progress add ca-certificates

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /go/traefik-certs-dumper/traefik-certs-dumper .

ENTRYPOINT ["/traefik-migration-tool"]
