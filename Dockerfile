# Building app with golang container
FROM golang:alpine as builder

RUN apk --no-cache --no-progress add git \
    && rm -rf /var/cache/apk/*

WORKDIR /app

COPY . /app

RUN GO111MODULE=on GOPROXY=https://proxy.golang.org go mod download \
    && CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o traefik-migration-tool .

# packaging app with scratch to have the smaller container possible
FROM scratch

COPY --from=builder /app/traefik-migration-tool .

ENTRYPOINT ["/traefik-migration-tool"]
CMD ["-h"]
