.PHONY: check test build fmt imports

export GO111MODULE=on

GOFILES := $(shell git ls-files '*.go')

default: check test build

test:
	go test -v -cover ./...

build:
	go build -v 

check:
	golangci-lint run

fmt:
	@gofmt -s -l -w $(GOFILES)

imports:
	@goimports -w $(GOFILES)
