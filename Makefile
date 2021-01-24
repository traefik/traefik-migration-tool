.PHONY: check clean test build package package-snapshot docs

export GO111MODULE=on

TAG_NAME := $(shell git tag -l --contains HEAD)
SHA := $(shell git rev-parse HEAD)
VERSION := $(if $(TAG_NAME),$(TAG_NAME),$(SHA))

default: check test build

test:
	go test -v -cover ./...

clean:
	rm -rf dist/

build: clean
	@echo Version: $(VERSION)
	go build -v -ldflags '-X "main.Version=${VERSION}" -X "main.ShortCommit=${SHA}"' .

check:
	golangci-lint run

doc:
	go run . doc

image:
	docker build -t traefik-migration-tool .

publish-images:
	seihon publish -v "$(TAG_NAME)" -v "latest" --image-name traefik/traefik-migration-tool --dry-run=false

package:
	goreleaser --skip-publish --skip-validate --rm-dist

package-snapshot:
	goreleaser --skip-publish --skip-validate --rm-dist --snapshot
