# traefik-migration-tool

[![GitHub release](https://img.shields.io/github/release/containous/traefik-migration-tool.svg)](https://github.com/containous/traefik-migration-tool/releases/latest)
[![Build Status](https://travis-ci.com/containous/traefik-migration-tool.svg?branch=master)](https://travis-ci.com/containous/traefik-migration-tool)

A migration tool from Traefik v1 to Traefik v2.

Features:

- ⛵ Migrate 'Ingress' to Traefik 'IngressRoute' resources.
- 🔒 Migrate acme.json file from Traefik v1 to Traefik v2.
- 🖹 Migrate the static configuration contained in the file `traefik.toml` to a Traefik v2 file.

## Usage

- [Commands documentation](docs/traefik-migration-tool.md)

## Install

### From Binaries

You can use pre-compiled binaries:

* To get the binary just download the latest release for your OS/Arch from [the releases page](https://github.com/containous/traefik-migration-tool/releases)
* Unzip the archive.
* Add `traefik-migration-tool` in your `PATH`.

### With docker

If you wish to use this command with docker

sh```
docker run --rm -v ${PWD}:/app purplebabar/traefik-migration-tool *options here*
```

## Limits

Unsupported annotations:

- `ingress.kubernetes.io/preserve-host`
- `ingress.kubernetes.io/session-cookie-name`
- `ingress.kubernetes.io/affinity`
- `ingress.kubernetes.io/buffering`
- `ingress.kubernetes.io/circuit-breaker-expression`
- `ingress.kubernetes.io/max-conn-amount`
- `ingress.kubernetes.io/max-conn-extractor-func`
- `ingress.kubernetes.io/responseforwarding-flushinterval`
- `ingress.kubernetes.io/load-balancer-method`
- `ingress.kubernetes.io/auth-realm`
- `ingress.kubernetes.io/service-weights`
- `ingress.kubernetes.io/error-pages`
