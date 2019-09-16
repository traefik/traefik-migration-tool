# traefik-migration-tool

[![GitHub release](https://img.shields.io/github/release/containous/traefik-migration-tool.svg)](https://github.com/containous/traefik-migration-tool/releases/latest)
[![Build Status](https://travis-ci.com/containous/traefik-migration-tool.svg?branch=master)](https://travis-ci.com/containous/traefik-migration-tool)

A migration tool from Traefik v1 to Traefik v2.

Features:

- ⛵ Migrate 'Ingress' to Traefik 'IngressRoute' resources.
- 🔒 Migrate acme.json file from Traefik v1 to Traefik v2.

## Usage

- [traefik-migration-tool](docs/traefik-migration-tool.md)

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
