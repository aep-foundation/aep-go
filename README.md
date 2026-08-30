# Agent Enrollment Protocol for Go

[![CI](https://github.com/aep-foundation/aep-go/actions/workflows/ci.yml/badge.svg)](https://github.com/aep-foundation/aep-go/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/aep-foundation/aep-go.svg)](https://pkg.go.dev/github.com/aep-foundation/aep-go)
[![Go](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

Official Go software development kit for the
[Agent Enrollment Protocol](https://www.aep.foundation/), the open protocol for Agent enrollment,
Service-issued credentials, and authenticated Agent access.

## Start here

| Goal                                               | Package    |
| -------------------------------------------------- | ---------- |
| Inspect, enroll with, and authenticate to Services | `agent`    |
| Integrate enrollment into a Service                | `service`  |
| Host managed Agent identities                      | `platform` |
| Use protocol models and validation directly        | `aep`      |

## Install

```sh
go get github.com/aep-foundation/aep-go@latest
```

## Module

```text
github.com/aep-foundation/aep-go
├── aep       Protocol models, validation, identity, assertions, and HTTP primitives
├── agent     Agent enrollment, credentials, and protected-resource authentication
├── service   Service enrollment, credential issuance, and request authentication
└── platform  Platform-hosted Agent identity management and delegated signing
```

The root import path uses package name `aep`.

```go
import (
	aep "github.com/aep-foundation/aep-go"
	"github.com/aep-foundation/aep-go/agent"
	"github.com/aep-foundation/aep-go/platform"
	"github.com/aep-foundation/aep-go/service"
)
```

Role packages depend toward the root `aep` package. The root package does not depend on role
packages. `agent` may compose `platform` for hosted identity workflows; `service` remains independent
of Agent behavior.

Claims and credential wire types belong to `aep`. Agent presentation behavior belongs to `agent`;
Service issuance and verification behavior belongs to `service`. Framework integrations remain
outside the protocol core.

## Development

Go 1.26 or newer is required. Run the complete merge gate with:

```sh
make verify
make consumer-smoke
```

See [DEVELOPMENT.md](./DEVELOPMENT.md) for the contributor workflow and
[`aep-specs`](https://github.com/aep-foundation/aep-specs) for the normative drafts, schemas,
registries, examples, and test vectors.

## Security

See [SECURITY.md](./SECURITY.md) for vulnerability reporting.

## License

MIT.
