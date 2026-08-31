# Development

## Requirements

- Go 1.26 or newer.

## Verification

Run the complete repository gate before merging:

```sh
make verify
make consumer-smoke
make conformance
```

The gate checks Go formatting, module-file drift, static analysis, race detection, tests, and
coverage generation. Continuous integration runs it on Go 1.26 and 1.27.

The conformance target exercises the public Agent, Service, and Platform APIs against the shared
test vectors in an adjacent `aep-specs` checkout. Install that repository's Ruby bundle before the
first local run. Set `AEP_SPECS_DIR` to use another location.

Use standard Go commands while iterating:

```sh
go test ./...
go test -race ./agent/...
go vet ./...
```

## Package boundaries

The root `aep` package owns transport-independent protocol behavior. `agent`, `service`, and
`platform` are role packages. Shared implementation details that are not public API belong under
`internal` when they are introduced.

The normative protocol is maintained in `aep-foundation/aep-specs`. Confirm draft, schema,
registry, and conformance behavior there before implementing or changing it in Go.

## Releases

Stable Go module releases use semantic-version tags such as `v0.1.0` and matching GitHub releases.
Release configuration, conformance evidence, interoperability, and clean external consumption are
verified before the first public version is published.
