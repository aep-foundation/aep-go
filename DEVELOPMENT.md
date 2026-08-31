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

## Node.js interoperability

The interoperability workflow runs a Go Agent against the Node.js Service and Platform, then runs
the Node.js Agent against the Go Service and Platform. Both scenarios use the public SDK HTTP
boundaries and cover Inspect, Enroll, Grant, protected-resource authentication, Revoke, Platform
discovery, identity recovery or provisioning, and delegated signing.

With an `aep-node` checkout next to this repository, run:

```sh
make interoperability
```

Set `AEP_NODE_DIR` when the Node.js repository is elsewhere. The report is written to
`.interop/reports/aep-go-node-interoperability.json`.

## Releases

Stable Go module releases use semantic-version tags such as `v0.1.0` and matching GitHub releases.
Versions follow semantic versioning and are not required to remain in lockstep with other AEP
development kits.

Run the `Release` workflow from `main` and provide the version without the `v` prefix. The workflow
verifies the repository, clean external consumption, shared Agent, Service, and Platform
conformance, and bidirectional Node.js interoperability before creating an annotated tag and
GitHub release. The conformance reports and interoperability report are attached to the release.
