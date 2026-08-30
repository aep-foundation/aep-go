# AGENTS.md

## Repository

This module contains the official Go packages for AEP:

- Root package `aep`: transport-independent protocol primitives.
- `agent`: Agent-side enrollment and credential workflows.
- `service`: Service-side enrollment, credential, and authentication integration.
- `platform`: Platform-hosted Agent identity integration.

The normative protocol is maintained in `aep-foundation/aep-specs`. Check that source before
implementing or changing wire behavior.

## Verification

Run `make verify` before merging. Public APIs are the exported identifiers outside `internal` and
must be backed by tests and authoritative protocol behavior.

## Conventions

- Support Go 1.26 and newer; continuous integration covers Go 1.26 and 1.27.
- Use the standard library when it is sufficient and justify every additional dependency.
- Do not implement JOSE or JWT cryptography directly; use a narrowly vetted dependency.
- Do not add a runtime JSON Schema engine. AEP uses bounded native wire validation.
- Accept `context.Context` first for operations that perform input/output or may block.
- Return errors rather than logging from library packages.
- Use extensible options structures for major Agent, Service, and Platform components.
- Keep dependency direction from role packages toward the root `aep` package.
- Keep implementation details under `internal` unless callers require them.
- Describe current behavior; do not leave speculative or historical comments.
- Keep public APIs small, idiomatic, and backed by tests and authoritative protocol behavior.
