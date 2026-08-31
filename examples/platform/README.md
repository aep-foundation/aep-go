# Hosted identity Platform

This runnable example constructs a hosted Agent identity Platform with explicit authorization, key custody, and Service DID resolution boundaries. It provisions a Service-scoped Agent identity, signs an Enroll assertion, and lists the identities owned by the calling principal.

Run it from the repository root:

```sh
go run ./examples/platform
```

The in-memory identity and idempotency stores and the single-process key store are suitable only for this example. A deployed Platform must provide durable tenant-scoped storage, production key custody, an authorization policy, and real Service DID resolution.
