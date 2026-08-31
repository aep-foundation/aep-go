# Agent and Service lifecycle

This runnable example creates an in-process loopback Service and an Agent with a `did:web` identity. It exercises the public SDK surface for:

- Inspect discovery;
- required and preferred Claims;
- Enroll;
- an API-key Grant;
- authenticated access to a protected resource; and
- per-credential Revoke.

The Service uses the SDK's in-memory stores to keep the example self-contained. Replace them with durable, tenant-aware stores before deploying a Service.

Run it from the repository root:

```sh
go run ./examples/agent-service
```

The program prints each completed lifecycle stage. The private key and issued credential exist only for the lifetime of the process.
