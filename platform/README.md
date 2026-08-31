# AEP Platform for Go

The `platform` package implements the hosted-identity role for Agent runtimes that delegate Service-scoped identity creation and assertion signing to a Platform.

## Integration boundaries

`platform.New` requires explicit implementations for:

- `Authorizer`, which enforces the calling principal for every management operation;
- `KeyStore`, which creates keys, publishes DID verification methods, signs assertions, and supplies verification keys;
- `ServiceDIDResolver`, which validates a Service before provisioning an identity; and
- unique identity and Agent DID identifiers when the defaults are not appropriate.

The default identity and idempotency stores are in-memory. Production Platforms should provide durable, tenant-scoped stores and production key custody.

```go
hosted, err := platform.New(platform.Options{
	Authorizer:     authorizer,
	DIDHost:        "platform.example",
	DIDPathPrefix:  "agents",
	DIDURLTemplate: "https://platform.example/agents/{agent_did_id}/did.json",
	Discovery: platform.DiscoveryOptions{
		EndpointBase:      "/aep/",
		LifecycleEndpoint: "/aep/identities/{agent_identity_id}",
		ListEndpoint:      "/aep/identities",
		PlatformName:      "Example Platform",
		ProvisionEndpoint: "/aep/identities",
		SignEndpoint:      "/aep/identities/{agent_identity_id}/sign",
	},
	KeyStore:           keys,
	ServiceDIDResolver: resolver,
	SigningAlgorithms:  []aep.SigningAlgorithm{aep.SigningAlgorithmES256},
})
if err != nil {
	return err
}
```

## Lifecycle

Applications expose the Platform methods through their authenticated HTTP layer. The calling application constructs a `RequestContext` from its authenticated principal and request metadata.

```go
provisioned, err := hosted.Provision(ctx,
	platform.ProvisionRequest{ServiceDID: serviceDID},
	platform.RequestContext{
		IdempotencyKey: "provision-1",
		Principal:      principalID,
	},
)
if err != nil {
	return err
}
```

Use `Sign` for operation-bound client assertions, `GetIdentity` and `List` for management, and `UpdateIdentity` for lifecycle transitions. `GetDIDDocument` returns the public DID document for an Agent DID identifier.

Hosted verification is opt-in. Enabling it requires a replay store so that accepted assertions are consumed atomically.

The [Platform example](../examples/platform/) demonstrates discovery, provisioning, signing, and listing.
