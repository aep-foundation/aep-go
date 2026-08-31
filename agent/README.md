# AEP Agent for Go

The `agent` package gives an Agent one Service-scoped workflow for Inspect, Enroll, Status, Grant, Revoke, credential storage, and protected-resource authentication.

## Create a Client

Every Client requires an `IdentityProvider`. It owns the Agent's Service-scoped identity and signs operation-bound client assertions.

```go
client, err := agent.New(agent.Options{
	IdentityProvider: identities,
	IdentityStore:    durableIdentities,
	CredentialStore:  durableCredentials,
})
if err != nil {
	return err
}

session, err := client.Service("https://service.example")
if err != nil {
	return err
}
```

The default identity, credential, Inspect-cache, and idempotency components are in-memory implementations. Pass durable stores when identities or issued credentials must survive process restarts.

## Use a hosted identity Platform

`NewPlatformIdentityProvider` discovers a Platform, recovers or provisions a Service-scoped Agent
identity, and delegates assertion signing. Platform API authentication is application-specific.

```go
identities, err := agent.NewPlatformIdentityProvider(agent.PlatformIdentityProviderOptions{
	Authorization: "Bearer platform-api-token",
	PlatformURL:   "https://platform.example",
	PendingSignResolver: func(ctx context.Context, pending agent.PlatformPendingSign) (map[string]json.RawMessage, error) {
		timer := time.NewTimer(time.Duration(pending.RetryAfterSeconds) * time.Second)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
			return pending.PlatformContext, nil
		}
	},
})
if err != nil {
	return err
}

client, err := agent.New(agent.Options{IdentityProvider: identities})
```

When delegated signing returns `202 Accepted`, the resolver controls waiting and supplies the opaque
Platform context for the next Sign request. Without a resolver, signing returns a
`PlatformSignPendingError`. Applications operating a Platform remain responsible for mapping the
Platform engine to their authenticated HTTP routes.

## Enroll

Inspect before collecting Claims so the application can explain what the Service requires. `Enroll` also checks the provided Claim Values against the advertised required Claim Names.

```go
inspection, err := session.Inspect(ctx)
if err != nil {
	return err
}

email := "agent-owner@example.com"
result, err := session.Enroll(ctx, agent.EnrollOptions{
	Claims: &aep.ClaimValues{ContactEmail: &email},
})
if err != nil {
	return err
}

if result.Body.Status == aep.EnrollmentPending {
	_, err = session.WaitForActive(ctx, agent.WaitOptions{})
	if err != nil {
		return err
	}
}
```

`WaitForActive` respects context cancellation and returns an `EnrollmentStateError` for terminal enrollment states.

## Receive and use a credential

The Agent can request an advertised OAuth Bearer, API-key, or HTTP Basic credential. A successful built-in Grant is stored automatically.

```go
_, err = session.Grant(ctx, agent.GrantOptions{
	GrantType:       aep.GrantTypeAPIKey,
	RequestedScopes: []string{"catalog:read"},
})
if err != nil {
	return err
}

resource, err := url.Parse("https://service.example/catalog")
if err != nil {
	return err
}
headers, err := session.AuthenticationHeaders(ctx, agent.AuthenticationOptions{
	Resource: resource,
})
if err != nil {
	return err
}
```

`AuthenticationHeaders` follows the Service's advertised preference order. A specific `CredentialID` or `GrantType` can be requested. Set `ClientAssertionOnly` only when the protected resource advertises `aep-jwt`.

## Revoke

```go
_, err := session.Revoke(ctx, agent.RevokeOptions{
	CredentialID: credentialID,
	GrantType:    aep.GrantTypeAPIKey,
})
```

The Agent removes successfully revoked built-in credentials from its configured store. `ForgetCredential` removes a local record without calling the Service.

## Runnable lifecycle

The [Agent and Service example](../examples/agent-service/) runs Inspect through Revoke against the `service` package.
