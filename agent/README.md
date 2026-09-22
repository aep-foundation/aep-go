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

## Send an authenticated resource request

`FetchProtectedResource` uses the advertised OpenAPI policy when it identifies a required
authentication method. Otherwise it sends an anonymous request and authenticates only
after a valid AEP `401` challenge. An unrelated `401`, a `403`, or another application
response is returned without an authentication retry.

```go
request, err := http.NewRequest(http.MethodPost,
	"https://service.example/catalog/search", strings.NewReader(`{"query":"flowers"}`))
if err != nil {
	return err
}
request.Header.Set("Content-Type", "application/json")
response, err := client.FetchProtectedResource(ctx, request, agent.ProtectedResourceOptions{})
if err != nil {
	return err
}
defer response.Body.Close()
```

The request is not modified or consumed. Nonempty bodies need `GetBody`; `http.NewRequest`
sets it for `strings.Reader`, `bytes.Reader`, and `bytes.Buffer`. Streams without `GetBody`
and request trailers are rejected before discovery. Each retry preserves the method and body.

If no compatible stored credential exists, the workflow can request an advertised Grant
using an existing identity and active enrollment. It never calls Enroll. An explicitly
selected missing credential, a store failure, or a signing failure is returned to the caller.

Same-origin redirects produce fresh resource-bound JWTs. Cross-origin redirects discard
all caller headers and generated credentials, restart anonymously, and require a new AEP
challenge before authenticating. `MaximumRedirects` defaults to five. `RequestTimeout`
bounds the whole operation, including reading the returned response body; close that body
when finished.

For payment composition, set `Authentication.Carrier` to `aep.ProtectedResourceDedicated`
and put payment headers in `AdditionalAuthenticationHeaders`. Those headers are sent only
on authenticated requests to the original origin. Put application headers such as
`Content-Type` on the request; do not put custom authentication secrets there, since
ordinary headers can accompany the initial anonymous request. Custom HTTP transports
must not inject credentials into anonymous requests.

## Read a resource's OpenAPI authentication policy

`OpenAPIPolicy` reads the OpenAPI document advertised by Inspect and selects the operation
using the request method and path. Query parameters do not select an operation.

```go
policy, err := session.OpenAPIPolicy(ctx, http.MethodGet, resource)
if err != nil {
	return err
}
```

The policy's `State` is `public`, `required`, or `fallback`. `required` includes the AEP
methods from complete alternatives; a compound requirement is not reduced to a single
method. `fallback` means the application must use an anonymous request and the Service's
live AEP challenge rather than assume authentication is required or unnecessary.
OpenAPI describes authentication; it does not authorize access.

Retrieval sends no authentication headers or cookies, follows at most five redirects,
and rejects transport downgrades. The Client's `RequestTimeout` and
`MaximumResponseBytes` bound retrieval (30 seconds and 1 MiB by default). Documents are
cached in memory using HTTP cache metadata, including conditional revalidation and
`no-store`. `AuthenticationOptions.AllowedMethods` can restrict header generation to
the methods allowed by an operation, intersected with those advertised by the Service.

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
