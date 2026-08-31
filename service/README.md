# AEP Service for Go

The `service` package publishes a Service's AEP document, handles the protocol commands, issues optional session credentials, and authenticates protected resources.

## Required integration boundaries

A Service must provide:

- a Service `did:web` identifier;
- at least one identity method;
- a client-assertion verifier; and
- an HTTP endpoint base.

The SDK supplies in-memory enrollment, replay, idempotency, and credential stores for examples and tests. Production Services should replace them with atomic, durable implementations shared by every application instance.

```go
serviceCore, err := service.New(service.Options{
	EndpointBase:    "/aep/",
	IdentityMethods: []aep.IdentityMethod{aep.IdentityMethodDIDWeb},
	ServiceDID:      "did:web:service.example",
	Verifier:        service.NewDIDWebAssertionVerifier(service.DIDWebVerifierOptions{}),
})
if err != nil {
	return err
}
```

## Claims

Declare only Claim Names the Service uses. Required Claims block enrollment when absent; preferred and optional Claims do not.

```go
Claims: &aep.InspectClaims{
	Required:  []aep.ClaimName{aep.ClaimContactEmail},
	Preferred: []aep.ClaimName{aep.ClaimPersonFirstName},
},
```

An `EnrollmentPolicy` decides whether a valid request becomes active, pending, or rejected. The policy receives validated Claim Values and can apply application-specific requirements.

## Credentials

Session credentials are optional. Configure a built-in profile with an issuer and a `ServiceCredentialStore`:

```go
credentials := service.NewMemoryServiceCredentialStore()

apiKey, err := service.StoredAPIKeyGrantType(
	service.StoredCredentialGrantTypeOptions[aep.APIKeyGrantResponse]{
		Issue: issueAPIKey,
		Store: credentials,
	},
)
if err != nil {
	return err
}
```

The corresponding constructors are:

| Credential   | Constructor                        | Protected-resource presentation                  |
| ------------ | ---------------------------------- | ------------------------------------------------ |
| OAuth Bearer | `StoredOAuthBearerGrantType`       | `Authorization: Bearer …` or `AEP-Authorization` |
| API key      | `StoredAPIKeyGrantType`            | Service-selected HTTP header                     |
| HTTP Basic   | `StoredBasicGrantType`             | `Authorization: Basic …` or `AEP-Authorization`  |

Add each definition to `Options.GrantTypes` and add the methods accepted by protected resources to `Options.AuthenticationMethods`. AEP command endpoints continue to use their operation-bound client assertions; `authentication.methods` describes protected application resources.

## Mount the HTTP handler

```go
handler, err := service.NewHTTPHandler(serviceCore, service.HTTPHandlerOptions{})
if err != nil {
	return err
}

mux.Handle(aep.WellKnownPath, handler)
mux.Handle("/aep/", handler)
```

The handler serves the Inspect document with cache validators and dispatches the fixed AEP command paths and methods.

Protect application routes with the framework-neutral middleware:

```go
protect, err := service.NewProtectedResourceMiddleware(serviceCore, "https://service.example")
if err != nil {
	return err
}

mux.Handle("/account", protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	principal, ok := service.PrincipalFromContext(r.Context())
	if !ok {
		http.Error(w, "missing principal", http.StatusInternalServerError)
		return
	}
	_ = principal
})))
```

The [Agent and Service example](../examples/agent-service/) shows the complete lifecycle.
