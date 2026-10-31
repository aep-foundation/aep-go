# AEP Service for Go

The `service` package publishes a Service's AEP document, handles the protocol commands, issues optional session credentials, and authenticates protected resources.

## Required integration boundaries

A Service must provide:

- a Service `did:web` identifier;
- at least one identity method;
- a client-assertion verifier; and
- an HTTP endpoint base.

The SDK supplies in-memory enrollment, replay, idempotency, and credential stores for examples and tests. Production Services should replace them with atomic, durable implementations shared by every application instance.

### Upgrading persisted state from v0.1.1

Keep enrollment, credential, and completed idempotency records. Service credential
storage does not require a hash conversion. Do not clear idempotency records to resolve
an upgrade: doing so can execute a completed Enroll, Grant, or Revoke request again.

`IdempotencyInput.RequestHash` retains the v0.1.1 calculation. Persist the optional
`CanonicalRequestHash` as well, and use `savedInput.Matches(requestInput)` inside your
store's atomic operation. It checks the Agent, command, and key, then compares canonical
hashes when both inputs contain them; otherwise it compares `RequestHash`. Records
without the new field need no backfill. For a database column, an empty string represents
an absent canonical hash.

Existing adapters that compare only `RequestHash` still recognize exact retries, but
retain v0.1.1's sensitivity to member ordering in nested request JSON. Workers on v0.1.1
can compare `RequestHash` from records written by upgraded workers. Keep that field and
the complete response until normal expiry; do not replace it with the canonical hash.

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

## Service documents and repeated enrollment

Configure `Options.ServiceDocuments` to advertise the extension and its documents:

```go
ServiceDocuments: []aep.ServiceDocument{{
	ID: "general-terms", Type: "terms_of_service", Title: "General terms",
	Enrollment: "required",
	Representations: []aep.DocumentRepresentation{{
		MediaType: "text/html", URL: "https://service.example/legal/terms",
	}},
}},
```

Use nil to disable the extension or an empty non-nil slice to support acknowledgements without publishing a document list. Each document needs an HTTPS HTML link. Document types are open strings; `aep.PreferredServiceDocumentTypes()` returns the conventional types. The catalog permits seven documents with identifiers of at most 32 ASCII characters.

Repeated Enroll evaluates the existing policy callback. Custom policies query their own authoritative storage when needed; the callback receives the request and current time, not an enrollment hint. The SDK merges supplied claims and accepted document identifiers while preserving the enrollment identity, creation time, status, and issued credentials. A policy can return `UpdateExisting` pointing to false to leave the record unchanged, or reject the update without modifying the stored enrollment.

Decision metadata is optional. On initial enrollment, nil `OwnerActionRequired` defaults to false and nil pending lists default to empty. On repeated enrollment, nil preserves the stored field, a boolean pointer explicitly sets true or false, and a non-nil list replaces the stored list (including an empty list to clear it). Stored enrollment fields remain concrete values.

Durable enrollment stores must persist `AcknowledgedDocumentIDs` and `RequiredDocumentIDs`. The latter lets the Service require renewed acknowledgement of an existing document. The Service owns its document-change policy and any notifications. Grant checks current required claims and document identifiers before issuing credentials and returns `requirements_unmet` when they are missing.

An explicit acknowledgement declaration is echoed without expansion, even if the catalog includes another required document. That later requirement can block a subsequent Grant; it does not invalidate the supplied enrollment declaration. Omitted declarations do not imply acceptance. Same-key retries replay the existing result; a separate explicit Enroll uses a new idempotency key.

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
