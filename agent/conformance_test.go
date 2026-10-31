package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	aep "github.com/aep-foundation/aep-go"
)

// ---------------------------------------------------------------- harness

type serviceStub struct {
	client     *Client
	document   aep.InspectDocument
	requests   []*http.Request
	server     *httptest.Server
	serviceDID string
	session    *Session
}

// newServiceStub starts a Service that serves testInspectDocument and answers every command with
// the supplied handler, falling back to a minimal success body.
func newServiceStub(t *testing.T, handler func(http.ResponseWriter, *http.Request) bool) *serviceStub {
	t.Helper()
	stub := &serviceStub{}
	provider := newTestIdentityProvider(t)
	stub.server = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == aep.WellKnownPath {
			response.Header().Set("Content-Type", aep.MediaType)
			_ = json.NewEncoder(response).Encode(stub.document)
			return
		}
		stub.requests = append(stub.requests, request.Clone(request.Context()))
		if handler != nil && handler(response, request) {
			return
		}
		response.Header().Set("Content-Type", aep.MediaType)
		switch request.URL.Path {
		case "/aep/status":
			_, _ = response.Write([]byte(`{"since":"2026-01-01T00:00:00Z","status":"active"}`))
		case "/aep/enroll":
			_, _ = response.Write([]byte(`{"status":"active"}`))
		case "/aep/grant":
			_, _ = response.Write([]byte(`{"access_token":"t","credential_id":"cred-1","expires_at":"2999-01-01T00:00:00Z","scopes":[],"token_type":"Bearer"}`))
		default:
			_, _ = response.Write([]byte("{}"))
		}
	}))
	t.Cleanup(stub.server.Close)
	stub.serviceDID = didWebForServer(stub.server.URL)
	stub.document = testInspectDocument(stub.serviceDID)
	stub.client = testClient(t, stub.server, provider)
	session, err := stub.client.Service(stub.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	stub.session = session
	return stub
}

func (stub *serviceStub) lastHeader(name string) string {
	for index := len(stub.requests) - 1; index >= 0; index-- {
		if value := stub.requests[index].Header.Get(name); value != "" {
			return value
		}
	}
	return ""
}

// ---------------------------------------------------------------- CORE-IDP: idempotency keys

func TestIdempotencyKeyMustSurviveAsAFieldValue(t *testing.T) {
	stub := newServiceStub(t, nil)

	rejected := []string{"   ", "\t", "\tkey", "key ", "bad\rkey", "bad\nkey", "bad\x00key"}
	for _, key := range rejected {
		_, err := stub.session.Revoke(context.Background(), RevokeOptions{
			GrantType: aep.GrantTypeOAuthBearer, IdempotencyKey: key,
		})
		if err == nil {
			t.Fatalf("idempotency key %q was accepted", key)
		}
	}

	if _, err := stub.session.Revoke(context.Background(), RevokeOptions{
		GrantType: aep.GrantTypeOAuthBearer, IdempotencyKey: "caller-supplied-key",
	}); err != nil {
		t.Fatalf("a usable idempotency key was rejected: %v", err)
	}
	if sent := stub.lastHeader("Idempotency-Key"); sent != "caller-supplied-key" {
		t.Fatalf("Idempotency-Key reached the Service as %q", sent)
	}
}

func TestIdempotencyKeyProviderResultIsValidated(t *testing.T) {
	for _, key := range []string{"", "   ", " key"} {
		provider := newTestIdentityProvider(t)
		var document aep.InspectDocument
		server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			response.Header().Set("Content-Type", aep.MediaType)
			if request.URL.Path == aep.WellKnownPath {
				_ = json.NewEncoder(response).Encode(document)
				return
			}
			_, _ = response.Write([]byte("{}"))
		}))
		document = testInspectDocument(didWebForServer(server.URL))
		client, err := New(Options{
			HTTPClient:       server.Client(),
			IdentityProvider: provider,
			IdempotencyKeys:  stubIdempotencyKeys{key: key},
		})
		if err != nil {
			t.Fatal(err)
		}
		session, err := client.Service(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := session.Enroll(context.Background(), EnrollOptions{}); err == nil {
			t.Fatalf("a provider key of %q was accepted", key)
		}
		server.Close()
	}
}

type stubIdempotencyKeys struct {
	err error
	key string
}

func (keys stubIdempotencyKeys) CreateKey(context.Context, OperationKey) (string, error) {
	return keys.key, keys.err
}

func TestIdempotencyKeyProviderFailurePropagates(t *testing.T) {
	provider := newTestIdentityProvider(t)
	var document aep.InspectDocument
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", aep.MediaType)
		if request.URL.Path == aep.WellKnownPath {
			_ = json.NewEncoder(response).Encode(document)
			return
		}
		_, _ = response.Write([]byte("{}"))
	}))
	defer server.Close()
	document = testInspectDocument(didWebForServer(server.URL))
	client, err := New(Options{
		HTTPClient:       server.Client(),
		IdentityProvider: provider,
		IdempotencyKeys:  stubIdempotencyKeys{err: errors.New("no keys")},
	})
	if err != nil {
		t.Fatal(err)
	}
	session, _ := client.Service(server.URL)
	if _, err := session.Enroll(context.Background(), EnrollOptions{}); err == nil {
		t.Fatal("a failing key provider was ignored")
	}
}

func TestValidIdempotencyKey(t *testing.T) {
	for _, value := range []string{"key", "a-b_c.1", "0123456789", "k e y"} {
		if !validIdempotencyKey(value) {
			t.Fatalf("%q was rejected", value)
		}
	}
	for _, value := range []string{"", " ", "key ", " key", "a\tb", "a\x7fb", "a\x1fb"} {
		if validIdempotencyKey(value) {
			t.Fatalf("%q was accepted", value)
		}
	}
}

// ---------------------------------------------------------------- advertised grant types

func TestRevokeRequiresAnAdvertisedGrantType(t *testing.T) {
	stub := newServiceStub(t, nil)

	if _, err := stub.session.Revoke(context.Background(), RevokeOptions{
		GrantType: aep.GrantTypeBasic,
	}); !errors.Is(err, ErrNoCompatibleGrantType) {
		t.Fatalf("an unadvertised grant type was revoked: %v", err)
	}

	if _, err := stub.session.Revoke(context.Background(), RevokeOptions{
		GrantType: aep.GrantTypeOAuthBearer,
	}); err != nil {
		t.Fatalf("an advertised grant type was refused: %v", err)
	}

	// The all-grant-types form names no grant type and stays available.
	if _, err := stub.session.Revoke(context.Background(), RevokeOptions{AllGrantTypes: true}); err != nil {
		t.Fatalf("all-grant-types Revoke was refused: %v", err)
	}
}

func TestRevokeTargetedFormRequiresAdvertisedSupport(t *testing.T) {
	stub := newServiceStub(t, nil)
	stub.document.Commands.GrantTypesConfig = map[string]aep.GrantTypeConfig{
		string(aep.GrantTypeOAuthBearer): {SupportsPerCredentialRevoke: "false"},
	}

	if _, err := stub.session.Revoke(context.Background(), RevokeOptions{
		CredentialID: "cred-1", GrantType: aep.GrantTypeOAuthBearer,
	}); err == nil {
		t.Fatal("per-credential Revoke was sent without advertised support")
	}
}

// ---------------------------------------------------------------- Service DID origin binding

func TestServiceIdentityBindingComparesAuthorityNotScheme(t *testing.T) {
	inspection := func(did string, final string) Inspection {
		return Inspection{
			Document:   aep.InspectDocument{Service: aep.ServiceIdentity{DID: did}},
			FinalURL:   mustURL(t, final),
			ServiceURL: mustURL(t, final),
		}
	}

	// An HTTPS Service on a loopback host binds whether or not plaintext loopback is permitted.
	for _, allow := range []bool{false, true} {
		if err := validateServiceIdentity(
			inspection("did:web:localhost%3A8443", "https://localhost:8443/.well-known/aep"), allow,
		); err != nil {
			t.Fatalf("loopback HTTPS binding failed with allowInsecureLoopback=%v: %v", allow, err)
		}
	}

	// Plaintext binds only when it is permitted, and only on a loopback host.
	if err := validateServiceIdentity(
		inspection("did:web:localhost%3A8443", "http://localhost:8443/.well-known/aep"), false,
	); err == nil {
		t.Fatal("plaintext Inspect bound without opting in")
	}
	if err := validateServiceIdentity(
		inspection("did:web:localhost%3A8443", "http://localhost:8443/.well-known/aep"), true,
	); err != nil {
		t.Fatalf("permitted plaintext loopback did not bind: %v", err)
	}
	if err := validateServiceIdentity(
		inspection("did:web:api.example.com", "http://api.example.com/.well-known/aep"), true,
	); err == nil {
		t.Fatal("plaintext bound on a non-loopback host")
	}

	// Authority mismatches stay rejected.
	mismatches := [][2]string{
		{"did:web:other.example", "https://api.example.com/.well-known/aep"},
		{"did:web:api.example.com%3A8443", "https://api.example.com/.well-known/aep"},
		{"did:web:api.example.com", "https://api.example.com:8443/.well-known/aep"},
		{"did:key:z6Mk", "https://api.example.com/.well-known/aep"},
		{"did:web:%ZZ", "https://api.example.com/.well-known/aep"},
	}
	for _, testCase := range mismatches {
		if err := validateServiceIdentity(inspection(testCase[0], testCase[1]), false); err == nil {
			t.Fatalf("DID %q bound to %q", testCase[0], testCase[1])
		}
	}

	// A default port on one side matches an implicit default on the other.
	if err := validateServiceIdentity(
		inspection("did:web:api.example.com", "https://api.example.com:443/.well-known/aep"), false,
	); err != nil {
		t.Fatalf("an explicit default port did not bind: %v", err)
	}
}

func TestSameAuthorityAndSchemeHelpers(t *testing.T) {
	if !sameAuthority(mustURL(t, "https://EXAMPLE.com/a"), mustURL(t, "https://example.com/b")) {
		t.Fatal("host comparison is case sensitive")
	}
	if sameAuthority(mustURL(t, "https://example.com:1/a"), mustURL(t, "https://example.com:2/b")) {
		t.Fatal("differing ports were treated as one authority")
	}
	if !acceptableInspectScheme(mustURL(t, "HTTPS://example.com"), false) {
		t.Fatal("an uppercase HTTPS scheme was refused")
	}
	if acceptableInspectScheme(mustURL(t, "ftp://example.com"), true) {
		t.Fatal("an unrelated scheme was accepted")
	}
}

// ---------------------------------------------------------------- command surface

func TestCommandsRequireAdvertisedSupport(t *testing.T) {
	stub := newServiceStub(t, nil)
	stub.document.Commands.Supported = []aep.Command{aep.CommandInspect}

	if _, err := stub.session.Enroll(context.Background(), EnrollOptions{}); err == nil {
		t.Fatal("Enroll was invoked without advertisement")
	}
	if _, err := stub.session.Status(context.Background()); err == nil {
		t.Fatal("Status was invoked without advertisement")
	}
	if _, err := stub.session.Revoke(context.Background(), RevokeOptions{AllGrantTypes: true}); err == nil {
		t.Fatal("Revoke was invoked without advertisement")
	}
	if _, err := stub.session.Grant(context.Background(), GrantOptions{}); err == nil {
		t.Fatal("Grant was invoked without advertisement")
	}
}

func TestGrantUsesAuthoritativeEnrollmentWithoutStatus(t *testing.T) {
	stub := newServiceStub(t, nil)
	if _, err := stub.session.Enroll(context.Background(), EnrollOptions{}); err != nil {
		t.Fatal(err)
	}
	stub.document.Commands.Supported = []aep.Command{
		aep.CommandInspect, aep.CommandEnroll, aep.CommandGrant, aep.CommandRevoke,
	}
	stub.client.inspectCache = NewMemoryInspectCache()

	if _, err := stub.session.Grant(context.Background(), GrantOptions{}); err != nil {
		t.Fatalf("Grant rejected authoritative active enrollment: %v", err)
	}
	for _, request := range stub.requests {
		if request.URL.Path == "/aep/status" {
			t.Fatal("Grant made an unnecessary Status request")
		}
	}
	other, err := stub.client.Service(stub.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Grant(context.Background(), GrantOptions{}); err == nil {
		t.Fatal("Grant proceeded without authoritative enrollment or Status")
	}
}

func TestGrantRefusesInactiveEnrollment(t *testing.T) {
	stub := newServiceStub(t, func(response http.ResponseWriter, request *http.Request) bool {
		if request.URL.Path != "/aep/status" {
			return false
		}
		response.Header().Set("Content-Type", aep.MediaType)
		_, _ = response.Write([]byte(`{"since":"2026-01-01T00:00:00Z","status":"pending"}`))
		return true
	})
	if _, err := stub.session.Enroll(context.Background(), EnrollOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := stub.session.Status(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, err := stub.session.Grant(context.Background(), GrantOptions{GrantType: aep.GrantTypeOAuthBearer})
	var commandErr *CommandError
	if !errors.As(err, &commandErr) || commandErr.Status != http.StatusUnauthorized {
		t.Fatalf("Grant proceeded on a pending enrollment: %v", err)
	}
}

func TestRevokeRejectsContradictorySelectors(t *testing.T) {
	stub := newServiceStub(t, nil)
	contradictions := []RevokeOptions{
		{AllGrantTypes: true, GrantType: aep.GrantTypeOAuthBearer},
		{AllGrantTypes: true, CredentialID: "cred-1"},
		{},
		{CredentialID: "cred-1"},
	}
	for _, options := range contradictions {
		if _, err := stub.session.Revoke(context.Background(), options); err == nil {
			t.Fatalf("%#v was accepted", options)
		}
	}
}

func TestCommandRejectsUnexpectedMediaType(t *testing.T) {
	stub := newServiceStub(t, func(response http.ResponseWriter, request *http.Request) bool {
		if request.URL.Path != "/aep/enroll" {
			return false
		}
		response.Header().Set("Content-Type", "text/plain")
		_, _ = response.Write([]byte("{}"))
		return true
	})
	if _, err := stub.session.Enroll(context.Background(), EnrollOptions{}); err == nil ||
		!strings.Contains(err.Error(), "media type") {
		t.Fatalf("an unexpected command media type was accepted: %v", err)
	}
}

func TestCommandRejectsOversizedResponse(t *testing.T) {
	stub := newServiceStub(t, func(response http.ResponseWriter, request *http.Request) bool {
		if request.URL.Path != "/aep/enroll" {
			return false
		}
		response.Header().Set("Content-Type", aep.MediaType)
		_, _ = response.Write([]byte(`{"padding":"` + strings.Repeat("a", 2048) + `","status":"active"}`))
		return true
	})
	stub.client.maximumResponseBytes = 64
	if _, err := stub.session.Enroll(context.Background(), EnrollOptions{}); err == nil {
		t.Fatal("an oversized command response was accepted")
	}
}

func TestEnrollPreservesServiceMissingClaimsError(t *testing.T) {
	stub := newServiceStub(t, func(response http.ResponseWriter, request *http.Request) bool {
		if request.URL.Path != "/aep/enroll" {
			return false
		}
		var body aep.EnrollRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body.Claims != nil && body.Claims.ContactEmail != nil {
			response.Header().Set("Content-Type", aep.MediaType)
			_, _ = response.Write([]byte(`{"status":"active"}`))
			return true
		}
		response.Header().Set("Content-Type", aep.ProblemMediaType)
		response.WriteHeader(422)
		_, _ = response.Write([]byte(`{"code":"requirements_unmet","status":422,"title":"Requirements unmet","type":"urn:aep:error:requirements_unmet","requirements_pending":["contact.email"]}`))
		return true
	})
	stub.document.Claims = &aep.InspectClaims{Required: []aep.ClaimName{aep.ClaimContactEmail}}

	_, err := stub.session.Enroll(context.Background(), EnrollOptions{})
	var claimErr *CommandError
	if !errors.As(err, &claimErr) || claimErr.Problem == nil || len(claimErr.Problem.RequirementsPending) != 1 || claimErr.Problem.RequirementsPending[0] != "contact.email" {
		t.Fatalf("missing required claims were not reported: %v", err)
	}

	email := "agent@example.com"
	if _, err := stub.session.Enroll(context.Background(), EnrollOptions{
		Claims: &aep.ClaimValues{ContactEmail: &email},
	}); err != nil {
		t.Fatalf("a satisfied claim requirement was refused: %v", err)
	}
}

func TestAssertionOperationMapping(t *testing.T) {
	expected := map[aep.Command]aep.AssertionOperation{
		aep.CommandEnroll:  aep.AssertionEnroll,
		aep.CommandGrant:   aep.AssertionGrant,
		aep.CommandRevoke:  aep.AssertionRevoke,
		aep.CommandStatus:  aep.AssertionStatus,
		aep.CommandInspect: "",
	}
	for command, operation := range expected {
		if assertionOperation(command) != operation {
			t.Fatalf("%s mapped to %q", command, assertionOperation(command))
		}
	}
}

// ---------------------------------------------------------------- identity and signing

func TestSignAssertionRejectsUnusableIdentities(t *testing.T) {
	stub := newServiceStub(t, nil)
	inspection, err := stub.session.Inspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	valid := ServiceIdentity{
		AgentDID:          "did:web:agent.example:agents:1",
		IdentityMethod:    aep.IdentityMethodDIDWeb,
		ServiceDID:        stub.serviceDID,
		SigningAlgorithms: []aep.SigningAlgorithm{aep.SigningAlgorithmEdDSA},
	}

	cases := map[string]func(*ServiceIdentity){
		"non-DID agent":       func(i *ServiceIdentity) { i.AgentDID = "agent.example" },
		"missing method":      func(i *ServiceIdentity) { i.IdentityMethod = "" },
		"foreign service":     func(i *ServiceIdentity) { i.ServiceDID = "did:web:other.example" },
		"no algorithms":       func(i *ServiceIdentity) { i.SigningAlgorithms = nil },
		"unsupported method":  func(i *ServiceIdentity) { i.IdentityMethod = "did:key" },
		"mismatched DID form": func(i *ServiceIdentity) { i.AgentDID = "did:key:z6Mk" },
		"foreign algorithm": func(i *ServiceIdentity) {
			i.SigningAlgorithms = []aep.SigningAlgorithm{"RS256"}
		},
	}
	for name, mutate := range cases {
		identity := valid
		identity.SigningAlgorithms = append([]aep.SigningAlgorithm(nil), valid.SigningAlgorithms...)
		mutate(&identity)
		if _, err := stub.client.signAssertion(
			context.Background(), inspection, identity, func(context.Context, aep.ClientAssertionClaims, []aep.SigningAlgorithm) (string, error) {
				return "a.b.c", nil
			}, aep.AssertionEnroll, nil,
		); err == nil {
			t.Fatalf("%s was signed", name)
		}
	}

	if _, err := stub.client.signAssertion(
		context.Background(), inspection, valid, nil, aep.AssertionEnroll, nil,
	); err == nil {
		t.Fatal("a nil signer produced an assertion")
	}
	if _, err := stub.client.signAssertion(
		context.Background(), inspection, valid,
		func(context.Context, aep.ClientAssertionClaims, []aep.SigningAlgorithm) (string, error) {
			return "", nil
		},
		aep.AssertionEnroll, nil,
	); err == nil {
		t.Fatal("an empty assertion was accepted")
	}
	if _, err := stub.client.signAssertion(
		context.Background(), inspection, valid,
		func(context.Context, aep.ClientAssertionClaims, []aep.SigningAlgorithm) (string, error) {
			return "", errors.New("signer failure")
		},
		aep.AssertionEnroll, nil,
	); err == nil {
		t.Fatal("a signer failure was ignored")
	}
}

func TestIntersectAlgorithmsPreservesServiceOrder(t *testing.T) {
	result := intersectAlgorithms(
		[]aep.SigningAlgorithm{aep.SigningAlgorithmEdDSA, aep.SigningAlgorithmES256},
		[]aep.SigningAlgorithm{aep.SigningAlgorithmES256, aep.SigningAlgorithmEdDSA},
	)
	if len(result) != 2 || result[0] != aep.SigningAlgorithmES256 {
		t.Fatalf("unexpected intersection: %v", result)
	}
	if len(intersectAlgorithms(nil, []aep.SigningAlgorithm{aep.SigningAlgorithmEdDSA})) != 0 {
		t.Fatal("an empty identity set produced an intersection")
	}
}

// ---------------------------------------------------------------- credentials

func TestCredentialHeadersRejectMalformedRecords(t *testing.T) {
	record := func(grantType aep.GrantType, payload string) CredentialRecord {
		return CredentialRecord{
			CredentialID: "cred-1",
			ExpiresAt:    time.Now().Add(time.Hour),
			GrantType:    grantType,
			Payload:      json.RawMessage(payload),
			ServiceDID:   "did:web:api.example.com",
		}
	}

	if _, err := credentialHeaders(record(aep.GrantTypeOAuthBearer, "{"), aep.ProtectedResourceStandard); err == nil {
		t.Fatal("a malformed payload produced headers")
	}
	if _, err := credentialHeaders(
		record(aep.GrantTypeOAuthBearer, `{"access_token":"t","credential_id":"other","expires_at":"2999-01-01T00:00:00Z","scopes":[],"token_type":"Bearer"}`),
		aep.ProtectedResourceStandard,
	); err == nil {
		t.Fatal("a payload naming another credential produced headers")
	}
	if _, err := credentialHeaders(
		record(aep.GrantTypeOAuthBearer, `{"access_token":"t","credential_id":"cred-1","expires_at":"2999-01-01T00:00:00Z","scopes":[],"token_type":"Bearer"}`),
		"Made-Up",
	); err == nil {
		t.Fatal("an unsupported carrier produced headers")
	}

	headers, err := credentialHeaders(
		record(aep.GrantTypeBasic, `{"credential_id":"cred-1","expires_at":"2999-01-01T00:00:00Z","password":"p","scopes":[],"username":"u"}`),
		aep.ProtectedResourceDedicated,
	)
	if err != nil || !strings.HasPrefix(headers.Get(aep.AuthorizationHeader), "Basic ") {
		t.Fatalf("unexpected Basic headers: %#v, %v", headers, err)
	}

	headers, err = credentialHeaders(
		record(aep.GrantTypeAPIKey, `{"api_key":"key","credential_id":"cred-1","expires_at":"2999-01-01T00:00:00Z","header":"x-api-key","scopes":[]}`),
		aep.ProtectedResourceStandard,
	)
	if err != nil || headers.Get("X-Api-Key") != "key" {
		t.Fatalf("unexpected API-key headers: %#v, %v", headers, err)
	}
}

func TestValidateStoredCredentialRejectsDrift(t *testing.T) {
	const serviceDID = "did:web:api.example.com"
	payload := `{"access_token":"t","credential_id":"cred-1","expires_at":"2999-01-01T00:00:00Z","scopes":[],"token_type":"Bearer"}`
	expiry, err := time.Parse(time.RFC3339, "2999-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	valid := CredentialRecord{
		CredentialID: "cred-1", ExpiresAt: expiry, GrantType: aep.GrantTypeOAuthBearer,
		Payload: json.RawMessage(payload), ServiceDID: serviceDID,
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := validateStoredCredential(valid, serviceDID, now); err != nil {
		t.Fatalf("a consistent record was rejected: %v", err)
	}

	cases := map[string]func(*CredentialRecord){
		"missing id":      func(r *CredentialRecord) { r.CredentialID = "" },
		"foreign service": func(r *CredentialRecord) { r.ServiceDID = "did:web:other.example" },
		"missing type":    func(r *CredentialRecord) { r.GrantType = "" },
		"zero expiry":     func(r *CredentialRecord) { r.ExpiresAt = time.Time{} },
		"expired":         func(r *CredentialRecord) { r.ExpiresAt = now.Add(-time.Hour) },
		"malformed body":  func(r *CredentialRecord) { r.Payload = json.RawMessage("{") },
		"drifted expiry":  func(r *CredentialRecord) { r.ExpiresAt = now.Add(time.Hour) },
	}
	for name, mutate := range cases {
		record := valid
		mutate(&record)
		if err := validateStoredCredential(record, serviceDID, now); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

func TestForgetCredentialRequiresAnIdentifier(t *testing.T) {
	stub := newServiceStub(t, nil)
	if err := stub.session.ForgetCredential(context.Background(), ""); err == nil {
		t.Fatal("an empty credential ID was accepted")
	}
	if err := stub.session.ForgetCredential(context.Background(), "cred-1"); err != nil {
		t.Fatalf("forgetting an absent credential failed: %v", err)
	}
}

// ---------------------------------------------------------------- protected-resource auth

func TestAuthenticationHeadersValidateTheResource(t *testing.T) {
	stub := newServiceStub(t, nil)
	origin := stub.server.URL

	rejected := map[string]*url.URL{
		"absent":       nil,
		"userinfo":     mustURL(t, "https://user@api.example.com/orders"),
		"fragment":     mustURL(t, strings.Replace(origin, "https://", "https://", 1)+"/orders#x"),
		"other origin": mustURL(t, "https://other.example/orders"),
		"plaintext":    mustURL(t, strings.Replace(origin, "https://", "http://", 1)+"/orders"),
	}
	for name, resource := range rejected {
		options := AuthenticationOptions{ClientAssertionOnly: true}
		if resource != nil {
			options.Resource = resource
		}
		if _, err := stub.session.AuthenticationHeaders(context.Background(), options); err == nil {
			t.Fatalf("resource %s was accepted", name)
		}
	}

	if _, err := stub.session.AuthenticationHeaders(context.Background(), AuthenticationOptions{
		ClientAssertionOnly: true, CredentialID: "cred-1", Resource: mustURL(t, origin+"/orders"),
	}); err == nil {
		t.Fatal("credential selection combined with client-assertion-only")
	}

	if _, err := stub.session.AuthenticationHeaders(context.Background(), AuthenticationOptions{
		Carrier: "Made-Up", Resource: mustURL(t, origin+"/orders"),
	}); err == nil {
		t.Fatal("an unsupported carrier was accepted")
	}

	if _, err := stub.session.AuthenticationHeaders(context.Background(), AuthenticationOptions{
		GrantType: aep.GrantTypeBasic, Resource: mustURL(t, origin+"/orders"),
	}); !errors.Is(err, ErrNoAuthenticationMethod) {
		t.Fatalf("an unadvertised grant type was selected: %v", err)
	}

	if _, err := stub.session.AuthenticationHeaders(context.Background(), AuthenticationOptions{
		CredentialID: "absent", Resource: mustURL(t, origin+"/orders"),
	}); err == nil {
		t.Fatal("an absent credential was presented")
	}
}

// ---------------------------------------------------------------- Inspect helpers

func TestInspectCacheFreshness(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	fresh := InspectCacheEntry{CachedAt: now}
	if !inspectCacheFresh(fresh, now.Add(time.Second)) {
		t.Fatal("a default-freshness entry expired immediately")
	}
	if inspectCacheFresh(fresh, now.Add(aep.DefaultInspectFreshness+time.Second)) {
		t.Fatal("a stale entry was reported fresh")
	}
	for _, control := range []string{"no-cache", "no-store", "max-age=abc", "max-age=-1", "max-age=99999999999999999999"} {
		entry := InspectCacheEntry{CacheControl: control, CachedAt: now}
		if inspectCacheFresh(entry, now.Add(time.Second)) {
			t.Fatalf("Cache-Control %q was treated as fresh", control)
		}
	}
	entry := InspectCacheEntry{CacheControl: "max-age=60", CachedAt: now}
	if !inspectCacheFresh(entry, now.Add(30*time.Second)) || inspectCacheFresh(entry, now.Add(90*time.Second)) {
		t.Fatal("max-age was not honoured")
	}
}

func TestCacheDirectiveParsing(t *testing.T) {
	if value, found := cacheDirectiveValue(`public, max-age="120"`, "max-age"); !found || value != "120" {
		t.Fatalf("quoted directive value not parsed: %q, %v", value, found)
	}
	if !cacheDirective("No-Store", "no-store") {
		t.Fatal("directive matching is case sensitive")
	}
	if cacheDirective("public", "no-store") {
		t.Fatal("an absent directive was reported")
	}
}

func TestMergeCacheHeadersOnlyOverwritesPresentValues(t *testing.T) {
	entry := InspectCacheEntry{CacheControl: "max-age=60", ETag: `"a"`, LastModified: "then"}
	mergeCacheHeaders(&entry, http.Header{})
	if entry.CacheControl != "max-age=60" || entry.ETag != `"a"` || entry.LastModified != "then" {
		t.Fatalf("absent headers cleared cached values: %#v", entry)
	}
	mergeCacheHeaders(&entry, http.Header{
		"Cache-Control": []string{"max-age=1"}, "Etag": []string{`"b"`}, "Last-Modified": []string{"now"},
	})
	if entry.CacheControl != "max-age=1" || entry.ETag != `"b"` || entry.LastModified != "now" {
		t.Fatalf("present headers were not merged: %#v", entry)
	}
}

func TestMediaTypeAndBoundedRead(t *testing.T) {
	if !mediaTypeMatches("application/aep+json; charset=utf-8", aep.MediaType) {
		t.Fatal("a parameterised media type did not match")
	}
	if mediaTypeMatches("", aep.MediaType) || mediaTypeMatches("!!", aep.MediaType) {
		t.Fatal("an unparseable media type matched")
	}
	if _, err := readBounded(strings.NewReader("abcdef"), 3); !errors.Is(err, errResponseTooLarge) {
		t.Fatalf("an oversized read was accepted: %v", err)
	}
	data, err := readBounded(strings.NewReader("abc"), 3)
	if err != nil || string(data) != "abc" {
		t.Fatalf("a bounded read failed: %q, %v", data, err)
	}
}

func TestEffectivePortDefaults(t *testing.T) {
	cases := map[string]string{
		"https://example.com":      "443",
		"http://example.com":       "80",
		"https://example.com:8443": "8443",
		"ftp://example.com":        "",
	}
	for value, expected := range cases {
		if port := effectivePort(mustURL(t, value)); port != expected {
			t.Fatalf("%s produced port %q, want %q", value, port, expected)
		}
	}
}

func TestValidInspectTarget(t *testing.T) {
	if !validInspectTarget(mustURL(t, "https://example.com/a")) {
		t.Fatal("a plain target was rejected")
	}
	for _, value := range []string{"https://user@example.com/a", "https://example.com/a#x", "mailto:a@example.com"} {
		if validInspectTarget(mustURL(t, value)) {
			t.Fatalf("%s was accepted as an Inspect target", value)
		}
	}
}

func TestIsRedirectStatuses(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		if !isRedirect(status) {
			t.Fatalf("%d was not treated as a redirect", status)
		}
	}
	for _, status := range []int{200, 304, 400, 500} {
		if isRedirect(status) {
			t.Fatalf("%d was treated as a redirect", status)
		}
	}
}

// ---------------------------------------------------------------- client construction

func TestServiceReferenceResolution(t *testing.T) {
	accepted := map[string]string{
		"https://api.example.com":      "https://api.example.com/",
		"api.example.com":              "https://api.example.com/",
		"https://api.example.com:8443": "https://api.example.com:8443/",
		"did:web:api.example.com":      "https://api.example.com/",
	}
	for reference, expected := range accepted {
		resolved, err := resolveServiceReference(reference, false)
		if err != nil || resolved.String() != expected {
			t.Fatalf("%q resolved to %v (%v), want %s", reference, resolved, err, expected)
		}
	}

	rejected := []string{
		"", "   ", "http://api.example.com", "https://user@api.example.com",
		"mailto:someone@example.com", "did:web:%ZZ", "https://",
	}
	for _, reference := range rejected {
		if resolved, err := resolveServiceReference(reference, false); err == nil {
			t.Fatalf("%q resolved to %s", reference, resolved)
		}
	}

	loopback, err := resolveServiceReference("http://127.0.0.1:8080", true)
	if err != nil || loopback.String() != "http://127.0.0.1:8080/" {
		t.Fatalf("permitted loopback was refused: %v, %v", loopback, err)
	}
	if _, err := resolveServiceReference("http://api.example.com", true); err == nil {
		t.Fatal("plaintext was accepted on a non-loopback host")
	}
}

func TestNewRejectsUnusableOptions(t *testing.T) {
	provider := newTestIdentityProvider(t)
	cases := map[string]Options{
		"missing provider":    {},
		"sub-second lifetime": {IdentityProvider: provider, AssertionLifetime: 500 * time.Millisecond},
		"excessive lifetime":  {IdentityProvider: provider, AssertionLifetime: 301 * time.Second},
		"fractional lifetime": {IdentityProvider: provider, AssertionLifetime: 1500 * time.Millisecond},
		"negative bytes":      {IdentityProvider: provider, MaximumResponseBytes: -1},
		"negative timeout":    {IdentityProvider: provider, RequestTimeout: -time.Second},
	}
	for name, options := range cases {
		if _, err := New(options); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	if _, err := New(Options{IdentityProvider: provider, AssertionLifetime: aep.MaxAssertionLifetime}); err != nil {
		t.Fatalf("the maximum lifetime was refused: %v", err)
	}
}

func TestRandomIdempotencyKeyProviderProducesUsableKeys(t *testing.T) {
	key, err := RandomIdempotencyKeyProvider{}.CreateKey(context.Background(), OperationKey{})
	if err != nil || !validIdempotencyKey(key) {
		t.Fatalf("unusable generated key %q: %v", key, err)
	}
}

func TestMemoryIdentityStoreClonesRecords(t *testing.T) {
	store := NewMemoryIdentityStore()
	identity := ServiceIdentity{
		AgentDID:          "did:web:agent.example",
		Metadata:          map[string]string{"a": "1"},
		ServiceDID:        "did:web:api.example.com",
		SigningAlgorithms: []aep.SigningAlgorithm{aep.SigningAlgorithmEdDSA},
	}
	if err := store.SaveIdentity(context.Background(), identity); err != nil {
		t.Fatal(err)
	}
	identity.Metadata["a"] = "2"
	identity.SigningAlgorithms[0] = aep.SigningAlgorithmES256

	found, err := store.FindIdentity(context.Background(), "did:web:api.example.com")
	if err != nil || found == nil {
		t.Fatalf("stored identity was not found: %v", err)
	}
	if found.Metadata["a"] != "1" || found.SigningAlgorithms[0] != aep.SigningAlgorithmEdDSA {
		t.Fatalf("the store shared mutable state: %#v", found)
	}

	missing, err := store.FindIdentity(context.Background(), "did:web:absent.example")
	if err != nil || missing != nil {
		t.Fatalf("an absent identity was returned: %#v, %v", missing, err)
	}
}
