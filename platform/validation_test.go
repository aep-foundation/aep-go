package platform

import (
	"encoding/json"
	"net/http"
	"testing"

	aep "github.com/aep-foundation/aep-go"
)

func TestDiscoveryAndDIDValidation(t *testing.T) {
	valid, _, _ := testOptions(t, false)
	cases := []Options{
		func() Options { copy := valid; copy.Discovery.EndpointBase = "https://platform.example"; return copy }(),
		func() Options { copy := valid; copy.Discovery.LifecycleEndpoint = "relative"; return copy }(),
		func() Options { copy := valid; copy.Discovery.PlatformName = ""; return copy }(),
		func() Options { copy := valid; copy.Discovery.PlatformDID = "not-a-did"; return copy }(),
		func() Options {
			copy := valid
			copy.HostedVerification = false
			copy.Discovery.HostedVerificationEndpoint = "/verify"
			return copy
		}(),
		func() Options {
			copy := valid
			copy.DIDURLTemplate = "http://platform.example/{agent_did_id}"
			return copy
		}(),
	}
	for index, options := range cases {
		if _, err := New(options); err == nil {
			t.Fatalf("invalid discovery configuration %d was accepted", index)
		}
	}

	record := identityRecord("identity", "agent", "owner", "did:web:service", testClock)
	method := DIDVerificationMethod{Controller: record.AgentDID, ID: record.KeyID, PublicKeyJWK: json.RawMessage(`{"kty":"EC"}`), Type: "JsonWebKey2020"}
	if _, err := CreateDIDDocument(record, method); err != nil {
		t.Fatal(err)
	}
	invalidRecord := record
	invalidRecord.Principal = ""
	if _, err := CreateDIDDocument(invalidRecord, method); err == nil {
		t.Fatal("invalid identity record produced a DID document")
	}
	invalidMethods := []DIDVerificationMethod{
		{Controller: record.AgentDID, ID: "wrong", PublicKeyJWK: method.PublicKeyJWK, Type: method.Type},
		{Controller: record.AgentDID, ID: record.KeyID, PublicKeyJWK: json.RawMessage(`[]`), Type: method.Type},
	}
	for _, invalid := range invalidMethods {
		if _, err := CreateDIDDocument(record, invalid); err == nil {
			t.Fatalf("invalid verification method was accepted: %#v", invalid)
		}
	}
	if _, err := renderDIDURL("https://platform.example/{agent_did_id}/{agent_did_id}", "agent"); err == nil {
		t.Fatal("multiple DID URL placeholders were accepted")
	}
	if err := validateEndpointPath("test", "/path?query=true"); err == nil {
		t.Fatal("endpoint query was accepted")
	}
}

func TestRequestAndResultValidation(t *testing.T) {
	for _, value := range []string{
		"did:web:example.com",
		"did:example:abc%20def",
		"did:example:a_b.c-d!$&'()*+,;=",
	} {
		if !isDID(value) {
			t.Fatalf("valid DID was rejected: %q", value)
		}
	}
	for _, value := range []string{"", "web:example", "did::example", "did:WEB:example", "did:web:", "did:web:bad value", "did:web:bad%2Z"} {
		if isDID(value) {
			t.Fatalf("invalid DID was accepted: %q", value)
		}
	}

	platform, _, _ := newTestPlatform(t, false)
	if _, err := platform.validateSignRequest(SignRequest{JWTID: "id", LifetimeSeconds: "not-a-number", Operation: aep.AssertionEnroll, ServiceDID: testServiceDID}); err == nil {
		t.Fatal("invalid lifetime was accepted")
	}
	verificationCases := []VerificationRequest{
		{},
		{ClientAssertion: "jwt", Operation: aep.AssertionAuthenticate, ServiceDID: testServiceDID},
		{ClientAssertion: "jwt", Operation: aep.AssertionEnroll, Resource: "https://example.com", ServiceDID: testServiceDID},
	}
	for _, request := range verificationCases {
		if err := validateVerificationRequest(request); err == nil {
			t.Fatalf("invalid verification request was accepted: %#v", request)
		}
	}

	validPending := Result[SignResponse]{Body: SignResponse{RetryAfterSeconds: "5", Status: SignPending}, ContentType: aep.MediaType, Status: http.StatusAccepted}
	identity := identityRecord("identity", "agent", "owner", testServiceDID, testClock)
	request := SignRequest{JWTID: "id", Operation: aep.AssertionEnroll, ServiceDID: testServiceDID}
	if err := validateSignResult(validPending, identity, request); err != nil {
		t.Fatal(err)
	}
	invalidResults := []Result[SignResponse]{
		{Body: SignResponse{RetryAfterSeconds: "0", Status: SignPending}, Status: http.StatusAccepted},
		{Body: SignResponse{Status: SignCompleted}, Status: http.StatusOK},
	}
	for _, result := range invalidResults {
		if err := validateSignResult(result, identity, request); err == nil {
			t.Fatalf("invalid sign result was accepted: %#v", result)
		}
	}
	problem := problemResult[SignResponse](http.StatusBadRequest, aep.ErrorInvalidRequest, "invalid")
	if err := validateSignResult(problem, identity, request); err != nil {
		t.Fatal(err)
	}

	stored, err := storeResult(successResult(http.StatusOK, AgentIdentity{AgentDID: "did:web:agent"}, http.Header{"X-Test": []string{"value"}}))
	if err != nil {
		t.Fatal(err)
	}
	restored, err := restoreResult[AgentIdentity](stored)
	if err != nil || restored.Body.AgentDID != "did:web:agent" || restored.Headers.Get("X-Test") != "value" {
		t.Fatalf("stored response was not restored: %#v, %v", restored, err)
	}
	if _, err := restoreResult[AgentIdentity](StoredResponse{Body: []byte(`{`), ContentType: aep.MediaType}); err == nil {
		t.Fatal("invalid stored body was accepted")
	}
	if _, err := restoreResult[AgentIdentity](StoredResponse{Body: []byte(`{`), ContentType: aep.ProblemMediaType}); err == nil {
		t.Fatal("invalid stored problem was accepted")
	}

	if _, err := randomIdentifier(); err != nil {
		t.Fatal(err)
	}
	if lifecycleErrorCode(ManagedAgentTerminated) != aep.ErrorIdentityTerminated || lifecycleErrorCode(ManagedAgentActive) != aep.ErrorIdentityUnavailable {
		t.Fatal("lifecycle error mapping is invalid")
	}
}

func TestDefaultListLimit(t *testing.T) {
	platform, _, _ := newTestPlatform(t, false)
	result, err := platform.List(t.Context(), IdentityListQuery{}, RequestContext{Principal: testPrincipal})
	if err != nil || result.Status != 200 || result.Body.Count != "0" {
		t.Fatalf("default list limit failed: %#v, %v", result, err)
	}
	invalid, err := platform.List(t.Context(), IdentityListQuery{Limit: maximumListLimit + 1}, RequestContext{Principal: testPrincipal})
	if err != nil || invalid.Status != 400 {
		t.Fatalf("oversized list limit was accepted: %#v, %v", invalid, err)
	}
	invalid, err = platform.List(t.Context(), IdentityListQuery{ServiceDID: "not-a-did"}, RequestContext{Principal: testPrincipal})
	if err != nil || invalid.Status != 400 {
		t.Fatalf("invalid Service DID filter was accepted: %#v, %v", invalid, err)
	}
}
