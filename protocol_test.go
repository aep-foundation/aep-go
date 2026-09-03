package aep

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestProtocolMessages(t *testing.T) {
	enroll, err := ParseEnrollRequest([]byte(`{"agent_did":"did:web:agent.example.com:agents:123","claims":{"contact.email":"ops@example.com"},"idempotency_key":"key-1"}`))
	if err != nil || enroll.Claims == nil || enroll.AgentDID == "" {
		t.Fatalf("unexpected Enroll parse: %#v, %v", enroll, err)
	}
	if _, err := ParseGrantRequest([]byte(`{"grant_type":"oauth-bearer","requested_scopes":["read"]}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRevokeRequest([]byte(`{"all_grant_types":"true"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseEnrollRequest([]byte(`{"agent_did":"did:web:agent.example.com:agents:123"}`)); err != nil {
		t.Fatalf("optional Enroll body idempotency key was rejected: %v", err)
	}
	if _, err := ParseEnrollRequest([]byte(`{"agent_did":"did:web:agent.example.com:agents:123","idempotency_key":""}`)); err == nil {
		t.Fatal("empty Enroll body idempotency key was accepted")
	}
	if _, err := ParseRevokeRequest([]byte(`{"credential_id":"credential-1","grant_type":"oauth-bearer"}`)); err != nil {
		t.Fatalf("targeted Revoke was rejected: %v", err)
	}
	if _, err := ParseRevokeRequest([]byte(`{"credential_id":"credential-1"}`)); err == nil {
		t.Fatal("credential-only Revoke was accepted")
	}
	if _, err := ParseRevokeRequest([]byte(`{"all_grant_types":"true","grant_type":"oauth-bearer"}`)); err == nil {
		t.Fatal("conflicting Revoke selectors were accepted")
	}
	if _, err := ParseRevokeRequest([]byte(`{"credential_id":"","grant_type":"oauth-bearer"}`)); err == nil {
		t.Fatal("empty targeted Revoke credential ID was accepted")
	}
	if _, err := ParseRevokeResponse([]byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRevokeResponse([]byte(`{"unexpected":true}`)); err == nil {
		t.Fatal("expected non-empty Revoke response to fail")
	}
}

func TestEnrollAndStatusResponses(t *testing.T) {
	enroll, err := ParseEnrollResponse([]byte(`{"status":"pending","owner_action_required":"false","verification_pending":["email"]}`))
	if err != nil || enroll.Status != AgentPending || enroll.OwnerActionRequired == nil {
		t.Fatalf("unexpected Enroll response: %#v, %v", enroll, err)
	}
	for _, lifecycle := range []AgentStatus{AgentActive, AgentPending, AgentRejected, AgentSuspended, AgentTerminated, AgentUnavailable} {
		response, parseErr := ParseEnrollResponse([]byte(`{"status":"` + string(lifecycle) + `"}`))
		if parseErr != nil || response.Status != lifecycle {
			t.Fatalf("Enroll did not accept %s: %#v, %v", lifecycle, response, parseErr)
		}
	}
	for name, body := range map[string]string{
		"empty":        `{}`,
		"empty-status": `{"status":""}`,
		"unknown":      `{"status":"unknown"}`,
		"wrong-type":   `{"status":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseEnrollResponse([]byte(body)); err == nil {
				t.Fatal("Enroll accepted an invalid Agent status")
			}
		})
	}
	status, err := ParseStatusResponse([]byte(`{"status":"active","since":"2026-08-29T12:00:00Z"}`))
	if err != nil || status.Status != AgentActive {
		t.Fatalf("unexpected Status response: %#v, %v", status, err)
	}
	if _, err := ParseStatusResponse([]byte(`{"status":"pending","requirements_pending":["email","email"]}`)); err == nil {
		t.Fatal("expected duplicate pending requirements to fail")
	}
}

func TestCoreMetadataModels(t *testing.T) {
	hash := "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	metadata, err := ParseIdempotencyMetadata([]byte(`{"idempotency_key":"key-1","first_body_hash":"` + hash + `","future":true}`))
	if err != nil || metadata.FirstBodyHash == nil || metadata.Additional["future"] == nil {
		t.Fatalf("unexpected Idempotency metadata: %#v, %v", metadata, err)
	}
	if _, err := ParseIdempotencyMetadata([]byte(`{"idempotency_key":"key-1","first_body_hash":"SHA256:bad"}`)); err == nil {
		t.Fatal("expected invalid body hash to fail")
	}
	scheme, err := ParseOpenAPIAEPSecurityScheme([]byte(`{"x-aep-authentication-method":"oauth-bearer","future":true}`))
	if err != nil || scheme.AuthenticationMethod != "oauth-bearer" || scheme.Additional["future"] == nil {
		t.Fatalf("unexpected OpenAPI extension: %#v, %v", scheme, err)
	}
}

func TestCanonicalOwnerActionSerialization(t *testing.T) {
	falseValue := "false"
	data, err := json.Marshal(EnrollResponse{Status: AgentPending, OwnerActionRequired: &falseValue})
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"status":"pending"}` {
		t.Fatalf("unexpected canonical response: %s", data)
	}
	trueValue := "true"
	data, err = json.Marshal(NewProblemDetails(ErrorRequirementsUnmet, "Requirements unmet", 409))
	if err != nil {
		t.Fatal(err)
	}
	var problem ProblemDetails
	if err := json.Unmarshal(data, &problem); err != nil {
		t.Fatal(err)
	}
	problem.OwnerActionRequired = &trueValue
	data, err = json.Marshal(problem)
	if err != nil || !json.Valid(data) {
		t.Fatalf("invalid Problem Details: %s, %v", data, err)
	}
}

func TestGrantResponses(t *testing.T) {
	response, err := ParseBuiltInGrantResponse(GrantTypeOAuthBearer, []byte(`{
		"access_token":"token",
		"credential_id":"credential-1",
		"expires_at":"2027-01-01T00:00:00Z",
		"scopes":null,
		"token_type":"Bearer"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if response.GrantType() != GrantTypeOAuthBearer {
		t.Fatalf("unexpected grant type: %s", response.GrantType())
	}
	if _, err := ParseAPIKeyGrantResponse([]byte(`{"api_key":"secret","credential_id":"credential-2","expires_at":"2027-01-01T00:00:00Z","header":"X-API-Key"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseBasicGrantResponse([]byte(`{"credential_id":"credential-3","expires_at":"2027-01-01T00:00:00Z","password":"secret","username":"agent"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseOAuthBearerGrantResponse([]byte(`{"access_token":"token","credential_id":"credential-1","expires_at":"bad","token_type":"Bearer"}`)); err == nil {
		t.Fatal("expected invalid expiration to fail")
	}
	if _, err := ParseBuiltInGrantResponse("future", []byte(`{}`)); err == nil {
		t.Fatal("expected unknown built-in grant type to fail")
	}
}

func TestBuiltInCredentialPresentationValuesAreSafe(t *testing.T) {
	apiKey := APIKeyGrantResponse{
		APIKey: "secret value", CredentialID: "credential-1", ExpiresAt: "2027-01-01T00:00:00Z", Header: "x-api-key",
	}
	if err := ValidateAPIKeyGrantResponse(apiKey); err == nil {
		t.Fatal("API key containing whitespace was accepted")
	}
	apiKey.APIKey = "safe-secret"
	apiKey.Header = "invalid header"
	if err := ValidateAPIKeyGrantResponse(apiKey); err == nil {
		t.Fatal("invalid API-key header name was accepted")
	}
	basic := BasicGrantResponse{
		CredentialID: "credential-2", ExpiresAt: "2027-01-01T00:00:00Z", Password: "secret", Username: "agent:name",
	}
	if err := ValidateBasicGrantResponse(basic); err == nil {
		t.Fatal("Basic username containing a colon was accepted")
	}
	basic.Username = "agent"
	basic.Password = "secret\n"
	if err := ValidateBasicGrantResponse(basic); err == nil {
		t.Fatal("Basic password containing a control character was accepted")
	}
}

func TestProblemDetailsPrivacy(t *testing.T) {
	problem := NewProblemDetails(ErrorNotRecognized, "Not recognized", 401)
	problem.RequirementsPending = []string{"contact.email"}
	err := ValidateProblemDetails(problem)
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("expected ValidationError, got %v", err)
	}
	assertIssue(t, validation.Issues, "$")
}

func TestProblemDetailsSemantics(t *testing.T) {
	for _, data := range []string{
		`{"type":"urn:aep:error:not_recognized","status":401,"code":"not_recognized"}`,
		`{"type":"urn:aep:error:not_recognized","title":null,"status":401,"code":"not_recognized"}`,
		`{"type":"urn:aep:error:not_recognized","title":"","status":401,"code":"not_recognized"}`,
		`{"type":"urn:aep:error:invalid_request","title":"Not recognized","status":401,"code":"not_recognized"}`,
		`{"type":"urn:aep:error:not_recognized","title":"Not recognized","status":401,"code":"not_recognized","owner_action_required":"true"}`,
		`{"type":"urn:aep:error:not_recognized","title":"Not recognized","status":401,"code":"not_recognized","requirements_pending":[]}`,
		`{"type":"urn:aep:error:not_recognized","title":"Not recognized","status":401,"code":"not_recognized","verification_pending":[]}`,
	} {
		if _, err := ParseProblemDetails([]byte(data)); err == nil {
			t.Fatalf("invalid Problem Details was accepted: %s", data)
		}
	}
}

func TestClientAssertionClaims(t *testing.T) {
	claims := ClientAssertionClaims{
		Audience:  "did:web:api.example.com",
		ExpiresAt: 1_748_428_860,
		IssuedAt:  1_748_428_800,
		Issuer:    "did:web:agent.example.com:agents:123",
		JWTID:     "jti-1",
		Operation: AssertionStatus,
		Subject:   "did:web:agent.example.com:agents:123",
	}
	if err := ValidateClientAssertionClaims(claims); err != nil {
		t.Fatal(err)
	}
	claims.Operation = AssertionAuthenticate
	if err := ValidateClientAssertionClaims(claims); err == nil {
		t.Fatal("expected authenticate without resource to fail")
	}
	claims.Resource = "https://api.example.com/private"
	if err := ValidateClientAssertionClaims(claims); err != nil {
		t.Fatal(err)
	}
}
