package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	aep "github.com/aep-foundation/aep-go"
)

func TestStoredBuiltInCredentialProfiles(t *testing.T) {
	store := NewMemoryServiceCredentialStore()
	oauth, err := StoredOAuthBearerGrantType(StoredCredentialGrantTypeOptions[aep.OAuthBearerGrantResponse]{
		Store: store,
		Issue: func(context.Context, aep.GrantRequest, GrantContext) (aep.OAuthBearerGrantResponse, error) {
			return aep.OAuthBearerGrantResponse{
				AccessToken: "oauth-secret", CredentialID: "oauth-1", ExpiresAt: testNow.Add(time.Hour).Format(time.RFC3339),
				Scopes: []string{"read"}, TokenType: "Bearer",
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	apiKey, err := StoredAPIKeyGrantType(StoredCredentialGrantTypeOptions[aep.APIKeyGrantResponse]{
		Config: aep.GrantTypeConfig{Additional: aep.AdditionalMembers{"header_names": json.RawMessage(`["x-api-key"]`)}},
		Store:  store,
		Issue: func(context.Context, aep.GrantRequest, GrantContext) (aep.APIKeyGrantResponse, error) {
			return aep.APIKeyGrantResponse{
				APIKey: "api-secret", CredentialID: "api-1", ExpiresAt: testNow.Add(time.Hour).Format(time.RFC3339),
				Header: "x-api-key", Scopes: []string{"read"},
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	basic, err := StoredBasicGrantType(StoredCredentialGrantTypeOptions[aep.BasicGrantResponse]{
		Store: store,
		Issue: func(context.Context, aep.GrantRequest, GrantContext) (aep.BasicGrantResponse, error) {
			return aep.BasicGrantResponse{
				CredentialID: "basic-1", ExpiresAt: testNow.Add(time.Hour).Format(time.RFC3339), Password: "basic-secret",
				Scopes: []string{"read"}, Username: "agent",
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	service := newTestService(t, Options{
		AuthenticationMethods: []aep.AuthenticationMethod{
			aep.AuthenticationMethod(aep.GrantTypeOAuthBearer), aep.AuthenticationMethod(aep.GrantTypeAPIKey),
			aep.AuthenticationMethod(aep.GrantTypeBasic), aep.AuthenticationMethodJWT,
		},
		GrantTypes: []GrantTypeDefinition{oauth, apiKey, basic},
	})
	seedEnrollment(t, service.enrollmentStore)

	for index, grantType := range []aep.GrantType{aep.GrantTypeOAuthBearer, aep.GrantTypeAPIKey, aep.GrantTypeBasic} {
		body, marshalErr := json.Marshal(aep.GrantRequest{GrantType: grantType})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		result, grantErr := service.Grant(context.Background(), body, commandOptions(aep.AssertionGrant, "grant-profile-"+string(rune('a'+index)), "grant-profile-"+string(rune('a'+index))))
		if grantErr != nil || result.Problem != nil {
			t.Fatalf("%s Grant failed: %#v, %v", grantType, result, grantErr)
		}
	}

	tests := []struct {
		credentialID string
		headers      http.Header
	}{
		{credentialID: "oauth-1", headers: http.Header{"Authorization": []string{"Bearer oauth-secret"}}},
		{credentialID: "api-1", headers: http.Header{"X-Api-Key": []string{"api-secret"}}},
		{credentialID: "basic-1", headers: http.Header{"Authorization": []string{"Basic " + base64.StdEncoding.EncodeToString([]byte("agent:basic-secret"))}}},
	}
	for _, test := range tests {
		result, authenticateErr := service.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{
			Headers: test.headers, Method: http.MethodGet, URL: mustURL(t, "https://service.example/private"),
		})
		if authenticateErr != nil || !result.Authenticated || result.Principal == nil || result.Principal.CredentialID != test.credentialID {
			t.Fatalf("credential %s was not authenticated: %#v, %v", test.credentialID, result, authenticateErr)
		}
	}
	wrongHeader, err := service.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{
		Headers: http.Header{"Service-Api-Key": []string{"api-secret"}}, Method: http.MethodGet,
		URL: mustURL(t, "https://service.example/private"),
	})
	if err != nil || wrongHeader.Authenticated || wrongHeader.Response == nil || wrongHeader.Response.Body.Code != aep.ErrorNotRecognized {
		t.Fatalf("API key under the wrong header was not rejected uniformly: %#v, %v", wrongHeader, err)
	}

	revoked, err := service.Revoke(context.Background(), []byte(`{"credential_id":"oauth-1","grant_type":"oauth-bearer"}`), commandOptions(aep.AssertionRevoke, "revoke-oauth", "revoke-oauth"))
	if err != nil || revoked.Problem != nil {
		t.Fatalf("targeted Revoke failed: %#v, %v", revoked, err)
	}
	result, err := service.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{
		Headers: http.Header{"Authorization": []string{"Bearer oauth-secret"}}, Method: http.MethodGet,
		URL: mustURL(t, "https://service.example/private"),
	})
	if err != nil || result.Authenticated || result.Response == nil || result.Response.Body.Code != aep.ErrorNotRecognized {
		t.Fatalf("revoked credential was not rejected uniformly: %#v, %v", result, err)
	}
}

func TestStoredAPIKeyGrantTypeRejectsUnadvertisedHeader(t *testing.T) {
	definition, err := StoredAPIKeyGrantType(StoredCredentialGrantTypeOptions[aep.APIKeyGrantResponse]{
		Config: aep.GrantTypeConfig{Additional: aep.AdditionalMembers{"header_names": json.RawMessage(`["service-api-key"]`)}},
		Issue: func(context.Context, aep.GrantRequest, GrantContext) (aep.APIKeyGrantResponse, error) {
			return aep.APIKeyGrantResponse{
				APIKey: "api-secret", CredentialID: "api-1", ExpiresAt: testNow.Add(time.Hour).Format(time.RFC3339), Header: "x-api-key",
			}, nil
		},
		Store: NewMemoryServiceCredentialStore(),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = definition.Handler.Grant(context.Background(), aep.GrantRequest{GrantType: aep.GrantTypeAPIKey}, GrantContext{
		AgentDID: "did:web:agent.example", GrantType: aep.GrantTypeAPIKey, Now: testNow,
	})
	if err == nil {
		t.Fatal("API-key issuer selected an unadvertised header")
	}
}

func TestMemoryServiceCredentialStoreRejectsReassignedIdentifier(t *testing.T) {
	store := NewMemoryServiceCredentialStore()
	record := ServiceCredentialRecord{
		AgentDID: "did:web:agent.example", CreatedAt: testNow,
		Credential: aep.APIKeyGrantResponse{
			APIKey: "first-secret", CredentialID: "credential-1", ExpiresAt: testNow.Add(time.Hour).Format(time.RFC3339), Header: "x-api-key",
		},
		CredentialID: "credential-1", ExpiresAt: testNow.Add(time.Hour), GrantType: aep.GrantTypeAPIKey,
	}
	if err := store.SaveCredential(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	record.Credential = aep.APIKeyGrantResponse{
		APIKey: "second-secret", CredentialID: "credential-1", ExpiresAt: testNow.Add(time.Hour).Format(time.RFC3339), Header: "x-api-key",
	}
	if err := store.SaveCredential(context.Background(), record); err == nil {
		t.Fatal("reassigned credential identifier was accepted")
	}
}

func TestServiceEnforcesClaimValueLimits(t *testing.T) {
	service := newTestService(t, Options{ClaimValueLimits: &ClaimValueLimits{MaxMemberCount: 1}})
	result, err := service.Enroll(
		context.Background(),
		[]byte(`{"agent_did":"did:web:agent.example","claims":{"contact.email":"agent@example.com","person.first_name":"Agent"}}`),
		commandOptions(aep.AssertionEnroll, "claims-limit", "claims-limit"),
	)
	if err != nil || result.Problem == nil || result.Problem.Code != aep.ErrorInvalidRequest {
		t.Fatalf("oversized Claim Values were not rejected: %#v, %v", result, err)
	}
}

func TestServiceRejectsInvalidClaimValueLimits(t *testing.T) {
	_, err := New(Options{
		ClaimValueLimits:  &ClaimValueLimits{MaxEncodedBytes: -1},
		IdentityMethods:   []aep.IdentityMethod{aep.IdentityMethodDIDWeb},
		ServiceDID:        "did:web:service.example",
		SigningAlgorithms: []aep.SigningAlgorithm{aep.SigningAlgorithmEdDSA, aep.SigningAlgorithmES256},
		Verifier: func(context.Context, string, AssertionVerificationContext) (aep.ClientAssertionClaims, error) {
			return aep.ClientAssertionClaims{}, nil
		},
	})
	if err == nil {
		t.Fatal("negative Claim Value limit was accepted")
	}
}
