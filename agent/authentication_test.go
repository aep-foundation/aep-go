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

func TestBuiltInCredentialAuthentication(t *testing.T) {
	var serviceDID string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		document := testInspectDocument(serviceDID)
		document.Authentication.Methods = []aep.AuthenticationMethod{
			aep.AuthenticationMethod(aep.GrantTypeAPIKey),
			aep.AuthenticationMethod(aep.GrantTypeBasic),
			aep.AuthenticationMethod(aep.GrantTypeOAuthBearer),
			aep.AuthenticationMethodJWT,
		}
		response.Header().Set("Content-Type", aep.MediaType)
		_ = json.NewEncoder(response).Encode(document)
	}))
	defer server.Close()
	serviceDID = didWebForServer(server.URL)
	clock := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	store := newMemoryCredentialStore(func() time.Time { return clock })
	records := []CredentialRecord{
		credentialTestRecord(serviceDID, aep.GrantTypeOAuthBearer, "oauth", `{"access_token":"bearer-token","credential_id":"oauth","expires_at":"2027-01-01T00:00:00Z","scopes":[],"token_type":"Bearer"}`),
		credentialTestRecord(serviceDID, aep.GrantTypeAPIKey, "api", `{"api_key":"secret","credential_id":"api","expires_at":"2027-01-01T00:00:00Z","header":"X-Service-Key","scopes":[]}`),
		credentialTestRecord(serviceDID, aep.GrantTypeBasic, "basic", `{"credential_id":"basic","expires_at":"2027-01-01T00:00:00Z","password":"pass","scopes":[],"username":"user"}`),
	}
	for _, record := range records {
		if err := store.SaveCredential(context.Background(), record); err != nil {
			t.Fatal(err)
		}
	}
	client, err := New(Options{Clock: func() time.Time { return clock }, CredentialStore: store, HTTPClient: server.Client(), IdentityProvider: newTestIdentityProvider(t)})
	if err != nil {
		t.Fatal(err)
	}
	session, _ := client.Service(server.URL)

	headers, err := session.AuthenticationHeaders(context.Background(), AuthenticationOptions{Resource: mustURL(t, server.URL+"/private")})
	if err != nil || headers.Get("X-Service-Key") != "secret" {
		t.Fatalf("Service-preferred credential was not selected: %#v, %v", headers, err)
	}
	headers, err = session.AuthenticationHeaders(context.Background(), AuthenticationOptions{CredentialID: "basic", Resource: mustURL(t, server.URL+"/private")})
	if err != nil || headers.Get("Authorization") != "Basic dXNlcjpwYXNz" {
		t.Fatalf("Basic credential was not rendered: %#v, %v", headers, err)
	}
	headers, err = session.AuthenticationHeaders(context.Background(), AuthenticationOptions{
		Carrier: aep.ProtectedResourceDedicated, CredentialID: "oauth", Resource: mustURL(t, server.URL+"/private"),
	})
	if err != nil || headers.Get(aep.AuthorizationHeader) != "Bearer bearer-token" || headers.Get("Authorization") != "" {
		t.Fatalf("dedicated OAuth credential was not rendered: %#v, %v", headers, err)
	}
	if _, err := session.AuthenticationHeaders(context.Background(), AuthenticationOptions{CredentialID: "missing", Resource: mustURL(t, server.URL+"/private")}); err == nil {
		t.Fatal("missing explicit credential was accepted")
	}
	if _, err := session.AuthenticationHeaders(context.Background(), AuthenticationOptions{CredentialID: "basic", GrantType: aep.GrantTypeOAuthBearer, Resource: mustURL(t, server.URL+"/private")}); err == nil {
		t.Fatal("mismatched explicit credential and grant type were accepted")
	}
	if _, err := session.AuthenticationHeaders(context.Background(), AuthenticationOptions{ClientAssertionOnly: true, CredentialID: "oauth", Resource: mustURL(t, server.URL+"/private")}); err == nil {
		t.Fatal("contradictory authentication selection was accepted")
	}
	if err := session.ForgetCredential(context.Background(), "basic"); err != nil {
		t.Fatal(err)
	}
	if credential, err := store.FindCredential(context.Background(), serviceDID, "basic"); err != nil || credential != nil {
		t.Fatalf("forgotten credential remained stored: %#v, %v", credential, err)
	}
	if err := session.ForgetCredential(context.Background(), ""); err == nil {
		t.Fatal("empty credential ID was accepted")
	}
}

func TestAuthenticationRejectsInvalidInputs(t *testing.T) {
	var serviceDID string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		document := testInspectDocument(serviceDID)
		document.Authentication.Methods = []aep.AuthenticationMethod{aep.AuthenticationMethodJWT}
		response.Header().Set("Content-Type", aep.MediaType)
		_ = json.NewEncoder(response).Encode(document)
	}))
	defer server.Close()
	serviceDID = didWebForServer(server.URL)
	client := testClient(t, server, newTestIdentityProvider(t))
	session, _ := client.Service(server.URL)
	if _, err := session.AuthenticationHeaders(context.Background(), AuthenticationOptions{ClientAssertionOnly: true}); err == nil {
		t.Fatal("JWT authentication without a resource was accepted")
	}
	if _, err := session.AuthenticationHeaders(context.Background(), AuthenticationOptions{ClientAssertionOnly: true, Resource: mustURL(t, "http://example.com/private")}); err == nil {
		t.Fatal("plaintext protected resource was accepted")
	}
	if _, err := session.AuthenticationHeaders(context.Background(), AuthenticationOptions{ClientAssertionOnly: true, Resource: mustURL(t, "https://different.example/private")}); err == nil {
		t.Fatal("cross-origin protected resource was accepted")
	}
	if _, err := session.AuthenticationHeaders(context.Background(), AuthenticationOptions{ClientAssertionOnly: true, Resource: mustURL(t, server.URL+"/private#fragment")}); err == nil {
		t.Fatal("fragment-bearing protected resource was accepted")
	}
	withUser := mustURL(t, server.URL+"/private")
	withUser.User = url.User("agent")
	if _, err := session.AuthenticationHeaders(context.Background(), AuthenticationOptions{ClientAssertionOnly: true, Resource: withUser}); err == nil {
		t.Fatal("credential-bearing protected resource URL was accepted")
	}
	if _, err := session.AuthenticationHeaders(context.Background(), AuthenticationOptions{GrantType: aep.GrantTypeOAuthBearer, Resource: mustURL(t, server.URL+"/private")}); !errors.Is(err, ErrNoAuthenticationMethod) {
		t.Fatalf("unadvertised grant type was accepted: %v", err)
	}
	if aep.IsHTTPFieldName("") || aep.IsHTTPFieldName("Bad Header") || !aep.IsHTTPFieldName("X-Service-Key") {
		t.Fatal("header-name validation is incorrect")
	}
}

func TestAuthenticationHonorsServiceMethodPreference(t *testing.T) {
	var serviceDID string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		document := testInspectDocument(serviceDID)
		document.Authentication.Methods = []aep.AuthenticationMethod{aep.AuthenticationMethodJWT, aep.AuthenticationMethod(aep.GrantTypeOAuthBearer)}
		response.Header().Set("Content-Type", aep.MediaType)
		_ = json.NewEncoder(response).Encode(document)
	}))
	defer server.Close()
	serviceDID = didWebForServer(server.URL)
	store := newMemoryCredentialStore(time.Now)
	record := credentialTestRecord(serviceDID, aep.GrantTypeOAuthBearer, "oauth", `{"access_token":"bearer-token","credential_id":"oauth","expires_at":"2027-01-01T00:00:00Z","scopes":[],"token_type":"Bearer"}`)
	if err := store.SaveCredential(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	client, err := New(Options{CredentialStore: store, HTTPClient: server.Client(), IdentityProvider: newTestIdentityProvider(t)})
	if err != nil {
		t.Fatal(err)
	}
	session, _ := client.Service(server.URL)
	headers, err := session.AuthenticationHeaders(context.Background(), AuthenticationOptions{Resource: mustURL(t, server.URL+"/private")})
	if err != nil || !strings.HasPrefix(headers.Get("Authorization"), "AEP ") {
		t.Fatalf("Service-preferred JWT method was not selected: %#v, %v", headers, err)
	}
}

func TestAPIKeyAuthenticationRejectsInvalidCarrier(t *testing.T) {
	var serviceDID string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		document := testInspectDocument(serviceDID)
		document.Authentication.Methods = []aep.AuthenticationMethod{aep.AuthenticationMethod(aep.GrantTypeAPIKey)}
		response.Header().Set("Content-Type", aep.MediaType)
		_ = json.NewEncoder(response).Encode(document)
	}))
	defer server.Close()
	serviceDID = didWebForServer(server.URL)
	store := newMemoryCredentialStore(time.Now)
	record := credentialTestRecord(serviceDID, aep.GrantTypeAPIKey, "api", `{"api_key":"secret","credential_id":"api","expires_at":"2027-01-01T00:00:00Z","header":"X-Service-Key","scopes":[]}`)
	if err := store.SaveCredential(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	client, err := New(Options{CredentialStore: store, HTTPClient: server.Client(), IdentityProvider: newTestIdentityProvider(t)})
	if err != nil {
		t.Fatal(err)
	}
	session, _ := client.Service(server.URL)
	_, err = session.AuthenticationHeaders(context.Background(), AuthenticationOptions{
		Carrier: "future", CredentialID: "api", Resource: mustURL(t, server.URL+"/private"),
	})
	if err == nil {
		t.Fatal("invalid authorization carrier was ignored for API-key authentication")
	}
}

func credentialTestRecord(serviceDID string, grantType aep.GrantType, credentialID string, payload string) CredentialRecord {
	return CredentialRecord{
		CredentialID: credentialID,
		ExpiresAt:    time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		GrantType:    grantType,
		IssuedAt:     time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC),
		Payload:      json.RawMessage(payload),
		ServiceDID:   serviceDID,
	}
}
