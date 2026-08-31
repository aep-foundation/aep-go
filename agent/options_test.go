package agent

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/url"
	"testing"
	"time"

	aep "github.com/aep-foundation/aep-go"
)

func TestClientOptionsAndServiceReferences(t *testing.T) {
	provider := newTestIdentityProvider(t)
	tests := []struct {
		name    string
		options Options
	}{
		{name: "missing identity provider", options: Options{}},
		{name: "short assertion lifetime", options: Options{IdentityProvider: provider, AssertionLifetime: time.Millisecond}},
		{name: "long assertion lifetime", options: Options{IdentityProvider: provider, AssertionLifetime: aep.MaxAssertionLifetime + time.Second}},
		{name: "fractional assertion lifetime", options: Options{IdentityProvider: provider, AssertionLifetime: time.Second + time.Millisecond}},
		{name: "negative response limit", options: Options{IdentityProvider: provider, MaximumResponseBytes: -1}},
		{name: "overflowing response limit", options: Options{IdentityProvider: provider, MaximumResponseBytes: math.MaxInt64}},
		{name: "negative timeout", options: Options{IdentityProvider: provider, RequestTimeout: -1}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := New(test.options); err == nil {
				t.Fatal("invalid Agent options were accepted")
			}
		})
	}
	client, err := New(Options{IdentityProvider: provider})
	if err != nil {
		t.Fatal(err)
	}
	valid := map[string]string{
		"example.com/path?query=1#fragment": "https://example.com/",
		" https://example.com/path ":        "https://example.com/",
		"did:web:example.com:service":       "https://example.com/",
	}
	for reference, expected := range valid {
		session, serviceErr := client.Service(reference)
		if serviceErr != nil || session.serviceURL.String() != expected {
			t.Fatalf("unexpected Service reference %q: %v, %v", reference, session, serviceErr)
		}
	}
	for _, reference := range []string{"", "https://user:pass@example.com", "http://example.com", "://"} {
		if _, err := client.Service(reference); err == nil {
			t.Fatalf("invalid Service reference %q was accepted", reference)
		}
	}
	loopback, err := New(Options{AllowInsecureLoopback: true, IdentityProvider: provider})
	if err != nil {
		t.Fatal(err)
	}
	if session, err := loopback.Service("http://127.0.0.1:4100/path"); err != nil || session.serviceURL.String() != "http://127.0.0.1:4100/" {
		t.Fatalf("loopback Service reference failed: %#v, %v", session, err)
	}
}

func TestMemoryStoresAreIsolatedAndExpireCredentials(t *testing.T) {
	clock := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	credentials := newMemoryCredentialStore(func() time.Time { return clock })
	record := CredentialRecord{
		CredentialID: "credential-1", ExpiresAt: clock.Add(time.Hour), GrantType: aep.GrantTypeOAuthBearer,
		IssuedAt: clock, Payload: json.RawMessage(`{"access_token":"token","credential_id":"credential-1","expires_at":"2026-08-30T13:00:00Z","scopes":[],"token_type":"Bearer"}`), ServiceDID: "did:web:service.example",
	}
	if err := credentials.SaveCredential(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	found, err := credentials.FindCredential(context.Background(), record.ServiceDID, record.CredentialID)
	if err != nil || found == nil {
		t.Fatalf("credential was not found: %#v, %v", found, err)
	}
	found.Payload[0] = 'x'
	again, _ := credentials.FindCredential(context.Background(), record.ServiceDID, record.CredentialID)
	if again == nil || string(again.Payload) != string(record.Payload) {
		t.Fatal("caller mutated stored credential")
	}
	clock = clock.Add(2 * time.Hour)
	if expired, _ := credentials.FindCredential(context.Background(), record.ServiceDID, record.CredentialID); expired != nil {
		t.Fatal("expired credential remained stored")
	}
	if records, err := credentials.ListCredentials(context.Background(), record.ServiceDID); err != nil || len(records) != 0 {
		t.Fatalf("unexpected expired credential list: %#v, %v", records, err)
	}
	if err := credentials.DeleteCredential(context.Background(), record.ServiceDID, record.CredentialID); err != nil {
		t.Fatal(err)
	}
	if NewMemoryCredentialStore() == nil {
		t.Fatal("default memory credential store was not created")
	}

	identities := NewMemoryIdentityStore()
	identity := ServiceIdentity{
		AgentDID: "did:web:agent.example", ServiceDID: record.ServiceDID,
		IdentityMethod:    aep.IdentityMethodDIDWeb,
		SigningAlgorithms: []aep.SigningAlgorithm{aep.SigningAlgorithmEdDSA}, Metadata: map[string]string{"key": "value"},
	}
	if err := identities.SaveIdentity(context.Background(), identity); err != nil {
		t.Fatal(err)
	}
	loaded, err := identities.FindIdentity(context.Background(), record.ServiceDID)
	if err != nil || loaded == nil {
		t.Fatalf("identity was not found: %#v, %v", loaded, err)
	}
	loaded.Metadata["key"] = "changed"
	loaded.SigningAlgorithms[0] = aep.SigningAlgorithmES256
	againIdentity, _ := identities.FindIdentity(context.Background(), record.ServiceDID)
	if againIdentity.Metadata["key"] != "value" || againIdentity.SigningAlgorithms[0] != aep.SigningAlgorithmEdDSA {
		t.Fatal("caller mutated stored identity")
	}
	missing, err := identities.FindIdentity(context.Background(), "did:web:missing.example")
	if err != nil || missing != nil {
		t.Fatalf("unexpected missing identity result: %#v, %v", missing, err)
	}
}

func TestInspectionCommandURL(t *testing.T) {
	serviceURL, _ := url.Parse("https://service.example/")
	inspection := Inspection{Document: testInspectDocument("did:web:service.example"), ServiceURL: serviceURL}
	commandURL, err := inspection.CommandURL(aep.CommandGrant)
	if err != nil || commandURL.String() != "https://service.example/aep/grant" {
		t.Fatalf("unexpected command URL: %v, %v", commandURL, err)
	}
	if _, err := inspection.CommandURL(aep.CommandInspect); err == nil {
		t.Fatal("Inspect was accepted as a command endpoint")
	}
}

func TestInspectErrorUnwrap(t *testing.T) {
	cause := errors.New("cause")
	err := inspectError(InspectHTTPError, 0, "operation", cause)
	if !errors.Is(err, cause) {
		t.Fatal("Inspect error did not preserve its cause")
	}
}
