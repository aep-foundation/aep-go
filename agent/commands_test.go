package agent

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	aep "github.com/aep-foundation/aep-go"
)

func TestCommandFailureIncludesProblemDetails(t *testing.T) {
	var serviceDID string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == aep.WellKnownPath {
			response.Header().Set("Content-Type", aep.MediaType)
			_ = json.NewEncoder(response).Encode(testInspectDocument(serviceDID))
			return
		}
		response.Header().Set("Content-Type", aep.ProblemMediaType)
		response.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = response.Write([]byte(`{"code":"requirements_unmet","status":422,"title":"Requirements unmet","type":"urn:aep:error:requirements_unmet"}`))
	}))
	defer server.Close()
	serviceDID = didWebForServer(server.URL)
	client := testClient(t, server, newTestIdentityProvider(t))
	session, _ := client.Service(server.URL)
	_, err := session.Enroll(context.Background(), EnrollOptions{})
	var commandErr *CommandError
	if !errors.As(err, &commandErr) || commandErr.Status != http.StatusUnprocessableEntity || commandErr.Problem == nil || commandErr.Problem.Code != aep.ErrorRequirementsUnmet {
		t.Fatalf("unexpected command error: %#v, %v", commandErr, err)
	}
}

func TestEnrollRejectsUnsatisfiedRequiredClaimsBeforeCommand(t *testing.T) {
	var commandCalls atomic.Int32
	var serviceDID string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", aep.MediaType)
		if request.URL.Path == aep.WellKnownPath {
			document := testInspectDocument(serviceDID)
			document.Claims = &aep.InspectClaims{Required: []aep.ClaimName{aep.ClaimContactEmail}}
			_ = json.NewEncoder(response).Encode(document)
			return
		}
		commandCalls.Add(1)
		_ = json.NewEncoder(response).Encode(aep.EnrollResponse{Status: aep.AgentActive})
	}))
	defer server.Close()
	serviceDID = didWebForServer(server.URL)
	client := testClient(t, server, newTestIdentityProvider(t))
	session, _ := client.Service(server.URL)
	_, err := session.Enroll(context.Background(), EnrollOptions{})
	var requirements *ClaimRequirementsError
	if !errors.As(err, &requirements) || len(requirements.MissingRequiredClaimNames) != 1 || requirements.MissingRequiredClaimNames[0] != aep.ClaimContactEmail {
		t.Fatalf("unexpected Claim requirements error: %#v, %v", requirements, err)
	}
	if commandCalls.Load() != 0 {
		t.Fatal("Enroll command was sent with unsatisfied required claims")
	}
}

func TestRevokeRejectsContradictorySelector(t *testing.T) {
	provider := newTestIdentityProvider(t)
	client, err := New(Options{IdentityProvider: provider})
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.Service("https://service.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Revoke(context.Background(), RevokeOptions{AllGrantTypes: true, GrantType: aep.GrantTypeOAuthBearer}); err == nil {
		t.Fatal("contradictory Revoke selector was accepted")
	}
}

func TestCommandFailureWithoutProblemDetails(t *testing.T) {
	var serviceDID string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == aep.WellKnownPath {
			response.Header().Set("Content-Type", aep.MediaType)
			_ = json.NewEncoder(response).Encode(testInspectDocument(serviceDID))
			return
		}
		response.WriteHeader(http.StatusBadGateway)
		_, _ = response.Write([]byte("not JSON"))
	}))
	defer server.Close()
	serviceDID = didWebForServer(server.URL)
	client := testClient(t, server, newTestIdentityProvider(t))
	session, _ := client.Service(server.URL)
	_, err := session.Status(context.Background())
	var commandErr *CommandError
	if !errors.As(err, &commandErr) || commandErr.Status != http.StatusBadGateway || commandErr.Problem != nil {
		t.Fatalf("unexpected generic command error: %#v, %v", commandErr, err)
	}
}

func TestWaitForActiveAndTerminalState(t *testing.T) {
	for _, terminal := range []aep.AgentStatus{aep.AgentActive, aep.AgentRejected} {
		t.Run(string(terminal), func(t *testing.T) {
			var serviceDID string
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				response.Header().Set("Content-Type", aep.MediaType)
				if request.URL.Path == aep.WellKnownPath {
					_ = json.NewEncoder(response).Encode(testInspectDocument(serviceDID))
					return
				}
				status := aep.AgentPending
				if calls.Add(1) > 1 {
					status = terminal
				}
				_ = json.NewEncoder(response).Encode(aep.StatusResponse{Status: status})
			}))
			defer server.Close()
			serviceDID = didWebForServer(server.URL)
			client := testClient(t, server, newTestIdentityProvider(t))
			session, _ := client.Service(server.URL)
			result, err := session.WaitForActive(context.Background(), WaitOptions{Interval: time.Millisecond})
			if result.Body.Status != terminal {
				t.Fatalf("unexpected terminal status: %#v", result)
			}
			if terminal == aep.AgentActive && err != nil {
				t.Fatal(err)
			}
			var stateErr *EnrollmentStateError
			if terminal == aep.AgentRejected && (!errors.As(err, &stateErr) || stateErr.Status != terminal) {
				t.Fatalf("unexpected terminal error: %#v, %v", stateErr, err)
			}
		})
	}
}

func TestCustomGrantResponseAndGrantSelection(t *testing.T) {
	var serviceDID string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", aep.MediaType)
		if request.URL.Path == aep.WellKnownPath {
			document := testInspectDocument(serviceDID)
			document.Commands.GrantTypes = []aep.GrantType{"custom", aep.GrantTypeOAuthBearer}
			document.Commands.GrantTypesConfig = nil
			_ = json.NewEncoder(response).Encode(document)
			return
		}
		if request.URL.Path == "/aep/status" {
			_, _ = response.Write([]byte(`{"status":"active"}`))
			return
		}
		_, _ = response.Write([]byte(`{"credential_id":"custom-1","credential":"opaque"}`))
	}))
	defer server.Close()
	serviceDID = didWebForServer(server.URL)
	client := testClient(t, server, newTestIdentityProvider(t))
	session, _ := client.Service(server.URL)
	if _, err := session.Identity(context.Background()); err != nil {
		t.Fatal(err)
	}
	result, err := session.Grant(context.Background(), GrantOptions{PreferredGrantTypes: []aep.GrantType{"unsupported", "custom"}})
	if err != nil || result.Body.GrantType != "custom" || result.Body.Credential != nil {
		t.Fatalf("unexpected custom Grant: %#v, %v", result, err)
	}
	if len(result.Body.Raw) == 0 {
		t.Fatal("custom Grant response was not preserved")
	}
	if _, err := selectGrantType(testInspectDocument(serviceDID), "unsupported", nil); !errors.Is(err, ErrNoCompatibleGrantType) {
		t.Fatalf("unadvertised selected Grant Type was accepted: %v", err)
	}
	if _, err := selectGrantType(aep.InspectDocument{}, "", nil); !errors.Is(err, ErrNoCompatibleGrantType) {
		t.Fatalf("missing Grant Type was accepted: %v", err)
	}
}

func TestInvalidIdentityProviderAndSignerResults(t *testing.T) {
	var serviceDID string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		document := testInspectDocument(serviceDID)
		document.Identity.Methods = append(document.Identity.Methods, "future")
		response.Header().Set("Content-Type", aep.MediaType)
		_ = json.NewEncoder(response).Encode(document)
	}))
	defer server.Close()
	serviceDID = didWebForServer(server.URL)
	for _, provider := range []*testIdentityProvider{
		{identity: ServiceIdentity{AgentDID: "not-a-did", IdentityMethod: aep.IdentityMethodDIDWeb, SigningAlgorithms: []aep.SigningAlgorithm{aep.SigningAlgorithmEdDSA}}},
		{identity: ServiceIdentity{AgentDID: "did:web:agent.example", IdentityMethod: aep.IdentityMethodDIDWeb}},
		{identity: ServiceIdentity{AgentDID: "did:web:agent.example", IdentityMethod: "future", SigningAlgorithms: []aep.SigningAlgorithm{aep.SigningAlgorithmEdDSA}}},
		{identity: ServiceIdentity{AgentDID: "did:key:agent", IdentityMethod: aep.IdentityMethodDIDWeb, SigningAlgorithms: []aep.SigningAlgorithm{aep.SigningAlgorithmEdDSA}}},
	} {
		client := testClient(t, server, provider)
		session, _ := client.Service(server.URL)
		if _, err := session.Identity(context.Background()); err == nil {
			t.Fatal("invalid identity provider result was accepted")
		}
	}
	provider := newTestIdentityProvider(t)
	provider.signer = func(context.Context, aep.ClientAssertionClaims, []aep.SigningAlgorithm) (string, error) {
		return "", nil
	}
	client := testClient(t, server, provider)
	session, _ := client.Service(server.URL)
	if _, err := session.Status(context.Background()); err == nil {
		t.Fatal("empty signed assertion was accepted")
	}
}

func TestWaitForActiveTimeout(t *testing.T) {
	var serviceDID string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", aep.MediaType)
		if request.URL.Path == aep.WellKnownPath {
			_ = json.NewEncoder(response).Encode(testInspectDocument(serviceDID))
			return
		}
		_, _ = response.Write([]byte(`{"status":"pending"}`))
	}))
	defer server.Close()
	serviceDID = didWebForServer(server.URL)
	client := testClient(t, server, newTestIdentityProvider(t))
	session, _ := client.Service(server.URL)
	if _, err := session.WaitForActive(context.Background(), WaitOptions{Interval: time.Millisecond, Timeout: 2 * time.Millisecond}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected bounded wait timeout, got %v", err)
	}
	if _, err := session.WaitForActive(context.Background(), WaitOptions{Interval: time.Millisecond, Timeout: -1}); err == nil {
		t.Fatal("invalid wait timeout was accepted")
	}
}

func TestAssertionExpirationOverflow(t *testing.T) {
	var serviceDID string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", aep.MediaType)
		_ = json.NewEncoder(response).Encode(testInspectDocument(serviceDID))
	}))
	defer server.Close()
	serviceDID = didWebForServer(server.URL)
	client, err := New(Options{
		Clock: func() time.Time { return time.Unix(math.MaxInt64-1, 0) }, HTTPClient: server.Client(),
		IdentityProvider: newTestIdentityProvider(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	session, _ := client.Service(server.URL)
	if _, err := session.Status(context.Background()); err == nil {
		t.Fatal("overflowing assertion expiration was accepted")
	}
}
