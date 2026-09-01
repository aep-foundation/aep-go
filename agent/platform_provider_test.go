package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	aep "github.com/aep-foundation/aep-go"
	"github.com/aep-foundation/aep-go/platform"
)

func TestPlatformIdentityProviderProvisionsAndSigns(t *testing.T) {
	var discoveryRequests atomic.Int32
	var listRequests atomic.Int32
	var provisionRequests atomic.Int32
	var signRequests atomic.Int32
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == platform.WellKnownPath:
			discoveryRequests.Add(1)
			response.Header().Set("Cache-Control", "max-age=300")
			writePlatformJSON(t, response, platformDiscovery(server.URL))
		case request.URL.Path == "/v1/aep/agent-identities" && request.Method == http.MethodGet:
			listRequests.Add(1)
			if request.URL.Query().Get("service_did") != "did:web:service.example" || request.URL.Query().Get("limit") != "100" || request.URL.Query().Get("descending") != "true" {
				t.Errorf("unexpected list query: %s", request.URL.RawQuery)
			}
			writePlatformJSON(t, response, platform.AgentIdentityListResponse{Count: "0", Data: []platform.AgentIdentity{}, Total: "0"})
		case request.URL.Path == "/v1/aep/agent-identities" && request.Method == http.MethodPost:
			provisionRequests.Add(1)
			assertPlatformHeaders(t, request)
			writePlatformJSON(t, response, platformIdentity(server.URL))
		case request.URL.Path == "/v1/aep/agent-identities/identity-1/sign":
			signRequests.Add(1)
			assertPlatformHeaders(t, request)
			var body platform.SignRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode Sign request: %v", err)
				return
			}
			writePlatformJSON(t, response, platform.SignResponse{
				AgentDID: "did:web:" + encodedTestHost(server.URL) + ":agents:one", ClientAssertion: "signed-assertion",
				ExpiresAt: time.Unix(1301, 0).UTC().Format(time.RFC3339), IssuedAt: time.Unix(1001, 0).UTC().Format(time.RFC3339),
				JWTID: body.JWTID, ServiceDID: body.ServiceDID, Status: platform.SignCompleted,
			})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	provider, err := NewPlatformIdentityProvider(PlatformIdentityProviderOptions{
		Authorization: "Bearer platform-token", HTTPClient: server.Client(), PlatformURL: server.URL,
		AuthenticationHeaders: func(context.Context) (http.Header, error) {
			return http.Header{"accept": {"text/plain"}, "authorization": {"Bearer rotating-token"}, "content-type": {"text/plain"}, "idempotency-key": {"caller-key"}, "x-tenant": {"tenant-1"}}, nil
		},
		IdempotencyKey: func() (string, error) { return "idempotency-1", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := provider.GetOrCreateIdentity(context.Background(), IdentityRequest{ServiceDID: "did:web:service.example"})
	if err != nil {
		t.Fatal(err)
	}
	if identity.AgentDID != platformIdentity(server.URL).AgentDID || identity.Metadata["agent_identity_id"] != "identity-1" {
		t.Fatalf("unexpected identity: %#v", identity)
	}
	signer, err := provider.SignerFor(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := signer(context.Background(), assertionClaims(identity), []aep.SigningAlgorithm{aep.SigningAlgorithmES256})
	if err != nil || assertion != "signed-assertion" {
		t.Fatalf("unexpected assertion: %q, %v", assertion, err)
	}
	if discoveryRequests.Load() != 1 || listRequests.Load() != 1 || provisionRequests.Load() != 1 || signRequests.Load() != 1 {
		t.Fatalf("unexpected request counts: discovery=%d list=%d provision=%d sign=%d", discoveryRequests.Load(), listRequests.Load(), provisionRequests.Load(), signRequests.Load())
	}
}

func TestCompletedPlatformSignResponseRequiresRequestedLifetime(t *testing.T) {
	identity := ServiceIdentity{AgentDID: "did:web:agent.example", ServiceDID: "did:web:service.example"}
	claims := assertionClaims(identity)
	response := platform.SignResponse{
		AgentDID: identity.AgentDID, ClientAssertion: "signed-assertion",
		ExpiresAt: time.Unix(1301, 0).UTC().Format(time.RFC3339), IssuedAt: time.Unix(1001, 0).UTC().Format(time.RFC3339),
		JWTID: claims.JWTID, ServiceDID: identity.ServiceDID, Status: platform.SignCompleted,
	}
	if !validCompletedSignResponse(http.StatusOK, response, identity, claims) {
		t.Fatal("completed Platform Sign response with the requested lifetime was rejected")
	}
	response.ExpiresAt = time.Unix(1302, 0).UTC().Format(time.RFC3339)
	if validCompletedSignResponse(http.StatusOK, response, identity, claims) {
		t.Fatal("completed Platform Sign response with a different lifetime was accepted")
	}
}

func TestPlatformIdentityProviderResolvesPendingSign(t *testing.T) {
	var signs atomic.Int32
	var firstIdempotencyKey string
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == platform.WellKnownPath {
			writePlatformJSON(t, response, platformDiscovery(server.URL))
			return
		}
		if request.URL.Path != "/v1/aep/agent-identities/identity-1/sign" {
			http.NotFound(response, request)
			return
		}
		if signs.Add(1) == 1 {
			firstIdempotencyKey = request.Header.Get("Idempotency-Key")
			response.Header().Set("Content-Type", aep.MediaType)
			response.WriteHeader(http.StatusAccepted)
			writePlatformJSON(t, response, platform.SignResponse{PlatformContext: map[string]json.RawMessage{"handle": json.RawMessage(`"approval-1"`)}, RetryAfterSeconds: "1", Status: platform.SignPending})
			return
		}
		if request.Header.Get("Idempotency-Key") == firstIdempotencyKey {
			t.Error("pending Sign continuation reused the initial idempotency key")
		}
		var body platform.SignRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode Sign request: %v", err)
			return
		}
		writePlatformJSON(t, response, platform.SignResponse{AgentDID: platformIdentity(server.URL).AgentDID, ClientAssertion: "completed", ExpiresAt: time.Unix(1300, 0).UTC().Format(time.RFC3339), IssuedAt: time.Unix(1000, 0).UTC().Format(time.RFC3339), JWTID: body.JWTID, ServiceDID: body.ServiceDID, Status: platform.SignCompleted})
	}))
	defer server.Close()

	var resolved atomic.Int32
	provider := newTestPlatformProvider(t, server, func(_ context.Context, pending PlatformPendingSign) (map[string]json.RawMessage, error) {
		resolved.Add(1)
		if pending.RetryAfterSeconds != 1 || string(pending.PlatformContext["handle"]) != `"approval-1"` {
			t.Fatalf("unexpected pending result: %#v", pending)
		}
		return pending.PlatformContext, nil
	})
	identity, err := provider.serviceIdentity(platformIdentity(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := provider.SignerFor(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := signer(context.Background(), assertionClaims(identity), []aep.SigningAlgorithm{aep.SigningAlgorithmES256})
	if err != nil || assertion != "completed" || signs.Load() != 2 || resolved.Load() != 1 {
		t.Fatalf("pending Sign was not resolved: assertion=%q signs=%d resolved=%d err=%v", assertion, signs.Load(), resolved.Load(), err)
	}
}

func TestPlatformIdentityProviderReusesActiveIdentity(t *testing.T) {
	var provisionRequests atomic.Int32
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == platform.WellKnownPath:
			writePlatformJSON(t, response, platformDiscovery(server.URL))
		case request.URL.Path == "/v1/aep/agent-identities" && request.Method == http.MethodGet:
			writePlatformJSON(t, response, platform.AgentIdentityListResponse{Count: "1", Data: []platform.AgentIdentity{platformIdentity(server.URL)}, Total: "1"})
		case request.URL.Path == "/v1/aep/agent-identities" && request.Method == http.MethodPost:
			provisionRequests.Add(1)
			http.Error(response, "unexpected provision", http.StatusInternalServerError)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	provider := newTestPlatformProvider(t, server, nil)
	identity, err := provider.GetOrCreateIdentity(context.Background(), IdentityRequest{ServiceDID: "did:web:service.example"})
	if err != nil {
		t.Fatal(err)
	}
	if identity.Metadata["agent_identity_id"] != "identity-1" || provisionRequests.Load() != 0 {
		t.Fatalf("active identity was not reused: identity=%#v provisions=%d", identity, provisionRequests.Load())
	}
}

func TestPlatformIdentityProviderEncodesOpaqueIdentityID(t *testing.T) {
	provider, err := NewPlatformIdentityProvider(PlatformIdentityProviderOptions{PlatformURL: "https://platform.example"})
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := provider.endpoint("/v1/aep/agent-identities/{agent_identity_id}/sign", "identity/one")
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.EscapedPath() != "/v1/aep/agent-identities/identity%2Fone/sign" {
		t.Fatalf("encoded endpoint path = %q", endpoint.EscapedPath())
	}
}

func TestPlatformIdentityProviderAcceptsCanonicalLoopbackDIDURL(t *testing.T) {
	provider, err := NewPlatformIdentityProvider(PlatformIdentityProviderOptions{AllowInsecureLoopback: true, PlatformURL: "http://127.0.0.1:4100"})
	if err != nil {
		t.Fatal(err)
	}
	identity := platformIdentity("http://127.0.0.1:4100")
	identity.DIDDocumentURL = "https://127.0.0.1:4100/agents/one/did.json"
	if _, err := provider.serviceIdentity(identity); err != nil {
		t.Fatalf("canonical loopback DID URL was rejected: %v", err)
	}
}

func TestPlatformIdentityProviderReturnsTypedPendingError(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == platform.WellKnownPath {
			writePlatformJSON(t, response, platformDiscovery(server.URL))
			return
		}
		response.Header().Set("Content-Type", aep.MediaType)
		response.WriteHeader(http.StatusAccepted)
		writePlatformJSON(t, response, platform.SignResponse{RetryAfterSeconds: "5", Status: platform.SignPending})
	}))
	defer server.Close()
	provider := newTestPlatformProvider(t, server, nil)
	identity, err := provider.serviceIdentity(platformIdentity(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := provider.SignerFor(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	_, err = signer(context.Background(), assertionClaims(identity), []aep.SigningAlgorithm{aep.SigningAlgorithmES256})
	var pending *PlatformSignPendingError
	if !errors.As(err, &pending) || pending.Pending.RetryAfterSeconds != 5 {
		t.Fatalf("expected typed pending error, got %v", err)
	}
}

func TestPlatformIdentityProviderReturnsTypedCommandError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		problem := aep.NewProblemDetails(aep.ErrorNotRecognized, "Identity not recognized", http.StatusNotFound)
		response.Header().Set("Content-Type", aep.ProblemMediaType)
		response.WriteHeader(http.StatusNotFound)
		writePlatformJSON(t, response, problem)
	}))
	defer server.Close()

	provider := newTestPlatformProvider(t, server, nil)
	endpoint, err := url.Parse(server.URL + "/v1/aep/agent-identities")
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = provider.command(context.Background(), http.MethodGet, endpoint, "", nil, &platform.AgentIdentityListResponse{})
	var commandError *PlatformCommandError
	if !errors.As(err, &commandError) || commandError.Status != http.StatusNotFound || commandError.Problem == nil || commandError.Problem.Code != aep.ErrorNotRecognized {
		t.Fatalf("expected typed Platform command error, got %v", err)
	}
}

func TestPlatformIdentityProviderRevalidatesDiscovery(t *testing.T) {
	var discoveryRequests atomic.Int32
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == platform.WellKnownPath {
			discoveryRequests.Add(1)
			response.Header().Set("Cache-Control", "no-cache")
			response.Header().Set("ETag", `"platform-1"`)
			if request.Header.Get("If-None-Match") == `"platform-1"` {
				response.WriteHeader(http.StatusNotModified)
				return
			}
			writePlatformJSON(t, response, struct {
				platform.DiscoveryDocument
				Extension bool `json:"extension"`
			}{DiscoveryDocument: platformDiscovery(server.URL), Extension: true})
			return
		}
		if request.URL.Path == "/v1/aep/agent-identities" {
			writePlatformJSON(t, response, platform.AgentIdentityListResponse{Count: "0", Data: []platform.AgentIdentity{}, Total: "0"})
			return
		}
		http.NotFound(response, request)
	}))
	defer server.Close()
	provider := newTestPlatformProvider(t, server, nil)
	for range 2 {
		if _, err := provider.FindIdentityByServiceDID(context.Background(), "did:web:service.example"); err != nil {
			t.Fatal(err)
		}
	}
	if discoveryRequests.Load() != 2 {
		t.Fatalf("discovery requests = %d, want 2", discoveryRequests.Load())
	}
}

func newTestPlatformProvider(t *testing.T, server *httptest.Server, resolver PlatformPendingSignResolver) *PlatformIdentityProvider {
	t.Helper()
	var keySequence atomic.Int32
	provider, err := NewPlatformIdentityProvider(PlatformIdentityProviderOptions{HTTPClient: server.Client(), IdempotencyKey: func() (string, error) { return fmt.Sprintf("key-%d", keySequence.Add(1)), nil }, PendingSignResolver: resolver, PlatformURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func platformDiscovery(serverURL string) platform.DiscoveryDocument {
	return platform.DiscoveryDocument{
		AEPVersion: aep.Version,
		Endpoints:  platform.DiscoveryEndpoints{Lifecycle: "/v1/aep/agent-identities/{agent_identity_id}", List: "/v1/aep/agent-identities", Provision: "/v1/aep/agent-identities", Sign: "/v1/aep/agent-identities/{agent_identity_id}/sign"},
		HTTP:       platform.DiscoveryHTTP{EndpointBase: "/v1/aep"},
		Identity:   platform.DiscoveryIdentity{DIDMethods: []string{"did:web"}, DIDURLTemplate: serverURL + "/agents/{agent_did_id}/did.json"},
		Platform:   platform.DiscoveryPlatform{Name: "Test Platform"},
		Signing:    platform.DiscoverySigning{Algorithms: []aep.SigningAlgorithm{aep.SigningAlgorithmES256}, DefaultLifetimeSeconds: "300"},
	}
}

func platformIdentity(serverURL string) platform.AgentIdentity {
	agentDID := "did:web:" + encodedTestHost(serverURL) + ":agents:one"
	return platform.AgentIdentity{AgentDID: agentDID, AgentIdentityID: "identity-1", CreatedAt: "2026-08-31T12:00:00Z", DIDDocumentURL: serverURL + "/agents/one/did.json", KeyID: agentDID, ServiceDID: "did:web:service.example", SigningAlgorithms: []aep.SigningAlgorithm{aep.SigningAlgorithmES256}, Status: platform.ManagedAgentActive, UpdatedAt: "2026-08-31T12:00:00Z"}
}

func assertionClaims(identity ServiceIdentity) aep.ClientAssertionClaims {
	return aep.ClientAssertionClaims{Audience: identity.ServiceDID, ExpiresAt: 1300, IssuedAt: 1000, Issuer: identity.AgentDID, JWTID: "assertion-1", Operation: aep.AssertionEnroll, Subject: identity.AgentDID}
}

func encodedTestHost(serverURL string) string {
	parsed, _ := url.Parse(serverURL)
	return strings.ReplaceAll(parsed.Host, ":", "%3A")
}

func assertPlatformHeaders(t *testing.T, request *http.Request) {
	t.Helper()
	if request.Header.Get("Authorization") != "Bearer rotating-token" || request.Header.Get("X-Tenant") != "tenant-1" || request.Header.Get("Accept") != aep.MediaType || request.Header.Get("Content-Type") != aep.MediaType || request.Header.Get("Idempotency-Key") != "idempotency-1" {
		t.Errorf("unexpected Platform headers: %#v", request.Header)
	}
}

func writePlatformJSON(t *testing.T, response http.ResponseWriter, value any) {
	t.Helper()
	response.Header().Set("Content-Type", aep.MediaType)
	if err := json.NewEncoder(response).Encode(value); err != nil {
		t.Errorf("write Platform response: %v", err)
	}
}
