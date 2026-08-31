package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	aep "github.com/aep-foundation/aep-go"
)

type testIdentityProvider struct {
	identity ServiceIdentity
	signer   AssertionSigner
	created  atomic.Int32
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func (provider *testIdentityProvider) GetOrCreateIdentity(_ context.Context, request IdentityRequest) (ServiceIdentity, error) {
	provider.created.Add(1)
	identity := cloneIdentity(provider.identity)
	identity.ServiceDID = request.ServiceDID
	return identity, nil
}

func (provider *testIdentityProvider) SignerFor(context.Context, ServiceIdentity) (AssertionSigner, error) {
	return provider.signer, nil
}

func newTestIdentityProvider(t *testing.T) *testIdentityProvider {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	agentDID := "did:web:agent.example:agents:1"
	return &testIdentityProvider{
		identity: ServiceIdentity{AgentDID: agentDID, IdentityMethod: aep.IdentityMethodDIDWeb, SigningAlgorithms: []aep.SigningAlgorithm{aep.SigningAlgorithmEdDSA}},
		signer: func(_ context.Context, claims aep.ClientAssertionClaims, algorithms []aep.SigningAlgorithm) (string, error) {
			if len(algorithms) != 1 || algorithms[0] != aep.SigningAlgorithmEdDSA {
				return "", errors.New("unexpected signing algorithms")
			}
			return aep.SignClientAssertion(claims, aep.SignClientAssertionOptions{
				Algorithm: aep.SigningAlgorithmEdDSA, Key: privateKey, KeyID: agentDID + "#key-1",
			})
		},
	}
}

func TestInspectAndCache(t *testing.T) {
	var requests atomic.Int32
	var serviceDID string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.URL.Path != aep.WellKnownPath {
			t.Fatalf("unexpected path %s", request.URL.Path)
		}
		if request.Header.Get("Accept") != aep.MediaType {
			t.Fatalf("unexpected Accept %s", request.Header.Get("Accept"))
		}
		response.Header().Set("Cache-Control", "max-age=300")
		response.Header().Set("Content-Type", aep.MediaType+"; charset=utf-8")
		response.Header().Set("ETag", `"inspect-1"`)
		_ = json.NewEncoder(response).Encode(testInspectDocument(serviceDID))
	}))
	defer server.Close()
	serviceDID = didWebForServer(server.URL)
	client := testClient(t, server, newTestIdentityProvider(t))
	session, err := client.Service(server.URL + "/ignored?q=1#fragment")
	if err != nil {
		t.Fatal(err)
	}
	first, err := session.Inspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	secondSession, err := client.Service(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	second, err := secondSession.Inspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 || first.Document.Service.DID != serviceDID || second.ETag != `"inspect-1"` {
		t.Fatalf("unexpected Inspect results: requests=%d first=%#v second=%#v", requests.Load(), first, second)
	}
	first.Document.Service.DID = "did:web:mutated.example"
	third, err := session.Inspect(context.Background())
	if err != nil || third.Document.Service.DID != serviceDID {
		t.Fatalf("caller mutated cached inspection: %#v, %v", third, err)
	}
}

func TestInspectDoesNotSendCookieJarCredentials(t *testing.T) {
	var serviceDID string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Cookie") != "" {
			t.Fatalf("Inspect sent cookies: %s", request.Header.Get("Cookie"))
		}
		response.Header().Set("Content-Type", aep.MediaType)
		_ = json.NewEncoder(response).Encode(testInspectDocument(serviceDID))
	}))
	defer server.Close()
	serviceDID = didWebForServer(server.URL)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	serverURL := mustURL(t, server.URL)
	jar.SetCookies(serverURL, []*http.Cookie{{Name: "session", Value: "secret"}})
	httpClient := server.Client()
	httpClient.Jar = jar
	client, err := New(Options{HTTPClient: httpClient, IdentityProvider: newTestIdentityProvider(t)})
	if err != nil {
		t.Fatal(err)
	}
	session, _ := client.Service(server.URL)
	if _, err := session.Inspect(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestInspectAndCommandsUseSeparateHTTPClients(t *testing.T) {
	var serviceDID string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", aep.MediaType)
		if request.URL.Path == aep.WellKnownPath {
			if request.Header.Get("X-Transport") != "inspect" {
				t.Fatalf("Inspect used the wrong HTTP client: %s", request.Header.Get("X-Transport"))
			}
			_ = json.NewEncoder(response).Encode(testInspectDocument(serviceDID))
			return
		}
		if request.Header.Get("X-Transport") != "command" {
			t.Fatalf("command used the wrong HTTP client: %s", request.Header.Get("X-Transport"))
		}
		_, _ = response.Write([]byte(`{"status":"active"}`))
	}))
	defer server.Close()
	serviceDID = didWebForServer(server.URL)
	transport := server.Client().Transport
	clientFor := func(name string) *http.Client {
		return &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			request.Header.Set("X-Transport", name)
			return transport.RoundTrip(request)
		})}
	}
	client, err := New(Options{
		CommandHTTPClient: clientFor("command"), IdentityProvider: newTestIdentityProvider(t),
		InspectHTTPClient: clientFor("inspect"),
	})
	if err != nil {
		t.Fatal(err)
	}
	session, _ := client.Service(server.URL)
	if _, err := session.Status(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestInspectConditionalRevalidation(t *testing.T) {
	clock := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	var serviceDID string
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		requests++
		response.Header().Set("Cache-Control", "max-age=0")
		response.Header().Set("ETag", `"inspect-1"`)
		if request.Header.Get("If-None-Match") == `"inspect-1"` {
			response.WriteHeader(http.StatusNotModified)
			return
		}
		response.Header().Set("Content-Type", aep.MediaType)
		_ = json.NewEncoder(response).Encode(testInspectDocument(serviceDID))
	}))
	defer server.Close()
	serviceDID = didWebForServer(server.URL)
	provider := newTestIdentityProvider(t)
	client, err := New(Options{Clock: func() time.Time { return clock }, HTTPClient: server.Client(), IdentityProvider: provider})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		session, sessionErr := client.Service(server.URL)
		if sessionErr != nil {
			t.Fatal(sessionErr)
		}
		if _, inspectErr := session.Inspect(context.Background()); inspectErr != nil {
			t.Fatal(inspectErr)
		}
	}
	if requests != 2 {
		t.Fatalf("expected conditional revalidation, got %d requests", requests)
	}
}

func TestInspectNoStoreIsNotReused(t *testing.T) {
	var requests atomic.Int32
	var serviceDID string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Content-Type", aep.MediaType)
		_ = json.NewEncoder(response).Encode(testInspectDocument(serviceDID))
	}))
	defer server.Close()
	serviceDID = didWebForServer(server.URL)
	client := testClient(t, server, newTestIdentityProvider(t))
	session, _ := client.Service(server.URL)
	for range 2 {
		if _, err := session.Inspect(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if requests.Load() != 2 {
		t.Fatalf("no-store Inspect document was reused: %d requests", requests.Load())
	}
}

func TestInspectRejectsUnsafeCachedFinalURL(t *testing.T) {
	var serviceDID string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "" {
			t.Errorf("Inspect sent authorization from cached URL: %s", request.Header.Get("Authorization"))
		}
		response.Header().Set("Content-Type", aep.MediaType)
		_ = json.NewEncoder(response).Encode(testInspectDocument(serviceDID))
	}))
	defer server.Close()
	serviceDID = didWebForServer(server.URL)
	cache := NewMemoryInspectCache()
	inspectURL := server.URL + aep.WellKnownPath
	credentialURL := strings.Replace(inspectURL, "https://", "https://user:pass@", 1)
	if err := cache.SaveInspect(context.Background(), inspectURL, InspectCacheEntry{
		CacheControl: "max-age=0", CachedAt: time.Now(), Document: testInspectDocument(serviceDID), FinalURL: credentialURL,
	}); err != nil {
		t.Fatal(err)
	}
	client, err := New(Options{HTTPClient: server.Client(), IdentityProvider: newTestIdentityProvider(t), InspectCache: cache})
	if err != nil {
		t.Fatal(err)
	}
	session, _ := client.Service(server.URL)
	if _, err := session.Inspect(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityChangesWithServiceDID(t *testing.T) {
	var serviceDID atomic.Value
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Content-Type", aep.MediaType)
		_ = json.NewEncoder(response).Encode(testInspectDocument(serviceDID.Load().(string)))
	}))
	defer server.Close()
	baseDID := didWebForServer(server.URL)
	serviceDID.Store(baseDID + ":first")
	provider := newTestIdentityProvider(t)
	client := testClient(t, server, provider)
	session, _ := client.Service(server.URL)
	first, err := session.Identity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	serviceDID.Store(baseDID + ":second")
	second, err := session.Identity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first.ServiceDID == second.ServiceDID || provider.created.Load() != 2 {
		t.Fatalf("Service DID change reused an identity: first=%s second=%s created=%d", first.ServiceDID, second.ServiceDID, provider.created.Load())
	}
}

func TestConcurrentSessionsShareServiceIdentity(t *testing.T) {
	var serviceDID string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", aep.MediaType)
		_ = json.NewEncoder(response).Encode(testInspectDocument(serviceDID))
	}))
	defer server.Close()
	serviceDID = didWebForServer(server.URL)
	provider := newTestIdentityProvider(t)
	client := testClient(t, server, provider)
	const sessions = 16
	errorsFound := make(chan error, sessions)
	var wait sync.WaitGroup
	for range sessions {
		wait.Add(1)
		go func() {
			defer wait.Done()
			session, err := client.Service(server.URL)
			if err == nil {
				_, err = session.Identity(context.Background())
			}
			errorsFound <- err
		}()
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatal(err)
		}
	}
	if provider.created.Load() != 1 {
		t.Fatalf("concurrent sessions created %d Service identities", provider.created.Load())
	}
}

func TestInspectRejectsUnsafeResponses(t *testing.T) {
	tests := []struct {
		name    string
		handler http.Handler
		code    InspectErrorCode
	}{
		{name: "media type", code: InspectInvalidMediaType, handler: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`{}`))
		})},
		{name: "malformed JSON", code: InspectInvalidJSON, handler: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			response.Header().Set("Content-Type", aep.MediaType)
			_, _ = response.Write([]byte(`{"aep_version":`))
		})},
		{name: "too large", code: InspectResponseTooLarge, handler: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			response.Header().Set("Content-Type", aep.MediaType)
			_, _ = response.Write([]byte(strings.Repeat("x", 65)))
		})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(test.handler)
			defer server.Close()
			client, err := New(Options{HTTPClient: server.Client(), IdentityProvider: newTestIdentityProvider(t), MaximumResponseBytes: 64})
			if err != nil {
				t.Fatal(err)
			}
			session, err := client.Service(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			_, err = session.Inspect(context.Background())
			var inspectErr *InspectError
			if !errors.As(err, &inspectErr) || inspectErr.Code != test.code {
				t.Fatalf("expected %s, got %v", test.code, err)
			}
		})
	}
}

func TestInspectRedirectAndServiceIdentityBinding(t *testing.T) {
	t.Run("same origin", func(t *testing.T) {
		var serviceDID string
		server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.URL.Path == aep.WellKnownPath {
				http.Redirect(response, request, "/metadata/aep", http.StatusTemporaryRedirect)
				return
			}
			response.Header().Set("Content-Type", aep.MediaType)
			_ = json.NewEncoder(response).Encode(testInspectDocument(serviceDID))
		}))
		defer server.Close()
		serviceDID = didWebForServer(server.URL)
		client := testClient(t, server, newTestIdentityProvider(t))
		session, _ := client.Service(server.URL)
		result, err := session.Inspect(context.Background())
		if err != nil || result.FinalURL.Path != "/metadata/aep" {
			t.Fatalf("unexpected redirect result: %#v, %v", result, err)
		}
	})

	t.Run("redirect credentials", func(t *testing.T) {
		var serverURL string
		server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.URL.Path == aep.WellKnownPath {
				target := strings.Replace(serverURL, "https://", "https://user:pass@", 1) + "/metadata/aep"
				http.Redirect(response, request, target, http.StatusFound)
				return
			}
			http.Error(response, "unexpected redirect follow", http.StatusInternalServerError)
		}))
		defer server.Close()
		serverURL = server.URL
		client := testClient(t, server, newTestIdentityProvider(t))
		session, _ := client.Service(server.URL)
		_, err := session.Inspect(context.Background())
		var inspectErr *InspectError
		if !errors.As(err, &inspectErr) || inspectErr.Code != InspectInvalidRedirect {
			t.Fatalf("credential-bearing redirect was not rejected: %v", err)
		}
	})

	t.Run("cross origin", func(t *testing.T) {
		target := httptest.NewTLSServer(http.NotFoundHandler())
		defer target.Close()
		server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			http.Redirect(response, request, target.URL, http.StatusFound)
		}))
		defer server.Close()
		client := testClient(t, server, newTestIdentityProvider(t))
		session, _ := client.Service(server.URL)
		_, err := session.Inspect(context.Background())
		var inspectErr *InspectError
		if !errors.As(err, &inspectErr) || inspectErr.Code != InspectInvalidRedirect {
			t.Fatalf("cross-origin redirect was not rejected: %v", err)
		}
	})

	t.Run("DID mismatch", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			response.Header().Set("Content-Type", aep.MediaType)
			_ = json.NewEncoder(response).Encode(testInspectDocument("did:web:different.example"))
		}))
		defer server.Close()
		client := testClient(t, server, newTestIdentityProvider(t))
		session, _ := client.Service(server.URL)
		_, err := session.Inspect(context.Background())
		var inspectErr *InspectError
		if !errors.As(err, &inspectErr) || inspectErr.Code != InspectServiceIdentityMismatch {
			t.Fatalf("Service identity mismatch was not rejected: %v", err)
		}
	})
}

func TestLifecycleAndCredentials(t *testing.T) {
	var serviceDID string
	provider := newTestIdentityProvider(t)
	var statusCalls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == aep.WellKnownPath {
			response.Header().Set("Content-Type", aep.MediaType)
			_ = json.NewEncoder(response).Encode(testInspectDocument(serviceDID))
			return
		}
		if !strings.HasPrefix(request.Header.Get("Authorization"), "AEP ") {
			t.Fatalf("missing AEP assertion: %s", request.Header.Get("Authorization"))
		}
		response.Header().Set("Content-Type", aep.MediaType)
		switch request.URL.Path {
		case "/aep/enroll":
			assertMutationHeaders(t, request)
			var body aep.EnrollRequest
			decodeRequest(t, request, &body)
			if body.AgentDID != provider.identity.AgentDID || body.IdempotencyKey != request.Header.Get("Idempotency-Key") {
				t.Fatalf("unexpected Enroll body %#v", body)
			}
			_, _ = response.Write([]byte(`{"status":"active"}`))
		case "/aep/status":
			statusCalls.Add(1)
			_, _ = response.Write([]byte(`{"status":"active"}`))
		case "/aep/grant":
			assertMutationHeaders(t, request)
			_, _ = response.Write([]byte(`{"access_token":"token","credential_id":"credential-1","expires_at":"2027-01-01T00:00:00Z","scopes":["read"],"token_type":"Bearer"}`))
		case "/aep/revoke":
			assertMutationHeaders(t, request)
			_, _ = response.Write([]byte(`{}`))
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	serviceDID = didWebForServer(server.URL)
	client := testClient(t, server, provider)
	session, _ := client.Service(server.URL)
	if _, err := session.Enroll(context.Background(), EnrollOptions{}); err != nil {
		t.Fatal(err)
	}
	grant, err := session.Grant(context.Background(), GrantOptions{GrantType: aep.GrantTypeOAuthBearer, RequestedScopes: []string{"read"}})
	if err != nil || grant.Body.Credential == nil || statusCalls.Load() != 1 {
		t.Fatalf("unexpected Grant: %#v, status=%d, error=%v", grant, statusCalls.Load(), err)
	}
	headers, err := session.AuthenticationHeaders(context.Background(), AuthenticationOptions{Resource: mustURL(t, server.URL+"/private")})
	if err != nil || headers.Get("Authorization") != "Bearer token" {
		t.Fatalf("unexpected credential headers: %#v, %v", headers, err)
	}
	if _, err := session.Revoke(context.Background(), RevokeOptions{CredentialID: "credential-1", GrantType: aep.GrantTypeOAuthBearer}); err != nil {
		t.Fatal(err)
	}
	record, err := client.credentialStore.FindCredential(context.Background(), serviceDID, "credential-1")
	if err != nil {
		t.Fatal(err)
	} else if record != nil {
		t.Fatal("revoked credential remained stored")
	}
}

func TestGrantDoesNotCreateIdentity(t *testing.T) {
	var serviceDID string
	provider := newTestIdentityProvider(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", aep.MediaType)
		_ = json.NewEncoder(response).Encode(testInspectDocument(serviceDID))
	}))
	defer server.Close()
	serviceDID = didWebForServer(server.URL)
	client := testClient(t, server, provider)
	session, _ := client.Service(server.URL)
	if _, err := session.Grant(context.Background(), GrantOptions{}); err == nil {
		t.Fatal("Grant without an existing identity was accepted")
	}
	if provider.created.Load() != 0 {
		t.Fatal("Grant implicitly created an identity")
	}
}

func TestWaitForActiveCancellation(t *testing.T) {
	var serviceDID string
	provider := newTestIdentityProvider(t)
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
	client := testClient(t, server, provider)
	session, _ := client.Service(server.URL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := session.WaitForActive(ctx, WaitOptions{Interval: time.Millisecond}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

func TestJWTAuthenticationAndOmittedMethods(t *testing.T) {
	for _, advertised := range []bool{true, false} {
		t.Run(map[bool]string{true: "advertised", false: "omitted"}[advertised], func(t *testing.T) {
			var serviceDID string
			provider := newTestIdentityProvider(t)
			server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				document := testInspectDocument(serviceDID)
				if !advertised {
					document.Authentication = nil
				} else {
					document.Authentication.Methods = []aep.AuthenticationMethod{aep.AuthenticationMethodJWT}
				}
				response.Header().Set("Content-Type", aep.MediaType)
				_ = json.NewEncoder(response).Encode(document)
			}))
			defer server.Close()
			serviceDID = didWebForServer(server.URL)
			client := testClient(t, server, provider)
			session, _ := client.Service(server.URL)
			headers, err := session.AuthenticationHeaders(context.Background(), AuthenticationOptions{
				ClientAssertionOnly: true, Resource: mustURL(t, server.URL+"/private"),
			})
			if advertised {
				if err != nil || !strings.HasPrefix(headers.Get("Authorization"), "AEP ") {
					t.Fatalf("unexpected JWT headers: %#v, %v", headers, err)
				}
			} else if !errors.Is(err, ErrNoAuthenticationMethod) {
				t.Fatalf("omitted methods inferred JWT: %v", err)
			}
		})
	}
}

func testClient(t *testing.T, server *httptest.Server, provider IdentityProvider) *Client {
	t.Helper()
	client, err := New(Options{HTTPClient: server.Client(), IdentityProvider: provider})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func testInspectDocument(serviceDID string) aep.InspectDocument {
	return aep.InspectDocument{
		AEPVersion: aep.Version,
		Authentication: &aep.Authentication{Methods: []aep.AuthenticationMethod{
			aep.AuthenticationMethod(aep.GrantTypeOAuthBearer), aep.AuthenticationMethodJWT,
		}},
		Bindings: aep.Bindings{Supported: []aep.Binding{aep.BindingHTTP}},
		Commands: aep.Commands{
			Supported:  []aep.Command{aep.CommandEnroll, aep.CommandGrant, aep.CommandInspect, aep.CommandRevoke, aep.CommandStatus},
			GrantTypes: []aep.GrantType{aep.GrantTypeOAuthBearer},
			GrantTypesConfig: map[string]aep.GrantTypeConfig{
				string(aep.GrantTypeOAuthBearer): {SupportsPerCredentialRevoke: "true"},
			},
		},
		Core:     aep.Core{SigningAlgorithms: []aep.SigningAlgorithm{aep.SigningAlgorithmES256, aep.SigningAlgorithmEdDSA}},
		HTTP:     aep.HTTPConfiguration{EndpointBase: "/aep/"},
		Identity: aep.Identity{Methods: []aep.IdentityMethod{aep.IdentityMethodDIDWeb}},
		Service:  aep.ServiceIdentity{DID: serviceDID},
	}
}

func didWebForServer(serverURL string) string {
	parsed, _ := url.Parse(serverURL)
	return "did:web:" + strings.ReplaceAll(parsed.Host, ":", "%3A")
}

func assertMutationHeaders(t *testing.T, request *http.Request) {
	t.Helper()
	if request.Header.Get("Content-Type") != aep.MediaType || request.Header.Get("Idempotency-Key") == "" {
		t.Fatalf("missing mutation headers: %#v", request.Header)
	}
}

func decodeRequest(t *testing.T, request *http.Request, target any) {
	t.Helper()
	if err := json.NewDecoder(request.Body).Decode(target); err != nil {
		t.Fatal(err)
	}
}

func mustURL(t *testing.T, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
