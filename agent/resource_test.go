package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	aep "github.com/aep-foundation/aep-go"
	"github.com/aep-foundation/aep-go/service"
)

type resourceCapture struct {
	path, method, body string
	headers            http.Header
}

func TestPublicOpenAPIChallengeRevalidation(t *testing.T) {
	for _, outcome := range []string{"updated", "unchanged", "failed", "cancelled", "public"} {
		t.Run(outcome, func(t *testing.T) {
			f := newResourceFixture(t, aep.AuthenticationMethodJWT, true)
			f.enroll(t)
			f.public.Store(outcome == "public")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var documents int
			transport := f.client.inspectHTTPClient.Transport
			f.client.inspectHTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path != "/openapi.json" {
					return transport.RoundTrip(r)
				}
				documents++
				expected := http.Header{"Accept": {"application/vnd.oai.openapi+json;version=3.1, application/json"}}
				if documents > 1 {
					expected.Set("If-None-Match", `"public-v1"`)
				}
				if !reflect.DeepEqual(r.Header, expected) {
					t.Errorf("metadata headers: %v", r.Header)
				}
				status := http.StatusOK
				body := `{"openapi":"3.1.0","security":[],"paths":{"/resource":{"get":{}}}}`
				if documents > 1 {
					switch outcome {
					case "cancelled":
						cancel()
						return nil, context.Canceled
					case "failed":
						return nil, errors.New("offline")
					case "unchanged":
						status = http.StatusNotModified
						body = ""
					default:
						body = `{"openapi":"3.1.0","security":[{"jwt":[]}],"paths":{"/resource":{"get":{}}},"components":{"securitySchemes":{"jwt":{"x-aep-authentication-method":"aep-jwt"}}}}`
					}
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}, "Cache-Control": {"max-age=3600"}, "Etag": {`"public-v1"`}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})}
			target, _ := url.Parse(f.server.URL + "/resource")
			policy, err := f.session.OpenAPIPolicy(ctx, http.MethodGet, target)
			if err != nil || policy.State != "public" || documents != 1 {
				t.Fatalf("warm cache: %v %v", policy, err)
			}
			request, _ := http.NewRequest(http.MethodGet, target.String(), nil)
			request.Header.Set("Cookie", "secret")
			request.Header.Set("Authorization", "Bearer secret")
			response, err := f.client.FetchProtectedResource(ctx, request, ProtectedResourceOptions{})
			if outcome == "cancelled" {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation: %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
				if response.StatusCode != http.StatusOK {
					t.Fatalf("status: %d", response.StatusCode)
				}
			}
			attempts := []bool{}
			for _, captured := range f.captured() {
				if captured.path == "/resource" {
					attempts = append(attempts, captured.headers.Get("Authorization") != "")
				}
			}
			expected := []bool{false, true}
			expectedDocuments := 2
			if outcome == "cancelled" || outcome == "public" {
				expected = []bool{false}
			}
			if outcome == "public" {
				expectedDocuments = 1
			}
			if documents != expectedDocuments || !reflect.DeepEqual(attempts, expected) {
				t.Fatalf("documents=%d attempts=%v", documents, attempts)
			}
			if outcome == "updated" {
				policy, err = f.session.OpenAPIPolicy(ctx, http.MethodGet, target)
				if err != nil || policy.State != "required" || documents != 2 {
					t.Fatalf("updated cache: %v %v", policy, err)
				}
			}
		})
	}
}

type resourceFixture struct {
	privateKey ed25519.PrivateKey
	server     *httptest.Server
	provider   *testIdentityProvider
	client     *Client
	session    *Session
	did        string
	grants     atomic.Int32
	redirect   atomic.Value
	public     atomic.Bool
	mu         sync.Mutex
	requests   []resourceCapture
	assertions []aep.ClientAssertionClaims
}

func newResourceFixture(t *testing.T, method aep.AuthenticationMethod, openAPI bool, existingKey ...ed25519.PrivateKey) *resourceFixture {
	t.Helper()
	f := &resourceFixture{}
	f.redirect.Store("")
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(existingKey) != 0 {
		private = existingKey[0]
		public = private.Public().(ed25519.PublicKey)
	}
	f.privateKey = private
	f.provider = newTestIdentityProvider(t)
	f.provider.signer = func(_ context.Context, claims aep.ClientAssertionClaims, _ []aep.SigningAlgorithm) (string, error) {
		return aep.SignClientAssertion(claims, aep.SignClientAssertionOptions{Algorithm: aep.SigningAlgorithmEdDSA, Key: private, KeyID: f.provider.identity.AgentDID + "#key-1"})
	}
	mux := http.NewServeMux()
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read failed", 400)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(data))
		f.mu.Lock()
		f.requests = append(f.requests, resourceCapture{r.URL.Path, r.Method, string(data), r.Header.Clone()})
		f.mu.Unlock()
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(f.server.Close)
	f.did = didWebForServer(f.server.URL)
	inspectURL, _ := url.Parse(f.server.URL + aep.WellKnownPath)
	options := service.Options{ServiceDID: f.did, InspectURL: inspectURL, IdentityMethods: []aep.IdentityMethod{aep.IdentityMethodDIDWeb}, AuthenticationMethods: []aep.AuthenticationMethod{method},
		Verifier: func(ctx context.Context, assertion string, verification service.AssertionVerificationContext) (aep.ClientAssertionClaims, error) {
			claims, err := aep.VerifyClientAssertion(ctx, assertion, aep.VerifyClientAssertionOptions{Algorithms: verification.SigningAlgorithms, Audience: verification.ServiceDID, CurrentTime: verification.CurrentTime, Key: public, Operation: verification.Operation, Resource: verification.Resource})
			if err == nil && verification.Operation == aep.AssertionAuthenticate {
				f.mu.Lock()
				f.assertions = append(f.assertions, claims)
				f.mu.Unlock()
			}
			return claims, err
		},
	}
	store := service.NewMemoryServiceCredentialStore()
	var grant service.GrantTypeDefinition
	switch method {
	case aep.AuthenticationMethod(aep.GrantTypeAPIKey):
		grant, err = service.StoredAPIKeyGrantType(service.StoredCredentialGrantTypeOptions[aep.APIKeyGrantResponse]{Store: store, Config: aep.GrantTypeConfig{Additional: aep.AdditionalMembers{"header_names": json.RawMessage(`["X-Agent-Key"]`)}}, Issue: func(_ context.Context, _ aep.GrantRequest, c service.GrantContext) (aep.APIKeyGrantResponse, error) {
			f.grants.Add(1)
			return aep.APIKeyGrantResponse{APIKey: f.did + "-secret", CredentialID: "credential", Header: "X-Agent-Key", Scopes: []string{}, ExpiresAt: c.Now.Add(time.Hour).Format(time.RFC3339)}, nil
		}})
	case aep.AuthenticationMethod(aep.GrantTypeOAuthBearer):
		grant, err = service.StoredOAuthBearerGrantType(service.StoredCredentialGrantTypeOptions[aep.OAuthBearerGrantResponse]{Store: store, Issue: func(_ context.Context, _ aep.GrantRequest, c service.GrantContext) (aep.OAuthBearerGrantResponse, error) {
			f.grants.Add(1)
			return aep.OAuthBearerGrantResponse{AccessToken: "token", CredentialID: "credential", TokenType: "Bearer", Scopes: []string{}, ExpiresAt: c.Now.Add(time.Hour).Format(time.RFC3339)}, nil
		}})
	case aep.AuthenticationMethod(aep.GrantTypeBasic):
		grant, err = service.StoredBasicGrantType(service.StoredCredentialGrantTypeOptions[aep.BasicGrantResponse]{Store: store, Issue: func(_ context.Context, _ aep.GrantRequest, c service.GrantContext) (aep.BasicGrantResponse, error) {
			f.grants.Add(1)
			return aep.BasicGrantResponse{Username: "user", Password: "secret", CredentialID: "credential", Scopes: []string{}, ExpiresAt: c.Now.Add(time.Hour).Format(time.RFC3339)}, nil
		}})
	}
	if err != nil {
		t.Fatal(err)
	}
	if method != aep.AuthenticationMethodJWT {
		options.GrantTypes = []service.GrantTypeDefinition{grant}
	}
	if openAPI {
		options.OpenAPI = &aep.OpenAPIReference{URL: "/openapi.json", PathMatching: aep.OpenAPIPathMatching{TrailingSlash: "strict"}}
		mux.HandleFunc("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"openapi":"3.1.0","security":[{"auth":[]}],"paths":{"/resource":{"post":{},"get":{}},"/redirect":{"post":{},"get":{}}},"components":{"securitySchemes":{"auth":{"x-aep-authentication-method":%q}}}}`, method)
		})
	}
	engine, err := service.New(options)
	if err != nil {
		t.Fatal(err)
	}
	protocol, err := service.NewHTTPHandler(engine, service.HTTPHandlerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle(aep.WellKnownPath, protocol)
	mux.Handle("/aep/", protocol)
	protect, err := service.NewProtectedResourceMiddleware(engine, f.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	protected := protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			w.Header().Set("Location", f.redirect.Load().(string))
			w.WriteHeader(307)
			return
		}
		io.Copy(w, r.Body)
	}))
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.public.Load() {
			io.WriteString(w, "public")
			return
		}
		protected.ServeHTTP(w, r)
	}))
	f.client, err = New(Options{IdentityProvider: f.provider, HTTPClient: f.server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	f.session, err = f.client.Service(f.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *resourceFixture) captured() []resourceCapture {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]resourceCapture(nil), f.requests...)
}

func (f *resourceFixture) enroll(t *testing.T) {
	t.Helper()
	result, err := f.session.Enroll(context.Background(), EnrollOptions{})
	if err != nil || result.Body.Status != aep.AgentActive {
		t.Fatalf("Enroll: %#v %v", result, err)
	}
}

func TestFetchResourceGrantsAfterExplicitEnrollment(t *testing.T) {
	for _, method := range []aep.AuthenticationMethod{"api-key", "oauth-bearer", "basic"} {
		t.Run(string(method), func(t *testing.T) {
			f := newResourceFixture(t, method, false)
			f.enroll(t)
			request, _ := http.NewRequest("POST", f.server.URL+"/resource", strings.NewReader("identical body"))
			request.Header.Set("Content-Type", "text/plain")
			before := request.Header.Clone()
			for i := 0; i < 2; i++ {
				response, err := f.client.FetchProtectedResource(context.Background(), request, ProtectedResourceOptions{})
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil || response.StatusCode != 200 || string(body) != "identical body" {
					t.Fatalf("%d %s %v", response.StatusCode, body, err)
				}
			}
			if f.grants.Load() != 1 {
				t.Fatalf("Grant count %d", f.grants.Load())
			}
			enrolls := 0
			resources := 0
			for _, r := range f.captured() {
				if r.path == "/aep/enroll" {
					enrolls++
				}
				if r.path == "/resource" {
					resources++
					if r.method != "POST" || r.body != "identical body" {
						t.Fatalf("changed request: %+v", r)
					}
				}
			}
			if enrolls != 1 || resources != 4 || !reflect.DeepEqual(request.Header, before) {
				t.Fatalf("enrolls=%d resources=%d", enrolls, resources)
			}
			original, _ := io.ReadAll(request.Body)
			request.Body.Close()
			if string(original) != "identical body" {
				t.Fatal("consumed caller body")
			}
		})
	}
}

func TestFetchResourceNeverEnrollsImplicitly(t *testing.T) {
	f := newResourceFixture(t, "api-key", false)
	request, _ := http.NewRequest("GET", f.server.URL+"/resource", nil)
	_, err := f.client.FetchProtectedResource(context.Background(), request, ProtectedResourceOptions{})
	if err == nil || f.grants.Load() != 0 || f.provider.created.Load() != 0 {
		t.Fatalf("unexpected implicit enrollment: %v", err)
	}
	for _, r := range f.captured() {
		if r.path == "/aep/enroll" || r.path == "/aep/grant" {
			t.Fatalf("unexpected command %s", r.path)
		}
	}
}

func TestFetchResourceRebindsJWTAndPreservesPaymentCarrier(t *testing.T) {
	for _, carrier := range []aep.ProtectedResourceCarrier{aep.ProtectedResourceStandard, aep.ProtectedResourceDedicated} {
		t.Run(string(carrier), func(t *testing.T) {
			f := newResourceFixture(t, aep.AuthenticationMethodJWT, false)
			f.redirect.Store("/resource")
			f.enroll(t)
			request, _ := http.NewRequest("POST", f.server.URL+"/redirect", strings.NewReader("payload"))
			request.Header.Set("Authorization", "Payment secret")
			request.Header.Set("PAYMENT-SIGNATURE", "payment-proof")
			response, err := f.client.FetchProtectedResource(context.Background(), request, ProtectedResourceOptions{Authentication: AuthenticationOptions{Carrier: carrier}})
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode != 200 {
				t.Fatalf("status %d", response.StatusCode)
			}
			f.mu.Lock()
			claims := append([]aep.ClientAssertionClaims(nil), f.assertions...)
			f.mu.Unlock()
			if len(claims) != 2 || claims[0].JWTID == claims[1].JWTID || claims[0].Resource != f.server.URL+"/redirect" || claims[1].Resource != f.server.URL+"/resource" {
				t.Fatalf("assertions %#v", claims)
			}
			header, _ := aep.ProtectedResourceAuthorizationHeader(carrier)
			for _, r := range f.captured() {
				if r.path != "/redirect" && r.path != "/resource" {
					continue
				}
				if r.headers.Get(header) == "" {
					if r.headers.Get("Authorization") != "" || r.headers.Get("PAYMENT-SIGNATURE") != "" {
						t.Fatal("anonymous probe leaked payment")
					}
				} else if carrier == aep.ProtectedResourceDedicated && r.headers.Get("Authorization") != "Payment secret" {
					t.Fatal("lost payment carrier")
				}
			}
		})
	}
}

func TestFetchResourceCrossOriginRequiresFreshChallenge(t *testing.T) {
	for _, public := range []bool{false, true} {
		t.Run(fmt.Sprint(public), func(t *testing.T) {
			source := newResourceFixture(t, "api-key", true)
			target := newResourceFixture(t, "api-key", true, source.privateKey)
			target.public.Store(public)
			source.redirect.Store(target.server.URL + "/resource")
			source.enroll(t)
			targetSession, err := source.client.Service(target.server.URL)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := targetSession.Enroll(context.Background(), EnrollOptions{}); err != nil {
				t.Fatal(err)
			}
			request, _ := http.NewRequest("GET", source.server.URL+"/redirect", nil)
			request.Header.Set("X-Caller-Key", "secret")
			request.Header.Set("Cookie", "session=secret")
			request.Header.Set("Authorization", "Payment secret")
			response, err := source.client.FetchProtectedResource(context.Background(), request, ProtectedResourceOptions{AdditionalAuthenticationHeaders: http.Header{"PAYMENT-SIGNATURE": {"proof"}}})
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode != 200 {
				t.Fatalf("status %d", response.StatusCode)
			}
			resources := 0
			for _, r := range target.captured() {
				if r.headers.Get("X-Caller-Key") != "" || r.headers.Get("Cookie") != "" || r.headers.Get("PAYMENT-SIGNATURE") != "" {
					t.Fatalf("cross-origin leak: %s", r.path)
				}
				if r.path == "/resource" {
					resources++
					if resources == 1 && (r.headers.Get("X-Agent-Key") != "" || r.headers.Get("Authorization") != "") {
						t.Fatal("destination authenticated without challenge")
					}
					if resources == 2 && r.headers.Get("X-Agent-Key") != target.did+"-secret" {
						t.Fatal("used source credential at destination")
					}
				}
			}
			if public {
				if resources != 1 || target.grants.Load() != 0 {
					t.Fatal("authenticated public destination")
				}
			} else if resources != 2 || target.grants.Load() != 1 {
				t.Fatal("did not authenticate after destination challenge")
			}
		})
	}
}

func TestFetchResourceRejectsUnreplayableBodyBeforeDiscovery(t *testing.T) {
	f := newResourceFixture(t, "api-key", false)
	request, _ := http.NewRequest("POST", f.server.URL+"/resource", io.NopCloser(strings.NewReader("stream")))
	if _, err := f.client.FetchProtectedResource(context.Background(), request, ProtectedResourceOptions{}); err == nil {
		t.Fatal("stream accepted")
	}
	if len(f.captured()) != 0 {
		t.Fatal("discovery started before replay validation")
	}
}

func TestFetchResourceDoesNotReplaceExplicitMissingCredential(t *testing.T) {
	f := newResourceFixture(t, "api-key", false)
	f.enroll(t)
	request, _ := http.NewRequest("GET", f.server.URL+"/resource", nil)
	_, err := f.client.FetchProtectedResource(context.Background(), request, ProtectedResourceOptions{Authentication: AuthenticationOptions{CredentialID: "missing"}})
	if !errors.Is(err, errCredentialNotFound) || f.grants.Load() != 0 {
		t.Fatalf("%v grants=%d", err, f.grants.Load())
	}
}

func TestFetchResourceChallengesAndHTTPFailures(t *testing.T) {
	for _, scenario := range []string{"public", "unrelated", "invalid", "duplicate", "wrong-did", "wrong-origin", "forbidden", "server-error", "missing-location", "unsafe-location", "loop", "cancel"} {
		t.Run(scenario, func(t *testing.T) {
			var stub *serviceStub
			stub = newServiceStub(t, func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != "/resource" {
					t.Errorf("unexpected command %s", r.URL.Path)
					return false
				}
				switch scenario {
				case "public":
					io.WriteString(w, "public")
					return true
				case "forbidden":
					w.WriteHeader(403)
					return true
				case "server-error":
					w.WriteHeader(500)
					return true
				case "missing-location":
					w.WriteHeader(302)
					return true
				case "unsafe-location":
					w.Header().Set("Location", "https://user:password@example.com/")
					w.WriteHeader(302)
					return true
				case "loop":
					w.Header().Set("Location", "/resource")
					w.WriteHeader(307)
					return true
				case "cancel":
					<-r.Context().Done()
					return true
				}
				challenge := fmt.Sprintf(`AEP service_did="%s",inspect="%s/.well-known/aep"`, stub.serviceDID, stub.server.URL)
				switch scenario {
				case "unrelated":
					challenge = `Bearer realm="other"`
				case "invalid":
					challenge = `AEP service_did="one"`
				case "duplicate":
					challenge += `,service_did="two"`
				case "wrong-did":
					challenge = fmt.Sprintf(`AEP service_did="did:web:wrong.example",inspect="%s/.well-known/aep"`, stub.server.URL)
				case "wrong-origin":
					challenge = `AEP service_did="did:web:wrong.example",inspect="https://wrong.example/.well-known/aep"`
				}
				w.Header().Set("WWW-Authenticate", challenge)
				w.WriteHeader(401)
				io.WriteString(w, "authentication response")
				return true
			})
			stub.client.requestTimeout = 200 * time.Millisecond
			request, _ := http.NewRequest("GET", stub.server.URL+"/resource", nil)
			response, err := stub.client.FetchProtectedResource(context.Background(), request, ProtectedResourceOptions{MaximumRedirects: 2})
			fails := scenario == "wrong-did" || scenario == "wrong-origin" || scenario == "missing-location" || scenario == "unsafe-location" || scenario == "loop" || scenario == "cancel"
			if fails {
				if err == nil {
					response.Body.Close()
					t.Fatal("unsafe/failed request accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			body, readErr := io.ReadAll(response.Body)
			response.Body.Close()
			if readErr != nil {
				t.Fatal(readErr)
			}
			if response.StatusCode == 401 && string(body) != "authentication response" {
				t.Fatal("response body was closed early")
			}
			if len(stub.requests) != 1 {
				t.Fatalf("unexpected retries %d", len(stub.requests))
			}
		})
	}
}

type resourceFailingStore struct{ CredentialStore }

func (resourceFailingStore) ListCredentials(context.Context, string) ([]CredentialRecord, error) {
	return nil, errors.New("store unavailable")
}

func TestFetchResourceDoesNotGrantOnStoreOrSigningFailure(t *testing.T) {
	for _, failure := range []string{"store", "signer", "pending", "excluded", "assertion-only"} {
		t.Run(failure, func(t *testing.T) {
			f := newResourceFixture(t, "oauth-bearer", true)
			f.enroll(t)
			options := ProtectedResourceOptions{}
			switch failure {
			case "store":
				f.client.credentialStore = resourceFailingStore{f.client.credentialStore}
			case "signer":
				f.provider.signer = func(context.Context, aep.ClientAssertionClaims, []aep.SigningAlgorithm) (string, error) {
					return "", errors.New("signer unavailable")
				}
			case "pending":
				f.provider.signer = func(context.Context, aep.ClientAssertionClaims, []aep.SigningAlgorithm) (string, error) {
					return "", &PlatformSignPendingError{}
				}
			case "excluded":
				options.Authentication.GrantType = aep.GrantTypeAPIKey
			case "assertion-only":
				options.Authentication.ClientAssertionOnly = true
			}
			request, _ := http.NewRequest("GET", f.server.URL+"/resource", nil)
			_, err := f.client.FetchProtectedResource(context.Background(), request, options)
			if err == nil || f.grants.Load() != 0 {
				t.Fatalf("%v grants=%d", err, f.grants.Load())
			}
			for _, r := range f.captured() {
				if r.path == "/aep/grant" {
					t.Fatal("failed dependency triggered Grant")
				}
			}
		})
	}
}

func TestResourceRedirectValidation(t *testing.T) {
	client := &Client{allowInsecureLoopback: true}
	current, _ := url.Parse("https://source.example/resource")
	for _, location := range []string{"", "://bad", "file:///tmp/test", "https://user@other.example/", "http://127.0.0.1/resource", "https://other.example/#fragment"} {
		response := &http.Response{Header: http.Header{"Location": {location}}}
		if _, err := client.resourceRedirect(response, current, 0, 5); err == nil {
			t.Fatalf("accepted %s", location)
		}
	}
	response := &http.Response{Header: http.Header{"Location": {"/next"}}}
	if _, err := client.resourceRedirect(response, current, 5, 5); err == nil {
		t.Fatal("limit ignored")
	}
	if next, err := client.resourceRedirect(response, current, 0, 5); err != nil || next.String() != "https://source.example/next" {
		t.Fatalf("%v %v", next, err)
	}
}

func TestFetchResourceRequestValidation(t *testing.T) {
	f := newResourceFixture(t, "api-key", false)
	for _, scenario := range []string{"nil", "url", "trailer", "get-body-error", "get-body-nil", "carrier", "conflicting-selection", "limit", "unsafe-url", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			request, _ := http.NewRequest("POST", f.server.URL+"/resource", strings.NewReader("body"))
			options := ProtectedResourceOptions{}
			ctx := context.Background()
			switch scenario {
			case "nil":
				request = nil
			case "url":
				request.URL = nil
			case "trailer":
				request.Trailer = http.Header{"Secret": {"value"}}
			case "get-body-error":
				request.GetBody = func() (io.ReadCloser, error) { return nil, errors.New("failed") }
			case "get-body-nil":
				request.GetBody = func() (io.ReadCloser, error) { return nil, nil }
			case "carrier":
				options.Authentication.Carrier = "other"
			case "conflicting-selection":
				options.Authentication.ClientAssertionOnly = true
				options.Authentication.CredentialID = "credential"
			case "limit":
				options.MaximumRedirects = -1
			case "unsafe-url":
				request.URL.User = url.UserPassword("user", "secret")
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, err := f.client.FetchProtectedResource(ctx, request, options); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
	if len(f.captured()) != 0 {
		t.Fatal("invalid request performed network work")
	}
}

func TestResourceHeadersAreAuthoritativeAndNotMutated(t *testing.T) {
	request, _ := http.NewRequest("GET", "https://service.example/resource", nil)
	request.Header = http.Header{"authorization": {"old"}, "aep-authorization": {"old"}, "x-agent-key": {"old"}, "X-Caller": {"kept"}}
	original := request.Header.Clone()
	controlled := http.Header{"X-Agent-Key": {"new"}}
	merged, err := mergeResourceHeaders(request, request.URL, http.Header{"Authorization": {"Payment secret"}}, controlled)
	if err != nil || merged.Get("X-Agent-Key") != "new" || merged.Get(aep.AuthorizationHeader) != "" || merged.Get("Authorization") != "Payment secret" || !reflect.DeepEqual(request.Header, original) {
		t.Fatalf("%v %v", merged, err)
	}
	for _, name := range []string{"x-agent-key", "aep-authorization"} {
		if _, err := mergeResourceHeaders(request, request.URL, http.Header{name: {"conflict"}}, controlled); err == nil {
			t.Fatalf("accepted %s", name)
		}
	}
	target, _ := url.Parse("https://other.example/resource")
	merged, err = mergeResourceHeaders(request, target, http.Header{"Authorization": {"Payment secret"}}, http.Header{"X-Agent-Key": {"destination"}})
	if err != nil || len(merged) != 1 || merged.Get("X-Agent-Key") != "destination" {
		t.Fatalf("cross-origin %v %v", merged, err)
	}
}

func TestResourceHeadersRemoveStaleAEPCarrier(t *testing.T) {
	request, _ := http.NewRequest("GET", "https://service.example/resource", nil)
	request.Header.Set("Authorization", "Bearer stale")
	for _, controlled := range []http.Header{{aep.AuthorizationHeader: {"AEP fresh"}}, {"X-Agent-Key": {"fresh"}}} {
		headers, err := mergeResourceHeaders(request, request.URL, nil, controlled)
		if err != nil || headers.Get("Authorization") != "" {
			t.Fatalf("stale credential retained: %v %v", headers, err)
		}
		if _, err := mergeResourceHeaders(request, request.URL, http.Header{"Authorization": {"Bearer explicit"}}, controlled); err == nil {
			t.Fatal("explicit conflicting AEP carrier accepted")
		}
	}
}

func TestFetchResourceDependencyFailuresDoNotRetry(t *testing.T) {
	for _, scenario := range []string{"inspect", "cancel-inspect", "authenticated-transport", "header-conflict", "redirect"} {
		t.Run(scenario, func(t *testing.T) {
			f := newResourceFixture(t, aep.AuthenticationMethodJWT, false)
			f.enroll(t)
			f.client.inspectCache = NewMemoryInspectCache()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			transport := f.server.Client().Transport
			f.client.commandHTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if scenario == "authenticated-transport" && strings.HasPrefix(r.Header.Get("Authorization"), "AEP ") && r.URL.Path == "/resource" {
					return nil, errors.New("connection lost")
				}
				return transport.RoundTrip(r)
			})}
			f.client.inspectHTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if scenario == "inspect" {
					return nil, errors.New("discovery unavailable")
				}
				if scenario == "cancel-inspect" {
					cancel()
					return nil, context.Canceled
				}
				return transport.RoundTrip(r)
			})}
			path := "/resource"
			options := ProtectedResourceOptions{}
			if scenario == "header-conflict" {
				options.AdditionalAuthenticationHeaders = http.Header{aep.AuthorizationHeader: {"AEP conflict"}}
			}
			if scenario == "redirect" {
				path = "/redirect"
				f.redirect.Store("file:///tmp/invalid")
			}
			request, _ := http.NewRequest("GET", f.server.URL+path, nil)
			if _, err := f.client.FetchProtectedResource(ctx, request, options); err == nil {
				t.Fatal("failure not propagated")
			}
			if f.grants.Load() != 0 {
				t.Fatal("failure triggered Grant")
			}
		})
	}
}

type resourceCloseError struct{ io.Reader }

func (resourceCloseError) Close() error { return errors.New("close failed") }

func TestFetchResourceBodyFactoryFailures(t *testing.T) {
	for _, scenario := range []string{"close", "retry-error", "retry-nil"} {
		t.Run(scenario, func(t *testing.T) {
			f := newResourceFixture(t, "api-key", false)
			request, _ := http.NewRequest("POST", f.server.URL+"/resource", strings.NewReader("payload"))
			calls := 0
			request.GetBody = func() (io.ReadCloser, error) {
				calls++
				if scenario == "close" {
					return resourceCloseError{strings.NewReader("payload")}, nil
				}
				if calls == 1 {
					return io.NopCloser(strings.NewReader("payload")), nil
				}
				if scenario == "retry-error" {
					return nil, errors.New("body unavailable")
				}
				return nil, nil
			}
			if _, err := f.client.FetchProtectedResource(context.Background(), request, ProtectedResourceOptions{}); err == nil {
				t.Fatal("body failure ignored")
			}
			for _, r := range f.captured() {
				if r.path != aep.WellKnownPath {
					t.Fatalf("unexpected request %s", r.path)
				}
			}
		})
	}
}

func TestFetchResourceChallengeWithoutAdvertisedMethods(t *testing.T) {
	var stub *serviceStub
	stub = newServiceStub(t, func(w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`AEP service_did="%s",inspect="%s/.well-known/aep"`, stub.serviceDID, stub.server.URL))
		w.WriteHeader(401)
		io.WriteString(w, "challenge")
		return true
	})
	stub.document.Authentication = nil
	request, _ := http.NewRequest("GET", stub.server.URL+"/resource", nil)
	response, err := stub.client.FetchProtectedResource(context.Background(), request, ProtectedResourceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != 401 || string(body) != "challenge" {
		t.Fatalf("%d %s %v", response.StatusCode, body, err)
	}
}
