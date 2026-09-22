package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	aep "github.com/aep-foundation/aep-go"
)

func TestOpenAPISecurityInheritance(t *testing.T) {
	for _, test := range []struct {
		name, root, operation, state string
		methods                      []aep.AuthenticationMethod
	}{
		{"inherited", `[{"a":[]}]`, `{}`, "required", []aep.AuthenticationMethod{"aep-jwt"}},
		{"public override", `[{"a":[]}]`, `{"security":[]}`, "public", nil},
		{"anonymous alternative", `[{"a":[]},{}]`, `{}`, "public", nil},
		{"alternatives", `[{"a":[]},{"b":[]},{"a":[]}]`, `{}`, "required", []aep.AuthenticationMethod{"aep-jwt", "api-key"}},
		{"compound", `[{"a":[],"b":[]}]`, `{}`, "fallback", nil},
		{"complete alternative", `[{"a":[],"unknown":[]},{"b":[]}]`, `{}`, "required", []aep.AuthenticationMethod{"api-key"}},
		{"unknown", `[{"unknown":[]}]`, `{}`, "fallback", nil},
		{"absent", `null`, `{}`, "fallback", nil},
		{"null override", `[{"a":[]}]`, `{"security":null}`, "fallback", nil},
		{"malformed", `[{"a":"scope"}]`, `{}`, "fallback", nil},
		{"null alternative", `[null]`, `{}`, "fallback", nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := []byte(`{"openapi":"3.1.0","security":` + test.root + `,"paths":{"/items/{id}":{"security":[],"get":` + test.operation + `}},"components":{"securitySchemes":{"a":{"x-aep-authentication-method":"aep-jwt"},"b":{"x-aep-authentication-method":"api-key"}}}}`)
			policy, err := InterpretOpenAPIOperation(data, aep.OpenAPIPathMatchOptions{Method: "get", Path: "/items/one", TrailingSlash: "strict"})
			if err != nil || policy.State != test.state || strings.Join(methodStrings(policy.Methods), ",") != strings.Join(methodStrings(test.methods), ",") {
				t.Fatalf("%#v, %v", policy, err)
			}
		})
	}
}

func methodStrings(methods []aep.AuthenticationMethod) []string {
	result := make([]string, len(methods))
	for i, method := range methods {
		result[i] = string(method)
	}
	return result
}

func TestOpenAPIOperationMatching(t *testing.T) {
	data := []byte(`{"openapi":"3.1.1","security":[],"paths":{"/items/{id}":{"get":{}},"/items/{name}":{"get":{}},"/items/fixed":{"post":{}}}}`)
	for _, test := range []struct{ method, path, mode, state string }{
		{"GET", "/items/1", "strict", "fallback"},
		{"POST", "/items/fixed", "strict", "public"},
		{"POST", "/items/fixed/", "strict", "fallback"},
		{"POST", "/items/fixed/", "equivalent", "public"},
		{"DELETE", "/items/fixed", "strict", "fallback"},
		{"", "/missing", "strict", "fallback"},
	} {
		policy, err := InterpretOpenAPIOperation(data, aep.OpenAPIPathMatchOptions{Method: test.method, Path: test.path, TrailingSlash: test.mode})
		if err != nil || policy.State != test.state {
			t.Fatalf("%+v: %#v %v", test, policy, err)
		}
	}
	for _, invalid := range []string{`{`, `null`, `{"openapi":"3.0.1"}`, `{"openapi":3}`} {
		if _, err := InterpretOpenAPIOperation([]byte(invalid), aep.OpenAPIPathMatchOptions{}); err == nil {
			t.Fatalf("accepted %s", invalid)
		}
	}
}

func TestOpenAPIPolicyAnonymousCachingAndRevalidation(t *testing.T) {
	var requests atomic.Int32
	var redirectRequests atomic.Int32
	var noStore atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.Header.Get(aep.AuthorizationHeader) != "" {
			t.Error("OpenAPI received credentials")
		}
		if r.URL.Path == "/start" {
			redirectRequests.Add(1)
			http.Redirect(w, r, "/document", http.StatusFound)
			return
		}
		requests.Add(1)
		w.Header().Set("Cache-Control", "no-cache")
		if noStore.Load() {
			w.Header().Set("Cache-Control", "no-store")
		}
		w.Header().Set("ETag", `"v1"`)
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "Application/Vnd.Oai.Openapi+Json; version=3.1; charset=utf-8")
		io.WriteString(w, `{"openapi":"3.1.0","security":[],"paths":{"/items":{"get":{}}}}`)
	}))
	t.Cleanup(server.Close)
	stub := newServiceStub(t, nil)
	stub.document.HTTP.OpenAPI = &aep.OpenAPIReference{URL: server.URL + "/start", PathMatching: aep.OpenAPIPathMatching{TrailingSlash: "strict"}}
	client := server.Client()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	target, _ := url.Parse(server.URL)
	jar.SetCookies(target, []*http.Cookie{{Name: "secret", Value: "cookie"}})
	client.Jar = jar
	stub.client.inspectHTTPClient = client
	resource, _ := url.Parse(stub.server.URL + "/items?filter=all")
	for i := 0; i < 3; i++ {
		if i == 2 {
			noStore.Store(true)
		}
		policy, err := stub.session.OpenAPIPolicy(context.Background(), "GET", resource)
		if err != nil || policy.State != "public" {
			t.Fatalf("%#v %v", policy, err)
		}
	}
	if requests.Load() != 3 || redirectRequests.Load() != 1 {
		t.Fatalf("requests=%d redirects=%d", requests.Load(), redirectRequests.Load())
	}
	if len(stub.client.openAPICache) != 0 {
		t.Fatal("no-store response was retained")
	}
}

func TestOpenAPIFreshCacheAndFailures(t *testing.T) {
	for _, scenario := range []string{"fresh", "media", "version", "malformed", "large", "status", "unexpected-304", "redirect-loop", "missing-location", "userinfo", "scheme", "cancel"} {
		t.Run(scenario, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("Content-Type", "application/json")
				switch scenario {
				case "media":
					w.Header().Set("Content-Type", "text/plain")
				case "version":
					io.WriteString(w, `{"openapi":"3.0.0"}`)
					return
				case "malformed":
					io.WriteString(w, `{`)
					return
				case "large":
					io.WriteString(w, strings.Repeat(" ", 2048))
					return
				case "status":
					w.WriteHeader(500)
					return
				case "unexpected-304":
					w.WriteHeader(304)
					return
				case "redirect-loop":
					http.Redirect(w, r, "/", 302)
					return
				case "missing-location":
					w.WriteHeader(302)
					return
				case "userinfo":
					w.Header().Set("Location", "https://user:secret@example.com/")
					w.WriteHeader(302)
					return
				case "scheme":
					w.Header().Set("Location", "file:///tmp/no")
					w.WriteHeader(302)
					return
				case "cancel":
					<-r.Context().Done()
					return
				}
				w.Header().Set("Cache-Control", "max-age=300")
				io.WriteString(w, `{"openapi":"3.1.0","paths":{}}`)
			}))
			t.Cleanup(server.Close)
			client, err := New(Options{IdentityProvider: newTestIdentityProvider(t), HTTPClient: server.Client(), MaximumResponseBytes: 1024, RequestTimeout: 100 * time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			target, _ := url.Parse(server.URL)
			first, err := client.openAPI(context.Background(), target, false)
			if scenario != "fresh" {
				if err == nil {
					t.Fatal("invalid response accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			first[0] = 'x'
			second, err := client.openAPI(context.Background(), target, false)
			if err != nil || !json.Valid(second) || requests.Load() != 1 {
				t.Fatalf("cache: %s %v %d", second, err, requests.Load())
			}
		})
	}
}

func TestAuthenticationAllowedMethodsDoNotMutateInspect(t *testing.T) {
	stub := newServiceStub(t, nil)
	before := append([]aep.AuthenticationMethod(nil), authenticationMethods(stub.document)...)
	resource, _ := url.Parse(stub.server.URL + "/private")
	_, err := stub.session.AuthenticationHeaders(context.Background(), AuthenticationOptions{Resource: resource, AllowedMethods: []aep.AuthenticationMethod{}})
	if err == nil {
		t.Fatal("empty allowed methods authenticated")
	}
	if !reflect.DeepEqual(before, authenticationMethods(stub.document)) {
		t.Fatal("mutated Inspect methods")
	}
	headers, err := stub.session.AuthenticationHeaders(context.Background(), AuthenticationOptions{Resource: resource, AllowedMethods: []aep.AuthenticationMethod{aep.AuthenticationMethodJWT}})
	if err != nil || !strings.HasPrefix(headers.Get("Authorization"), "AEP ") {
		t.Fatalf("%v %v", headers, err)
	}
}

func TestOpenAPIPolicyRejectsInvalidResourcesBeforeDiscovery(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) }))
	t.Cleanup(server.Close)
	client, err := New(Options{IdentityProvider: newTestIdentityProvider(t), HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.Service(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := url.Parse("https://other.example/resource")
	for _, resource := range []*url.URL{nil, other} {
		if _, err := session.OpenAPIPolicy(context.Background(), "GET", resource); err == nil {
			t.Fatal("invalid resource accepted")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid resource initiated discovery")
	}
}

func TestOpenAPIPolicyPreservesInspectFailure(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)
	client, err := New(Options{IdentityProvider: newTestIdentityProvider(t), HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.Service(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resource, _ := url.Parse(server.URL + "/resource")
	if _, err := session.OpenAPIPolicy(context.Background(), "GET", resource); err == nil {
		t.Fatal("Inspect failure suppressed")
	}
}

func TestOpenAPILastModifiedRevalidationRetainsDocument(t *testing.T) {
	const modified = "Mon, 06 Jul 2026 12:00:00 GMT"
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Last-Modified", modified)
		if r.Header.Get("If-Modified-Since") == modified {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"openapi":"3.1.0","paths":{},"security":[]}`)
	}))
	t.Cleanup(server.Close)
	client, err := New(Options{IdentityProvider: newTestIdentityProvider(t), HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	target, _ := url.Parse(server.URL)
	first, err := client.openAPI(context.Background(), target, false)
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.openAPI(context.Background(), target, false)
	if err != nil || string(first) != string(second) || calls.Load() != 2 {
		t.Fatalf("revalidation: %s %v calls=%d", second, err, calls.Load())
	}
}

func TestOpenAPIRetrievalRejectsInvalidDocumentAndDowngrade(t *testing.T) {
	for _, mode := range []string{"malformed", "version", "downgrade"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				switch mode {
				case "malformed":
					io.WriteString(w, `{`)
				case "version":
					io.WriteString(w, `{"openapi":"3.0.0","paths":{}}`)
				case "downgrade":
					w.Header().Set("Location", "http://127.0.0.1:1/document")
					w.WriteHeader(302)
				}
			}))
			t.Cleanup(server.Close)
			client, err := New(Options{IdentityProvider: newTestIdentityProvider(t), HTTPClient: server.Client(), AllowInsecureLoopback: true})
			if err != nil {
				t.Fatal(err)
			}
			target, _ := url.Parse(server.URL)
			if _, err := client.openAPI(context.Background(), target, false); err == nil {
				t.Fatal("invalid response accepted")
			}
			if calls.Load() != 1 || len(client.openAPICache) != 0 {
				t.Fatal("invalid response followed or cached")
			}
		})
	}
}

type openAPIFailingBody struct {
	closed  bool
	failure error
}

func (body *openAPIFailingBody) Read([]byte) (int, error) { return 0, body.failure }
func (body *openAPIFailingBody) Close() error             { body.closed = true; return nil }

func TestOpenAPIReadFailureClosesBodyWithoutCaching(t *testing.T) {
	failure := errors.New("connection interrupted")
	body := &openAPIFailingBody{failure: failure}
	client, err := New(Options{IdentityProvider: newTestIdentityProvider(t), HTTPClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: body, Request: request}, nil
	})}})
	if err != nil {
		t.Fatal(err)
	}
	target, _ := url.Parse("https://service.example/openapi.json")
	if _, err := client.openAPI(context.Background(), target, false); !errors.Is(err, failure) {
		t.Fatalf("%v", err)
	}
	if !body.closed || len(client.openAPICache) != 0 {
		t.Fatal("failed response leaked or cached")
	}
}
