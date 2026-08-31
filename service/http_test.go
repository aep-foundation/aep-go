package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	aep "github.com/aep-foundation/aep-go"
)

func TestHTTPHandlerServesInspectAndAdvertisedRoutes(t *testing.T) {
	service := newTestService(t, Options{})
	handler, err := NewHTTPHandler(service, HTTPHandlerOptions{})
	if err != nil {
		t.Fatal(err)
	}

	inspect := serveRequest(handler, http.MethodGet, aep.WellKnownPath, "", nil)
	if inspect.Code != http.StatusOK || inspect.Header().Get("Content-Type") != aep.MediaType || inspect.Header().Get("Cache-Control") != defaultInspectCacheControl || inspect.Header().Get("ETag") == "" {
		t.Fatalf("unexpected Inspect response: %d %v %s", inspect.Code, inspect.Header(), inspect.Body.String())
	}
	var document aep.InspectDocument
	if err := json.Unmarshal(inspect.Body.Bytes(), &document); err != nil || document.Service.DID != "did:web:service.example" {
		t.Fatalf("unexpected Inspect document: %#v, %v", document, err)
	}

	conditional := serveRequest(handler, http.MethodGet, aep.WellKnownPath, "", http.Header{"If-None-Match": []string{inspect.Header().Get("ETag")}})
	if conditional.Code != http.StatusNotModified || conditional.Body.Len() != 0 || conditional.Header().Get("ETag") != inspect.Header().Get("ETag") {
		t.Fatalf("unexpected conditional Inspect response: %d %v %q", conditional.Code, conditional.Header(), conditional.Body.String())
	}

	wrongMethod := serveRequest(handler, http.MethodPost, aep.WellKnownPath, "", nil)
	if wrongMethod.Code != http.StatusMethodNotAllowed || wrongMethod.Header().Get("Allow") != http.MethodGet || wrongMethod.Header().Get("Content-Type") != aep.ProblemMediaType {
		t.Fatalf("unexpected Inspect method response: %d %v", wrongMethod.Code, wrongMethod.Header())
	}

	unadvertisedGrant := serveRequest(handler, http.MethodPost, "/aep/grant", `{}`, commandHeaders("unused", "key"))
	if unadvertisedGrant.Code != http.StatusNotFound {
		t.Fatalf("unadvertised Grant route returned %d", unadvertisedGrant.Code)
	}
}

func TestHTTPHandlerUsesTheAdvertisedEndpointBase(t *testing.T) {
	service := newTestService(t, Options{EndpointBase: "/identity"})
	handler, err := NewHTTPHandler(service, HTTPHandlerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defaultPath := serveRequest(handler, http.MethodPost, "/aep/enroll", `{}`, commandHeaders("unused", "unused"))
	if defaultPath.Code != http.StatusNotFound {
		t.Fatalf("default command path returned %d", defaultPath.Code)
	}
	customPath := serveRequest(
		handler, http.MethodPost, "/identity/enroll", `{"agent_did":"did:web:agent.example"}`,
		commandHeaders(assertion(aep.AssertionEnroll, "custom-endpoint", ""), "custom-endpoint"),
	)
	if customPath.Code != http.StatusOK {
		t.Fatalf("advertised command path returned %d: %s", customPath.Code, customPath.Body.String())
	}
}

func TestHTTPHandlerExecutesCommandsAndPreservesFailures(t *testing.T) {
	service := newTestService(t, Options{GrantTypes: []GrantTypeDefinition{{GrantType: "custom-session", Handler: &testGrantHandler{}}}})
	handler, err := NewHTTPHandler(service, HTTPHandlerOptions{MaximumRequestBodyBytes: 256})
	if err != nil {
		t.Fatal(err)
	}

	enrollToken := assertion(aep.AssertionEnroll, "http-enroll", "")
	enrolled := serveRequest(
		handler, http.MethodPost, "/aep/enroll", `{"agent_did":"did:web:agent.example"}`,
		commandHeaders(enrollToken, "http-enroll"),
	)
	if enrolled.Code != http.StatusOK || enrolled.Header().Get("Content-Type") != aep.MediaType {
		t.Fatalf("unexpected Enroll response: %d %v %s", enrolled.Code, enrolled.Header(), enrolled.Body.String())
	}
	if enrolled.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Enroll response was cacheable: %v", enrolled.Header())
	}
	response, err := aep.ParseEnrollResponse(enrolled.Body.Bytes())
	if err != nil || response.Status != aep.EnrollmentActive {
		t.Fatalf("unexpected Enroll body: %#v, %v", response, err)
	}

	status := serveRequest(
		handler, http.MethodGet, "/aep/status", "",
		http.Header{"Authorization": []string{"AEP " + assertion(aep.AssertionStatus, "http-status", "")}},
	)
	if status.Code != http.StatusOK {
		t.Fatalf("unexpected Status response: %d %s", status.Code, status.Body.String())
	}

	missingAssertion := serveRequest(handler, http.MethodPost, "/aep/grant", `{"grant_type":"custom-session"}`, commandHeaders("", "grant-missing"))
	assertAEPProblem(t, missingAssertion, http.StatusUnauthorized, aep.ErrorNotRecognized)
	if missingAssertion.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("missing command assertion response omitted the challenge")
	}
	duplicateAuthorizationHeaders := commandHeaders(assertion(aep.AssertionGrant, "grant-duplicate-authorization", ""), "grant-duplicate-authorization")
	duplicateAuthorizationHeaders.Add("Authorization", "AEP duplicate")
	duplicateAuthorization := serveRequest(handler, http.MethodPost, "/aep/grant", `{"grant_type":"custom-session"}`, duplicateAuthorizationHeaders)
	assertAEPProblem(t, duplicateAuthorization, http.StatusUnauthorized, aep.ErrorNotRecognized)

	duplicateIdempotencyHeaders := commandHeaders(assertion(aep.AssertionGrant, "grant-duplicate-idempotency", ""), "first")
	duplicateIdempotencyHeaders.Add("Idempotency-Key", "second")
	duplicateIdempotency := serveRequest(handler, http.MethodPost, "/aep/grant", `{"grant_type":"custom-session"}`, duplicateIdempotencyHeaders)
	assertAEPProblem(t, duplicateIdempotency, http.StatusBadRequest, aep.ErrorInvalidRequest)

	wrongMethod := serveRequest(handler, http.MethodGet, "/aep/enroll", "", nil)
	if wrongMethod.Code != http.StatusMethodNotAllowed || wrongMethod.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("unexpected command method response: %d %v", wrongMethod.Code, wrongMethod.Header())
	}

	wrongMediaType := commandHeaders(assertion(aep.AssertionEnroll, "http-media", ""), "http-media")
	wrongMediaType.Set("Content-Type", "application/json")
	unsupported := serveRequest(handler, http.MethodPost, "/aep/enroll", `{}`, wrongMediaType)
	if unsupported.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("unexpected media-type response: %d %s", unsupported.Code, unsupported.Body.String())
	}
	duplicateMediaTypeHeaders := commandHeaders(assertion(aep.AssertionEnroll, "http-duplicate-media", ""), "http-duplicate-media")
	duplicateMediaTypeHeaders.Add("Content-Type", aep.MediaType)
	duplicateMediaType := serveRequest(handler, http.MethodPost, "/aep/enroll", `{}`, duplicateMediaTypeHeaders)
	if duplicateMediaType.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("unexpected duplicate media-type response: %d %s", duplicateMediaType.Code, duplicateMediaType.Body.String())
	}

	large := serveRequest(
		handler, http.MethodPost, "/aep/enroll", strings.Repeat("x", 257),
		commandHeaders(assertion(aep.AssertionEnroll, "http-large", ""), "http-large"),
	)
	if large.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("unexpected oversized response: %d %s", large.Code, large.Body.String())
	}
}

func TestProtectedResourceMiddlewareAuthenticatesAndProvidesPrincipal(t *testing.T) {
	service := newTestService(t, Options{AuthenticationMethods: []aep.AuthenticationMethod{aep.AuthenticationMethodJWT}})
	seedEnrollment(t, service.enrollmentStore)
	middleware, err := NewProtectedResourceMiddleware(service, "https://service.example")
	if err != nil {
		t.Fatal(err)
	}
	called := false
	protected := middleware(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		called = true
		principal, ok := PrincipalFromContext(request.Context())
		if !ok || principal.AgentDID != "did:web:agent.example" || principal.AuthenticationKind != AuthenticationKindJWT {
			t.Fatalf("unexpected principal: %#v, %t", principal, ok)
		}
		response.WriteHeader(http.StatusNoContent)
	}))

	resource := "https://service.example/private?view=full"
	request := httptest.NewRequest(http.MethodGet, "http://internal/private?view=full", nil)
	request.Header.Set("Authorization", "AEP "+assertion(aep.AssertionAuthenticate, "http-authenticate", resource))
	authenticated := httptest.NewRecorder()
	protected.ServeHTTP(authenticated, request)
	if authenticated.Code != http.StatusNoContent || !called {
		t.Fatalf("protected handler was not called: %d %s", authenticated.Code, authenticated.Body.String())
	}

	called = false
	missing := httptest.NewRecorder()
	protected.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "http://internal/private", nil))
	assertAEPProblem(t, missing, http.StatusUnauthorized, aep.ErrorAuthenticationRequired)
	if called || !strings.Contains(missing.Header().Get("WWW-Authenticate"), `inspect="https://service.example/.well-known/aep"`) {
		t.Fatalf("unexpected protected-resource challenge: called=%t header=%q", called, missing.Header().Get("WWW-Authenticate"))
	}
}

func TestHTTPIntegrationRejectsInvalidConstruction(t *testing.T) {
	if _, err := NewHTTPHandler(nil, HTTPHandlerOptions{}); err == nil {
		t.Fatal("nil Service was accepted by the HTTP handler")
	}
	service := newTestService(t, Options{})
	if _, err := NewHTTPHandler(service, HTTPHandlerOptions{MaximumRequestBodyBytes: -1}); err == nil {
		t.Fatal("negative request limit was accepted")
	}
	if _, err := NewHTTPHandler(service, HTTPHandlerOptions{InspectCacheControl: "public\r\nInjected: true"}); err == nil {
		t.Fatal("invalid Cache-Control value was accepted")
	}
	if _, err := NewHTTPHandler(service, HTTPHandlerOptions{InspectCacheControl: " "}); err == nil {
		t.Fatal("empty Cache-Control value was accepted")
	}
	for _, origin := range []string{
		"http://service.example", "https://service.example/path", "https://service.example?", "https://service.example/#", "https://user@service.example",
	} {
		if _, err := NewProtectedResourceMiddleware(service, origin); err == nil {
			t.Fatalf("invalid protected-resource origin %q was accepted", origin)
		}
	}
	if _, ok := PrincipalFromContext(context.Background()); ok {
		t.Fatal("principal was found in an unrelated context")
	}
}

func TestProtectedResourceMiddlewareDoesNotExposeInternalErrors(t *testing.T) {
	service := newTestService(t, Options{
		AuthenticationMethods: []aep.AuthenticationMethod{aep.AuthenticationMethodJWT},
		EnrollmentStore:       failingEnrollmentStore{},
	})
	middleware, err := NewProtectedResourceMiddleware(service, "https://service.example")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://internal/private", nil)
	request.Header.Set("Authorization", "AEP "+assertion(aep.AssertionAuthenticate, "http-error", "https://service.example/private"))
	response := httptest.NewRecorder()
	middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("protected handler ran after an authentication error")
	})).ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), "storage failed") {
		t.Fatalf("unexpected internal-error response: %d %s", response.Code, response.Body.String())
	}
}

type failingEnrollmentStore struct{}

func (failingEnrollmentStore) FindEnrollment(context.Context, string) (*EnrollmentRecord, error) {
	return nil, errors.New("storage failed")
}

func (failingEnrollmentStore) FindOrCreateEnrollment(context.Context, string, func() (EnrollmentRecord, error)) (EnrollmentRecord, bool, error) {
	return EnrollmentRecord{}, false, errors.New("storage failed")
}

func (failingEnrollmentStore) SaveEnrollment(context.Context, EnrollmentRecord) (EnrollmentRecord, error) {
	return EnrollmentRecord{}, errors.New("storage failed")
}

func serveRequest(handler http.Handler, method string, target string, body string, headers http.Header) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.Header = headers.Clone()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func commandHeaders(assertion string, idempotencyKey string) http.Header {
	header := http.Header{"Content-Type": []string{aep.MediaType + "; charset=utf-8"}, "Idempotency-Key": []string{idempotencyKey}}
	if assertion != "" {
		header.Set("Authorization", "AEP "+assertion)
	}
	return header
}

func assertAEPProblem(t *testing.T, response *httptest.ResponseRecorder, status int, code aep.ErrorCode) {
	t.Helper()
	if response.Code != status || response.Header().Get("Content-Type") != aep.ProblemMediaType {
		t.Fatalf("unexpected Problem response: %d %v %s", response.Code, response.Header(), response.Body.String())
	}
	problem, err := aep.ParseProblemDetails(response.Body.Bytes())
	if err != nil || problem.Code != code {
		t.Fatalf("unexpected Problem body: %#v, %v", problem, err)
	}
}
