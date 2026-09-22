package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"time"

	aep "github.com/aep-foundation/aep-go"
	"github.com/aep-foundation/aep-go/service"
)

type serviceResourceFixture struct {
	instance *service.Service
	key      ed25519.PrivateKey
	now      time.Time
	agentDID string
	issued   int
}

func newServiceResourceFixture() (*serviceResourceFixture, error) {
	return newServiceResourceFixtureForAgent("did:web:agent.example")
}

func newServiceResourceFixtureForAgent(agentDID string) (*serviceResourceFixture, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	store := service.NewMemoryEnrollmentStore()
	if _, err := store.SaveEnrollment(context.Background(), service.EnrollmentRecord{AgentDID: agentDID, EnrollmentID: "resource", Status: aep.AgentActive, CreatedAt: serviceNow, UpdatedAt: serviceNow, Since: serviceNow}); err != nil {
		return nil, err
	}
	fixture := &serviceResourceFixture{key: private, now: serviceNow, agentDID: agentDID}
	definition, err := service.StoredOAuthBearerGrantType(service.StoredCredentialGrantTypeOptions[aep.OAuthBearerGrantResponse]{
		Store: service.NewMemoryServiceCredentialStore(),
		Issue: func(context.Context, aep.GrantRequest, service.GrantContext) (aep.OAuthBearerGrantResponse, error) {
			fixture.issued++
			suffix := ""
			if fixture.issued > 1 {
				suffix = fmt.Sprintf("-%d", fixture.issued)
			}
			return aep.OAuthBearerGrantResponse{AccessToken: "opaque-token" + suffix, CredentialID: "resource-token" + suffix, TokenType: "Bearer", Scopes: []string{"read"}, ExpiresAt: fixture.now.Add(time.Hour).Format(time.RFC3339)}, nil
		},
	})
	if err != nil {
		return nil, err
	}
	verifier := func(ctx context.Context, token string, verification service.AssertionVerificationContext) (aep.ClientAssertionClaims, error) {
		return aep.VerifyClientAssertion(ctx, token, aep.VerifyClientAssertionOptions{Key: public, Algorithms: verification.SigningAlgorithms, Audience: verification.ServiceDID, Operation: verification.Operation, Resource: verification.Resource, CurrentTime: verification.CurrentTime})
	}
	instance, err := service.New(service.Options{
		AuthenticationMethods: []aep.AuthenticationMethod{aep.AuthenticationMethodJWT, aep.AuthenticationMethod(aep.GrantTypeOAuthBearer)},
		Clock:                 func() time.Time { return fixture.now },
		EnrollmentStore:       store,
		GrantTypes:            []service.GrantTypeDefinition{definition},
		IdentityMethods:       []aep.IdentityMethod{aep.IdentityMethodDIDWeb},
		ServiceDID:            "did:web:service.example",
		Verifier:              verifier,
	})
	if err != nil {
		return nil, err
	}
	fixture.instance = instance
	token, err := fixture.assertion(aep.AssertionGrant, "", "grant")
	if err != nil {
		return nil, err
	}
	granted, err := instance.Grant(context.Background(), []byte(`{"grant_type":"oauth-bearer"}`), service.CommandOptions{ClientAssertion: token, IdempotencyKey: "grant"})
	if err != nil || granted.Status != http.StatusOK {
		return nil, fmt.Errorf("credential setup failed: %#v, %v", granted, err)
	}
	return fixture, nil
}

func evaluateServiceAuthenticationFailures(request adapterRequest) (bool, error) {
	cases, err := requiredField[[]string](request.Case.Input, "cases")
	if err != nil {
		return false, err
	}
	for _, name := range cases {
		expected, err := requiredField[aep.ErrorCode](request.Case.Expected, name)
		if err != nil {
			return false, err
		}
		fixture, err := newServiceResourceFixture()
		if err != nil {
			return false, err
		}
		wrap, err := service.NewProtectedResourceMiddleware(fixture.instance, "https://service.example")
		if err != nil {
			return false, err
		}
		calls := 0
		requiredScope := "read"
		handler := wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			principal, found := service.PrincipalFromContext(r.Context())
			if !found || principal.AgentDID != "did:web:agent.example" {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			// Application policy, not authentication middleware, enforces resource scopes.
			if name == "insufficient_scope" && !slices.Contains(principal.Scopes, requiredScope) {
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(aep.NewProblemDetails(aep.ErrorInsufficientScope, "Insufficient scope", http.StatusForbidden))
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		send := func(value string) *httptest.ResponseRecorder {
			incoming := httptest.NewRequest(http.MethodGet, "https://service.example/private", nil)
			incoming.Header.Set("Authorization", value)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, incoming)
			return response
		}
		token, err := fixture.assertion(aep.AssertionAuthenticate, "https://service.example/private", name)
		if err != nil {
			return false, err
		}
		value := "AEP " + token
		status, expectedCalls := http.StatusUnauthorized, 0
		switch name {
		case "wrong_audience":
			token, err = aep.SignClientAssertion(aep.ClientAssertionClaims{Issuer: "did:web:agent.example", Subject: "did:web:agent.example", Audience: "did:web:other.example", IssuedAt: serviceNow.Unix(), ExpiresAt: serviceNow.Add(time.Minute).Unix(), JWTID: name, Operation: aep.AssertionAuthenticate, Resource: "https://service.example/private"}, aep.SignClientAssertionOptions{Algorithm: aep.SigningAlgorithmEdDSA, Key: fixture.key, KeyID: "did:web:agent.example#key-1"})
			if err != nil {
				return false, err
			}
			value = "AEP " + token
		case "expired_assertion":
			fixture.now = serviceNow.Add(2 * time.Minute)
		case "replayed_assertion":
			if send(value).Code != http.StatusOK || calls != 1 {
				return false, fmt.Errorf("initial assertion failed")
			}
			expectedCalls = 1
		case "malformed_credential":
			value = "Bearer invalid token"
		case "expired_credential", "insufficient_scope":
			value = "Bearer opaque-token"
			if send(value).Code != http.StatusOK || calls != 1 {
				return false, fmt.Errorf("initial credential failed")
			}
			expectedCalls = 1
			if name == "expired_credential" {
				fixture.now = serviceNow.Add(2 * time.Hour)
			} else {
				requiredScope = "write"
				status, expectedCalls = http.StatusForbidden, 2
			}
		case "unsupported_method":
			value = "Basic dXNlcjpwYXNz"
		default:
			return false, fmt.Errorf("unknown authentication failure %q", name)
		}
		response := send(value)
		problem, err := aep.ParseProblemDetails(response.Body.Bytes())
		if err != nil || response.Code != status || problem.Code != expected || calls != expectedCalls || strings.Contains(response.Body.String(), "opaque-token") || strings.Contains(response.Body.String(), "did:web:agent.example") {
			return false, fmt.Errorf("%s returned status %d, code %q, downstream calls %d: %v", name, response.Code, problem.Code, calls, err)
		}
	}
	return len(cases) > 0, nil
}

func (fixture *serviceResourceFixture) assertion(operation aep.AssertionOperation, resource, id string) (string, error) {
	return aep.SignClientAssertion(aep.ClientAssertionClaims{Issuer: fixture.agentDID, Subject: fixture.agentDID, Audience: "did:web:service.example", IssuedAt: fixture.now.Unix(), ExpiresAt: fixture.now.Add(time.Minute).Unix(), JWTID: id, Operation: operation, Resource: resource}, aep.SignClientAssertionOptions{Algorithm: aep.SigningAlgorithmEdDSA, Key: fixture.key, KeyID: fixture.agentDID + "#key-1"})
}

func evaluateServiceCommandHeader(request adapterRequest) (bool, error) {
	commands, err := requiredField[[]aep.Command](request.Case.Input, "commands")
	if err != nil {
		return false, err
	}
	key, err := requiredField[string](request.Case.Input, "idempotency_key")
	if err != nil {
		return false, err
	}
	var expected struct {
		EnrollBodyKey  string        `json:"enroll_body_key"`
		HeaderRequired bool          `json:"header_required"`
		MismatchStatus int           `json:"mismatched_enroll_body_status"`
		MissingCode    aep.ErrorCode `json:"missing_or_empty_code"`
		MissingStatus  int           `json:"missing_or_empty_status"`
	}
	encoded, err := json.Marshal(request.Case.Expected)
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(encoded, &expected); err != nil {
		return false, err
	}
	if !expected.HeaderRequired || expected.EnrollBodyKey != "optional" || len(commands) == 0 {
		return false, nil
	}
	for _, command := range commands {
		var body map[string]string
		switch command {
		case aep.CommandEnroll:
			body = map[string]string{"agent_did": "did:web:agent.example"}
		case aep.CommandGrant:
			body = map[string]string{"grant_type": "oauth-bearer"}
		case aep.CommandRevoke:
			body = map[string]string{"grant_type": "oauth-bearer", "credential_id": "resource-token"}
		default:
			return false, fmt.Errorf("unsupported idempotent command %q", command)
		}
		variants := []string{"missing", "empty", "valid"}
		if command == aep.CommandEnroll {
			variants = append(variants, "matching", "mismatched", "body-only")
		}
		for _, variant := range variants {
			fixture, err := newServiceResourceFixture()
			if err != nil {
				return false, err
			}
			handler, err := service.NewHTTPHandler(fixture.instance, service.HTTPHandlerOptions{})
			if err != nil {
				return false, err
			}
			document, err := fixture.instance.InspectDocument()
			if err != nil {
				return false, err
			}
			path, err := aep.CommandPathFromInspect(document, command)
			if err != nil {
				return false, err
			}
			delete(body, "idempotency_key")
			if variant == "matching" || variant == "body-only" {
				body["idempotency_key"] = key
			} else if variant == "mismatched" {
				body["idempotency_key"] = key + "-different"
			}
			encoded, err := json.Marshal(body)
			if err != nil {
				return false, err
			}
			token, err := fixture.assertion(aep.AssertionOperation(command), "", string(command)+"-"+variant)
			if err != nil {
				return false, err
			}
			incoming := httptest.NewRequest(http.MethodPost, "https://service.example"+path, strings.NewReader(string(encoded)))
			incoming.Header.Set("Authorization", "AEP "+token)
			incoming.Header.Set("Content-Type", aep.MediaType)
			if variant == "empty" {
				incoming.Header.Set("Idempotency-Key", "")
			} else if variant != "missing" && variant != "body-only" {
				incoming.Header.Set("Idempotency-Key", key)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, incoming)
			if variant == "valid" || variant == "matching" {
				if response.Code != http.StatusOK {
					return false, fmt.Errorf("%s %s failed: %d %s", command, variant, response.Code, response.Body.String())
				}
				continue
			}
			status := expected.MissingStatus
			if variant == "mismatched" {
				status = expected.MismatchStatus
			}
			problem, err := aep.ParseProblemDetails(response.Body.Bytes())
			if err != nil || response.Code != status || problem.Code != expected.MissingCode {
				return false, fmt.Errorf("%s %s returned %d %s: %v", command, variant, response.Code, problem.Code, err)
			}
		}
	}
	return true, nil
}

func evaluateServiceReplayConflict(request adapterRequest) (bool, error) {
	input, err := json.Marshal(request.Case.Input)
	if err != nil {
		return false, err
	}
	var scenario struct {
		AgentDID      string      `json:"agent_did"`
		Key           string      `json:"idempotency_key"`
		FirstCommand  aep.Command `json:"first_command"`
		SecondCommand aep.Command `json:"second_command"`
		FirstHash     string      `json:"first_body_hash"`
		SecondHash    string      `json:"second_body_hash"`
	}
	if err := json.Unmarshal(input, &scenario); err != nil {
		return false, err
	}
	retention, err := requiredField[int64](request.Case.Expected, "retention_seconds_minimum")
	if err != nil {
		return false, err
	}
	scope, err := requiredField[[]string](request.Case.Expected, "scope")
	if err != nil {
		return false, err
	}
	retry, err := requiredField[string](request.Case.Expected, "exact_retry")
	if err != nil {
		return false, err
	}
	if scenario.FirstCommand != aep.CommandGrant || scenario.SecondCommand != aep.CommandRevoke || scenario.FirstHash == "" || scenario.SecondHash == "" || scenario.Key == "" || retention != 3600 || retry != "cached_or_equivalent_success" || !slices.Equal(scope, []string{"agent_did", "idempotency_key"}) {
		return false, fmt.Errorf("unsupported replay scenario")
	}
	fixture, err := newServiceResourceFixtureForAgent(scenario.AgentDID)
	if err != nil {
		return false, err
	}
	handler, err := service.NewHTTPHandler(fixture.instance, service.HTTPHandlerOptions{})
	if err != nil {
		return false, err
	}
	document, err := fixture.instance.InspectDocument()
	if err != nil {
		return false, err
	}
	sequence := 0
	send := func(command aep.Command, key string, body map[string]string) (*httptest.ResponseRecorder, error) {
		sequence++
		path, err := aep.CommandPathFromInspect(document, command)
		if err != nil {
			return nil, err
		}
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		token, err := fixture.assertion(aep.AssertionOperation(command), "", fmt.Sprintf("retry-%d", sequence))
		if err != nil {
			return nil, err
		}
		incoming := httptest.NewRequest(http.MethodPost, "https://service.example"+path, strings.NewReader(string(encoded)))
		incoming.Header.Set("Authorization", "AEP "+token)
		incoming.Header.Set("Content-Type", aep.MediaType)
		incoming.Header.Set("Idempotency-Key", key)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, incoming)
		return response, nil
	}
	// Vector hashes identify distinct bodies; the Service computes their actual canonical hashes.
	body := map[string]string{"grant_type": "oauth-bearer", "conformance_input": scenario.FirstHash}
	first, err := send(scenario.FirstCommand, scenario.Key, body)
	if err != nil || first.Code != http.StatusOK {
		return false, fmt.Errorf("initial Grant failed: %v", err)
	}
	issued := fixture.issued
	fixture.now = serviceNow.Add(time.Duration(retention)*time.Second - time.Nanosecond)
	replayed, err := send(scenario.FirstCommand, scenario.Key, body)
	if err != nil || replayed.Code != first.Code || !jsonEqual(json.RawMessage(first.Body.Bytes()), json.RawMessage(replayed.Body.Bytes())) || fixture.issued != issued {
		return false, fmt.Errorf("retry was not cached for the required window: %v", err)
	}
	for _, name := range []string{"changed_body", "changed_command"} {
		expected, err := requiredField[struct {
			Code   aep.ErrorCode `json:"code"`
			Status int           `json:"status"`
		}](request.Case.Expected, name)
		if err != nil {
			return false, err
		}
		command := scenario.FirstCommand
		body["conformance_input"] = scenario.SecondHash
		if name == "changed_command" {
			command = scenario.SecondCommand
			body["conformance_input"] = scenario.FirstHash
		}
		response, err := send(command, scenario.Key, body)
		if err != nil {
			return false, err
		}
		problem, err := aep.ParseProblemDetails(response.Body.Bytes())
		if err != nil || response.Code != expected.Status || problem.Code != expected.Code || fixture.issued != issued {
			return false, fmt.Errorf("%s returned %d %s: %v", name, response.Code, problem.Code, err)
		}
	}
	wrap, err := service.NewProtectedResourceMiddleware(fixture.instance, "https://service.example")
	if err != nil {
		return false, err
	}
	protected := wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	credentialRequest := httptest.NewRequest(http.MethodGet, "https://service.example/private", nil)
	credentialRequest.Header.Set("Authorization", "Bearer opaque-token-2")
	credentialResponse := httptest.NewRecorder()
	protected.ServeHTTP(credentialResponse, credentialRequest)
	if credentialResponse.Code != http.StatusOK {
		return false, fmt.Errorf("conflicting Revoke changed the existing credential")
	}
	body["conformance_input"] = scenario.FirstHash
	otherKey, err := send(scenario.FirstCommand, scenario.Key+"-other", body)
	if err != nil || otherKey.Code != http.StatusOK || fixture.issued != issued+1 {
		return false, fmt.Errorf("different idempotency key did not execute: %v", err)
	}
	fixture.agentDID = "did:web:other-agent.example"
	enrolled, err := send(aep.CommandEnroll, "other-enrollment", map[string]string{"agent_did": fixture.agentDID})
	if err != nil || enrolled.Code != http.StatusOK {
		return false, fmt.Errorf("second Agent enrollment failed: %v", err)
	}
	otherAgent, err := send(scenario.FirstCommand, scenario.Key, body)
	return err == nil && otherAgent.Code == http.StatusOK && fixture.issued == issued+2, err
}

func evaluateServiceFieldSafety(request adapterRequest) (bool, error) {
	field, err := requiredField[string](request.Case.Input, "field_name")
	if err != nil {
		return false, err
	}
	match, err := requiredField[string](request.Case.Expected, "field_name_match")
	if err != nil {
		return false, err
	}
	if match != "case-insensitive" {
		return false, nil
	}
	for _, name := range []string{"sensitive_headers_redacted", "cache_key_excluded", "idempotency_fingerprint_excluded"} {
		expected, err := requiredField[bool](request.Case.Expected, name)
		if err != nil || !expected {
			return false, err
		}
	}
	fixture, err := newServiceResourceFixture()
	if err != nil {
		return false, err
	}
	wrap, err := service.NewProtectedResourceMiddleware(fixture.instance, "https://service.example")
	if err != nil {
		return false, err
	}
	calls := 0
	handler := wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, found := service.PrincipalFromContext(r.Context())
		if !found || principal.CredentialID != "resource-token" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	for index, value := range []string{"Bearer opaque-token", "Bearer secret-invalid-token"} {
		incoming := httptest.NewRequest(http.MethodGet, "https://service.example/private", nil)
		// Preserve the vector's spelling instead of canonicalizing it with Header.Set.
		incoming.Header[field] = []string{value}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, incoming)
		if index == 0 && response.Code != http.StatusOK || index == 1 && response.Code != http.StatusUnauthorized || calls != 1 {
			return false, fmt.Errorf("case-insensitive carrier authentication failed")
		}
		if strings.Contains(response.Body.String()+fmt.Sprint(response.Header()), value) || strings.Contains(response.Body.String(), "secret-invalid-token") {
			return false, fmt.Errorf("response disclosed authorization")
		}
	}
	inspect, err := service.NewHTTPHandler(fixture.instance, service.HTTPHandlerOptions{})
	if err != nil {
		return false, err
	}
	var first *httptest.ResponseRecorder
	var firstGrant service.Result[json.RawMessage]
	issued := fixture.issued
	for index := range 2 {
		token, err := fixture.assertion(aep.AssertionGrant, "", fmt.Sprintf("field-%d", index))
		if err != nil {
			return false, err
		}
		incoming := httptest.NewRequest(http.MethodGet, "https://service.example"+aep.WellKnownPath, nil)
		incoming.Header.Set("Authorization", "AEP "+token)
		incoming.Header[field] = []string{fmt.Sprintf("Bearer private-%d", index)}
		response := httptest.NewRecorder()
		inspect.ServeHTTP(response, incoming)
		if response.Code != http.StatusOK || strings.Contains(response.Body.String(), token) || strings.Contains(response.Body.String(), "private-") {
			return false, fmt.Errorf("Inspect disclosed authorization or failed")
		}
		grant, err := fixture.instance.Grant(context.Background(), []byte(`{"grant_type":"oauth-bearer"}`), service.CommandOptions{ClientAssertion: token, IdempotencyKey: "field-safety"})
		if err != nil || grant.Status != http.StatusOK || fixture.issued != issued+1 {
			return false, fmt.Errorf("changed assertion altered idempotent execution: %v", err)
		}
		if index == 0 {
			first, firstGrant = response, grant
		} else if response.Header().Get("ETag") != first.Header().Get("ETag") || response.Body.String() != first.Body.String() || !jsonEqual(firstGrant.Body, grant.Body) {
			return false, fmt.Errorf("authorization altered Inspect representation or cached Grant")
		}
	}
	return true, nil
}

func evaluateServicePaymentComposition(request adapterRequest) (bool, error) {
	fixture, err := newServiceResourceFixture()
	if err != nil {
		return false, err
	}
	wrap, err := service.NewProtectedResourceMiddleware(fixture.instance, "https://service.example")
	if err != nil {
		return false, err
	}
	status, err := requiredField[int](request.Case.Input, "anonymous_status")
	if err != nil {
		return false, err
	}
	scheme, err := requiredField[string](request.Case.Input, "anonymous_challenge")
	if err != nil {
		return false, err
	}
	after, err := requiredField[bool](request.Case.Expected, "payment_advertised_after_aep")
	if err != nil {
		return false, err
	}
	for _, protocol := range []string{"mpp", "x402"} {
		fields, err := requiredField[map[string]json.RawMessage](request.Case.Expected, protocol)
		if err != nil {
			return false, err
		}
		headers := make(http.Header)
		for name, raw := range fields {
			if name == "ambiguous" {
				var ambiguous bool
				if json.Unmarshal(raw, &ambiguous) != nil || ambiguous {
					return false, nil
				}
				continue
			}
			var value string
			if err := json.Unmarshal(raw, &value); err != nil {
				return false, err
			}
			if value == "AEP compact-jws" {
				token, err := fixture.assertion(aep.AssertionAuthenticate, "https://service.example/private", protocol)
				if err != nil {
					return false, err
				}
				value = "AEP " + token
			}
			headers.Set(name, value)
		}
		calls := 0
		unchanged := false
		handler := wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			principal, found := service.PrincipalFromContext(r.Context())
			unchanged = found && principal.AgentDID == "did:web:agent.example" && jsonEqual(r.Header, headers)
			w.WriteHeader(http.StatusPaymentRequired)
		}))
		anonymous := httptest.NewRecorder()
		handler.ServeHTTP(anonymous, httptest.NewRequest(http.MethodGet, "https://service.example/private", nil))
		if anonymous.Code != status || !strings.HasPrefix(anonymous.Header().Get("WWW-Authenticate"), scheme+" ") || calls != 0 {
			return false, fmt.Errorf("%s reached payment before authentication", protocol)
		}
		incoming := httptest.NewRequest(http.MethodGet, "https://service.example/private", nil)
		incoming.Header = headers.Clone()
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, incoming)
		if !after || response.Code != http.StatusPaymentRequired || calls != 1 || !unchanged || !jsonEqual(incoming.Header, headers) {
			return false, fmt.Errorf("%s payment composition failed", protocol)
		}
	}
	return true, nil
}

func evaluateServiceAmbiguity(request adapterRequest) (bool, error) {
	cases, err := requiredField[[]string](request.Case.Input, "cases")
	if err != nil {
		return false, err
	}
	code, err := requiredField[aep.ErrorCode](request.Case.Expected, "code")
	if err != nil {
		return false, err
	}
	disclosure, err := requiredField[string](request.Case.Expected, "disclosure")
	if err != nil {
		return false, err
	}
	fallback, err := requiredField[bool](request.Case.Expected, "fallback")
	if err != nil {
		return false, err
	}
	selected, err := rawField(request.Case.Expected, "selected_credential")
	if err != nil {
		return false, err
	}
	if disclosure != "none" || fallback || string(selected) != "null" {
		return false, nil
	}
	fixture, err := newServiceResourceFixture()
	if err != nil {
		return false, err
	}
	wrap, err := service.NewProtectedResourceMiddleware(fixture.instance, "https://service.example")
	if err != nil {
		return false, err
	}
	calls := 0
	handler := wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(http.StatusOK) }))
	for _, name := range cases {
		incoming := httptest.NewRequest(http.MethodGet, "https://service.example/private", nil)
		switch name {
		case "both-aep-recognized":
			incoming.Header.Set(aep.AuthorizationHeader, "Bearer opaque-token")
			incoming.Header.Set("Authorization", "Bearer opaque-token")
		case "invalid-dedicated-plus-valid-standard":
			incoming.Header.Set(aep.AuthorizationHeader, "invalid")
			incoming.Header.Set("Authorization", "Bearer opaque-token")
		case "duplicate-dedicated-lines":
			incoming.Header[aep.AuthorizationHeader] = []string{"Bearer opaque-token", "Bearer opaque-token"}
		case "combined-dedicated-values":
			incoming.Header.Set(aep.AuthorizationHeader, "Bearer opaque-token, Bearer opaque-token")
		default:
			return false, fmt.Errorf("unknown ambiguity case %q", name)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, incoming)
		problem, err := aep.ParseProblemDetails(response.Body.Bytes())
		if err != nil || response.Code != http.StatusUnauthorized || problem.Code != code || calls != 0 || strings.Contains(response.Body.String(), "did:web:agent.example") || strings.Contains(response.Body.String(), "opaque-token") {
			return false, fmt.Errorf("%s did not reject ambiguity without disclosure: %v", name, err)
		}
	}
	// The same credential succeeds alone, so rejection above is not a bad-token test.
	valid := httptest.NewRequest(http.MethodGet, "https://service.example/private", nil)
	valid.Header.Set("Authorization", "Bearer opaque-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, valid)
	return response.Code == http.StatusOK && calls == 1, nil
}
