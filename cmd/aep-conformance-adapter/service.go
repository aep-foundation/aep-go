package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	aep "github.com/aep-foundation/aep-go"
	"github.com/aep-foundation/aep-go/service"
)

var serviceNow = time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)

type conformanceEnrollmentPolicy struct{ calls *atomic.Int32 }

func (policy conformanceEnrollmentPolicy) DecideEnrollment(context.Context, aep.EnrollRequest, service.EnrollmentPolicyContext) (service.EnrollmentDecision, error) {
	if policy.calls != nil {
		policy.calls.Add(1)
	}
	return service.EnrollmentDecision{Status: aep.EnrollmentActive}, nil
}

type conformanceGrantHandler struct{}

func (conformanceGrantHandler) Grant(context.Context, aep.GrantRequest, service.GrantContext) (json.RawMessage, error) {
	return json.RawMessage(`{"credential_id":"credential-1"}`), nil
}

func (conformanceGrantHandler) Revoke(context.Context, aep.RevokeRequest, service.RevokeContext) error {
	return nil
}

func (conformanceGrantHandler) AuthenticateCredential(context.Context, service.CredentialAuthenticationInput) (*service.AuthenticatedPrincipal, error) {
	return nil, nil
}

func (conformanceGrantHandler) HasCredentialPresentation(context.Context, service.CredentialAuthenticationInput) (bool, error) {
	return false, nil
}

func newConformanceService(policy service.EnrollmentPolicy) (*service.Service, error) {
	return newConfiguredConformanceService(policy, nil, []service.GrantTypeDefinition{{GrantType: "custom-session", Handler: conformanceGrantHandler{}}}, nil, nil)
}

func newConfiguredConformanceService(policy service.EnrollmentPolicy, authenticationMethods []aep.AuthenticationMethod, grantTypes []service.GrantTypeDefinition, verifier service.AssertionVerifier, enrollmentStore service.EnrollmentStore) (*service.Service, error) {
	if policy == nil {
		policy = conformanceEnrollmentPolicy{}
	}
	var assertions atomic.Int32
	if verifier == nil {
		verifier = func(_ context.Context, _ string, verification service.AssertionVerificationContext) (aep.ClientAssertionClaims, error) {
			return aep.ClientAssertionClaims{
				Audience: verification.ServiceDID, ExpiresAt: verification.CurrentTime.Add(time.Minute).Unix(), IssuedAt: verification.CurrentTime.Unix(),
				Issuer: "did:web:agent.example", JWTID: fmt.Sprintf("assertion-%d", assertions.Add(1)), Operation: verification.Operation,
				Resource: verification.Resource, Subject: "did:web:agent.example",
			}, nil
		}
	}
	return service.New(service.Options{
		AuthenticationMethods: authenticationMethods,
		Clock:                 func() time.Time { return serviceNow },
		EnrollmentStore:       enrollmentStore,
		EnrollmentPolicy:      policy,
		GrantTypes:            grantTypes,
		Identifier:            func() (string, error) { return "enrollment-1", nil },
		IdentityMethods:       []aep.IdentityMethod{aep.IdentityMethodDIDWeb},
		ServiceDID:            "did:web:service.example",
		Verifier:              verifier,
	})
}

func serviceCommandOptions(operation aep.AssertionOperation, key string) service.CommandOptions {
	return serviceCommandOptionsForAgent(operation, key, "did:web:agent.example")
}

func serviceCommandOptionsForAgent(_ aep.AssertionOperation, key string, agentDID string) service.CommandOptions {
	header, _ := json.Marshal(map[string]string{"alg": "EdDSA", "kid": agentDID + "#key-1", "typ": "JWT"})
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	assertion := base64.RawURLEncoding.EncodeToString(header) + "." + payload + ".signature"
	return service.CommandOptions{ClientAssertion: assertion, IdempotencyKey: key}
}

func evaluateService(request adapterRequest) (bool, error) {
	switch request.Vector.ID {
	case "response-active", "response-pending-verification-owner-action", "response-pending-requirements", "revoke-response-empty",
		"not-recognized-problem", "requirements-unmet-problem", "verification-pending-problem":
		return evaluateServiceCommandResponse(request)
	}
	if handled, passed, err := evaluateShared(request); handled {
		return passed, err
	}
	switch request.Vector.ID {
	case "did-web-resolution":
		return evaluateServiceDIDResolution(request)
	case "repeated-existing":
		return evaluateRepeatedEnrollment(request)
	case "grant-before-enroll-rejected":
		return evaluateServiceGrantBeforeEnrollment(request)
	case "command-header":
		return evaluateServiceCommandHeader(request)
	case "command-replay-conflict":
		return evaluateServiceReplayConflict(request)
	case "enroll-conflict":
		return evaluateServiceEnrollConflict(request)
	case "transport-requirements":
		return evaluateServiceTransport(request)
	case "api-key-wrong-header-rejected":
		return evaluateServiceAPIKeyHeader(request)
	case "authenticate-assertion":
		return evaluateServiceAuthenticateAssertion(request)
	case "authorization-payment-composition":
		return evaluateServicePaymentComposition(request)
	case "operation-substitution-rejected":
		return evaluateServiceOperationBinding(request)
	case "redirect-safety":
		return evaluateRedirectSafety(request)
	case "authorization-ambiguity":
		return evaluateServiceAmbiguity(request)
	case "assertion-and-credential-failures":
		return evaluateServiceAuthenticationFailures(request)
	case "authorization-field-safety":
		return evaluateServiceFieldSafety(request)
	}
	return false, fmt.Errorf("no Service operation maps vector %s/%s", request.Vector.Category, request.Vector.ID)
}

func evaluateServiceCommandResponse(request adapterRequest) (bool, error) {
	store := service.NewMemoryEnrollmentStore()
	record := service.EnrollmentRecord{AgentDID: "did:web:agent.example", EnrollmentID: "response-vector", Status: aep.AgentActive, CreatedAt: serviceNow, UpdatedAt: serviceNow, Since: serviceNow}
	policy := service.NewStaticEnrollmentPolicy(service.EnrollmentDecision{Status: aep.EnrollmentActive})
	method, path, body := http.MethodPost, "/aep/enroll", `{"agent_did":"did:web:agent.example"}`
	var verifier service.AssertionVerifier
	var claims *aep.InspectClaims
	switch {
	case request.Vector.Category == "status":
		value, err := requiredField[aep.StatusResponse](request.Case.Expected, "body")
		if err != nil {
			return false, err
		}
		record.Status, record.RequirementsPending = value.Status, value.RequirementsPending
		record.Since, err = time.Parse(time.RFC3339, value.Since)
		if err != nil {
			return false, err
		}
		method, path, body = http.MethodGet, "/aep/status", ""
	case request.Vector.ID == "response-pending-verification-owner-action":
		policy = service.NewStaticEnrollmentPolicy(service.EnrollmentDecision{Status: aep.EnrollmentPending, OwnerActionRequired: true, VerificationPending: []string{"contact.email"}})
	case request.Vector.ID == "revoke-response-empty":
		path, body = "/aep/revoke", `{"all_grant_types":"true"}`
	case request.Vector.ID == "not-recognized-problem":
		method, path, body = http.MethodGet, "/aep/status", ""
		verifier = func(context.Context, string, service.AssertionVerificationContext) (aep.ClientAssertionClaims, error) {
			return aep.ClientAssertionClaims{}, fmt.Errorf("bad signature")
		}
	case request.Vector.ID == "requirements-unmet-problem":
		claims = &aep.InspectClaims{Required: []aep.ClaimName{"company.registration"}}
	case request.Vector.ID == "verification-pending-problem":
		record.Status, record.OwnerActionRequired, record.VerificationPending = aep.AgentPending, true, []string{"contact.email"}
		path, body = "/aep/grant", `{"grant_type":"custom-session"}`
	}
	if path != "/aep/enroll" {
		if _, err := store.SaveEnrollment(context.Background(), record); err != nil {
			return false, err
		}
	}
	if verifier == nil {
		verifier = func(_ context.Context, _ string, verification service.AssertionVerificationContext) (aep.ClientAssertionClaims, error) {
			return aep.ClientAssertionClaims{Audience: verification.ServiceDID, Issuer: record.AgentDID, Subject: record.AgentDID, Operation: verification.Operation, JWTID: "response-vector", IssuedAt: serviceNow.Unix(), ExpiresAt: serviceNow.Add(time.Minute).Unix()}, nil
		}
	}
	instance, err := service.New(service.Options{ServiceDID: "did:web:service.example", IdentityMethods: []aep.IdentityMethod{aep.IdentityMethodDIDWeb}, Clock: func() time.Time { return serviceNow }, EnrollmentPolicy: policy, EnrollmentStore: store, Claims: claims, GrantTypes: []service.GrantTypeDefinition{{GrantType: "custom-session", Handler: conformanceGrantHandler{}}}, Verifier: verifier})
	if err != nil {
		return false, err
	}
	handler, err := service.NewHTTPHandler(instance, service.HTTPHandlerOptions{})
	if err != nil {
		return false, err
	}
	incoming := httptest.NewRequest(method, "https://service.example"+path, strings.NewReader(body))
	incoming.Header.Set("Authorization", "AEP "+serviceCommandOptions(aep.AssertionEnroll, "response-vector").ClientAssertion)
	incoming.Header.Set("Content-Type", aep.MediaType)
	incoming.Header.Set("Idempotency-Key", "response-vector")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, incoming)
	return jsonEqual(map[string]any{"status": recorder.Code, "content_type": recorder.Header().Get("Content-Type"), "body": json.RawMessage(recorder.Body.Bytes())}, request.Case.Expected), nil
}

func evaluateServiceAuthenticateAssertion(request adapterRequest) (bool, error) {
	claims, err := requiredField[aep.ClientAssertionClaims](request.Case.Expected, "claims")
	if err != nil {
		return false, err
	}
	challenge, err := requiredField[struct {
		Scheme     string `json:"scheme"`
		ServiceDID string `json:"service_did"`
		Inspect    string `json:"inspect"`
		Reason     string `json:"reason"`
	}](request.Case.Expected, "challenge")
	if err != nil {
		return false, err
	}
	resource, err := requiredField[string](request.Case.Input, "url")
	if err != nil {
		return false, err
	}
	method, err := requiredField[string](request.Case.Input, "method")
	if err != nil {
		return false, err
	}
	scheme, err := requiredField[string](request.Case.Expected, "authorization_scheme")
	if err != nil {
		return false, err
	}
	target, err := url.Parse(resource)
	if err != nil {
		return false, err
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return false, err
	}
	now := time.Unix(claims.IssuedAt, 0)
	store := service.NewMemoryEnrollmentStore()
	if _, err := store.SaveEnrollment(context.Background(), service.EnrollmentRecord{AgentDID: claims.Subject, EnrollmentID: "resource-enrollment", Status: aep.AgentActive, CreatedAt: now, UpdatedAt: now, Since: now}); err != nil {
		return false, err
	}
	instance, err := service.New(service.Options{
		ServiceDID: challenge.ServiceDID, IdentityMethods: []aep.IdentityMethod{aep.IdentityMethodDIDWeb},
		AuthenticationMethods: []aep.AuthenticationMethod{aep.AuthenticationMethodJWT}, EnrollmentStore: store,
		Clock: func() time.Time { return now },
		Verifier: func(ctx context.Context, token string, verification service.AssertionVerificationContext) (aep.ClientAssertionClaims, error) {
			return aep.VerifyClientAssertion(ctx, token, aep.VerifyClientAssertionOptions{Key: public, Algorithms: verification.SigningAlgorithms, Audience: verification.ServiceDID, Operation: verification.Operation, Resource: verification.Resource, CurrentTime: verification.CurrentTime})
		},
	})
	if err != nil {
		return false, err
	}
	input := service.ProtectedResourceRequest{Method: method, URL: target}
	anonymous, err := instance.AuthenticateProtectedResource(context.Background(), input)
	expectedChallenge := fmt.Sprintf(`%s service_did=%q,inspect=%q,reason=%q`, challenge.Scheme, challenge.ServiceDID, challenge.Inspect, challenge.Reason)
	if err != nil || anonymous.Authenticated || anonymous.Response == nil || anonymous.Response.Status != http.StatusUnauthorized || anonymous.Response.Headers.Get("WWW-Authenticate") != expectedChallenge || string(anonymous.Response.Body.Code) != challenge.Reason {
		return false, fmt.Errorf("unexpected anonymous resource response: %#v, %v", anonymous, err)
	}
	token, err := aep.SignClientAssertion(claims, aep.SignClientAssertionOptions{Algorithm: aep.SigningAlgorithmEdDSA, Key: private, KeyID: claims.Issuer + "#key-1"})
	if err != nil {
		return false, err
	}
	input.Headers = http.Header{"Authorization": {scheme + " " + token}}
	authenticated, err := instance.AuthenticateProtectedResource(context.Background(), input)
	if err != nil || !authenticated.Authenticated || authenticated.Principal == nil || authenticated.Principal.AgentDID != claims.Subject || authenticated.Principal.AuthenticationMethod != aep.AuthenticationMethodJWT {
		return false, fmt.Errorf("signed resource assertion was not accepted: %#v, %v", authenticated, err)
	}
	replayed, err := instance.AuthenticateProtectedResource(context.Background(), input)
	return err == nil && !replayed.Authenticated && replayed.Response != nil && replayed.Response.Status == http.StatusUnauthorized && replayed.Response.Body.Code == aep.ErrorNotRecognized, err
}

func evaluateServiceDIDResolution(request adapterRequest) (bool, error) {
	did, err := requiredField[string](request.Case.Input, "did")
	if err != nil {
		return false, err
	}
	expected, err := requiredField[string](request.Case.Expected, "document_url")
	if err != nil {
		return false, err
	}
	resolved, err := aep.DIDWebDocumentURL(did)
	return err == nil && resolved.String() == expected, err
}

func evaluateRepeatedEnrollment(request adapterRequest) (bool, error) {
	type existingEnrollment struct {
		AgentDID string          `json:"agent_did"`
		Since    string          `json:"since"`
		Status   aep.AgentStatus `json:"status"`
	}
	type enrollmentRequest struct {
		AgentDID       string `json:"agent_did"`
		IdempotencyKey string `json:"idempotency_key"`
	}
	type expectedResponse struct {
		Body        json.RawMessage `json:"body"`
		ContentType string          `json:"content_type"`
		Status      int             `json:"status"`
	}

	existing, err := requiredField[existingEnrollment](request.Case.Input, "existing")
	if err != nil {
		return false, err
	}
	enrollRequest, err := requiredField[enrollmentRequest](request.Case.Input, "request")
	if err != nil {
		return false, err
	}
	expected, err := requiredField[expectedResponse](request.Case.Expected, "response")
	if err != nil {
		return false, err
	}
	expectedPolicyEvaluated, err := requiredField[bool](request.Case.Expected, "policy_evaluated")
	if err != nil {
		return false, err
	}
	expectedRecordReplaced, err := requiredField[bool](request.Case.Expected, "record_replaced")
	if err != nil {
		return false, err
	}
	since, err := time.Parse(time.RFC3339, existing.Since)
	if err != nil {
		return false, err
	}
	expectedBody, err := aep.ParseEnrollResponse(expected.Body)
	if err != nil {
		return false, err
	}

	var calls atomic.Int32
	store := service.NewMemoryEnrollmentStore()
	seeded := service.EnrollmentRecord{
		AgentDID: existing.AgentDID, CreatedAt: since, EnrollmentID: "existing-enrollment", Since: since, Status: existing.Status, UpdatedAt: since,
	}
	if _, err := store.SaveEnrollment(context.Background(), seeded); err != nil {
		return false, err
	}
	verifier := func(_ context.Context, _ string, verification service.AssertionVerificationContext) (aep.ClientAssertionClaims, error) {
		return aep.ClientAssertionClaims{
			Audience: verification.ServiceDID, ExpiresAt: verification.CurrentTime.Add(time.Minute).Unix(), IssuedAt: verification.CurrentTime.Unix(),
			Issuer: enrollRequest.AgentDID, JWTID: "repeated-existing", Operation: verification.Operation, Resource: verification.Resource, Subject: enrollRequest.AgentDID,
		}, nil
	}
	instance, err := newConfiguredConformanceService(
		conformanceEnrollmentPolicy{calls: &calls}, nil,
		[]service.GrantTypeDefinition{{GrantType: "custom-session", Handler: conformanceGrantHandler{}}}, verifier, store,
	)
	if err != nil {
		return false, err
	}
	body, err := json.Marshal(enrollRequest)
	if err != nil {
		return false, err
	}
	result, err := instance.Enroll(context.Background(), body, serviceCommandOptionsForAgent(aep.AssertionEnroll, enrollRequest.IdempotencyKey, enrollRequest.AgentDID))
	if err != nil {
		return false, err
	}
	after, err := store.FindEnrollment(context.Background(), enrollRequest.AgentDID)
	if err != nil || after == nil {
		return false, err
	}
	policyEvaluated := calls.Load() != 0
	recordReplaced := !jsonEqual(seeded, *after)
	if result.Status != expected.Status || result.ContentType != expected.ContentType || result.Problem != nil || !jsonEqual(result.Body, expectedBody) ||
		policyEvaluated != expectedPolicyEvaluated || recordReplaced != expectedRecordReplaced {
		return false, fmt.Errorf(
			"repeated enrollment mismatch: result=%#v expected=%#v policy_evaluated=%t expected_policy_evaluated=%t record_replaced=%t expected_record_replaced=%t",
			result, expected, policyEvaluated, expectedPolicyEvaluated, recordReplaced, expectedRecordReplaced,
		)
	}
	return true, nil
}

func evaluateServiceGrantBeforeEnrollment(request adapterRequest) (bool, error) {
	operation, err := requiredField[string](request.Case.Input, "operation")
	if err != nil || operation != "grant" {
		return false, err
	}
	enrollment, err := requiredField[string](request.Case.Input, "enrollment")
	if err != nil || enrollment != "unrecognized" {
		return false, err
	}
	status, err := requiredField[int](request.Case.Expected, "status")
	if err != nil {
		return false, err
	}
	implicit, err := requiredField[bool](request.Case.Expected, "implicit_enrollment")
	if err != nil {
		return false, err
	}
	store := service.NewMemoryEnrollmentStore()
	var policyCalls atomic.Int32
	instance, err := newConfiguredConformanceService(conformanceEnrollmentPolicy{calls: &policyCalls}, nil, []service.GrantTypeDefinition{{GrantType: "custom-session", Handler: conformanceGrantHandler{}}}, nil, store)
	if err != nil {
		return false, err
	}
	result, err := instance.Grant(context.Background(), []byte(`{"grant_type":"custom-session"}`), serviceCommandOptions(aep.AssertionGrant, "grant"))
	expected, fieldErr := requiredField[aep.ErrorCode](request.Case.Expected, "code")
	if fieldErr != nil {
		return false, fieldErr
	}
	if err != nil {
		return false, err
	}
	record, err := store.FindEnrollment(context.Background(), "did:web:agent.example")
	return err == nil && result.Status == status && result.Problem != nil && result.Problem.Code == expected && (record != nil) == implicit && policyCalls.Load() == 0, err
}

func evaluateServiceEnrollConflict(request adapterRequest) (bool, error) {
	agentDID, err := requiredField[string](request.Case.Input, "agent_did")
	if err != nil {
		return false, err
	}
	key, err := requiredField[string](request.Case.Input, "idempotency_key")
	if err != nil {
		return false, err
	}
	firstHash, err := requiredField[string](request.Case.Input, "first_body_hash")
	if err != nil {
		return false, err
	}
	secondHash, err := requiredField[string](request.Case.Input, "second_body_hash")
	if err != nil {
		return false, err
	}
	store := service.NewMemoryIdempotencyStore()
	input := service.IdempotencyInput{AgentDID: agentDID, Command: service.IdempotentEnroll, IdempotencyKey: key, RequestHash: firstHash}
	calls := 0
	execute := func() (service.StoredResponse, error) {
		calls++
		return service.StoredResponse{Status: http.StatusOK, ContentType: aep.MediaType, Body: json.RawMessage(`{"status":"active"}`)}, nil
	}
	firstStored, err := store.ExecuteIdempotent(context.Background(), input, execute)
	if err != nil || firstStored.State != service.IdempotencyCreated {
		return false, err
	}
	input.RequestHash = secondHash
	secondStored, err := store.ExecuteIdempotent(context.Background(), input, execute)
	if err != nil || secondStored.State != service.IdempotencyConflict || calls != 1 {
		return false, err
	}
	// Vector hashes exercise the store directly; real request bodies exercise response mapping.
	var assertions atomic.Int32
	verifier := func(_ context.Context, _ string, verification service.AssertionVerificationContext) (aep.ClientAssertionClaims, error) {
		return aep.ClientAssertionClaims{Audience: verification.ServiceDID, Issuer: agentDID, Subject: agentDID, IssuedAt: serviceNow.Unix(), ExpiresAt: serviceNow.Add(time.Minute).Unix(), JWTID: fmt.Sprintf("conflict-%d", assertions.Add(1)), Operation: verification.Operation}, nil
	}
	instance, err := newConfiguredConformanceService(nil, nil, nil, verifier, nil)
	if err != nil {
		return false, err
	}
	body, err := json.Marshal(map[string]string{"agent_did": agentDID})
	if err != nil {
		return false, err
	}
	first, err := instance.Enroll(context.Background(), body, serviceCommandOptionsForAgent(aep.AssertionEnroll, key, agentDID))
	if err != nil {
		return false, err
	}
	replay, err := instance.Enroll(context.Background(), body, serviceCommandOptionsForAgent(aep.AssertionEnroll, key, agentDID))
	if err != nil {
		return false, err
	}
	changed, err := json.Marshal(map[string]any{"agent_did": agentDID, "claims": map[string]string{"contact.email": "agent@example.com"}})
	if err != nil {
		return false, err
	}
	conflict, err := instance.Enroll(context.Background(), changed, serviceCommandOptionsForAgent(aep.AssertionEnroll, key, agentDID))
	if err != nil || first.Status != http.StatusOK || replay.Status != http.StatusOK || !jsonEqual(first.Body, replay.Body) || conflict.Problem == nil {
		return false, fmt.Errorf("idempotency mismatch: first=%#v replay=%#v conflict=%#v error=%v", first, replay, conflict, err)
	}
	return jsonEqual(map[string]any{"status": conflict.Status, "content_type": conflict.ContentType, "body": conflict.Problem}, request.Case.Expected), nil
}

func evaluateServiceTransport(request adapterRequest) (bool, error) {
	instance, err := newConformanceService(nil)
	if err != nil {
		return false, err
	}
	handler, err := service.NewHTTPHandler(instance, service.HTTPHandlerOptions{})
	if err != nil {
		return false, err
	}
	requestURL, err := requiredField[string](request.Case.Input, "request_url")
	if err != nil {
		return false, err
	}
	target, err := url.ParseRequestURI(requestURL)
	if err != nil || target.Scheme != "https" || target.Host == "" {
		return false, fmt.Errorf("invalid Inspect request URL: %q", requestURL)
	}
	expectedMediaType, err := requiredField[string](request.Case.Expected, "media_type_essence")
	if err != nil {
		return false, err
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, requestURL, nil))
	mediaType, _, err := mime.ParseMediaType(response.Header().Get("Content-Type"))
	if err != nil || response.Code != http.StatusOK || mediaType != expectedMediaType {
		return false, fmt.Errorf("Inspect returned status %d and media type %q", response.Code, mediaType)
	}
	document, err := aep.ParseInspectDocument(response.Body.Bytes())
	return err == nil && document.Service.DID == "did:web:service.example", err
}

func evaluateServiceAPIKeyHeader(request adapterRequest) (bool, error) {
	store := service.NewMemoryServiceCredentialStore()
	definition, err := service.StoredAPIKeyGrantType(service.StoredCredentialGrantTypeOptions[aep.APIKeyGrantResponse]{
		Issue: func(context.Context, aep.GrantRequest, service.GrantContext) (aep.APIKeyGrantResponse, error) {
			return aep.APIKeyGrantResponse{APIKey: "opaque-api-key", CredentialID: "credential-1", ExpiresAt: "2027-01-01T00:00:00Z", Header: "x-api-key", Scopes: []string{}}, nil
		},
		Store: store,
	})
	if err != nil {
		return false, err
	}
	instance, err := newConfiguredConformanceService(nil, []aep.AuthenticationMethod{aep.AuthenticationMethod(aep.GrantTypeAPIKey)}, []service.GrantTypeDefinition{definition}, nil, nil)
	if err != nil {
		return false, err
	}
	if _, err := instance.Enroll(context.Background(), []byte(`{"agent_did":"did:web:agent.example"}`), serviceCommandOptions(aep.AssertionEnroll, "enroll")); err != nil {
		return false, err
	}
	if _, err := instance.Grant(context.Background(), []byte(`{"grant_type":"api-key"}`), serviceCommandOptions(aep.AssertionGrant, "grant")); err != nil {
		return false, err
	}
	presentedHeader, err := requiredField[string](request.Case.Input, "presented_header")
	if err != nil {
		return false, err
	}
	resource, _ := url.Parse("https://service.example/private")
	result, err := instance.AuthenticateProtectedResource(context.Background(), service.ProtectedResourceRequest{Headers: http.Header{presentedHeader: []string{"opaque-api-key"}}, Method: http.MethodGet, URL: resource})
	expectedCode, expectedErr := requiredField[string](request.Case.Expected, "code")
	if expectedErr != nil {
		return false, expectedErr
	}
	return err == nil && result.Response != nil && string(result.Response.Body.Code) == expectedCode, err
}

func evaluateServiceOperationBinding(request adapterRequest) (bool, error) {
	operations, err := requiredField[[]aep.AssertionOperation](request.Case.Input, "operations")
	if err != nil {
		return false, err
	}
	endpoints, err := requiredField[[]string](request.Case.Input, "command_endpoints")
	if err != nil {
		return false, err
	}
	resource, err := requiredField[string](request.Case.Input, "protected_resource")
	if err != nil {
		return false, err
	}
	expectedAllowed, err := requiredField[[]string](request.Case.Expected, "allowed")
	if err != nil {
		return false, err
	}
	expectedFailure, err := requiredField[aep.ErrorCode](request.Case.Expected, "all_other_pairs")
	if err != nil {
		return false, err
	}
	target, err := url.Parse(resource)
	if err != nil {
		return false, err
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return false, err
	}
	verifier := func(ctx context.Context, token string, verification service.AssertionVerificationContext) (aep.ClientAssertionClaims, error) {
		return aep.VerifyClientAssertion(ctx, token, aep.VerifyClientAssertionOptions{Key: public, Algorithms: verification.SigningAlgorithms, Audience: verification.ServiceDID, Operation: verification.Operation, Resource: verification.Resource, CurrentTime: verification.CurrentTime})
	}
	store := service.NewMemoryEnrollmentStore()
	if _, err := store.SaveEnrollment(context.Background(), service.EnrollmentRecord{AgentDID: "did:web:agent.example", EnrollmentID: "operations", Status: aep.AgentActive, CreatedAt: serviceNow, UpdatedAt: serviceNow, Since: serviceNow}); err != nil {
		return false, err
	}
	instance, err := newConfiguredConformanceService(nil, []aep.AuthenticationMethod{aep.AuthenticationMethodJWT}, []service.GrantTypeDefinition{{GrantType: "custom-session", Handler: conformanceGrantHandler{}}}, verifier, store)
	if err != nil {
		return false, err
	}
	handler, err := service.NewHTTPHandler(instance, service.HTTPHandlerOptions{})
	if err != nil {
		return false, err
	}
	document, err := instance.InspectDocument()
	if err != nil {
		return false, err
	}
	bodies := map[string]string{"enroll": `{"agent_did":"did:web:agent.example"}`, "grant": `{"grant_type":"custom-session"}`, "revoke": `{"grant_type":"custom-session"}`, "status": ""}
	var allowed []string
	for _, operation := range operations {
		for _, endpoint := range append(slices.Clone(endpoints), "protected-resource") {
			pair := string(operation) + ":" + endpoint
			claims := aep.ClientAssertionClaims{Audience: "did:web:service.example", Issuer: "did:web:agent.example", Subject: "did:web:agent.example", Operation: operation, IssuedAt: serviceNow.Unix(), ExpiresAt: serviceNow.Add(time.Minute).Unix(), JWTID: pair}
			if operation == aep.AssertionAuthenticate {
				claims.Resource = resource
			}
			token, err := aep.SignClientAssertion(claims, aep.SignClientAssertionOptions{Algorithm: aep.SigningAlgorithmEdDSA, Key: private, KeyID: "did:web:agent.example#key-1"})
			if err != nil {
				return false, err
			}
			status, code := 0, aep.ErrorCode("")
			if endpoint == "protected-resource" {
				result, err := instance.AuthenticateProtectedResource(context.Background(), service.ProtectedResourceRequest{Method: http.MethodGet, URL: target, Headers: http.Header{"Authorization": {"AEP " + token}}})
				if err != nil {
					return false, err
				}
				if result.Authenticated {
					status = http.StatusOK
				} else if result.Response != nil {
					status, code = result.Response.Status, result.Response.Body.Code
				}
			} else {
				path, err := aep.CommandPathFromInspect(document, aep.Command(endpoint))
				if err != nil {
					return false, err
				}
				method := http.MethodPost
				if endpoint == "status" {
					method = http.MethodGet
				}
				incoming := httptest.NewRequest(method, "https://service.example"+path, strings.NewReader(bodies[endpoint]))
				incoming.Header.Set("Authorization", "AEP "+token)
				incoming.Header.Set("Content-Type", aep.MediaType)
				incoming.Header.Set("Idempotency-Key", pair)
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, incoming)
				status = response.Code
				if status != http.StatusOK {
					problem, err := aep.ParseProblemDetails(response.Body.Bytes())
					if err != nil {
						return false, err
					}
					code = problem.Code
				}
			}
			if status == http.StatusOK {
				allowed = append(allowed, pair)
			} else if status != http.StatusUnauthorized || code != expectedFailure {
				return false, fmt.Errorf("%s returned %d %s", pair, status, code)
			}
		}
	}
	slices.Sort(allowed)
	slices.Sort(expectedAllowed)
	return slices.Equal(allowed, expectedAllowed), nil
}
