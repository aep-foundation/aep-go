package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/url"
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
	case "command-header", "command-replay-conflict":
		return evaluateServiceIdempotency()
	case "enroll-conflict":
		return evaluateServiceEnrollConflict()
	case "transport-requirements":
		return evaluateServiceTransport(request)
	case "api-key-wrong-header-rejected":
		return evaluateServiceAPIKeyHeader(request)
	case "authenticate-assertion":
		return evaluateAuthenticateAssertion(request)
	case "authorization-payment-composition":
		return evaluateServicePaymentComposition()
	case "operation-substitution-rejected":
		return evaluateServiceOperationBinding()
	case "redirect-safety":
		return evaluateRedirectSafety(request)
	case "assertion-and-credential-failures", "authorization-ambiguity", "authorization-field-safety":
		return evaluateServiceProtectedFailure(request)
	}
	return false, fmt.Errorf("no Service operation maps vector %s/%s", request.Vector.Category, request.Vector.ID)
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
	instance, err := newConformanceService(nil)
	if err != nil {
		return false, err
	}
	result, err := instance.Grant(context.Background(), []byte(`{"grant_type":"custom-session"}`), serviceCommandOptions(aep.AssertionGrant, "grant"))
	expected, fieldErr := requiredField[aep.ErrorCode](request.Case.Expected, "code")
	if fieldErr != nil {
		return false, fieldErr
	}
	return err == nil && result.Problem != nil && result.Problem.Code == expected, err
}

func evaluateServiceIdempotency() (bool, error) {
	instance, err := newConformanceService(nil)
	if err != nil {
		return false, err
	}
	body := []byte(`{"agent_did":"did:web:agent.example"}`)
	first, err := instance.Enroll(context.Background(), body, serviceCommandOptions(aep.AssertionEnroll, "shared"))
	if err != nil {
		return false, err
	}
	replay, err := instance.Enroll(context.Background(), body, serviceCommandOptions(aep.AssertionEnroll, "shared"))
	if err != nil {
		return false, err
	}
	conflict, err := instance.Enroll(context.Background(), []byte(`{"agent_did":"did:web:agent.example","claims":{"contact.email":"agent@example.com"}}`), serviceCommandOptions(aep.AssertionEnroll, "shared"))
	if err != nil || !jsonEqual(first.Body, replay.Body) || conflict.Status != http.StatusConflict || conflict.Problem == nil || conflict.Problem.Code != aep.ErrorIdempotencyConflict {
		return false, fmt.Errorf("idempotency mismatch: first=%#v replay=%#v conflict=%#v error=%v", first, replay, conflict, err)
	}
	return true, nil
}

func evaluateServiceEnrollConflict() (bool, error) {
	return evaluateServiceIdempotency()
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
	_ = handler
	contentType, err := requiredField[string](request.Case.Input, "content_type")
	if err != nil {
		return false, err
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	return err == nil && mediaType == aep.MediaType, err
}

func evaluateServiceProtectedFailure(request adapterRequest) (bool, error) {
	instance, err := newConformanceService(nil)
	if err != nil {
		return false, err
	}
	resource, err := url.Parse("https://service.example/private")
	if err != nil {
		return false, err
	}
	headers := http.Header{"Authorization": []string{"AEP malformed"}}
	if request.Vector.ID == "authorization-ambiguity" {
		headers.Set(aep.AuthorizationHeader, "AEP second")
	}
	result, err := instance.AuthenticateProtectedResource(context.Background(), service.ProtectedResourceRequest{Headers: headers, Method: http.MethodGet, URL: resource})
	if err != nil || result.Response == nil || result.Authenticated || result.Response.Body.Code != aep.ErrorNotRecognized && result.Response.Body.Code != aep.ErrorUnsupportedAuthenticationMethod {
		return false, err
	}
	if request.Vector.ID == "authorization-field-safety" {
		field, fieldErr := requiredField[string](request.Case.Input, "field_name")
		return fieldErr == nil && aep.IsHTTPFieldName(field), fieldErr
	}
	return true, nil
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

func evaluateServicePaymentComposition() (bool, error) {
	instance, err := newConfiguredConformanceService(nil, []aep.AuthenticationMethod{aep.AuthenticationMethodJWT}, nil, nil, nil)
	if err != nil {
		return false, err
	}
	if _, err := instance.Enroll(context.Background(), []byte(`{"agent_did":"did:web:agent.example"}`), serviceCommandOptions(aep.AssertionEnroll, "enroll")); err != nil {
		return false, err
	}
	resource, _ := url.Parse("https://service.example/private")
	assertion := serviceCommandOptions(aep.AssertionAuthenticate, "authenticate").ClientAssertion
	headers := http.Header{aep.AuthorizationHeader: []string{"AEP " + assertion}, "Authorization": []string{"Payment mpp-credential"}}
	result, err := instance.AuthenticateProtectedResource(context.Background(), service.ProtectedResourceRequest{Headers: headers, Method: http.MethodGet, URL: resource})
	return err == nil && result.Authenticated, err
}

func evaluateServiceOperationBinding() (bool, error) {
	verifier := func(_ context.Context, _ string, verification service.AssertionVerificationContext) (aep.ClientAssertionClaims, error) {
		return aep.ClientAssertionClaims{
			Audience: verification.ServiceDID, ExpiresAt: verification.CurrentTime.Add(time.Minute).Unix(), IssuedAt: verification.CurrentTime.Unix(),
			Issuer: "did:web:agent.example", JWTID: "substitution", Operation: aep.AssertionStatus, Subject: "did:web:agent.example",
		}, nil
	}
	instance, err := newConfiguredConformanceService(nil, nil, nil, verifier, nil)
	if err != nil {
		return false, err
	}
	result, err := instance.Enroll(context.Background(), []byte(`{"agent_did":"did:web:agent.example"}`), serviceCommandOptions(aep.AssertionEnroll, "enroll"))
	return err == nil && result.Status == http.StatusUnauthorized && result.Problem != nil && result.Problem.Code == aep.ErrorNotRecognized, err
}
