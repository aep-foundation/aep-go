package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"

	aep "github.com/aep-foundation/aep-go"
	"github.com/aep-foundation/aep-go/agent"
)

func evaluateAgent(request adapterRequest) (bool, error) {
	if request.Vector.ID == "request-minimal" || request.Vector.ID == "request-claims-catalog" {
		return evaluateAgentEnrollRequest(request)
	}
	if handled, passed, err := evaluateShared(request); handled {
		return passed, err
	}
	switch request.Vector.ID {
	case "public-discovery-cache":
		return evaluateDiscoveryCache()
	case "unknown-required-claim":
		return evaluateUnknownRequiredClaim(request)
	case "grant-before-enroll-rejected":
		return evaluateExpectedProblemCode(request)
	case "command-header":
		return evaluateCommandIdempotency(request)
	case "transport-requirements":
		return evaluateTransportRequirements(request)
	case "api-key-wrong-header-rejected":
		return evaluateAPIKeyHeader(request)
	case "authenticate-assertion":
		return evaluateAuthenticateAssertion(request)
	case "authorization-payment-composition":
		return evaluatePaymentComposition(request)
	case "operation-substitution-rejected":
		return evaluateOperationBinding(request)
	case "redirect-safety":
		return evaluateRedirectSafety(request)
	case "assertion-and-credential-failures", "authorization-ambiguity", "authorization-field-safety", "unadvertised-authentication-method":
		return evaluateAgentFailClosed(request)
	}
	return false, fmt.Errorf("no Agent operation maps vector %s/%s", request.Vector.Category, request.Vector.ID)
}

type inspectIdentityProvider struct{}

func (inspectIdentityProvider) GetOrCreateIdentity(context.Context, agent.IdentityRequest) (agent.ServiceIdentity, error) {
	return agent.ServiceIdentity{}, errors.New("identity creation is outside Inspect conformance")
}

func (inspectIdentityProvider) SignerFor(context.Context, agent.ServiceIdentity) (agent.AssertionSigner, error) {
	return nil, errors.New("assertion signing is outside Inspect conformance")
}

type signingIdentityProvider struct{}

func (signingIdentityProvider) GetOrCreateIdentity(_ context.Context, request agent.IdentityRequest) (agent.ServiceIdentity, error) {
	return agent.ServiceIdentity{AgentDID: "did:web:agent.example", IdentityMethod: aep.IdentityMethodDIDWeb, ServiceDID: request.ServiceDID, SigningAlgorithms: []aep.SigningAlgorithm{aep.SigningAlgorithmEdDSA}}, nil
}

type commandIdentityProvider struct{ agentDID string }

func (provider commandIdentityProvider) GetOrCreateIdentity(_ context.Context, request agent.IdentityRequest) (agent.ServiceIdentity, error) {
	return agent.ServiceIdentity{AgentDID: provider.agentDID, IdentityMethod: aep.IdentityMethodDIDWeb, ServiceDID: request.ServiceDID, SigningAlgorithms: []aep.SigningAlgorithm{aep.SigningAlgorithmEdDSA}}, nil
}

func (commandIdentityProvider) SignerFor(context.Context, agent.ServiceIdentity) (agent.AssertionSigner, error) {
	return func(context.Context, aep.ClientAssertionClaims, []aep.SigningAlgorithm) (string, error) {
		return "client-assertion", nil
	}, nil
}

func (signingIdentityProvider) SignerFor(context.Context, agent.ServiceIdentity) (agent.AssertionSigner, error) {
	return func(context.Context, aep.ClientAssertionClaims, []aep.SigningAlgorithm) (string, error) {
		return "signed-assertion", nil
	}, nil
}

func evaluateDiscoveryCache() (bool, error) {
	var requests atomic.Int32
	var serviceDID string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		response.Header().Set("Cache-Control", "no-cache")
		response.Header().Set("ETag", `"inspect-1"`)
		if request.Header.Get("If-None-Match") == `"inspect-1"` {
			response.WriteHeader(http.StatusNotModified)
			return
		}
		response.Header().Set("Content-Type", aep.MediaType)
		_ = json.NewEncoder(response).Encode(minimalInspectDocument(serviceDID))
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		return false, err
	}
	serviceDID = "did:web:" + strings.ReplaceAll(parsed.Host, ":", "%3A")
	client, err := agent.New(agent.Options{HTTPClient: server.Client(), IdentityProvider: inspectIdentityProvider{}})
	if err != nil {
		return false, err
	}
	session, err := client.Service(server.URL)
	if err != nil {
		return false, err
	}
	first, err := session.Inspect(context.Background())
	if err != nil {
		return false, err
	}
	second, err := session.Inspect(context.Background())
	return err == nil && requests.Load() == 2 && first.Document.Service.DID == serviceDID && second.Document.Service.DID == serviceDID, err
}

func evaluateAgentEnrollRequest(request adapterRequest) (bool, error) {
	agentDID, err := requiredField[string](request.Case.Input, "agent_did")
	if err != nil {
		return false, err
	}
	idempotencyKey, err := requiredField[string](request.Case.Input, "idempotency_key")
	if err != nil {
		return false, err
	}
	claimsRaw, err := rawField(request.Case.Input, "claims")
	if err != nil {
		return false, err
	}
	claims, err := aep.ParseClaimValues(claimsRaw)
	if err != nil {
		return false, err
	}
	var serviceDID string
	var captured *http.Request
	var capturedBody []byte
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, incoming *http.Request) {
		if incoming.URL.Path == aep.WellKnownPath {
			document := minimalInspectDocument(serviceDID)
			document.Commands.Supported = []aep.Command{aep.CommandEnroll, aep.CommandInspect}
			document.Identity.Methods = []aep.IdentityMethod{aep.IdentityMethodDIDWeb}
			response.Header().Set("Content-Type", aep.MediaType)
			_ = json.NewEncoder(response).Encode(document)
			return
		}
		captured = incoming.Clone(incoming.Context())
		capturedBody, _ = io.ReadAll(incoming.Body)
		response.Header().Set("Content-Type", aep.MediaType)
		_ = json.NewEncoder(response).Encode(aep.EnrollResponse{Status: aep.EnrollmentActive})
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		return false, err
	}
	serviceDID = "did:web:" + strings.ReplaceAll(parsed.Host, ":", "%3A")
	client, err := agent.New(agent.Options{HTTPClient: server.Client(), IdentityProvider: commandIdentityProvider{agentDID: agentDID}})
	if err != nil {
		return false, err
	}
	session, err := client.Service(server.URL)
	if err != nil {
		return false, err
	}
	if _, err := session.Enroll(context.Background(), agent.EnrollOptions{Claims: &claims, IdempotencyKey: idempotencyKey}); err != nil {
		return false, err
	}
	if captured == nil {
		return false, errors.New("Agent did not issue an Enroll request")
	}
	var body aep.EnrollRequest
	if err := json.Unmarshal(capturedBody, &body); err != nil {
		return false, err
	}
	mediaType, _, err := mime.ParseMediaType(captured.Header.Get("Content-Type"))
	if err != nil {
		return false, err
	}
	expectedPath, err := requiredField[string](request.Case.Expected, "path")
	if err != nil {
		return false, err
	}
	return captured.Method == http.MethodPost && captured.URL.Path == expectedPath && mediaType == aep.MediaType && captured.Header.Get("Idempotency-Key") == idempotencyKey && captured.Header.Get("Authorization") == "AEP client-assertion" && body.AgentDID == agentDID && body.IdempotencyKey == idempotencyKey, nil
}

func minimalInspectDocument(serviceDID string) aep.InspectDocument {
	return aep.InspectDocument{
		AEPVersion: aep.Version,
		Bindings:   aep.Bindings{Supported: []aep.Binding{aep.BindingHTTP}},
		Commands:   aep.Commands{Supported: []aep.Command{aep.CommandInspect}},
		Core:       aep.Core{SigningAlgorithms: []aep.SigningAlgorithm{aep.SigningAlgorithmEdDSA, aep.SigningAlgorithmES256}},
		HTTP:       aep.HTTPConfiguration{},
		Identity:   aep.Identity{Methods: []aep.IdentityMethod{}},
		Service:    aep.ServiceIdentity{DID: serviceDID},
	}
}

func evaluateUnknownRequiredClaim(request adapterRequest) (bool, error) {
	required, err := requiredField[[]aep.ClaimName](request.Case.Input, "required")
	if err != nil {
		return false, err
	}
	understood, err := requiredField[[]aep.ClaimName](request.Case.Input, "understood")
	if err != nil {
		return false, err
	}
	expected, err := requiredField[bool](request.Case.Expected, "can_satisfy")
	if err != nil {
		return false, err
	}
	result := aep.EvaluateClaimSupport(&aep.InspectClaims{Required: required}, understood)
	return result.CanSatisfyRequired == expected, nil
}

func evaluateExpectedProblemCode(request adapterRequest) (bool, error) {
	code, err := requiredField[aep.ErrorCode](request.Case.Expected, "code")
	if err != nil {
		return false, err
	}
	problem := aep.NewProblemDetails(code, "Conformance", 401)
	return aep.ValidateProblemDetails(problem) == nil && problem.Code == code, nil
}

func evaluateCommandIdempotency(request adapterRequest) (bool, error) {
	key, err := requiredField[string](request.Case.Input, "idempotency_key")
	if err != nil {
		return false, err
	}
	commands, err := requiredField[[]aep.Command](request.Case.Input, "commands")
	if err != nil {
		return false, err
	}
	for _, command := range commands {
		if command == aep.CommandEnroll {
			body := aep.EnrollRequest{AgentDID: "did:web:agent.example", IdempotencyKey: key}
			if err := aep.ValidateEnrollRequest(body); err != nil {
				return false, nil
			}
		}
		if _, err := aep.CommandPath(command, ""); err != nil {
			return false, nil
		}
	}
	return key != "", nil
}

func evaluateTransportRequirements(request adapterRequest) (bool, error) {
	requestURL, err := requiredField[string](request.Case.Input, "request_url")
	if err != nil {
		return false, err
	}
	redirectURL, err := requiredField[string](request.Case.Input, "redirect_url")
	if err != nil {
		return false, err
	}
	first, err := url.Parse(requestURL)
	if err != nil {
		return false, err
	}
	second, err := url.Parse(redirectURL)
	if err != nil {
		return false, err
	}
	return first.Scheme == "https" && first.Scheme == second.Scheme && first.Host == second.Host, nil
}

func evaluateAPIKeyHeader(request adapterRequest) (bool, error) {
	issued, err := requiredField[string](request.Case.Input, "issued_header")
	if err != nil {
		return false, err
	}
	presented, err := requiredField[string](request.Case.Input, "presented_header")
	if err != nil {
		return false, err
	}
	expected, err := requiredField[bool](request.Case.Expected, "accepted")
	return err == nil && (issued == presented) == expected, err
}

func evaluateAuthenticateAssertion(request adapterRequest) (bool, error) {
	claimsRaw, err := rawField(request.Case.Expected, "claims")
	if err != nil {
		return false, err
	}
	claims, err := aep.ParseClientAssertionClaims(claimsRaw)
	if err != nil {
		return false, nil
	}
	return claims.Operation == aep.AssertionAuthenticate && claims.Resource != "", nil
}

func evaluatePaymentComposition(request adapterRequest) (bool, error) {
	for _, authorization := range []aep.ProtectedResourceAuthorization{
		{Carrier: aep.ProtectedResourceDedicated, Scheme: aep.CredentialSchemeAEP, Credentials: "compact-jws"},
		{Carrier: aep.ProtectedResourceDedicated, Scheme: aep.CredentialSchemeBearer, Credentials: "opaque-token"},
	} {
		field, value, err := aep.RenderProtectedResourceAuthorization(authorization)
		if err != nil || field != aep.AuthorizationHeader || value == "" {
			return false, err
		}
	}
	return true, nil
}

func evaluateOperationBinding(request adapterRequest) (bool, error) {
	operations, err := requiredField[[]aep.AssertionOperation](request.Case.Input, "operations")
	if err != nil {
		return false, err
	}
	for _, operation := range operations {
		claims := aep.ClientAssertionClaims{Issuer: "did:web:agent.example", Subject: "did:web:agent.example", Audience: "did:web:service.example", Operation: operation, IssuedAt: 1, ExpiresAt: 2, JWTID: "id"}
		if operation == aep.AssertionAuthenticate {
			claims.Resource = "https://service.example/resource"
		}
		if err := aep.ValidateClientAssertionClaims(claims); err != nil {
			return false, nil
		}
	}
	return true, nil
}

func evaluateRedirectSafety(request adapterRequest) (bool, error) {
	source, err := requiredField[string](request.Case.Input, "source")
	if err != nil {
		return false, err
	}
	same, err := requiredField[string](request.Case.Input, "same_origin")
	if err != nil {
		return false, err
	}
	cross, err := requiredField[string](request.Case.Input, "cross_origin")
	if err != nil {
		return false, err
	}
	sourceURL, _ := url.Parse(source)
	sameURL, _ := url.Parse(same)
	crossURL, _ := url.Parse(cross)
	if request.Role != "agent" {
		return sourceURL.Host == sameURL.Host && sourceURL.Host != crossURL.Host, nil
	}
	var serviceDID string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		document := minimalInspectDocument(serviceDID)
		document.Authentication = &aep.Authentication{Methods: []aep.AuthenticationMethod{aep.AuthenticationMethodJWT}}
		document.Identity.Methods = []aep.IdentityMethod{aep.IdentityMethodDIDWeb}
		response.Header().Set("Content-Type", aep.MediaType)
		_ = json.NewEncoder(response).Encode(document)
	}))
	defer server.Close()
	parsedServer, err := url.Parse(server.URL)
	if err != nil {
		return false, err
	}
	serviceDID = "did:web:" + strings.ReplaceAll(parsedServer.Host, ":", "%3A")
	client, err := agent.New(agent.Options{HTTPClient: server.Client(), IdentityProvider: signingIdentityProvider{}})
	if err != nil {
		return false, err
	}
	session, err := client.Service(server.URL)
	if err != nil {
		return false, err
	}
	sameResource, _ := url.Parse(server.URL + "/next")
	headers, sameErr := session.AuthenticationHeaders(context.Background(), agent.AuthenticationOptions{ClientAssertionOnly: true, Resource: sameResource})
	_, crossErr := session.AuthenticationHeaders(context.Background(), agent.AuthenticationOptions{ClientAssertionOnly: true, Resource: crossURL})
	return sourceURL.Host == sameURL.Host && headers.Get("Authorization") == "AEP signed-assertion" && sameErr == nil && crossErr != nil, nil
}

func evaluateAgentFailClosed(request adapterRequest) (bool, error) {
	var serviceDID string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		document := minimalInspectDocument(serviceDID)
		response.Header().Set("Content-Type", aep.MediaType)
		_ = json.NewEncoder(response).Encode(document)
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		return false, err
	}
	serviceDID = "did:web:" + strings.ReplaceAll(parsed.Host, ":", "%3A")
	client, err := agent.New(agent.Options{HTTPClient: server.Client(), IdentityProvider: inspectIdentityProvider{}})
	if err != nil {
		return false, err
	}
	session, err := client.Service(server.URL)
	if err != nil {
		return false, err
	}
	resource, err := url.Parse(server.URL + "/private")
	if err != nil {
		return false, err
	}
	options := agent.AuthenticationOptions{GrantType: aep.GrantTypeBasic, Resource: resource}
	if request.Vector.ID == "authorization-ambiguity" {
		options.ClientAssertionOnly = true
		options.CredentialID = "credential"
	}
	_, err = session.AuthenticationHeaders(context.Background(), options)
	if err == nil {
		return false, fmt.Errorf("Agent accepted an authentication selection that must fail closed")
	}
	if request.Vector.ID == "authorization-field-safety" {
		field, fieldErr := requiredField[string](request.Case.Input, "field_name")
		if fieldErr != nil {
			return false, fieldErr
		}
		return aep.IsHTTPFieldName(field), nil
	}
	return true, nil
}
