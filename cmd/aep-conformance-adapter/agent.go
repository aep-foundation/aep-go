package main

import (
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
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	aep "github.com/aep-foundation/aep-go"
	"github.com/aep-foundation/aep-go/agent"
	"github.com/aep-foundation/aep-go/service"
)

func evaluateAgent(request adapterRequest) (bool, error) {
	switch request.Vector.ID {
	case "response-active", "response-pending-verification-owner-action", "response-pending-requirements", "revoke-response-empty",
		"not-recognized-problem", "requirements-unmet-problem", "verification-pending-problem":
		return evaluateAgentCommandResponse(request)
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
		return evaluateAgentGrantBeforeEnrollment(request)
	case "command-header":
		return evaluateCommandIdempotency(request)
	case "transport-requirements":
		return evaluateTransportRequirements(request)
	case "api-key-wrong-header-rejected":
		return evaluateAgentAPIKeyPresentation(request)
	case "authenticate-assertion":
		return evaluateAgentAuthenticateAssertion(request)
	case "authorization-payment-composition":
		return evaluateAgentPaymentRequests(request)
	case "operation-substitution-rejected":
		return evaluateOperationBinding(request)
	case "redirect-safety":
		return evaluateRedirectSafety(request)
	case "assertion-and-credential-failures":
		return evaluateAgentFailureResponses(request)
	case "authorization-ambiguity", "authorization-field-safety", "unadvertised-authentication-method":
		return evaluateAgentFailClosed(request)
	}
	return false, fmt.Errorf("no Agent operation maps vector %s/%s", request.Vector.Category, request.Vector.ID)
}

func evaluateAgentCommandResponse(request adapterRequest) (bool, error) {
	status, err := requiredField[int](request.Case.Expected, "status")
	if err != nil {
		return false, err
	}
	contentType, err := requiredField[string](request.Case.Expected, "content_type")
	if err != nil {
		return false, err
	}
	body, err := rawField(request.Case.Expected, "body")
	if err != nil {
		return false, err
	}
	document := minimalInspectDocument(vectorDID)
	document.Commands.Supported = []aep.Command{aep.CommandInspect, aep.CommandEnroll, aep.CommandStatus, aep.CommandRevoke}
	document.Commands.GrantTypes = []aep.GrantType{aep.GrantTypeOAuthBearer}
	document.Identity.Methods = []aep.IdentityMethod{aep.IdentityMethodDIDWeb}
	calls := 0
	client, err := agent.New(agent.Options{IdentityProvider: commandIdentityProvider{agentDID: "did:web:agent.example"}, HTTPClient: &http.Client{Transport: conformanceRoundTripper(func(incoming *http.Request) (*http.Response, error) {
		recorder := httptest.NewRecorder()
		if incoming.URL.Path == aep.WellKnownPath {
			recorder.Header().Set("Content-Type", aep.MediaType)
			_ = json.NewEncoder(recorder).Encode(document)
		} else {
			calls++
			recorder.Header().Set("Content-Type", contentType)
			recorder.WriteHeader(status)
			_, _ = recorder.Write(body)
		}
		return recorder.Result(), nil
	})}})
	if err != nil {
		return false, err
	}
	session, err := client.Service(vectorOrigin)
	if err != nil {
		return false, err
	}
	if _, err := session.Identity(context.Background()); err != nil {
		return false, err
	}
	var actualBody any
	var actualStatus int
	switch {
	case request.Vector.Category == "enroll":
		result, callErr := session.Enroll(context.Background(), agent.EnrollOptions{IdempotencyKey: "response-vector"})
		actualBody, actualStatus, err = result.Body, result.Status, callErr
	case request.Vector.ID == "revoke-response-empty":
		result, callErr := session.Revoke(context.Background(), agent.RevokeOptions{AllGrantTypes: true, IdempotencyKey: "response-vector"})
		actualBody, actualStatus, err = result.Body, result.Status, callErr
	default:
		result, callErr := session.Status(context.Background())
		actualBody, actualStatus, err = result.Body, result.Status, callErr
	}
	if request.Vector.Category == "errors" {
		var commandError *agent.CommandError
		return calls == 1 && errors.As(err, &commandError) && commandError.Status == status && jsonEqual(commandError.Problem, json.RawMessage(body)), nil
	}
	return calls == 1 && err == nil && actualStatus == status && jsonEqual(actualBody, json.RawMessage(body)), err
}

type inspectIdentityProvider struct{}

func evaluateAgentGrantResponse(grantType aep.GrantType, body []byte, valid bool) (bool, error) {
	document := minimalInspectDocument(vectorDID)
	document.Commands.Supported = []aep.Command{aep.CommandInspect, aep.CommandGrant, aep.CommandStatus}
	document.Commands.GrantTypes = []aep.GrantType{grantType}
	document.Identity.Methods = []aep.IdentityMethod{aep.IdentityMethodDIDWeb}
	grants := 0
	client, err := agent.New(agent.Options{IdentityProvider: commandIdentityProvider{agentDID: "did:web:agent.example"}, Clock: func() time.Time { return serviceNow }, HTTPClient: &http.Client{Transport: conformanceRoundTripper(func(incoming *http.Request) (*http.Response, error) {
		recorder := httptest.NewRecorder()
		recorder.Header().Set("Content-Type", aep.MediaType)
		switch incoming.URL.Path {
		case aep.WellKnownPath:
			_ = json.NewEncoder(recorder).Encode(document)
		case "/aep/status":
			_, _ = recorder.WriteString(`{"status":"active"}`)
		case "/aep/grant":
			grants++
			_, _ = recorder.Write(body)
		default:
			return nil, fmt.Errorf("unexpected request %s", incoming.URL)
		}
		return recorder.Result(), nil
	})}})
	if err != nil {
		return false, err
	}
	session, err := client.Service(vectorOrigin)
	if err != nil {
		return false, err
	}
	if _, err := session.Identity(context.Background()); err != nil {
		return false, err
	}
	result, grantErr := session.Grant(context.Background(), agent.GrantOptions{GrantType: grantType, IdempotencyKey: "grant-response"})
	if !valid {
		var validation *aep.ValidationError
		return grants == 1 && errors.As(grantErr, &validation), nil
	}
	return grants == 1 && grantErr == nil && result.Status == http.StatusOK && result.Body.GrantType == grantType && result.Body.Credential != nil && jsonEqual(result.Body.Raw, json.RawMessage(body)), grantErr
}

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

func evaluateAgentGrantBeforeEnrollment(request adapterRequest) (bool, error) {
	code, err := requiredField[aep.ErrorCode](request.Case.Expected, "code")
	if err != nil {
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
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return false, err
	}
	var handler http.Handler
	var enrollCalls, statusCalls, grantCalls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/aep/enroll":
			enrollCalls.Add(1)
		case "/aep/status":
			statusCalls.Add(1)
		case "/aep/grant":
			grantCalls.Add(1)
		}
		handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	parsed, _ := url.Parse(server.URL)
	did := "did:web:" + strings.ReplaceAll(parsed.Host, ":", "%3A")
	instance, err := service.New(service.Options{
		ServiceDID: did, IdentityMethods: []aep.IdentityMethod{aep.IdentityMethodDIDWeb},
		EnrollmentPolicy: conformanceEnrollmentPolicy{},
		GrantTypes:       []service.GrantTypeDefinition{{GrantType: "custom-session", Handler: conformanceGrantHandler{}}},
		Verifier: func(ctx context.Context, token string, verification service.AssertionVerificationContext) (aep.ClientAssertionClaims, error) {
			return aep.VerifyClientAssertion(ctx, token, aep.VerifyClientAssertionOptions{Key: public, Algorithms: []aep.SigningAlgorithm{aep.SigningAlgorithmEdDSA}, Audience: did, Operation: verification.Operation, CurrentTime: verification.CurrentTime})
		},
	})
	if err != nil {
		return false, err
	}
	handler, err = service.NewHTTPHandler(instance, service.HTTPHandlerOptions{})
	if err != nil {
		return false, err
	}
	identities := agent.NewMemoryIdentityStore()
	if err := identities.SaveIdentity(context.Background(), agent.ServiceIdentity{AgentDID: "did:web:agent.example", ServiceDID: did, IdentityMethod: aep.IdentityMethodDIDWeb, SigningAlgorithms: []aep.SigningAlgorithm{aep.SigningAlgorithmEdDSA}}); err != nil {
		return false, err
	}
	client, err := agent.New(agent.Options{HTTPClient: server.Client(), IdentityProvider: resourceIdentityProvider{key: private}, IdentityStore: identities})
	if err != nil {
		return false, err
	}
	session, err := client.Service(server.URL)
	if err != nil {
		return false, err
	}
	_, err = session.Grant(context.Background(), agent.GrantOptions{GrantType: "custom-session"})
	var commandError *agent.CommandError
	return errors.As(err, &commandError) && commandError.Status == status && commandError.Problem != nil && commandError.Problem.Code == code && statusCalls.Load() == 1 && grantCalls.Load() == 0 && (enrollCalls.Load() != 0) == implicit, nil
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
	type commandRequest struct {
		path, method, key string
		body              []byte
	}
	var captured []commandRequest
	var serviceDID string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", aep.MediaType)
		if r.URL.Path == aep.WellKnownPath {
			document := minimalInspectDocument(serviceDID)
			document.Commands.Supported = append([]aep.Command{aep.CommandInspect}, commands...)
			document.Commands.GrantTypes = []aep.GrantType{aep.GrantTypeOAuthBearer}
			document.Identity.Methods = []aep.IdentityMethod{aep.IdentityMethodDIDWeb}
			_ = json.NewEncoder(w).Encode(document)
			return
		}
		body, _ := io.ReadAll(r.Body)
		captured = append(captured, commandRequest{r.URL.Path, r.Method, r.Header.Get("Idempotency-Key"), body})
		switch r.URL.Path {
		case "/aep/enroll":
			_ = json.NewEncoder(w).Encode(aep.EnrollResponse{Status: aep.AgentActive})
		case "/aep/grant":
			_ = json.NewEncoder(w).Encode(aep.OAuthBearerGrantResponse{AccessToken: "credential", CredentialID: "credential-1", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339), Scopes: []string{}, TokenType: "Bearer"})
		case "/aep/revoke":
			_ = json.NewEncoder(w).Encode(aep.RevokeResponse{})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		return false, err
	}
	serviceDID = "did:web:" + strings.ReplaceAll(parsed.Host, ":", "%3A")
	client, err := agent.New(agent.Options{HTTPClient: server.Client(), IdentityProvider: commandIdentityProvider{agentDID: "did:web:agent.example"}})
	if err != nil {
		return false, err
	}
	session, err := client.Service(server.URL)
	if err != nil {
		return false, err
	}
	for _, command := range commands {
		switch command {
		case aep.CommandEnroll:
			_, err = session.Enroll(context.Background(), agent.EnrollOptions{IdempotencyKey: key})
		case aep.CommandGrant:
			_, err = session.Grant(context.Background(), agent.GrantOptions{GrantType: aep.GrantTypeOAuthBearer, IdempotencyKey: key})
		case aep.CommandRevoke:
			_, err = session.Revoke(context.Background(), agent.RevokeOptions{GrantType: aep.GrantTypeOAuthBearer, IdempotencyKey: key})
		default:
			return false, fmt.Errorf("unexpected idempotent command %s", command)
		}
		if err != nil {
			return false, err
		}
	}
	if len(captured) != len(commands) {
		return false, errors.New("Agent did not issue each command")
	}
	for index, incoming := range captured {
		path, err := aep.CommandPath(commands[index], "")
		if err != nil || incoming.path != path || incoming.method != http.MethodPost || incoming.key != key || key == "" {
			return false, err
		}
		if commands[index] == aep.CommandEnroll {
			var body aep.EnrollRequest
			if err := json.Unmarshal(incoming.body, &body); err != nil {
				return false, err
			}
			if body.IdempotencyKey != "" && body.IdempotencyKey != incoming.key {
				return false, nil
			}
		}
	}
	return true, nil
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
	contentType, err := requiredField[string](request.Case.Input, "content_type")
	if err != nil {
		return false, err
	}
	document := minimalInspectDocument("did:web:" + strings.ReplaceAll(first.Host, ":", "%3A"))
	body, err := json.Marshal(document)
	if err != nil {
		return false, err
	}
	for _, mode := range []string{"same-origin", "cross-origin", "downgrade", "bound", "wrong-media-type"} {
		calls := 0
		options := agent.Options{IdentityProvider: inspectIdentityProvider{}, HTTPClient: &http.Client{Transport: conformanceRoundTripper(func(incoming *http.Request) (*http.Response, error) {
			calls++
			if calls == 1 && mode != "bound" && mode != "wrong-media-type" {
				location := redirectURL
				if mode == "cross-origin" {
					location = "https://other.example/aep"
				}
				if mode == "downgrade" {
					location = "http://" + first.Host + "/aep"
				}
				return vectorResponse(incoming, 302, http.Header{"Location": {location}}, ""), nil
			}
			mediaType := contentType
			if mode == "wrong-media-type" {
				mediaType = "text/html"
			}
			return vectorResponse(incoming, 200, http.Header{"Content-Type": {mediaType}}, string(body)), nil
		})}}
		if mode == "bound" {
			options.MaximumResponseBytes = int64(len(body) - 1)
		}
		client, err := agent.New(options)
		if err != nil {
			return false, err
		}
		session, err := client.Service(requestURL)
		if err != nil {
			return false, err
		}
		inspection, err := session.Inspect(context.Background())
		if mode == "same-origin" {
			if err != nil || calls != 2 || inspection.FinalURL.String() != redirectURL {
				return false, err
			}
		} else if err == nil || calls != 1 {
			return false, nil
		}
	}
	return true, nil
}

type assertionConformanceProvider struct {
	commandIdentityProvider
	claims *aep.ClientAssertionClaims
}

func (provider assertionConformanceProvider) SignerFor(context.Context, agent.ServiceIdentity) (agent.AssertionSigner, error) {
	return func(_ context.Context, claims aep.ClientAssertionClaims, _ []aep.SigningAlgorithm) (string, error) {
		*provider.claims = claims
		return "compact-jws", nil
	}, nil
}

type conformanceRoundTripper func(*http.Request) (*http.Response, error)

func (transport conformanceRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func evaluateAgentAuthenticateAssertion(request adapterRequest) (bool, error) {
	expected, err := requiredField[aep.ClientAssertionClaims](request.Case.Expected, "claims")
	if err != nil {
		return false, err
	}
	resource, err := requiredField[string](request.Case.Input, "url")
	if err != nil {
		return false, err
	}
	target, err := url.Parse(resource)
	if err != nil {
		return false, err
	}
	document := minimalInspectDocument(expected.Audience)
	document.Authentication = &aep.Authentication{Methods: []aep.AuthenticationMethod{aep.AuthenticationMethodJWT}}
	document.Identity.Methods = []aep.IdentityMethod{aep.IdentityMethodDIDWeb}
	body, err := json.Marshal(document)
	if err != nil {
		return false, err
	}
	var claims aep.ClientAssertionClaims
	client, err := agent.New(agent.Options{
		Clock:             func() time.Time { return time.Unix(expected.IssuedAt, 0) },
		AssertionLifetime: time.Duration(expected.ExpiresAt-expected.IssuedAt) * time.Second,
		JTI:               func() (string, error) { return expected.JWTID, nil },
		IdentityProvider:  assertionConformanceProvider{commandIdentityProvider{agentDID: expected.Issuer}, &claims},
		HTTPClient: &http.Client{Transport: conformanceRoundTripper(func(incoming *http.Request) (*http.Response, error) {
			if incoming.URL.String() != target.Scheme+"://"+target.Host+aep.WellKnownPath {
				return nil, errors.New("unexpected request during assertion conformance")
			}
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {aep.MediaType}}, Body: io.NopCloser(strings.NewReader(string(body))), Request: incoming}, nil
		})},
	})
	if err != nil {
		return false, err
	}
	session, err := client.Service(resource)
	if err != nil {
		return false, err
	}
	headers, err := session.AuthenticationHeaders(context.Background(), agent.AuthenticationOptions{Resource: target})
	return err == nil && headers.Get("Authorization") == "AEP compact-jws" && reflect.DeepEqual(claims, expected), err
}

func evaluateOperationBinding(request adapterRequest) (bool, error) {
	operations, err := requiredField[[]aep.AssertionOperation](request.Case.Input, "operations")
	if err != nil {
		return false, err
	}
	expected, err := requiredField[[]string](request.Case.Expected, "allowed")
	if err != nil {
		return false, err
	}
	resource, err := requiredField[string](request.Case.Input, "protected_resource")
	if err != nil {
		return false, err
	}
	target, err := url.Parse(resource)
	if err != nil {
		return false, err
	}
	document := minimalInspectDocument(vectorDID)
	document.Identity.Methods = []aep.IdentityMethod{aep.IdentityMethodDIDWeb}
	document.Authentication = &aep.Authentication{Methods: []aep.AuthenticationMethod{aep.AuthenticationMethodJWT}}
	document.Commands.Supported = []aep.Command{aep.CommandInspect, aep.CommandEnroll, aep.CommandGrant, aep.CommandRevoke, aep.CommandStatus}
	document.Commands.GrantTypes = []aep.GrantType{aep.GrantTypeOAuthBearer}
	discovery, err := json.Marshal(document)
	if err != nil {
		return false, err
	}
	credential, err := vectorCredential(aep.GrantTypeOAuthBearer, "", "opaque-token")
	if err != nil {
		return false, err
	}
	var claims aep.ClientAssertionClaims
	var observed []string
	valid := true
	client, err := agent.New(agent.Options{IdentityProvider: assertionConformanceProvider{commandIdentityProvider{agentDID: "did:web:agent.example"}, &claims}, HTTPClient: &http.Client{Transport: conformanceRoundTripper(func(incoming *http.Request) (*http.Response, error) {
		if incoming.URL.Path == aep.WellKnownPath {
			return vectorResponse(incoming, 200, http.Header{"Content-Type": {aep.MediaType}}, string(discovery)), nil
		}
		endpoint := strings.TrimPrefix(incoming.URL.Path, "/aep/")
		observed = append(observed, string(claims.Operation)+":"+endpoint)
		valid = valid && claims.Resource == "" && claims.Audience == vectorDID && incoming.Header.Get("Authorization") == "AEP compact-jws"
		body := `{"status":"active"}`
		if endpoint == "grant" {
			body = string(credential)
		}
		if endpoint == "revoke" {
			body = `{}`
		}
		return vectorResponse(incoming, 200, http.Header{"Content-Type": {aep.MediaType}}, body), nil
	})}})
	if err != nil {
		return false, err
	}
	session, err := client.Service(vectorOrigin)
	if err != nil {
		return false, err
	}
	for _, operation := range operations {
		switch operation {
		case aep.AssertionEnroll:
			_, err = session.Enroll(context.Background(), agent.EnrollOptions{})
		case aep.AssertionGrant:
			_, err = session.Grant(context.Background(), agent.GrantOptions{GrantType: aep.GrantTypeOAuthBearer})
		case aep.AssertionRevoke:
			_, err = session.Revoke(context.Background(), agent.RevokeOptions{GrantType: aep.GrantTypeOAuthBearer})
		case aep.AssertionStatus:
			_, err = session.Status(context.Background())
		case aep.AssertionAuthenticate:
			var headers http.Header
			headers, err = session.AuthenticationHeaders(context.Background(), agent.AuthenticationOptions{ClientAssertionOnly: true, Resource: target})
			observed = append(observed, string(claims.Operation)+":protected-resource")
			valid = valid && claims.Resource == resource && claims.Audience == vectorDID && headers.Get("Authorization") == "AEP compact-jws"
		default:
			return false, fmt.Errorf("unknown assertion operation %s", operation)
		}
		if err != nil {
			return false, err
		}
	}
	slices.Sort(observed)
	slices.Sort(expected)
	return valid && slices.Equal(observed, expected), nil
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
	return evaluateAgentRedirectRequests(sourceURL, sameURL, crossURL, aep.ProtectedResourceStandard)
}

type resourceIdentityProvider struct{ key ed25519.PrivateKey }

func (provider resourceIdentityProvider) GetOrCreateIdentity(ctx context.Context, request agent.IdentityRequest) (agent.ServiceIdentity, error) {
	return signingIdentityProvider{}.GetOrCreateIdentity(ctx, request)
}

func (provider resourceIdentityProvider) SignerFor(context.Context, agent.ServiceIdentity) (agent.AssertionSigner, error) {
	return func(_ context.Context, claims aep.ClientAssertionClaims, _ []aep.SigningAlgorithm) (string, error) {
		return aep.SignClientAssertion(claims, aep.SignClientAssertionOptions{Algorithm: aep.SigningAlgorithmEdDSA, Key: provider.key, KeyID: "did:web:agent.example#key-1"})
	}, nil
}

func evaluateAgentRedirectRequests(source, same, cross *url.URL, carrier aep.ProtectedResourceCarrier) (bool, error) {
	if source == nil || same == nil || cross == nil || source.Host != same.Host || source.Host == cross.Host {
		return false, nil
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return false, err
	}
	headerName, err := aep.ProtectedResourceAuthorizationHeader(carrier)
	if err != nil {
		return false, err
	}
	var mu sync.Mutex
	var resources []string
	ids := map[string]bool{}
	valid := true
	destinationProbed := false
	var originURL, destinationURL string
	handler := func(destination bool) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := originURL
			if destination {
				origin = destinationURL
			}
			parsed, _ := url.Parse(origin)
			did := "did:web:" + strings.ReplaceAll(parsed.Host, ":", "%3A")
			if r.URL.Path == aep.WellKnownPath {
				document := minimalInspectDocument(did)
				document.Authentication = &aep.Authentication{Methods: []aep.AuthenticationMethod{aep.AuthenticationMethodJWT}}
				document.Identity.Methods = []aep.IdentityMethod{aep.IdentityMethodDIDWeb}
				w.Header().Set("Content-Type", aep.MediaType)
				json.NewEncoder(w).Encode(document)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if destination && (r.Header.Get("X-Agent-Key") != "" || r.Header.Get("PAYMENT-SIGNATURE") != "") {
				valid = false
			}
			otherHeader := aep.AuthorizationHeader
			if carrier == aep.ProtectedResourceDedicated {
				otherHeader = "Authorization"
			}
			if r.Header.Get(otherHeader) != "" {
				valid = false
			}
			authorization := r.Header.Get(headerName)
			if authorization == "" {
				if destination {
					destinationProbed = true
				}
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`AEP service_did="%s",inspect="%s/.well-known/aep"`, did, origin))
				w.WriteHeader(401)
				return
			}
			parsedAuth, err := aep.ParseProtectedResourceAuthorization(authorization, carrier)
			if err != nil {
				valid = false
				w.WriteHeader(401)
				return
			}
			claims, err := aep.VerifyClientAssertion(r.Context(), parsedAuth.Credentials, aep.VerifyClientAssertionOptions{Key: public, Algorithms: []aep.SigningAlgorithm{aep.SigningAlgorithmEdDSA}, Audience: did, Operation: aep.AssertionAuthenticate, Resource: origin + r.URL.RequestURI(), CurrentTime: time.Now()})
			if err != nil || ids[claims.JWTID] {
				valid = false
				w.WriteHeader(401)
				return
			}
			ids[claims.JWTID] = true
			resources = append(resources, claims.Resource)
			if destination {
				if !destinationProbed {
					valid = false
				}
				w.WriteHeader(200)
				return
			}
			location := originURL + same.RequestURI()
			if r.URL.Path == same.Path {
				location = destinationURL + cross.RequestURI()
			}
			w.Header().Set("Location", location)
			w.WriteHeader(307)
		})
	}
	destination := httptest.NewTLSServer(handler(true))
	defer destination.Close()
	destinationURL = destination.URL
	origin := httptest.NewTLSServer(handler(false))
	defer origin.Close()
	originURL = origin.URL
	client, err := agent.New(agent.Options{HTTPClient: origin.Client(), IdentityProvider: resourceIdentityProvider{key: private}})
	if err != nil {
		return false, err
	}
	request, err := http.NewRequest("GET", origin.URL+source.RequestURI(), nil)
	if err != nil {
		return false, err
	}
	response, err := client.FetchProtectedResource(context.Background(), request, agent.ProtectedResourceOptions{Authentication: agent.AuthenticationOptions{Carrier: carrier}, AdditionalAuthenticationHeaders: http.Header{"X-Agent-Key": {"source-key"}, "PAYMENT-SIGNATURE": {"payment"}}})
	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	mu.Lock()
	defer mu.Unlock()
	return valid && response.StatusCode == 200 && destinationProbed && len(resources) == 3 && resources[0] == originURL+source.RequestURI() && resources[1] == originURL+same.RequestURI() && resources[2] == destinationURL+cross.RequestURI(), nil
}

func evaluateAgentFailClosed(request adapterRequest) (bool, error) {
	if request.Vector.ID == "unadvertised-authentication-method" {
		return evaluateAgentUnadvertisedMethods(request)
	}
	return evaluateAgentCarrierRequests(request)
}
