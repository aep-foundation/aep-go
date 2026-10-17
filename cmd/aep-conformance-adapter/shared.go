package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	aep "github.com/aep-foundation/aep-go"
	"github.com/aep-foundation/aep-go/agent"
	"github.com/aep-foundation/aep-go/service"
	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

var claimValueVectors = map[string]struct{}{
	"forward-compatible-address": {},
	"invalid-address":            {},
	"invalid-birthdate":          {},
	"invalid-country-shape":      {},
	"invalid-email-domain":       {},
	"invalid-email-dot-string":   {},
	"invalid-email-format":       {},
	"invalid-empty-email":        {},
	"invalid-mobile":             {},
	"invalid-value-type":         {},
	"minimal-email":              {},
	"quoted-email":               {},
}

func evaluateShared(request adapterRequest) (bool, bool, error) {
	id := request.Vector.ID
	if _, found := claimValueVectors[id]; found {
		passed, err := parseValidity(request, "claim_values", func(data []byte) error {
			_, parseErr := aep.ParseClaimValues(data)
			return parseErr
		})
		return true, passed, err
	}

	switch id {
	case "person-contact-catalog":
		passed, err := evaluateClaimCatalog(request)
		return true, passed, err
	case "negotiation-compatibility":
		passed, err := evaluateClaimNegotiation(request)
		return true, passed, err
	case "enroll-claims":
		passed, err := evaluateClientAssertionClaims(request)
		return true, passed, err
	case "validation-requirements":
		passed, err := evaluateClientAssertionValidation(request)
		return true, passed, err
	case "grant-response", "grant-response-missing-credential-id":
		passed, err := evaluateCredentialResponse(request)
		return true, passed, err
	case "request-minimal", "request-claims-catalog":
		passed, err := evaluateCommandRequest(request, aep.CommandEnroll)
		return true, passed, err
	case "grant-request-oauth-bearer":
		passed, err := evaluateCommandRequest(request, aep.CommandGrant)
		return true, passed, err
	case "revoke-request-all-grant-types", "revoke-request-oauth-bearer", "revoke-request-targeted-oauth-bearer",
		"revoke-request-conflicting-targets", "revoke-request-credential-id-without-grant-type":
		passed, err := evaluateRevokeRequest(request)
		return true, passed, err
	case "problem-details-validation":
		passed, err := evaluateProblemDetailsValidation(request)
		return true, passed, err
	case "authenticate-command-prohibited", "authenticated-command-without-identity-method", "authentication-method-limit", "command-without-inspect",
		"forward-compatible-advertisements", "grant-without-grant-types", "invalid-advertisement-identifiers",
		"invalid-openapi-reference", "missing-signing-algorithm":
		passed, err := parseValidity(request, "document", func(data []byte) error {
			_, parseErr := aep.ParseInspectDocument(data)
			return parseErr
		})
		return true, passed, err
	case "claims-catalog-advertisement", "minimal-http":
		passed, err := evaluateExpectedDocument(request)
		return true, passed, err
	case "default-endpoint-base":
		passed, err := evaluateDefaultEndpointBase(request)
		return true, passed, err
	case "protocol-version":
		passed, err := evaluateProtocolVersion(request)
		return true, passed, err
	case "service-did-origin-binding":
		passed, err := evaluateServiceDIDBinding(request)
		return true, passed, err
	case "path-matching":
		passed, err := evaluateOpenAPIPathMatching(request)
		return true, passed, err
	case "security-inheritance":
		passed, err := evaluateOpenAPISecurity(request)
		return true, passed, err
	case "url-resolution":
		passed, err := evaluateOpenAPIURL(request)
		return true, passed, err
	case "authorization-carriers":
		passed, err := evaluateAuthorizationCarriers(request)
		return true, passed, err
	case "credential-presentations":
		passed, err := evaluateCredentialPresentations(request)
		return true, passed, err
	case "inspect-authentication-methods":
		passed, err := evaluateInspectAuthenticationMethods(request)
		return true, passed, err
	}
	return false, false, nil
}

func evaluateProblemDetailsValidation(request adapterRequest) (bool, error) {
	type problemCase struct {
		Body  json.RawMessage `json:"body"`
		Valid bool            `json:"valid"`
	}
	cases, err := requiredField[[]problemCase](request.Case.Input, "cases")
	if err != nil {
		return false, err
	}
	for _, item := range cases {
		_, parseErr := aep.ParseProblemDetails(item.Body)
		if (parseErr == nil) != item.Valid {
			return false, nil
		}
	}
	return true, nil
}

func evaluateClaimCatalog(request adapterRequest) (bool, error) {
	encoded, err := json.Marshal(request.Case.Expected)
	if err != nil {
		return false, err
	}
	values, err := aep.ParseClaimValues(encoded)
	if err != nil || !jsonEqual(values, request.Case.Expected) {
		return false, err
	}
	registered := aep.RegisteredClaims()
	for name := range request.Case.Expected {
		if !slices.Contains(registered, aep.ClaimName(name)) {
			return false, nil
		}
	}
	return len(registered) == len(request.Case.Expected), nil
}

func evaluateClaimNegotiation(request adapterRequest) (bool, error) {
	inspect, err := requiredField[aep.InspectClaims](request.Case.Input, "inspect")
	if err != nil {
		return false, err
	}
	result := aep.EvaluateClaimSupport(&inspect, aep.RegisteredClaims())
	expected, err := requiredField[bool](request.Case.Expected, "enrollment_requirement_satisfied")
	if err != nil {
		return false, err
	}
	if result.CanSatisfyRequired != expected {
		return false, nil
	}
	omitted, err := requiredField[bool](request.Case.Expected, "omitted_preferred_allowed")
	if err != nil || !omitted {
		return false, err
	}
	for _, field := range []string{"unknown_optional_action", "unknown_preferred_action", "unknown_submitted_default_action"} {
		action, err := requiredField[string](request.Case.Expected, field)
		if err != nil || action != "ignore" {
			return false, err
		}
	}
	if len(result.SupportedOptional) != 0 || len(result.SupportedPreferred) != 0 {
		return false, nil
	}
	raw, err := rawField(request.Case.Input, "submitted")
	if err != nil {
		return false, err
	}
	values, err := aep.ParseClaimValues(raw)
	if err != nil {
		return false, err
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return false, err
	}
	instance, err := service.New(service.Options{
		ServiceDID: vectorDID, Claims: &inspect,
		IdentityMethods:  []aep.IdentityMethod{aep.IdentityMethodDIDWeb},
		Clock:            func() time.Time { return serviceNow },
		EnrollmentPolicy: conformanceEnrollmentPolicy{},
		Verifier: func(ctx context.Context, assertion string, verification service.AssertionVerificationContext) (aep.ClientAssertionClaims, error) {
			return aep.VerifyClientAssertion(ctx, assertion, aep.VerifyClientAssertionOptions{Key: public, Audience: verification.ServiceDID, Operation: verification.Operation, CurrentTime: verification.CurrentTime})
		},
	})
	if err != nil {
		return false, err
	}
	handler, err := service.NewHTTPHandler(instance, service.HTTPHandlerOptions{})
	if err != nil {
		return false, err
	}
	client, err := agent.New(agent.Options{IdentityProvider: resourceIdentityProvider{key: private}, Clock: func() time.Time { return serviceNow }, HTTPClient: &http.Client{Transport: conformanceRoundTripper(func(incoming *http.Request) (*http.Response, error) {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, incoming)
		return recorder.Result(), nil
	})}})
	if err != nil {
		return false, err
	}
	session, err := client.Service(vectorOrigin)
	if err != nil {
		return false, err
	}
	enrolled, err := session.Enroll(context.Background(), agent.EnrollOptions{Claims: &values, IdempotencyKey: "claims-negotiation"})
	return err == nil && enrolled.Status == http.StatusOK && enrolled.Body.Status == aep.AgentActive, err
}

func evaluateClientAssertionClaims(request adapterRequest) (bool, error) {
	input := request.Case.Input
	claims := aep.ClientAssertionClaims{}
	var err error
	if claims.Issuer, err = requiredField[string](input, "agent_did"); err != nil {
		return false, err
	}
	claims.Subject = claims.Issuer
	if claims.Audience, err = requiredField[string](input, "service_did"); err != nil {
		return false, err
	}
	if claims.Operation, err = requiredField[aep.AssertionOperation](input, "command"); err != nil {
		return false, err
	}
	if claims.IssuedAt, err = requiredField[int64](input, "issued_at"); err != nil {
		return false, err
	}
	if claims.ExpiresAt, err = requiredField[int64](input, "expires_at"); err != nil {
		return false, err
	}
	if claims.JWTID, err = requiredField[string](input, "jti"); err != nil {
		return false, err
	}
	if err := aep.ValidateClientAssertionClaims(claims); err != nil {
		return false, err
	}
	return jsonEqual(claims, request.Case.Expected), nil
}

func evaluateClientAssertionValidation(request adapterRequest) (bool, error) {
	input, err := json.Marshal(request.Case.Input)
	if err != nil {
		return false, err
	}
	var fields struct {
		AgentDID   string               `json:"agent_did"`
		ServiceDID string               `json:"service_did"`
		Algorithm  aep.SigningAlgorithm `json:"algorithm"`
		IssuedAt   int64                `json:"issued_at"`
		ExpiresAt  int64                `json:"expires_at"`
		JWTID      string               `json:"jti"`
	}
	if err := json.Unmarshal(input, &fields); err != nil {
		return false, err
	}
	if fields.Algorithm != aep.SigningAlgorithmES256 {
		return false, errors.New("assertion vector requires an ES256 signing fixture")
	}
	claims := aep.ClientAssertionClaims{Issuer: fields.AgentDID, Subject: fields.AgentDID, Audience: fields.ServiceDID,
		IssuedAt: fields.IssuedAt, ExpiresAt: fields.ExpiresAt, JWTID: fields.JWTID, Operation: aep.AssertionEnroll}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return false, err
	}
	header, err := requiredField[map[string]any](request.Case.Expected, "header")
	if err != nil {
		return false, err
	}
	assertion, err := aep.SignClientAssertion(claims, aep.SignClientAssertionOptions{Algorithm: fields.Algorithm, Key: privateKey, KeyID: fields.AgentDID})
	if err != nil {
		return false, err
	}
	decoded, err := aep.DecodeJWTUnverified(assertion)
	if err != nil || !jsonEqual(decoded.Header, header) || !jsonEqual(decoded.Payload, request.Case.Expected["claims"]) {
		return false, err
	}
	verification := aep.VerifyClientAssertionOptions{Algorithms: []aep.SigningAlgorithm{fields.Algorithm}, Key: &privateKey.PublicKey,
		Audience: fields.ServiceDID, Operation: aep.AssertionEnroll, CurrentTime: time.Unix(fields.IssuedAt, 0)}
	if _, err := aep.VerifyClientAssertion(context.Background(), assertion, verification); err != nil {
		return false, err
	}
	rejections, err := requiredField[[]string](request.Case.Expected, "reject")
	if err != nil {
		return false, err
	}
	seen := make(map[string]bool)
	for _, rejection := range rejections {
		if seen[rejection] {
			return false, fmt.Errorf("duplicate assertion rejection %s", rejection)
		}
		seen[rejection] = true
		value := claims
		keyID, tokenType := fields.AgentDID, "JWT"
		switch rejection {
		case "excessive_lifetime":
			value.ExpiresAt = value.IssuedAt + 301
		case "nonpositive_lifetime":
			value.ExpiresAt = value.IssuedAt
		case "missing_resource":
			value.Operation = aep.AssertionAuthenticate
		case "unexpected_resource":
			value.Resource = "https://api.example.com/orders"
		case "insecure_resource":
			value.Operation = aep.AssertionAuthenticate
			value.Resource = "http://api.example.com/orders"
		case "fragmented_resource":
			value.Operation = aep.AssertionAuthenticate
			value.Resource = "https://api.example.com/orders#item"
		case "mismatched_subject":
			value.Subject = "did:web:different.example"
		case "mismatched_kid":
			keyID = "did:web:different.example#key-1"
		case "missing_kid":
			keyID = ""
		case "wrong_typ":
			tokenType = "application/aep"
		default:
			return false, fmt.Errorf("unknown assertion rejection %s", rejection)
		}
		// Sign invalid protocol values directly so rejection cannot be caused by a bad signature.
		options := (&jose.SignerOptions{}).WithType(jose.ContentType(tokenType))
		if keyID != "" {
			options.WithHeader(jose.HeaderKey("kid"), keyID)
		}
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: privateKey}, options)
		if err != nil {
			return false, err
		}
		token, err := josejwt.Signed(signer).Claims(value).Serialize()
		if err != nil {
			return false, err
		}
		verification.Operation = value.Operation
		if _, err := aep.VerifyClientAssertion(context.Background(), token, verification); err == nil {
			return false, fmt.Errorf("accepted %s", rejection)
		}
		if rejection != "wrong_typ" {
			if _, err := aep.SignClientAssertion(value, aep.SignClientAssertionOptions{Algorithm: fields.Algorithm, Key: privateKey, KeyID: keyID}); err == nil {
				return false, fmt.Errorf("signed %s", rejection)
			}
		}
	}
	return len(seen) == 10, nil
}

func evaluateCredentialResponse(request adapterRequest) (bool, error) {
	grantType := aep.GrantType(strings.TrimPrefix(request.Vector.Category, "credentials/"))
	field := "expected"
	expectedValid := true
	if request.Vector.ID == "grant-response-missing-credential-id" {
		field = "input"
		var err error
		expectedValid, err = validExpectation(request)
		if err != nil {
			return false, err
		}
	}
	var raw []byte
	if field == "input" {
		encoded, err := json.Marshal(request.Case.Input)
		if err != nil {
			return false, err
		}
		raw = encoded
	} else {
		encoded, err := json.Marshal(request.Case.Expected)
		if err != nil {
			return false, err
		}
		raw = encoded
	}
	if request.Role == "agent" {
		return evaluateAgentGrantResponse(grantType, raw, expectedValid)
	}
	store := service.NewMemoryServiceCredentialStore()
	var definition service.GrantTypeDefinition
	var err error
	switch grantType {
	case aep.GrantTypeAPIKey:
		var credential aep.APIKeyGrantResponse
		if err = json.Unmarshal(raw, &credential); err == nil {
			definition, err = service.StoredAPIKeyGrantType(service.StoredCredentialGrantTypeOptions[aep.APIKeyGrantResponse]{Store: store, Issue: func(context.Context, aep.GrantRequest, service.GrantContext) (aep.APIKeyGrantResponse, error) {
				return credential, nil
			}})
		}
	case aep.GrantTypeBasic:
		var credential aep.BasicGrantResponse
		if err = json.Unmarshal(raw, &credential); err == nil {
			definition, err = service.StoredBasicGrantType(service.StoredCredentialGrantTypeOptions[aep.BasicGrantResponse]{Store: store, Issue: func(context.Context, aep.GrantRequest, service.GrantContext) (aep.BasicGrantResponse, error) {
				return credential, nil
			}})
		}
	case aep.GrantTypeOAuthBearer:
		var credential aep.OAuthBearerGrantResponse
		if err = json.Unmarshal(raw, &credential); err == nil {
			definition, err = service.StoredOAuthBearerGrantType(service.StoredCredentialGrantTypeOptions[aep.OAuthBearerGrantResponse]{Store: store, Issue: func(context.Context, aep.GrantRequest, service.GrantContext) (aep.OAuthBearerGrantResponse, error) {
				return credential, nil
			}})
		}
	default:
		return false, fmt.Errorf("unsupported credential vector %s", grantType)
	}
	if err != nil {
		return false, err
	}
	instance, err := newConfiguredConformanceService(nil, nil, []service.GrantTypeDefinition{definition}, nil, nil)
	if err != nil {
		return false, err
	}
	enrollment, err := instance.Enroll(context.Background(), []byte(`{"agent_did":"did:web:agent.example"}`), serviceCommandOptions(aep.AssertionEnroll, "grant-enroll"))
	if err != nil || enrollment.Status != http.StatusOK {
		return false, err
	}
	grantBody, err := json.Marshal(aep.GrantRequest{GrantType: grantType})
	if err != nil {
		return false, err
	}
	result, grantErr := instance.Grant(context.Background(), grantBody, serviceCommandOptions(aep.AssertionGrant, "grant-response"))
	if !expectedValid {
		var validation *aep.ValidationError
		return errors.As(grantErr, &validation), nil
	}
	expected, err := aep.ParseBuiltInGrantResponse(grantType, raw)
	return err == nil && grantErr == nil && result.Status == http.StatusOK && result.ContentType == aep.MediaType && jsonEqual(result.Body, expected), err
}

func evaluateRevokeRequest(request adapterRequest) (bool, error) {
	if _, invalid := request.Case.Expected["valid"]; !invalid {
		return evaluateCommandRequest(request, aep.CommandRevoke)
	}
	encoded, err := json.Marshal(request.Case.Input)
	if err != nil {
		return false, err
	}
	_, parseErr := aep.ParseRevokeRequest(encoded)
	expectedValid := true
	if raw, found := request.Case.Expected["valid"]; found {
		if err := json.Unmarshal(raw, &expectedValid); err != nil {
			return false, err
		}
	}
	return (parseErr == nil) == expectedValid, nil
}

type commandVectorIdentityProvider struct {
	commandIdentityProvider
	key ed25519.PrivateKey
}

func (provider commandVectorIdentityProvider) SignerFor(context.Context, agent.ServiceIdentity) (agent.AssertionSigner, error) {
	return func(_ context.Context, claims aep.ClientAssertionClaims, _ []aep.SigningAlgorithm) (string, error) {
		return aep.SignClientAssertion(claims, aep.SignClientAssertionOptions{Algorithm: aep.SigningAlgorithmEdDSA, Key: provider.key, KeyID: provider.agentDID + "#key-1"})
	}, nil
}

func evaluateCommandRequest(request adapterRequest, command aep.Command) (bool, error) {
	raw, err := json.Marshal(request.Case.Input)
	if err != nil {
		return false, err
	}
	agentDID, key := "did:web:agent.example", "command-vector"
	var enroll aep.EnrollRequest
	var grant aep.GrantRequest
	var revoke aep.RevokeRequest
	switch command {
	case aep.CommandEnroll:
		enroll, err = aep.ParseEnrollRequest(raw)
		agentDID, key = enroll.AgentDID, enroll.IdempotencyKey
	case aep.CommandGrant:
		grant, err = aep.ParseGrantRequest(raw)
	case aep.CommandRevoke:
		revoke, err = aep.ParseRevokeRequest(raw)
	}
	if err != nil {
		return false, err
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return false, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	store := service.NewMemoryEnrollmentStore()
	if command != aep.CommandEnroll {
		if _, err := store.SaveEnrollment(context.Background(), service.EnrollmentRecord{AgentDID: agentDID, EnrollmentID: "command-vector", Status: aep.AgentActive, CreatedAt: now, UpdatedAt: now, Since: now}); err != nil {
			return false, err
		}
	}
	definition, err := service.StoredOAuthBearerGrantType(service.StoredCredentialGrantTypeOptions[aep.OAuthBearerGrantResponse]{Store: service.NewMemoryServiceCredentialStore(), Issue: func(context.Context, aep.GrantRequest, service.GrantContext) (aep.OAuthBearerGrantResponse, error) {
		return aep.OAuthBearerGrantResponse{CredentialID: "command-vector", AccessToken: "opaque-token", TokenType: "Bearer", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Scopes: []string{}}, nil
	}})
	if err != nil {
		return false, err
	}
	instance, err := service.New(service.Options{ServiceDID: vectorDID, IdentityMethods: []aep.IdentityMethod{aep.IdentityMethodDIDWeb}, EnrollmentStore: store, EnrollmentPolicy: conformanceEnrollmentPolicy{}, GrantTypes: []service.GrantTypeDefinition{definition}, Clock: func() time.Time { return now }, Verifier: func(ctx context.Context, token string, verification service.AssertionVerificationContext) (aep.ClientAssertionClaims, error) {
		return aep.VerifyClientAssertion(ctx, token, aep.VerifyClientAssertionOptions{Key: public, Audience: verification.ServiceDID, Operation: verification.Operation, CurrentTime: verification.CurrentTime})
	}})
	if err != nil {
		return false, err
	}
	handler, err := service.NewHTTPHandler(instance, service.HTTPHandlerOptions{})
	if err != nil {
		return false, err
	}
	var observed map[string]any
	var body json.RawMessage
	calls := 0
	client, err := agent.New(agent.Options{IdentityProvider: commandVectorIdentityProvider{commandIdentityProvider{agentDID: agentDID}, private}, Clock: func() time.Time { return now }, HTTPClient: &http.Client{Transport: conformanceRoundTripper(func(incoming *http.Request) (*http.Response, error) {
		if incoming.Method == http.MethodPost {
			calls++
			body, err = io.ReadAll(incoming.Body)
			if err != nil {
				return nil, err
			}
			incoming.Body = io.NopCloser(strings.NewReader(string(body)))
			scheme, token, _ := strings.Cut(incoming.Header.Get("Authorization"), " ")
			claims, err := aep.VerifyClientAssertion(incoming.Context(), token, aep.VerifyClientAssertionOptions{Key: public, Audience: vectorDID, CurrentTime: now})
			if err != nil {
				return nil, err
			}
			observed = map[string]any{"method": incoming.Method, "path": incoming.URL.Path, "content_type": incoming.Header.Get("Content-Type"), "authorization_scheme": scheme, "client_assertion_op": claims.Operation}
			if command == aep.CommandEnroll {
				observed["idempotency_key"] = incoming.Header.Get("Idempotency-Key")
			} else {
				observed["body"] = body
			}
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, incoming)
		return recorder.Result(), nil
	})}})
	if err != nil {
		return false, err
	}
	session, err := client.Service(vectorOrigin)
	if err != nil {
		return false, err
	}
	if command != aep.CommandEnroll {
		if _, err := session.Identity(context.Background()); err != nil {
			return false, err
		}
	}
	switch command {
	case aep.CommandEnroll:
		_, err = session.Enroll(context.Background(), agent.EnrollOptions{Claims: enroll.Claims, IdempotencyKey: key})
	case aep.CommandGrant:
		_, err = session.Grant(context.Background(), agent.GrantOptions{GrantType: grant.GrantType, RequestedScopes: grant.RequestedScopes, IdempotencyKey: key})
	case aep.CommandRevoke:
		_, err = session.Revoke(context.Background(), agent.RevokeOptions{GrantType: revoke.GrantType, CredentialID: revoke.CredentialID, AllGrantTypes: revoke.AllGrantTypes == "true", IdempotencyKey: key})
	}
	if err != nil || calls != 1 || !jsonEqual(body, json.RawMessage(raw)) {
		return false, err
	}
	if excluded, found := request.Case.Expected["must_not_contain"]; found {
		var names []string
		var members map[string]json.RawMessage
		if err := json.Unmarshal(excluded, &names); err != nil {
			return false, err
		}
		if err := json.Unmarshal(body, &members); err != nil {
			return false, err
		}
		for _, name := range names {
			if _, present := members[name]; present {
				return false, nil
			}
		}
		observed["must_not_contain"] = names
	}
	return jsonEqual(observed, request.Case.Expected), nil
}

func evaluateExpectedDocument(request adapterRequest) (bool, error) {
	raw, err := json.Marshal(request.Case.Expected)
	if err != nil {
		return false, err
	}
	_, err = aep.ParseInspectDocument(raw)
	return err == nil, nil
}

func evaluateDefaultEndpointBase(request adapterRequest) (bool, error) {
	raw, err := rawField(request.Case.Expected, "document")
	if err != nil {
		return false, err
	}
	document, err := aep.ParseInspectDocument(raw)
	if err != nil {
		return false, nil
	}
	expected, err := requiredField[string](request.Case.Expected, "endpoint_base")
	if err != nil {
		return false, err
	}
	endpointBase, err := aep.NormalizeEndpointBase(document.HTTP.EndpointBase)
	return err == nil && endpointBase == expected, nil
}

func evaluateProtocolVersion(request adapterRequest) (bool, error) {
	type versionCase struct {
		Compatible bool   `json:"compatible"`
		Received   string `json:"received"`
		Supported  string `json:"supported"`
		Valid      bool   `json:"valid"`
	}
	cases, err := requiredField[[]versionCase](request.Case.Expected, "cases")
	if err != nil {
		return false, err
	}
	for _, item := range cases {
		supported := item.Supported
		if supported == "" {
			supported = aep.Version
		}
		valid := regexp.MustCompile(`^[1-9][0-9]*\.[0-9]+$`).MatchString(item.Received)
		compatible := valid && aep.IsVersionCompatible(item.Received, supported)
		if compatible != item.Compatible || valid != item.Valid {
			return false, nil
		}
	}
	return true, nil
}

type bindingIdentityProvider struct {
	commandIdentityProvider
	identities int
	signatures int
}

func (provider *bindingIdentityProvider) GetOrCreateIdentity(ctx context.Context, request agent.IdentityRequest) (agent.ServiceIdentity, error) {
	provider.identities++
	return provider.commandIdentityProvider.GetOrCreateIdentity(ctx, request)
}

func (provider *bindingIdentityProvider) SignerFor(ctx context.Context, identity agent.ServiceIdentity) (agent.AssertionSigner, error) {
	signer, err := provider.commandIdentityProvider.SignerFor(ctx, identity)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, claims aep.ClientAssertionClaims, algorithms []aep.SigningAlgorithm) (string, error) {
		provider.signatures++
		return signer(ctx, claims, algorithms)
	}, nil
}

func evaluateServiceDIDBinding(request adapterRequest) (bool, error) {
	inspectURL, err := requiredField[string](request.Case.Input, "inspect_url")
	if err != nil {
		return false, err
	}
	for _, name := range []string{"provision_identity", "request_assertion", "transmit_credentials"} {
		expected, err := requiredField[bool](request.Case.Expected, name)
		if err != nil || expected {
			return false, err
		}
	}
	for _, name := range []string{"matching_service_did", "mismatched_service_did", "unsupported_service_did"} {
		did, err := requiredField[string](request.Case.Input, name)
		if err != nil {
			return false, err
		}
		expected, err := requiredField[string](request.Case.Expected, name)
		if err != nil {
			return false, err
		}
		document := minimalInspectDocument(did)
		document.Commands.Supported = []aep.Command{aep.CommandInspect, aep.CommandEnroll}
		document.Identity.Methods = []aep.IdentityMethod{aep.IdentityMethodDIDWeb}
		encoded, err := json.Marshal(document)
		if err != nil {
			return false, err
		}
		provider := &bindingIdentityProvider{commandIdentityProvider: commandIdentityProvider{agentDID: "did:web:agent.example"}}
		discoveries, commands, credentials := 0, 0, 0
		client, err := agent.New(agent.Options{IdentityProvider: provider, HTTPClient: &http.Client{Transport: conformanceRoundTripper(func(incoming *http.Request) (*http.Response, error) {
			if incoming.Header.Get("Authorization") != "" || incoming.Header.Get(aep.AuthorizationHeader) != "" {
				credentials++
			}
			if incoming.URL.String() == inspectURL && incoming.Method == http.MethodGet {
				discoveries++
				return vectorResponse(incoming, http.StatusOK, http.Header{"Content-Type": {aep.MediaType}}, string(encoded)), nil
			}
			commands++
			return vectorResponse(incoming, http.StatusOK, http.Header{"Content-Type": {aep.MediaType}}, `{"status":"active"}`), nil
		})}})
		if err != nil {
			return false, err
		}
		session, err := client.Service(inspectURL)
		if err != nil {
			return false, err
		}
		result, enrollErr := session.Enroll(context.Background(), agent.EnrollOptions{})
		if expected == "accept" {
			if enrollErr != nil || result.Body.Status != aep.AgentActive || discoveries != 1 || commands != 1 || credentials != 1 || provider.identities != 1 || provider.signatures != 1 {
				return false, fmt.Errorf("matching Service did not enroll: %v", enrollErr)
			}
		} else {
			var failure *agent.InspectError
			if !errors.As(enrollErr, &failure) || string(failure.Code) != expected || discoveries != 1 || commands != 0 || credentials != 0 || provider.identities != 0 || provider.signatures != 0 {
				return false, fmt.Errorf("%s did not reject before identity or credential use: %v", name, enrollErr)
			}
		}
	}
	return true, nil
}

func evaluateAuthorizationCarriers(request adapterRequest) (bool, error) {
	type expectedCarrier struct {
		Carrier     string `json:"carrier"`
		Credentials string `json:"credentials"`
		Scheme      string `json:"scheme"`
	}
	for _, name := range []string{"standard_jwt", "dedicated_jwt", "standard_bearer", "dedicated_bearer", "standard_basic", "dedicated_basic"} {
		expected, err := requiredField[expectedCarrier](request.Case.Expected, name)
		if err != nil {
			return false, err
		}
		carrier := aep.ProtectedResourceStandard
		if expected.Carrier == aep.AuthorizationHeader {
			carrier = aep.ProtectedResourceDedicated
		}
		value := expected.Scheme + " " + expected.Credentials
		parsed, err := aep.ParseProtectedResourceAuthorization(value, carrier)
		if err != nil {
			return false, nil
		}
		field, value, err := aep.RenderProtectedResourceAuthorization(parsed)
		if err != nil || field != expected.Carrier || value != expected.Scheme+" "+expected.Credentials {
			return false, nil
		}
	}
	return true, nil
}

func evaluateCredentialPresentations(request adapterRequest) (bool, error) {
	resource, err := requiredField[string](request.Case.Input, "resource")
	if err != nil {
		return false, err
	}
	target, err := url.Parse(resource)
	if err != nil {
		return false, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	expires := now.Add(time.Hour)
	for _, grantType := range []aep.GrantType{aep.GrantTypeOAuthBearer, aep.GrantTypeAPIKey, aep.GrantTypeBasic} {
		expected, err := requiredField[struct {
			Header string `json:"header"`
			Scheme string `json:"scheme"`
			Value  string `json:"value"`
		}](request.Case.Expected, string(grantType))
		if err != nil {
			return false, err
		}
		store := service.NewMemoryServiceCredentialStore()
		var definition service.GrantTypeDefinition
		switch grantType {
		case aep.GrantTypeOAuthBearer:
			definition, err = service.StoredOAuthBearerGrantType(service.StoredCredentialGrantTypeOptions[aep.OAuthBearerGrantResponse]{Store: store, Issue: func(context.Context, aep.GrantRequest, service.GrantContext) (aep.OAuthBearerGrantResponse, error) {
				return aep.OAuthBearerGrantResponse{CredentialID: "presentation", AccessToken: "opaque-token", TokenType: "Bearer", ExpiresAt: expires.Format(time.RFC3339), Scopes: []string{}}, nil
			}})
		case aep.GrantTypeAPIKey:
			definition, err = service.StoredAPIKeyGrantType(service.StoredCredentialGrantTypeOptions[aep.APIKeyGrantResponse]{Store: store, Issue: func(context.Context, aep.GrantRequest, service.GrantContext) (aep.APIKeyGrantResponse, error) {
				return aep.APIKeyGrantResponse{CredentialID: "presentation", APIKey: "opaque-api-key", Header: "x-api-key", ExpiresAt: expires.Format(time.RFC3339), Scopes: []string{}}, nil
			}})
		case aep.GrantTypeBasic:
			definition, err = service.StoredBasicGrantType(service.StoredCredentialGrantTypeOptions[aep.BasicGrantResponse]{Store: store, Issue: func(context.Context, aep.GrantRequest, service.GrantContext) (aep.BasicGrantResponse, error) {
				return aep.BasicGrantResponse{CredentialID: "presentation", Username: "user", Password: "password", ExpiresAt: expires.Format(time.RFC3339), Scopes: []string{}}, nil
			}})
		}
		if err != nil {
			return false, err
		}
		payload, err := definition.Handler.Grant(context.Background(), aep.GrantRequest{GrantType: grantType}, service.GrantContext{AgentDID: "did:web:agent.example", GrantType: grantType, Now: now})
		if err != nil {
			return false, err
		}
		credentials := agent.NewMemoryCredentialStore()
		if err := credentials.SaveCredential(context.Background(), agent.CredentialRecord{CredentialID: "presentation", GrantType: grantType, Payload: payload, ServiceDID: vectorDID, ServiceURL: vectorOrigin, IssuedAt: now, ExpiresAt: expires}); err != nil {
			return false, err
		}
		document := minimalInspectDocument(vectorDID)
		document.Authentication = &aep.Authentication{Methods: []aep.AuthenticationMethod{aep.AuthenticationMethod(grantType)}}
		document.Identity.Methods = []aep.IdentityMethod{aep.IdentityMethodDIDWeb}
		document.Commands.Supported = []aep.Command{aep.CommandInspect, aep.CommandGrant}
		document.Commands.GrantTypes = []aep.GrantType{grantType}
		encoded, err := json.Marshal(document)
		if err != nil {
			return false, err
		}
		client, err := agent.New(agent.Options{CredentialStore: credentials, IdentityProvider: commandIdentityProvider{}, Clock: func() time.Time { return now }, HTTPClient: &http.Client{Transport: conformanceRoundTripper(func(incoming *http.Request) (*http.Response, error) {
			return vectorResponse(incoming, http.StatusOK, http.Header{"Content-Type": {aep.MediaType}}, string(encoded)), nil
		})}})
		if err != nil {
			return false, err
		}
		session, err := client.Service(vectorOrigin)
		if err != nil {
			return false, err
		}
		headers, err := session.AuthenticationHeaders(context.Background(), agent.AuthenticationOptions{Resource: target, CredentialID: "presentation"})
		value := expected.Value
		if grantType == aep.GrantTypeOAuthBearer {
			value = expected.Scheme + " opaque-token"
		} else if grantType == aep.GrantTypeBasic {
			value = expected.Scheme + " dXNlcjpwYXNzd29yZA=="
		}
		if err != nil || len(headers) != 1 || headers.Get(expected.Header) != value {
			return false, err
		}
		authenticator, ok := definition.Handler.(service.CredentialAuthenticator)
		if !ok {
			return false, fmt.Errorf("%s handler does not authenticate credentials", grantType)
		}
		principal, err := authenticator.AuthenticateCredential(context.Background(), service.CredentialAuthenticationInput{Headers: headers, Method: http.MethodGet, URL: target, Now: now})
		if err != nil || principal == nil || principal.AgentDID != "did:web:agent.example" || principal.CredentialID != "presentation" || principal.GrantType != grantType {
			return false, err
		}
		headers.Set(expected.Header, "invalid")
		principal, err = authenticator.AuthenticateCredential(context.Background(), service.CredentialAuthenticationInput{Headers: headers, Method: http.MethodGet, URL: target, Now: now})
		if err != nil || principal != nil {
			return false, nil
		}
	}
	return true, nil
}

func evaluateInspectAuthenticationMethods(request adapterRequest) (bool, error) {
	omitted, err := requiredField[string](request.Case.Expected, "omitted_means")
	if err != nil || omitted != "no-advertised-method" {
		return false, err
	}
	for _, name := range []string{"jwt_only", "credentials_only", "ordered_mixed", "omitted"} {
		var fragment struct {
			Authentication *aep.Authentication `json:"authentication"`
		}
		if name != "omitted" {
			raw, err := rawField(request.Case.Expected, name)
			if err != nil {
				return false, err
			}
			if err := json.Unmarshal(raw, &fragment); err != nil || fragment.Authentication == nil {
				return false, err
			}
		}
		var methods []aep.AuthenticationMethod
		if fragment.Authentication != nil {
			methods = fragment.Authentication.Methods
		}
		var definitions []service.GrantTypeDefinition
		for _, method := range methods {
			if method != aep.AuthenticationMethodJWT {
				definitions = append(definitions, service.GrantTypeDefinition{GrantType: aep.GrantType(method), Handler: conformanceGrantHandler{}})
			}
		}
		instance, err := newConfiguredConformanceService(nil, methods, definitions, nil, nil)
		if err != nil {
			return false, err
		}
		handler, err := service.NewHTTPHandler(instance, service.HTTPHandlerOptions{})
		if err != nil {
			return false, err
		}
		client, err := agent.New(agent.Options{IdentityProvider: inspectIdentityProvider{}, HTTPClient: &http.Client{Transport: conformanceRoundTripper(func(incoming *http.Request) (*http.Response, error) {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, incoming)
			return recorder.Result(), nil
		})}})
		if err != nil {
			return false, err
		}
		session, err := client.Service("https://service.example")
		if err != nil {
			return false, err
		}
		inspection, err := session.Inspect(context.Background())
		if err != nil || !jsonEqual(inspection.Document.Authentication, fragment.Authentication) {
			return false, err
		}
		if name == "omitted" {
			resource, _ := url.Parse("https://service.example/private")
			_, err := session.AuthenticationHeaders(context.Background(), agent.AuthenticationOptions{Resource: resource})
			if !errors.Is(err, agent.ErrNoAuthenticationMethod) {
				return false, fmt.Errorf("omitted authentication did not prevent credential selection: %v", err)
			}
		}
	}
	return true, nil
}

func evaluateOpenAPIPathMatching(request adapterRequest) (bool, error) {
	method, err := requiredField[string](request.Case.Input, "method")
	if err != nil {
		return false, err
	}
	path, err := requiredField[string](request.Case.Input, "path")
	if err != nil {
		return false, err
	}
	templates, err := requiredField[[]string](request.Case.Input, "templates")
	if err != nil {
		return false, err
	}
	query, err := requiredField[string](request.Case.Input, "query")
	if err != nil {
		return false, err
	}
	expectedMethod, err := requiredField[string](request.Case.Expected, "method")
	if err != nil {
		return false, err
	}
	querySelects, err := requiredField[bool](request.Case.Expected, "query_selects_operation")
	if err != nil || querySelects {
		return false, err
	}
	literalPrecedence, err := requiredField[bool](request.Case.Expected, "literal_precedence")
	if err != nil || !literalPrecedence {
		return false, err
	}
	strictExpected, err := requiredField[map[string]string](request.Case.Expected, "strict")
	if err != nil || strictExpected["/items"] != "different-from-/items/" {
		return false, err
	}
	equivalentExpected, err := requiredField[map[string]string](request.Case.Expected, "equivalent")
	if err != nil || equivalentExpected["/items"] != "same-as-/items/" || equivalentExpected["/"] != "unchanged" {
		return false, err
	}
	ambiguousExpected, err := requiredField[string](request.Case.Expected, "similar_templates")
	if err != nil || ambiguousExpected != "contradiction" {
		return false, err
	}
	staleExpected, err := requiredField[string](request.Case.Expected, "stale_contradiction")
	if err != nil || staleExpected != "revalidate-and-live-challenge" {
		return false, err
	}
	match, err := aep.MatchOpenAPIPath(templates, aep.OpenAPIPathMatchOptions{Method: method, Path: path, TrailingSlash: "strict"})
	if err != nil || match.Method != expectedMethod || match.Template != "/v1/orders/{id}" {
		return false, nil
	}
	reversed := slices.Clone(templates)
	slices.Reverse(reversed)
	other, err := aep.MatchOpenAPIPath(reversed, aep.OpenAPIPathMatchOptions{Method: method, Path: path, TrailingSlash: "strict"})
	if err != nil || other != match {
		return false, err
	}
	strict, strictErr := aep.MatchOpenAPIPath([]string{"/items"}, aep.OpenAPIPathMatchOptions{Method: method, Path: "/items/", TrailingSlash: "strict"})
	equivalent, equivalentErr := aep.MatchOpenAPIPath([]string{"/items"}, aep.OpenAPIPathMatchOptions{Method: method, Path: "/items/", TrailingSlash: "equivalent"})
	root, rootErr := aep.MatchOpenAPIPath([]string{"/"}, aep.OpenAPIPathMatchOptions{Method: method, Path: "/", TrailingSlash: "equivalent"})
	_, ambiguousErr := aep.MatchOpenAPIPath([]string{"/items/{id}", "/items/{name}"}, aep.OpenAPIPathMatchOptions{Method: method, Path: "/items/1", TrailingSlash: "strict"})
	if strictErr == nil || strict.Template != "" || equivalentErr != nil || equivalent.Template != "/items" || rootErr != nil || root.Template != "/" || ambiguousErr == nil {
		return false, nil
	}
	return checkOpenAPIPathRequests(method, path, query, templates, match)
}

func checkOpenAPIPathRequests(method, path, query string, templates []string, expected aep.OpenAPIPathMatch) (bool, error) {
	paths := make(map[string]any)
	for _, template := range templates {
		paths[template] = map[string]any{strings.ToLower(method): map[string]any{}}
	}
	openAPI, err := json.Marshal(map[string]any{"openapi": "3.1.0", "security": []any{}, "paths": paths})
	if err != nil {
		return false, err
	}
	document := minimalInspectDocument(vectorDID)
	document.Identity.Methods = []aep.IdentityMethod{aep.IdentityMethodDIDWeb}
	document.Authentication = &aep.Authentication{Methods: []aep.AuthenticationMethod{aep.AuthenticationMethodJWT}}
	document.HTTP.OpenAPI = &aep.OpenAPIReference{URL: "/openapi.json", PathMatching: aep.OpenAPIPathMatching{TrailingSlash: "strict"}}
	inspect, err := json.Marshal(document)
	if err != nil {
		return false, err
	}
	now := time.Now()
	documents, anonymous, authenticated := 0, 0, 0
	valid := true
	provider := &bindingIdentityProvider{commandIdentityProvider: commandIdentityProvider{agentDID: "did:web:agent.example"}}
	client, err := agent.New(agent.Options{IdentityProvider: provider, Clock: func() time.Time { return now }, HTTPClient: &http.Client{Transport: conformanceRoundTripper(func(incoming *http.Request) (*http.Response, error) {
		switch incoming.URL.Path {
		case aep.WellKnownPath:
			return vectorResponse(incoming, http.StatusOK, http.Header{"Content-Type": {aep.MediaType}}, string(inspect)), nil
		case "/openapi.json":
			documents++
			valid = valid && incoming.Header.Get("Authorization") == "" && incoming.Header.Get(aep.AuthorizationHeader) == ""
			if documents > 1 {
				valid = valid && incoming.Header.Get("If-None-Match") == `"public"`
				return vectorResponse(incoming, http.StatusNotModified, nil, ""), nil
			}
			return vectorResponse(incoming, http.StatusOK, http.Header{"Content-Type": {"application/json"}, "Cache-Control": {"max-age=1"}, "ETag": {`"public"`}}, string(openAPI)), nil
		case path:
			valid = valid && incoming.Method == expected.Method && incoming.URL.RawQuery == query
			if incoming.Header.Get("Authorization") == "" {
				anonymous++
				return vectorResponse(incoming, http.StatusUnauthorized, http.Header{"WWW-Authenticate": {`AEP service_did="` + vectorDID + `",inspect="` + vectorOrigin + aep.WellKnownPath + `"`}}, ""), nil
			}
			authenticated++
			valid = valid && incoming.Header.Get("Authorization") == "AEP client-assertion"
			return vectorResponse(incoming, http.StatusOK, nil, "ok"), nil
		default:
			return nil, fmt.Errorf("unexpected OpenAPI vector request %s", incoming.URL)
		}
	})}})
	if err != nil {
		return false, err
	}
	session, err := client.Service(vectorOrigin)
	if err != nil {
		return false, err
	}
	resource, err := http.NewRequest(expected.Method, vectorOrigin+path+"?"+query, nil)
	if err != nil {
		return false, err
	}
	for _, rawQuery := range []string{"", query} {
		target := *resource.URL
		target.RawQuery = rawQuery
		policy, err := session.OpenAPIPolicy(context.Background(), method, &target)
		if err != nil || policy.State != "public" || policy.MatchedOperation == nil || *policy.MatchedOperation != expected {
			return false, fmt.Errorf("query affected operation matching: %v", err)
		}
	}
	// Expire the cached public document; the live resource still requires authentication.
	now = now.Add(2 * time.Second)
	response, err := client.FetchProtectedResource(context.Background(), resource, agent.ProtectedResourceOptions{})
	if err != nil {
		return false, err
	}
	response.Body.Close()
	return valid && response.StatusCode == http.StatusOK && documents == 3 && anonymous == 1 && authenticated == 1 && provider.signatures == 1, nil
}

func evaluateOpenAPISecurity(request adapterRequest) (bool, error) {
	raw, err := rawField(request.Case.Input, "security_scheme")
	if err != nil {
		return false, err
	}
	scheme, err := aep.ParseOpenAPIAEPSecurityScheme(raw)
	if err != nil || scheme.AuthenticationMethod != aep.AuthenticationMethodJWT {
		return false, nil
	}
	// A Service's advertised security is evaluated by its consuming Agent.
	for _, scenario := range []struct {
		field, meaning, security, operation, state string
		methods                                    []aep.AuthenticationMethod
	}{
		{"root_inherited", "required", `[{"a":[]}]`, `{}`, "required", []aep.AuthenticationMethod{"aep-jwt"}},
		{"operation_empty_array", "public", `[{"a":[]}]`, `{"security":[]}`, "public", nil},
		{"empty_requirement_alternative", "optional-anonymous", `[{"a":[]},{}]`, `{}`, "public", nil},
		{"multiple_objects", "alternatives", `[{"a":[]},{"b":[]}]`, `{}`, "required", []aep.AuthenticationMethod{"aep-jwt", "api-key"}},
		{"multiple_schemes_one_object", "all-required", `[{"a":[],"b":[]}]`, `{}`, "fallback", nil},
		{"unsupported_compound", "fallback-live-challenge", `[{"a":[],"unknown":[]}]`, `{}`, "fallback", nil},
	} {
		expected, err := requiredField[string](request.Case.Expected, scenario.field)
		if err != nil || expected != scenario.meaning {
			return false, err
		}
		document := []byte(`{"openapi":"3.1.0","security":` + scenario.security + `,"paths":{"/resource":{"get":` + scenario.operation + `}},"components":{"securitySchemes":{"a":` + string(raw) + `,"b":{"type":"apiKey","in":"header","name":"X-API-Key","x-aep-authentication-method":"api-key"}}}}`)
		policy, err := agent.InterpretOpenAPIOperation(document, aep.OpenAPIPathMatchOptions{Method: "GET", Path: "/resource", TrailingSlash: "strict"})
		if err != nil || policy.State != scenario.state || !slices.Equal(policy.Methods, scenario.methods) {
			return false, fmt.Errorf("%s security mapping mismatch: %v", scenario.field, err)
		}
	}
	return true, nil
}

func evaluateOpenAPIURL(request adapterRequest) (bool, error) {
	finalInspectURL, err := requiredField[string](request.Case.Input, "final_inspect_url")
	if err != nil {
		return false, err
	}
	relative, err := requiredField[string](request.Case.Input, "relative")
	if err != nil {
		return false, err
	}
	crossOrigin, err := requiredField[string](request.Case.Input, "cross_origin")
	if err != nil {
		return false, err
	}
	expected, err := requiredField[string](request.Case.Expected, "relative_resolved")
	if err != nil {
		return false, err
	}
	resolved, err := aep.ResolveOpenAPIURL(finalInspectURL, relative, false)
	if err != nil || resolved.String() != expected {
		return false, nil
	}
	if _, err := aep.ResolveOpenAPIURL(finalInspectURL, crossOrigin, false); err != nil {
		return false, nil
	}
	for _, unsafe := range []string{"http://api.example.com/openapi.json", "https://user@api.example.com/openapi.json"} {
		if _, err := aep.ResolveOpenAPIURL(finalInspectURL, unsafe, false); err == nil {
			return false, nil
		}
	}
	for field, meaning := range map[string]string{"cross_origin_https": "allowed-anonymous", "userinfo": "reject", "downgrade": "reject"} {
		expected, err := requiredField[string](request.Case.Expected, field)
		if err != nil || expected != meaning {
			return false, err
		}
	}
	headers, err := requiredField[[]string](request.Case.Expected, "forwarded_headers")
	if err != nil || len(headers) != 0 {
		return false, err
	}
	mediaTypes, err := requiredField[[]string](request.Case.Expected, "accepted_media_types")
	if err != nil || len(mediaTypes) == 0 {
		return false, err
	}
	for _, mediaType := range mediaTypes {
		for _, reference := range []string{relative, crossOrigin} {
			if passed, err := checkAnonymousOpenAPIRetrieval(finalInspectURL, reference, mediaType); err != nil || !passed {
				return false, err
			}
		}
	}
	return true, nil
}

func checkAnonymousOpenAPIRetrieval(finalInspectURL, reference, mediaType string) (bool, error) {
	final, err := url.Parse(finalInspectURL)
	if err != nil {
		return false, err
	}
	target, err := aep.ResolveOpenAPIURL(finalInspectURL, reference, false)
	if err != nil {
		return false, err
	}
	origin := final.Scheme + "://" + final.Host
	document := minimalInspectDocument("did:web:" + final.Hostname())
	document.HTTP.OpenAPI = &aep.OpenAPIReference{URL: reference, PathMatching: aep.OpenAPIPathMatching{TrailingSlash: "strict"}}
	encoded, err := json.Marshal(document)
	if err != nil {
		return false, err
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return false, err
	}
	for _, address := range []*url.URL{final, target} {
		jar.SetCookies(address, []*http.Cookie{{Name: "session", Value: "private", Path: "/", Secure: true}})
	}
	discoveries, documents, resources := 0, 0, 0
	leaked := false
	provider := &bindingIdentityProvider{commandIdentityProvider: commandIdentityProvider{agentDID: "did:web:agent.example"}}
	client, err := agent.New(agent.Options{IdentityProvider: provider, HTTPClient: &http.Client{Jar: jar, Transport: conformanceRoundTripper(func(incoming *http.Request) (*http.Response, error) {
		switch incoming.URL.String() {
		case origin + aep.WellKnownPath:
			return vectorResponse(incoming, http.StatusFound, http.Header{"Location": {finalInspectURL}}, ""), nil
		case finalInspectURL:
			discoveries++
			return vectorResponse(incoming, http.StatusOK, http.Header{"Content-Type": {aep.MediaType}, "Cache-Control": {"no-store"}}, string(encoded)), nil
		case target.String():
			documents++
			for _, name := range []string{"Authorization", aep.AuthorizationHeader, "Cookie", "Proxy-Authorization", "X-API-Key", "X-Caller-Header"} {
				if incoming.Header.Get(name) != "" {
					leaked = true
					return nil, fmt.Errorf("OpenAPI received caller header %s", name)
				}
			}
			return vectorResponse(incoming, http.StatusOK, http.Header{"Content-Type": {mediaType}, "Cache-Control": {"no-store"}}, `{"openapi":"3.1.0","security":[],"paths":{"/resource":{"get":{}}}}`), nil
		case origin + "/resource?view=full":
			resources++
			return vectorResponse(incoming, http.StatusOK, nil, "public resource"), nil
		default:
			return nil, fmt.Errorf("unexpected URL %s", incoming.URL)
		}
	})}})
	if err != nil {
		return false, err
	}
	// The policy call exposes retrieval failures that FetchProtectedResource correctly
	// handles by falling back to a live resource request.
	session, err := client.Service(origin)
	if err != nil {
		return false, err
	}
	resource, err := http.NewRequest(http.MethodGet, origin+"/resource?view=full", nil)
	if err != nil {
		return false, err
	}
	policy, err := session.OpenAPIPolicy(context.Background(), resource.Method, resource.URL)
	if err != nil || policy.State != "public" || policy.MatchedOperation == nil || policy.MatchedOperation.Template != "/resource" {
		return false, fmt.Errorf("OpenAPI retrieval failed: %v", err)
	}
	for _, name := range []string{"Authorization", aep.AuthorizationHeader, "Cookie", "Proxy-Authorization", "X-API-Key", "X-Caller-Header"} {
		resource.Header.Set(name, "private")
	}
	response, err := client.FetchProtectedResource(context.Background(), resource, agent.ProtectedResourceOptions{})
	if err != nil {
		return false, err
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || leaked || discoveries != 2 || documents != 2 || resources != 1 || provider.identities != 0 || provider.signatures != 0 {
		return false, fmt.Errorf("anonymous retrieval mismatch: status=%d leaked=%t inspect=%d openapi=%d resource=%d identities=%d signatures=%d", response.StatusCode, leaked, discoveries, documents, resources, provider.identities, provider.signatures)
	}
	return true, nil
}
