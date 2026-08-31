package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"regexp"
	"slices"
	"strings"

	aep "github.com/aep-foundation/aep-go"
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
		passed, err := evaluateEnrollRequest(request)
		return true, passed, err
	case "response-active", "response-pending-verification-owner-action":
		if request.Vector.Category == "enroll" {
			passed, err := evaluateExpectedBody(request, aep.ParseEnrollResponse)
			return true, passed, err
		}
		passed, err := evaluateExpectedBody(request, aep.ParseStatusResponse)
		return true, passed, err
	case "response-pending-requirements":
		passed, err := evaluateExpectedBody(request, aep.ParseStatusResponse)
		return true, passed, err
	case "grant-request-oauth-bearer":
		passed, err := evaluateParseAndExpected(request, "input", aep.ParseGrantRequest)
		return true, passed, err
	case "revoke-request-all-grant-types", "revoke-request-oauth-bearer", "revoke-request-targeted-oauth-bearer",
		"revoke-request-conflicting-targets", "revoke-request-credential-id-without-grant-type":
		passed, err := evaluateRevokeRequest(request)
		return true, passed, err
	case "revoke-response-empty":
		passed, err := evaluateExpectedBody(request, aep.ParseRevokeResponse)
		return true, passed, err
	case "not-recognized-problem", "requirements-unmet-problem", "verification-pending-problem":
		passed, err := evaluateExpectedBody(request, aep.ParseProblemDetails)
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
	return (len(result.UnsupportedRequired) == 0) == expected, nil
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
	claimsRaw, err := rawField(request.Case.Expected, "claims")
	if err != nil {
		return false, err
	}
	claims, err := aep.ParseClientAssertionClaims(claimsRaw)
	if err != nil {
		return false, nil
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return false, err
	}
	header, err := requiredField[map[string]any](request.Case.Expected, "header")
	if err != nil {
		return false, err
	}
	keyID, _ := header["kid"].(string)
	assertion, err := aep.SignClientAssertion(claims, aep.SignClientAssertionOptions{Algorithm: aep.SigningAlgorithmES256, Key: privateKey, KeyID: keyID})
	if err != nil {
		return false, err
	}
	decoded, err := aep.DecodeJWTUnverified(assertion)
	if err != nil || !jsonEqual(decoded.Header, header) || !jsonEqual(decoded.Payload, request.Case.Expected["claims"]) {
		return false, err
	}
	invalid := []aep.ClientAssertionClaims{
		func() aep.ClientAssertionClaims {
			value := claims
			value.ExpiresAt = value.IssuedAt + 301
			return value
		}(),
		func() aep.ClientAssertionClaims { value := claims; value.ExpiresAt = value.IssuedAt; return value }(),
		func() aep.ClientAssertionClaims {
			value := claims
			value.Operation = aep.AssertionAuthenticate
			return value
		}(),
		func() aep.ClientAssertionClaims {
			value := claims
			value.Resource = "https://api.example.com/orders"
			return value
		}(),
		func() aep.ClientAssertionClaims {
			value := claims
			value.Operation = aep.AssertionAuthenticate
			value.Resource = "http://api.example.com/orders"
			return value
		}(),
		func() aep.ClientAssertionClaims {
			value := claims
			value.Operation = aep.AssertionAuthenticate
			value.Resource = "https://api.example.com/orders#item"
			return value
		}(),
		func() aep.ClientAssertionClaims {
			value := claims
			value.Subject = "did:web:different.example"
			return value
		}(),
	}
	for _, value := range invalid {
		if aep.ValidateClientAssertionClaims(value) == nil {
			return false, nil
		}
	}
	if _, err := aep.SignClientAssertion(claims, aep.SignClientAssertionOptions{Algorithm: aep.SigningAlgorithmES256, Key: privateKey}); err == nil {
		return false, nil
	}
	if _, err := aep.SignClientAssertion(claims, aep.SignClientAssertionOptions{Algorithm: aep.SigningAlgorithmES256, Key: privateKey, KeyID: "did:web:different.example#key-1"}); err == nil {
		return false, nil
	}
	return true, nil
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
	_, parseErr := aep.ParseBuiltInGrantResponse(grantType, raw)
	return (parseErr == nil) == expectedValid, nil
}

func evaluateParseAndExpected[T any](request adapterRequest, inputName string, parse func([]byte) (T, error)) (bool, error) {
	var raw []byte
	var err error
	if inputName == "input" {
		raw, err = json.Marshal(request.Case.Input)
	} else {
		raw, err = rawField(request.Case.Input, inputName)
	}
	if err != nil {
		return false, err
	}
	_, err = parse(raw)
	return err == nil, nil
}

func evaluateExpectedBody[T any](request adapterRequest, parse func([]byte) (T, error)) (bool, error) {
	body, err := rawField(request.Case.Expected, "body")
	if err != nil {
		return false, err
	}
	parsed, err := parse(body)
	if err != nil {
		return false, nil
	}
	return jsonEqual(parsed, json.RawMessage(body)), nil
}

func evaluateRevokeRequest(request adapterRequest) (bool, error) {
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

func evaluateServiceDIDBinding(request adapterRequest) (bool, error) {
	matching, err := requiredField[string](request.Case.Input, "matching_service_did")
	if err != nil {
		return false, err
	}
	resolved, err := aep.DIDWebDocumentURL(matching)
	if err != nil {
		return false, nil
	}
	return resolved.Scheme == "https", nil
}

func evaluateAuthorizationCarriers(request adapterRequest) (bool, error) {
	type expectedCarrier struct {
		Carrier     string `json:"carrier"`
		Credentials string `json:"credentials"`
		Scheme      string `json:"scheme"`
	}
	for _, raw := range request.Case.Expected {
		var expected expectedCarrier
		if err := json.Unmarshal(raw, &expected); err != nil {
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
	for name, raw := range request.Case.Expected {
		var expected struct {
			Header string `json:"header"`
			Scheme string `json:"scheme"`
			Value  string `json:"value"`
		}
		if err := json.Unmarshal(raw, &expected); err != nil {
			return false, err
		}
		if name == string(aep.GrantTypeAPIKey) {
			if expected.Header == "" || expected.Value == "" {
				return false, nil
			}
			continue
		}
		credentials := "credential"
		parsed, err := aep.ParseProtectedResourceAuthorization(expected.Scheme+" "+credentials, aep.ProtectedResourceStandard)
		if err != nil || parsed.Credentials != credentials || expected.Header != "Authorization" {
			return false, nil
		}
	}
	return true, nil
}

func evaluateEnrollRequest(request adapterRequest) (bool, error) {
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
		return false, nil
	}
	body := aep.EnrollRequest{AgentDID: agentDID, Claims: &claims, IdempotencyKey: idempotencyKey}
	if err := aep.ValidateEnrollRequest(body); err != nil {
		return false, nil
	}
	path, err := aep.CommandPath(aep.CommandEnroll, "")
	if err != nil {
		return false, err
	}
	expectedPath, err := requiredField[string](request.Case.Expected, "path")
	if err != nil {
		return false, err
	}
	return path == expectedPath, nil
}

func evaluateInspectAuthenticationMethods(request adapterRequest) (bool, error) {
	for _, name := range []string{"jwt_only", "credentials_only", "ordered_mixed"} {
		raw, err := rawField(request.Case.Expected, name)
		if err != nil {
			return false, err
		}
		var fragment struct {
			Authentication aep.Authentication `json:"authentication"`
		}
		if err := json.Unmarshal(raw, &fragment); err != nil {
			return false, err
		}
		document := minimalInspectDocument("did:web:api.example.com")
		document.Authentication = &fragment.Authentication
		document.Identity.Methods = []aep.IdentityMethod{aep.IdentityMethodDIDWeb}
		for _, method := range fragment.Authentication.Methods {
			if method != aep.AuthenticationMethodJWT {
				document.Commands.Supported = []aep.Command{aep.CommandEnroll, aep.CommandGrant, aep.CommandInspect, aep.CommandRevoke, aep.CommandStatus}
				document.Commands.GrantTypes = append(document.Commands.GrantTypes, aep.GrantType(method))
			}
		}
		if err := aep.ValidateInspectDocument(document); err != nil {
			return false, nil
		}
	}
	document := minimalInspectDocument("did:web:api.example.com")
	return document.Authentication == nil && aep.ValidateInspectDocument(document) == nil, nil
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
	match, err := aep.MatchOpenAPIPath(templates, aep.OpenAPIPathMatchOptions{Method: method, Path: path, TrailingSlash: "strict"})
	if err != nil || match.Method != strings.ToUpper(method) || match.Template != templates[0] {
		return false, nil
	}
	strict, strictErr := aep.MatchOpenAPIPath([]string{"/items"}, aep.OpenAPIPathMatchOptions{Method: method, Path: "/items/", TrailingSlash: "strict"})
	equivalent, equivalentErr := aep.MatchOpenAPIPath([]string{"/items"}, aep.OpenAPIPathMatchOptions{Method: method, Path: "/items/", TrailingSlash: "equivalent"})
	_, ambiguousErr := aep.MatchOpenAPIPath([]string{"/items/{id}", "/items/{name}"}, aep.OpenAPIPathMatchOptions{Method: method, Path: "/items/1", TrailingSlash: "strict"})
	return strictErr != nil && strict.Template == "" && equivalentErr == nil && equivalent.Template == "/items" && ambiguousErr != nil, nil
}

func evaluateOpenAPISecurity(request adapterRequest) (bool, error) {
	raw, err := rawField(request.Case.Input, "security_scheme")
	if err != nil {
		return false, err
	}
	scheme, err := aep.ParseOpenAPIAEPSecurityScheme(raw)
	if err != nil {
		return false, nil
	}
	return scheme.AuthenticationMethod == aep.AuthenticationMethodJWT, nil
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
	return true, nil
}
