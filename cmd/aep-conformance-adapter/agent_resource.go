package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	aep "github.com/aep-foundation/aep-go"
	"github.com/aep-foundation/aep-go/agent"
)

const vectorOrigin = "https://api.example.com"
const vectorDID = "did:web:api.example.com"

func vectorResponse(request *http.Request, status int, headers http.Header, body string) *http.Response {
	normalized := make(http.Header)
	for name, values := range headers {
		for _, value := range values {
			normalized.Add(name, value)
		}
	}
	return &http.Response{StatusCode: status, Header: normalized, Body: io.NopCloser(strings.NewReader(body)), Request: request}
}

// Only discovery and the remote application's responses are supplied here. Selection,
// credential presentation, challenge handling and retries run through the Agent.
func vectorResourceClient(methods []aep.AuthenticationMethod, grantType aep.GrantType, payload json.RawMessage, resource conformanceRoundTripper) (*agent.Client, error) {
	document := minimalInspectDocument(vectorDID)
	document.Identity.Methods = []aep.IdentityMethod{aep.IdentityMethodDIDWeb}
	if methods != nil {
		document.Authentication = &aep.Authentication{Methods: methods}
	}
	body, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}
	store := agent.NewMemoryCredentialStore()
	if payload != nil {
		var metadata struct {
			CredentialID string `json:"credential_id"`
			ExpiresAt    string `json:"expires_at"`
		}
		if err := json.Unmarshal(payload, &metadata); err != nil {
			return nil, err
		}
		expires, err := time.Parse(time.RFC3339, metadata.ExpiresAt)
		if err != nil {
			return nil, err
		}
		if err := store.SaveCredential(context.Background(), agent.CredentialRecord{CredentialID: metadata.CredentialID, ExpiresAt: expires, GrantType: grantType, Payload: payload, ServiceDID: vectorDID, ServiceURL: vectorOrigin}); err != nil {
			return nil, err
		}
	}
	return agent.New(agent.Options{CredentialStore: store, IdentityProvider: commandIdentityProvider{agentDID: "did:web:agent.example"}, HTTPClient: &http.Client{Transport: conformanceRoundTripper(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() == vectorOrigin+aep.WellKnownPath {
			return vectorResponse(request, 200, http.Header{"Content-Type": {aep.MediaType}}, string(body)), nil
		}
		if resource == nil {
			return nil, errors.New("unexpected resource request")
		}
		return resource(request)
	})}})
}

func vectorCredential(grantType aep.GrantType, header, secret string) (json.RawMessage, error) {
	fields := map[string]any{"credential_id": "credential-1", "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339), "scopes": []string{}}
	switch grantType {
	case aep.GrantTypeAPIKey:
		fields["api_key"], fields["header"] = secret, header
	case aep.GrantTypeOAuthBearer:
		fields["access_token"], fields["token_type"] = secret, "Bearer"
	default:
		return nil, errors.New("unsupported vector credential")
	}
	return json.Marshal(fields)
}

func evaluateAgentAPIKeyPresentation(request adapterRequest) (bool, error) {
	issued, err := requiredField[string](request.Case.Input, "issued_header")
	if err != nil {
		return false, err
	}
	presented, err := requiredField[string](request.Case.Input, "presented_header")
	if err != nil {
		return false, err
	}
	secret, err := requiredField[string](request.Case.Input, "api_key")
	if err != nil {
		return false, err
	}
	expected, err := requiredField[bool](request.Case.Expected, "accepted")
	if err != nil {
		return false, err
	}
	payload, err := vectorCredential(aep.GrantTypeAPIKey, issued, secret)
	if err != nil {
		return false, err
	}
	client, err := vectorResourceClient([]aep.AuthenticationMethod{"api-key"}, aep.GrantTypeAPIKey, payload, nil)
	if err != nil {
		return false, err
	}
	session, err := client.Service(vectorOrigin)
	if err != nil {
		return false, err
	}
	target, _ := url.Parse(vectorOrigin + "/resource")
	headers, err := session.AuthenticationHeaders(context.Background(), agent.AuthenticationOptions{Resource: target})
	return err == nil && len(headers) == 1 && headers.Get(issued) == secret && (headers.Get(presented) == secret) == expected, err
}

func evaluateAgentPaymentRequests(request adapterRequest) (bool, error) {
	for _, protocol := range []string{"mpp", "x402"} {
		var expected struct {
			Dedicated     string `json:"AEP-Authorization"`
			Authorization string `json:"Authorization"`
			Signature     string `json:"PAYMENT-SIGNATURE"`
		}
		raw, err := rawField(request.Case.Expected, protocol)
		if err != nil {
			return false, err
		}
		if err := json.Unmarshal(raw, &expected); err != nil {
			return false, err
		}
		methods := []aep.AuthenticationMethod{aep.AuthenticationMethodJWT}
		var payload json.RawMessage
		if protocol == "x402" {
			methods = []aep.AuthenticationMethod{"oauth-bearer"}
			payload, err = vectorCredential(aep.GrantTypeOAuthBearer, "", "opaque-token")
			if err != nil {
				return false, err
			}
		}
		anonymous, authenticated, valid := 0, 0, true
		client, err := vectorResourceClient(methods, aep.GrantTypeOAuthBearer, payload, func(incoming *http.Request) (*http.Response, error) {
			if incoming.Header.Get(aep.AuthorizationHeader) == "" {
				anonymous++
				valid = valid && incoming.Header.Get("Authorization") == "" && incoming.Header.Get("PAYMENT-SIGNATURE") == ""
				return vectorResponse(incoming, 401, http.Header{"WWW-Authenticate": {`AEP service_did="` + vectorDID + `",inspect="` + vectorOrigin + aep.WellKnownPath + `"`}}, ""), nil
			}
			authenticated++
			// The vector's compact-jws is an opaque signer result, not a JWT fixture.
			dedicated := strings.Replace(expected.Dedicated, "compact-jws", "client-assertion", 1)
			valid = valid && incoming.Header.Get(aep.AuthorizationHeader) == dedicated && incoming.Header.Get("Authorization") == expected.Authorization && incoming.Header.Get("PAYMENT-SIGNATURE") == expected.Signature
			return vectorResponse(incoming, 200, make(http.Header), "ok"), nil
		})
		if err != nil {
			return false, err
		}
		incoming, _ := http.NewRequest("GET", vectorOrigin+"/resource", nil)
		extra := make(http.Header)
		if protocol == "mpp" {
			extra.Set("Authorization", "Payment mpp-credential")
		} else {
			extra.Set("PAYMENT-SIGNATURE", "x402-signature")
		}
		response, err := client.FetchProtectedResource(context.Background(), incoming, agent.ProtectedResourceOptions{Authentication: agent.AuthenticationOptions{Carrier: aep.ProtectedResourceDedicated}, AdditionalAuthenticationHeaders: extra})
		if err != nil {
			return false, err
		}
		response.Body.Close()
		if !valid || response.StatusCode != 200 || anonymous != 1 || authenticated != 1 {
			return false, nil
		}
	}
	return true, nil
}

func evaluateAgentFailureResponses(request adapterRequest) (bool, error) {
	cases, err := requiredField[[]string](request.Case.Input, "cases")
	if err != nil {
		return false, err
	}
	for _, failure := range cases {
		code, err := requiredField[string](request.Case.Expected, failure)
		if err != nil {
			return false, err
		}
		status := 401
		if failure == "insufficient_scope" {
			status = 403
		}
		body, err := json.Marshal(map[string]any{"type": "urn:aep:error:" + code, "status": status, "code": code})
		if err != nil {
			return false, err
		}
		calls := 0
		methods := []aep.AuthenticationMethod{aep.AuthenticationMethodJWT}
		var payload json.RawMessage
		if strings.Contains(failure, "credential") {
			methods = []aep.AuthenticationMethod{"oauth-bearer"}
			payload, err = vectorCredential(aep.GrantTypeOAuthBearer, "", "opaque-token")
			if err != nil {
				return false, err
			}
		}
		client, err := vectorResourceClient(methods, aep.GrantTypeOAuthBearer, payload, func(incoming *http.Request) (*http.Response, error) {
			calls++
			if incoming.Header.Get("Authorization") == "" {
				return vectorResponse(incoming, 401, http.Header{"WWW-Authenticate": {`AEP service_did="` + vectorDID + `",inspect="` + vectorOrigin + aep.WellKnownPath + `"`}}, ""), nil
			}
			return vectorResponse(incoming, status, http.Header{"Content-Type": {"application/problem+json"}}, string(body)), nil
		})
		if err != nil {
			return false, err
		}
		incoming, _ := http.NewRequest("GET", vectorOrigin+"/resource", nil)
		response, err := client.FetchProtectedResource(context.Background(), incoming, agent.ProtectedResourceOptions{})
		if err != nil {
			return false, err
		}
		actual, readErr := io.ReadAll(response.Body)
		response.Body.Close()
		if readErr != nil {
			return false, readErr
		}
		if calls != 2 || response.StatusCode != status || string(actual) != string(body) {
			return false, nil
		}
	}
	return true, nil
}

func evaluateAgentUnadvertisedMethods(request adapterRequest) (bool, error) {
	methods, err := requiredField[[]aep.AuthenticationMethod](request.Case.Input, "advertised_methods")
	if err != nil {
		return false, err
	}
	credentialType, err := requiredField[aep.GrantType](request.Case.Input, "unadvertised_credential")
	if err != nil {
		return false, err
	}
	grantType, err := requiredField[aep.GrantType](request.Case.Input, "unadvertised_grant_type")
	if err != nil {
		return false, err
	}
	payload, err := vectorCredential(credentialType, "", "opaque-token")
	if err != nil {
		return false, err
	}
	target, _ := url.Parse(vectorOrigin + "/resource")
	for _, advertised := range [][]aep.AuthenticationMethod{nil, methods} {
		client, err := vectorResourceClient(advertised, credentialType, payload, nil)
		if err != nil {
			return false, err
		}
		session, err := client.Service(vectorOrigin)
		if err != nil {
			return false, err
		}
		for _, options := range []agent.AuthenticationOptions{{Resource: target}, {Resource: target, GrantType: grantType}, {Resource: target, CredentialID: "credential-1"}} {
			if _, err := session.AuthenticationHeaders(context.Background(), options); !errors.Is(err, agent.ErrNoAuthenticationMethod) {
				return false, err
			}
		}
	}
	return true, nil
}

func evaluateAgentCarrierRequests(request adapterRequest) (bool, error) {
	cases := []string{"field-name"}
	if request.Vector.ID == "authorization-ambiguity" {
		var err error
		cases, err = requiredField[[]string](request.Case.Input, "cases")
		if err != nil {
			return false, err
		}
	}
	for _, name := range cases {
		calls, valid := 0, true
		client, err := vectorResourceClient([]aep.AuthenticationMethod{aep.AuthenticationMethodJWT}, "", nil, func(incoming *http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				valid = valid && incoming.Header.Get("Authorization") == "" && incoming.Header.Get(aep.AuthorizationHeader) == ""
				return vectorResponse(incoming, 401, http.Header{"WWW-Authenticate": {`AEP service_did="` + vectorDID + `",inspect="` + vectorOrigin + aep.WellKnownPath + `"`}}, ""), nil
			}
			valid = valid && len(incoming.Header.Values(aep.AuthorizationHeader)) == 1 && incoming.Header.Get(aep.AuthorizationHeader) == "AEP client-assertion" && incoming.Header.Get("Authorization") == ""
			return vectorResponse(incoming, 200, make(http.Header), "ok"), nil
		})
		if err != nil {
			return false, err
		}
		incoming, _ := http.NewRequest("GET", vectorOrigin+"/resource", nil)
		switch name {
		case "both-aep-recognized":
			incoming.Header.Set("Authorization", "Bearer stale")
			incoming.Header.Set(aep.AuthorizationHeader, "AEP stale")
		case "invalid-dedicated-plus-valid-standard":
			incoming.Header.Set("Authorization", "Bearer stale")
			incoming.Header.Set(aep.AuthorizationHeader, "invalid")
		case "duplicate-dedicated-lines":
			incoming.Header.Add(aep.AuthorizationHeader, "AEP first")
			incoming.Header.Add(aep.AuthorizationHeader, "AEP second")
		case "combined-dedicated-values":
			incoming.Header.Set(aep.AuthorizationHeader, "AEP first, Bearer second")
		case "field-name":
			field, err := requiredField[string](request.Case.Input, "field_name")
			if err != nil {
				return false, err
			}
			incoming.Header[field] = []string{"AEP stale"}
		default:
			return false, errors.New("unknown carrier safety case")
		}
		response, err := client.FetchProtectedResource(context.Background(), incoming, agent.ProtectedResourceOptions{Authentication: agent.AuthenticationOptions{Carrier: aep.ProtectedResourceDedicated}})
		if err != nil {
			return false, err
		}
		response.Body.Close()
		if !valid || calls != 2 || response.StatusCode != 200 {
			return false, nil
		}
	}
	if request.Vector.ID == "authorization-field-safety" {
		source, _ := url.Parse(vectorOrigin + "/source")
		same, _ := url.Parse(vectorOrigin + "/next")
		cross, _ := url.Parse("https://other.example/resource")
		return evaluateAgentRedirectRequests(source, same, cross, aep.ProtectedResourceDedicated)
	}
	return true, nil
}
