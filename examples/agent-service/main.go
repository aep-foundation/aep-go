package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	aep "github.com/aep-foundation/aep-go"
	"github.com/aep-foundation/aep-go/agent"
	"github.com/aep-foundation/aep-go/service"
)

func main() {
	if err := run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	mux := http.NewServeMux()
	server := httptest.NewUnstartedServer(mux)
	server.Start()
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		return err
	}
	host := strings.ReplaceAll(serverURL.Host, ":", "%3A")
	serviceDID := "did:web:" + host + ":services:store"
	agentDID := "did:web:" + host + ":agents:buyer"

	identity, didDocument, err := newAgentIdentity(agentDID)
	if err != nil {
		return err
	}
	mux.HandleFunc("/agents/buyer/did.json", jsonHandler(didDocument, "application/did+json"))

	credentialStore := service.NewMemoryServiceCredentialStore()
	apiKey, err := service.StoredAPIKeyGrantType(service.StoredCredentialGrantTypeOptions[aep.APIKeyGrantResponse]{
		Config: aep.GrantTypeConfig{Additional: aep.AdditionalMembers{
			"header_names": json.RawMessage(`["X-Agent-Key"]`),
		}},
		Issue: func(_ context.Context, request aep.GrantRequest, grant service.GrantContext) (aep.APIKeyGrantResponse, error) {
			return aep.APIKeyGrantResponse{
				APIKey:       "example-secret",
				CredentialID: "credential-1",
				ExpiresAt:    grant.Now.Add(time.Hour).UTC().Format(time.RFC3339),
				Header:       "X-Agent-Key",
				Scopes:       append([]string(nil), request.RequestedScopes...),
			}, nil
		},
		Store: credentialStore,
	})
	if err != nil {
		return err
	}

	inspectURL, err := url.Parse(server.URL + aep.WellKnownPath)
	if err != nil {
		return err
	}
	serviceCore, err := service.New(service.Options{
		AuthenticationMethods: []aep.AuthenticationMethod{aep.AuthenticationMethod(aep.GrantTypeAPIKey)},
		Claims: &aep.InspectClaims{
			Required:  []aep.ClaimName{aep.ClaimContactEmail},
			Preferred: []aep.ClaimName{aep.ClaimPersonFirstName},
		},
		ClientAssertion: service.ClientAssertionOptions{AllowInsecureLoopback: true},
		EndpointBase:    "/aep/",
		GrantTypes:      []service.GrantTypeDefinition{apiKey},
		IdentityMethods: []aep.IdentityMethod{aep.IdentityMethodDIDWeb},
		InspectURL:      inspectURL,
		ServiceDID:      serviceDID,
		Verifier: service.NewDIDWebAssertionVerifier(service.DIDWebVerifierOptions{
			HTTPClient: server.Client(),
		}),
	})
	if err != nil {
		return err
	}
	protocolHandler, err := service.NewHTTPHandler(serviceCore, service.HTTPHandlerOptions{})
	if err != nil {
		return err
	}
	mux.Handle("/.well-known/aep", protocolHandler)
	mux.Handle("/aep/", protocolHandler)

	protect, err := service.NewProtectedResourceMiddleware(serviceCore, server.URL)
	if err != nil {
		return err
	}
	mux.Handle("/account", protect(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		principal, ok := service.PrincipalFromContext(request.Context())
		if !ok {
			http.Error(response, "missing principal", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(response).Encode(map[string]string{"agent_did": principal.AgentDID})
	})))

	client, err := agent.New(agent.Options{
		HTTPClient:            server.Client(),
		IdentityProvider:      identity,
		AllowInsecureLoopback: true,
	})
	if err != nil {
		return err
	}
	session, err := client.Service(server.URL)
	if err != nil {
		return err
	}

	inspection, err := session.Inspect(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Inspected %s\n", inspection.Document.Service.DID)

	email := "buyer@example.com"
	name := "Ari"
	enrolled, err := session.Enroll(ctx, agent.EnrollOptions{Claims: &aep.ClaimValues{
		ContactEmail:    &email,
		PersonFirstName: &name,
	}})
	if err != nil {
		return err
	}
	fmt.Printf("Enrollment: %s\n", enrolled.Body.Status)

	granted, err := session.Grant(ctx, agent.GrantOptions{
		GrantType:       aep.GrantTypeAPIKey,
		RequestedScopes: []string{"account:read"},
	})
	if err != nil {
		return err
	}
	credential, ok := granted.Body.Credential.(aep.APIKeyGrantResponse)
	if !ok {
		return fmt.Errorf("Grant returned %T instead of an API-key credential", granted.Body.Credential)
	}
	fmt.Printf("Credential: %s (%s)\n", granted.Body.GrantType, credential.CredentialID)

	resource, err := url.Parse(server.URL + "/account")
	if err != nil {
		return err
	}
	headers, err := session.AuthenticationHeaders(ctx, agent.AuthenticationOptions{Resource: resource})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, resource.String(), nil)
	if err != nil {
		return err
	}
	request.Header = headers
	response, err := server.Client().Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("protected resource returned HTTP %d", response.StatusCode)
	}
	fmt.Printf("Protected resource: HTTP %d\n", response.StatusCode)

	_, err = session.Revoke(ctx, agent.RevokeOptions{
		CredentialID: credential.CredentialID,
		GrantType:    aep.GrantTypeAPIKey,
	})
	if err != nil {
		return err
	}
	fmt.Println("Credential revoked")
	if _, err := session.AuthenticationHeaders(ctx, agent.AuthenticationOptions{Resource: resource}); !errors.Is(err, agent.ErrNoAuthenticationMethod) {
		return fmt.Errorf("revoked credential remained selectable: %v", err)
	}
	fmt.Println("Revoked credential rejected")
	return nil
}

type localIdentity struct {
	did        string
	privateKey ed25519.PrivateKey
}

func newAgentIdentity(did string) (*localIdentity, map[string]any, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	keyID := did + "#key-1"
	document := map[string]any{
		"@context": []string{"https://www.w3.org/ns/did/v1"},
		"id":       did,
		"verificationMethod": []map[string]any{{
			"controller":   did,
			"id":           keyID,
			"publicKeyJwk": jose.JSONWebKey{Key: publicKey},
			"type":         "JsonWebKey2020",
		}},
		"authentication": []string{keyID},
	}
	return &localIdentity{did: did, privateKey: privateKey}, document, nil
}

func (identity *localIdentity) GetOrCreateIdentity(_ context.Context, request agent.IdentityRequest) (agent.ServiceIdentity, error) {
	return agent.ServiceIdentity{
		AgentDID:          identity.did,
		IdentityMethod:    aep.IdentityMethodDIDWeb,
		ServiceDID:        request.ServiceDID,
		SigningAlgorithms: []aep.SigningAlgorithm{aep.SigningAlgorithmEdDSA},
	}, nil
}

func (identity *localIdentity) SignerFor(context.Context, agent.ServiceIdentity) (agent.AssertionSigner, error) {
	return func(_ context.Context, claims aep.ClientAssertionClaims, _ []aep.SigningAlgorithm) (string, error) {
		return aep.SignClientAssertion(claims, aep.SignClientAssertionOptions{
			Algorithm: aep.SigningAlgorithmEdDSA,
			Key:       identity.privateKey,
			KeyID:     identity.did + "#key-1",
		})
	}, nil
}

func jsonHandler(value any, mediaType string) http.HandlerFunc {
	return func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", mediaType)
		if err := json.NewEncoder(response).Encode(value); err != nil {
			http.Error(response, err.Error(), http.StatusInternalServerError)
		}
	}
}
