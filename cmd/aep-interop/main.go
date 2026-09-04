package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-jose/go-jose/v4"

	aep "github.com/aep-foundation/aep-go"
	"github.com/aep-foundation/aep-go/agent"
	"github.com/aep-foundation/aep-go/platform"
	"github.com/aep-foundation/aep-go/service"
)

const platformAuthorization = "Bearer demo-agent"

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: aep-interop agent|server")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch os.Args[1] {
	case "agent":
		err = runAgent(ctx, os.Args[2:])
	case "server":
		err = runServer(ctx, os.Args[2:])
	default:
		err = fmt.Errorf("unknown interoperability command %q", os.Args[1])
	}
	if err != nil {
		log.Fatal(err)
	}
}

type agentResult struct {
	Agent                   string `json:"agent"`
	CredentialMode          string `json:"credential_mode"`
	Enrollment              string `json:"enrollment"`
	Platform                string `json:"platform"`
	ProtectedResourceStatus int    `json:"protected_resource_status"`
	Revoked                 bool   `json:"revoked"`
	Service                 string `json:"service"`
}

func runAgent(ctx context.Context, arguments []string) error {
	flags := flag.NewFlagSet("agent", flag.ContinueOnError)
	platformURL := flags.String("platform-url", "", "Node Platform URL")
	serviceURL := flags.String("service-url", "", "Node Service URL")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *platformURL == "" || *serviceURL == "" {
		return errors.New("agent requires platform-url and service-url")
	}
	identities, err := agent.NewPlatformIdentityProvider(agent.PlatformIdentityProviderOptions{
		AllowInsecureLoopback: true,
		Authorization:         platformAuthorization,
		PlatformURL:           *platformURL,
	})
	if err != nil {
		return err
	}
	client, err := agent.New(agent.Options{AllowInsecureLoopback: true, IdentityProvider: identities})
	if err != nil {
		return err
	}
	session, err := client.Service(*serviceURL)
	if err != nil {
		return err
	}
	inspection, err := session.Inspect(ctx)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(inspection.Document.Service.DID, "did:web:") {
		return errors.New("Node Service did not advertise a did:web Service DID")
	}
	enrolled, err := session.Enroll(ctx, agent.EnrollOptions{})
	if err != nil {
		return err
	}
	if enrolled.Body.Status != aep.AgentActive {
		return fmt.Errorf("Node Service enrollment returned %q", enrolled.Body.Status)
	}
	granted, err := session.Grant(ctx, agent.GrantOptions{
		GrantType:       aep.GrantTypeAPIKey,
		RequestedScopes: []string{"read:resource", "write:profile"},
	})
	if err != nil {
		return err
	}
	credential, ok := granted.Body.Credential.(aep.APIKeyGrantResponse)
	if !ok {
		return fmt.Errorf("Node Service Grant returned %T", granted.Body.Credential)
	}
	resource, err := url.Parse(*serviceURL + "/api/resource")
	if err != nil {
		return err
	}
	headers, err := session.AuthenticationHeaders(ctx, agent.AuthenticationOptions{
		CredentialID: credential.CredentialID,
		GrantType:    aep.GrantTypeAPIKey,
		Resource:     resource,
	})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, resource.String(), nil)
	if err != nil {
		return err
	}
	request.Header = headers
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("Node protected resource returned HTTP %d", response.StatusCode)
	}
	if _, err := session.Revoke(ctx, agent.RevokeOptions{CredentialID: credential.CredentialID, GrantType: aep.GrantTypeAPIKey}); err != nil {
		return err
	}
	if _, err := session.AuthenticationHeaders(ctx, agent.AuthenticationOptions{Resource: resource}); !errors.Is(err, agent.ErrNoAuthenticationMethod) {
		return fmt.Errorf("revoked Node credential remained selectable: %v", err)
	}
	return json.NewEncoder(os.Stdout).Encode(agentResult{
		Agent:                   "go",
		CredentialMode:          string(granted.Body.GrantType),
		Enrollment:              string(enrolled.Body.Status),
		Platform:                "node",
		ProtectedResourceStatus: response.StatusCode,
		Revoked:                 true,
		Service:                 "node",
	})
}

func runServer(ctx context.Context, arguments []string) error {
	flags := flag.NewFlagSet("server", flag.ContinueOnError)
	listen := flags.String("listen", "127.0.0.1:4320", "listen address")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	baseURL := "http://" + *listen
	encodedHost := strings.ReplaceAll(*listen, ":", "%3A")
	serviceDID := "did:web:" + encodedHost + ":services:store"
	platformServiceDID := os.Getenv("AEP_INTEROP_SERVICE_DID")
	if platformServiceDID == "" {
		platformServiceDID = serviceDID
	}
	hosted, err := newPlatform(*listen, platformServiceDID)
	if err != nil {
		return err
	}
	protocol, err := newService(baseURL, serviceDID)
	if err != nil {
		return err
	}
	serviceHandler, err := service.NewHTTPHandler(protocol, service.HTTPHandlerOptions{})
	if err != nil {
		return err
	}
	protected, err := service.NewProtectedResourceMiddleware(protocol, baseURL)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle(aep.WellKnownPath, serviceHandler)
	mux.Handle("/aep/", serviceHandler)
	mux.Handle("GET /api/resource", protected(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		writeJSON(response, http.StatusOK, "application/json", map[string]bool{"available": true})
	})))
	mux.Handle("POST /api/profile", protected(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		writeJSON(response, http.StatusOK, "application/json", map[string]bool{"updated": true})
	})))
	mux.HandleFunc("GET /.well-known/aep-platform", func(response http.ResponseWriter, _ *http.Request) {
		writePlatformResult(response, hosted.Discovery(), nil)
	})
	mux.HandleFunc("GET /platform/agent-identities", func(response http.ResponseWriter, request *http.Request) {
		result, listErr := hosted.List(request.Context(), platformListQuery(request.URL.Query()), platformRequestContext(request))
		writePlatformResult(response, result, listErr)
	})
	mux.HandleFunc("POST /platform/agent-identities", func(response http.ResponseWriter, request *http.Request) {
		var body platform.ProvisionRequest
		if !decodeJSON(response, request, &body) {
			return
		}
		result, provisionErr := hosted.Provision(request.Context(), body, platformRequestContext(request))
		writePlatformResult(response, result, provisionErr)
	})
	mux.HandleFunc("GET /platform/agent-identities/{identity}", func(response http.ResponseWriter, request *http.Request) {
		result, identityErr := hosted.GetIdentity(request.Context(), request.PathValue("identity"), platformRequestContext(request))
		writePlatformResult(response, result, identityErr)
	})
	mux.HandleFunc("PATCH /platform/agent-identities/{identity}", func(response http.ResponseWriter, request *http.Request) {
		var body platform.LifecycleRequest
		if !decodeJSON(response, request, &body) {
			return
		}
		result, lifecycleErr := hosted.UpdateIdentity(request.Context(), request.PathValue("identity"), body, platformRequestContext(request))
		writePlatformResult(response, result, lifecycleErr)
	})
	mux.HandleFunc("POST /platform/agent-identities/{identity}/sign", func(response http.ResponseWriter, request *http.Request) {
		var body platform.SignRequest
		if !decodeJSON(response, request, &body) {
			return
		}
		result, signErr := hosted.Sign(request.Context(), request.PathValue("identity"), body, platformRequestContext(request))
		writePlatformResult(response, result, signErr)
	})
	mux.HandleFunc("GET /agents/{agent}/did.json", func(response http.ResponseWriter, request *http.Request) {
		result, documentErr := hosted.GetDIDDocument(request.Context(), request.PathValue("agent"))
		writePlatformResult(response, result, documentErr)
	})
	mux.HandleFunc("GET /services/store/did.json", func(response http.ResponseWriter, _ *http.Request) {
		writeJSON(response, http.StatusOK, platform.DIDMediaType, map[string]any{"@context": []string{"https://www.w3.org/ns/did/v1"}, "id": serviceDID})
	})
	mux.HandleFunc("GET /health", func(response http.ResponseWriter, _ *http.Request) {
		writeJSON(response, http.StatusOK, "application/json", map[string]bool{"ok": true})
	})

	server := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- server.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownContext)
	case serveErr := <-serverErrors:
		if errors.Is(serveErr, http.ErrServerClosed) {
			return nil
		}
		return serveErr
	}
}

func newService(baseURL string, serviceDID string) (*service.Service, error) {
	credentials := service.NewMemoryServiceCredentialStore()
	apiKey, err := service.StoredAPIKeyGrantType(service.StoredCredentialGrantTypeOptions[aep.APIKeyGrantResponse]{
		Config: aep.GrantTypeConfig{Additional: aep.AdditionalMembers{"header_names": json.RawMessage(`["x-api-key"]`)}},
		Issue: func(_ context.Context, request aep.GrantRequest, grant service.GrantContext) (aep.APIKeyGrantResponse, error) {
			return aep.APIKeyGrantResponse{
				APIKey:       "interop-secret",
				CredentialID: "interop-credential",
				ExpiresAt:    grant.Now.Add(time.Hour).UTC().Format(time.RFC3339),
				Header:       "x-api-key",
				Scopes:       append([]string(nil), request.RequestedScopes...),
			}, nil
		},
		Store: credentials,
	})
	if err != nil {
		return nil, err
	}
	inspectURL, err := url.Parse(baseURL + aep.WellKnownPath)
	if err != nil {
		return nil, err
	}
	return service.New(service.Options{
		AuthenticationMethods: []aep.AuthenticationMethod{aep.AuthenticationMethod(aep.GrantTypeAPIKey)},
		ClientAssertion:       service.ClientAssertionOptions{AllowInsecureLoopback: true},
		EndpointBase:          "/aep/",
		GrantTypes:            []service.GrantTypeDefinition{apiKey},
		IdentityMethods:       []aep.IdentityMethod{aep.IdentityMethodDIDWeb},
		InspectURL:            inspectURL,
		ServiceDID:            serviceDID,
		Verifier:              service.NewDIDWebAssertionVerifier(service.DIDWebVerifierOptions{}),
	})
}

func newPlatform(host string, serviceDID string) (*platform.Platform, error) {
	return platform.New(platform.Options{
		Authorizer:     interopAuthorizer{},
		DIDHost:        host,
		DIDPathPrefix:  "agents",
		DIDURLTemplate: "https://" + host + "/agents/{agent_did_id}/did.json",
		Discovery: platform.DiscoveryOptions{
			EndpointBase:      "/platform/",
			LifecycleEndpoint: "/platform/agent-identities/{agent_identity_id}",
			ListEndpoint:      "/platform/agent-identities",
			PlatformDID:       "did:web:" + strings.ReplaceAll(host, ":", "%3A"),
			PlatformName:      "Go Interoperability Platform",
			ProvisionEndpoint: "/platform/agent-identities",
			SignEndpoint:      "/platform/agent-identities/{agent_identity_id}/sign",
		},
		KeyStore:           newInteropKeyStore(),
		ServiceDIDResolver: interopServiceResolver{serviceDID: serviceDID},
		SigningAlgorithms:  []aep.SigningAlgorithm{aep.SigningAlgorithmES256},
	})
}

type interopAuthorizer struct{}

func (interopAuthorizer) Authorize(_ context.Context, _ platform.AuthorizationRequest, request platform.RequestContext) (bool, error) {
	return request.Authorization == platformAuthorization && request.Principal == "interop-agent", nil
}

type interopServiceResolver struct {
	serviceDID string
}

func (resolver interopServiceResolver) ResolveServiceDID(_ context.Context, candidate string) (bool, error) {
	return candidate == resolver.serviceDID, nil
}

type interopKeyStore struct {
	keys map[string]*ecdsa.PrivateKey
	mu   sync.RWMutex
}

func newInteropKeyStore() *interopKeyStore {
	return &interopKeyStore{keys: make(map[string]*ecdsa.PrivateKey)}
}

func (store *interopKeyStore) CreateKey(_ context.Context, identity platform.IdentityRecord) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.keys[identity.AgentIdentityID] != nil {
		return errors.New("identity key already exists")
	}
	store.keys[identity.AgentIdentityID] = key
	return nil
}

func (store *interopKeyStore) DIDVerificationMethod(_ context.Context, identity platform.IdentityRecord) (platform.DIDVerificationMethod, error) {
	key, err := store.key(identity.AgentIdentityID)
	if err != nil {
		return platform.DIDVerificationMethod{}, err
	}
	encoded, err := json.Marshal(jose.JSONWebKey{Key: &key.PublicKey})
	if err != nil {
		return platform.DIDVerificationMethod{}, err
	}
	return platform.DIDVerificationMethod{Controller: identity.AgentDID, ID: identity.KeyID, PublicKeyJWK: encoded, Type: "JsonWebKey2020"}, nil
}

func (store *interopKeyStore) Sign(_ context.Context, identity platform.IdentityRecord, claims aep.ClientAssertionClaims) (string, error) {
	key, err := store.key(identity.AgentIdentityID)
	if err != nil {
		return "", err
	}
	return aep.SignClientAssertion(claims, aep.SignClientAssertionOptions{Algorithm: aep.SigningAlgorithmES256, Key: key, KeyID: identity.KeyID})
}

func (store *interopKeyStore) VerificationKey(_ context.Context, identity platform.IdentityRecord) (any, error) {
	key, err := store.key(identity.AgentIdentityID)
	if err != nil {
		return nil, err
	}
	return &key.PublicKey, nil
}

func (store *interopKeyStore) key(identityID string) (*ecdsa.PrivateKey, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	key := store.keys[identityID]
	if key == nil {
		return nil, errors.New("identity key not found")
	}
	return key, nil
}

func platformRequestContext(request *http.Request) platform.RequestContext {
	authorization := request.Header.Get("Authorization")
	principal := ""
	if authorization == platformAuthorization {
		principal = "interop-agent"
	}
	return platform.RequestContext{
		Authorization:  authorization,
		IdempotencyKey: request.Header.Get("Idempotency-Key"),
		Principal:      principal,
	}
}

func platformListQuery(values url.Values) platform.IdentityListQuery {
	limit, _ := strconv.Atoi(values.Get("limit"))
	offset, _ := strconv.Atoi(values.Get("offset"))
	return platform.IdentityListQuery{
		Descending: values.Get("descending") == "true",
		Limit:      limit,
		Offset:     offset,
		ServiceDID: values.Get("service_did"),
		Status:     platform.ManagedAgentStatus(values.Get("status")),
	}
}

func decodeJSON(response http.ResponseWriter, request *http.Request, target any) bool {
	if err := json.NewDecoder(request.Body).Decode(target); err != nil {
		http.Error(response, "invalid JSON", http.StatusBadRequest)
		return false
	}
	return true
}

func writePlatformResult[T any](response http.ResponseWriter, result platform.Result[T], err error) {
	if err != nil {
		http.Error(response, "internal error", http.StatusInternalServerError)
		return
	}
	for name, values := range result.Headers {
		for _, value := range values {
			response.Header().Add(name, value)
		}
	}
	if result.Problem != nil {
		writeJSON(response, result.Status, aep.ProblemMediaType, result.Problem)
		return
	}
	writeJSON(response, result.Status, result.ContentType, result.Body)
}

func writeJSON(response http.ResponseWriter, status int, contentType string, value any) {
	response.Header().Set("Content-Type", contentType)
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
