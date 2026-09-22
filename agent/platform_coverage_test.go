package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	aep "github.com/aep-foundation/aep-go"
	"github.com/aep-foundation/aep-go/platform"
)

func TestPlatformProvisionFailuresDoNotReturnIdentity(t *testing.T) {
	for _, mode := range []string{"key failure", "headers failure", "HTTP failure", "wrong service", "inactive", "invalid identity", "invalid JSON", "trailing JSON", "invalid list"} {
		t.Run(mode, func(t *testing.T) {
			var provisions atomic.Int32
			failure := errors.New("dependency unavailable")
			stub := newPlatformStub(t, func(options *PlatformIdentityProviderOptions) {
				if mode == "key failure" {
					options.IdempotencyKey = func() (string, error) { return "", failure }
				}
				if mode == "headers failure" {
					options.AuthenticationHeaders = func(context.Context) (http.Header, error) { return nil, failure }
				}
			}, func(server *httptest.Server, w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != "/v1/aep/agent-identities" {
					return false
				}
				if r.Method == http.MethodGet {
					count := "0"
					if mode == "invalid list" {
						count = "1"
					}
					writePlatformJSON(t, w, platform.AgentIdentityListResponse{Count: count, Total: count, Data: []platform.AgentIdentity{}})
					return true
				}
				provisions.Add(1)
				if mode == "HTTP failure" {
					w.WriteHeader(503)
					return true
				}
				w.Header().Set("Content-Type", aep.MediaType)
				if mode == "invalid JSON" {
					_, _ = w.Write([]byte(`{`))
					return true
				}
				identity := platformIdentity(server.URL)
				switch mode {
				case "wrong service":
					identity.ServiceDID = "did:web:other.example"
				case "inactive":
					identity.Status = platform.ManagedAgentSuspended
				case "invalid identity":
					identity.KeyID = "wrong"
				}
				writePlatformJSON(t, w, identity)
				if mode == "trailing JSON" {
					_, _ = w.Write([]byte(`{}`))
				}
				return true
			})
			identity, err := stub.provider.GetOrCreateIdentity(context.Background(), IdentityRequest{ServiceDID: "did:web:service.example"})
			if err == nil || identity.AgentDID != "" {
				t.Fatalf("returned identity on failure: %#v %v", identity, err)
			}
			if mode == "key failure" || mode == "headers failure" || mode == "invalid list" {
				if provisions.Load() != 0 {
					t.Fatal("provisioned after prerequisite failure")
				}
			} else if provisions.Load() != 1 {
				t.Fatalf("expected one provision, got %d", provisions.Load())
			}
		})
	}
}

func TestPlatformSignerRejectsInvalidContextBeforeSending(t *testing.T) {
	for _, mode := range []string{"invalid identity", "wrong audience", "wrong subject", "wrong issuer", "algorithm mismatch", "context failure", "key failure", "invalid context JSON"} {
		t.Run(mode, func(t *testing.T) {
			var commands atomic.Int32
			stub := newPlatformStub(t, func(options *PlatformIdentityProviderOptions) {
				if mode == "context failure" {
					options.PlatformContext = func(context.Context, ServiceIdentity, aep.ClientAssertionClaims) (map[string]json.RawMessage, error) {
						return nil, errors.New("context unavailable")
					}
				}
				if mode == "invalid context JSON" {
					options.PlatformContext = func(context.Context, ServiceIdentity, aep.ClientAssertionClaims) (map[string]json.RawMessage, error) {
						return map[string]json.RawMessage{"value": json.RawMessage(`{`)}, nil
					}
				}
				if mode == "key failure" {
					options.IdempotencyKey = func() (string, error) { return "", errors.New("key unavailable") }
				}
			}, func(_ *httptest.Server, w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path == platform.WellKnownPath {
					return false
				}
				commands.Add(1)
				w.WriteHeader(500)
				return true
			})
			identity, err := stub.provider.serviceIdentity(platformIdentity(stub.server.URL))
			if err != nil {
				t.Fatal(err)
			}
			if mode == "invalid identity" {
				identity.Metadata["platform_url"] = "https://other.example"
			}
			signer, err := stub.provider.SignerFor(context.Background(), identity)
			if mode == "invalid identity" {
				if err == nil || signer != nil {
					t.Fatal("accepted foreign identity")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			claims := assertionClaims(identity)
			algorithms := identity.SigningAlgorithms
			switch mode {
			case "wrong audience":
				claims.Audience = "did:web:other.example"
			case "wrong subject":
				claims.Subject = "did:web:other.example"
			case "wrong issuer":
				claims.Issuer = "did:web:other.example"
			case "algorithm mismatch":
				algorithms = []aep.SigningAlgorithm{aep.SigningAlgorithmEdDSA}
			}
			token, err := signer(context.Background(), claims, algorithms)
			if err == nil || token != "" || commands.Load() != 0 {
				t.Fatalf("invalid signing inputs escaped: token=%q commands=%d error=%v", token, commands.Load(), err)
			}
		})
	}
}

func TestPlatformPendingSignRequiresNewIdempotencyKey(t *testing.T) {
	var signs atomic.Int32
	stub := newPlatformStub(t, func(options *PlatformIdentityProviderOptions) {
		options.PendingSignResolver = func(context.Context, PlatformPendingSign) (map[string]json.RawMessage, error) { return nil, nil }
	}, func(_ *httptest.Server, w http.ResponseWriter, r *http.Request) bool {
		if !strings.HasSuffix(r.URL.Path, "/sign") {
			return false
		}
		signs.Add(1)
		w.Header().Set("Content-Type", aep.MediaType)
		w.WriteHeader(http.StatusAccepted)
		writePlatformJSON(t, w, platform.SignResponse{Status: platform.SignPending, RetryAfterSeconds: "1"})
		return true
	})
	identity, err := stub.provider.serviceIdentity(platformIdentity(stub.server.URL))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := stub.provider.SignerFor(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	token, err := signer(context.Background(), assertionClaims(identity), identity.SigningAlgorithms)
	if err == nil || !strings.Contains(err.Error(), "distinct idempotency keys") || token != "" || signs.Load() != 1 {
		t.Fatalf("reused pending key: token=%q calls=%d error=%v", token, signs.Load(), err)
	}
}

func TestPlatformSignDiscoveryAndResponseReadFailures(t *testing.T) {
	for _, mode := range []string{"discovery", "read"} {
		t.Run(mode, func(t *testing.T) {
			stub := newPlatformStub(t, nil, nil)
			identity, err := stub.provider.serviceIdentity(platformIdentity(stub.server.URL))
			if err != nil {
				t.Fatal(err)
			}
			failure := errors.New("interrupted Platform request")
			body := &interruptedResponseBody{failure: failure}
			stub.provider.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == platform.WellKnownPath {
					if mode == "discovery" {
						return nil, failure
					}
					recorder := httptest.NewRecorder()
					writePlatformJSON(t, recorder, platformDiscovery(stub.server.URL))
					return recorder.Result(), nil
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {aep.MediaType}}, Body: body}, nil
			})}
			signer, err := stub.provider.SignerFor(context.Background(), identity)
			if err != nil {
				t.Fatal(err)
			}
			token, err := signer(context.Background(), assertionClaims(identity), identity.SigningAlgorithms)
			if !errors.Is(err, failure) || token != "" || (mode == "read" && !body.closed) {
				t.Fatalf("lost failure or leaked body: token=%q error=%v closed=%v", token, err, body.closed)
			}
		})
	}
}

func TestPlatformInvalidListedIdentityDoesNotTriggerProvision(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*platform.AgentIdentity)
	}{
		{"missing identifier", func(identity *platform.AgentIdentity) { identity.AgentIdentityID = "" }},
		{"wrong key", func(identity *platform.AgentIdentity) { identity.KeyID = "did:web:other.example" }},
		{"unsupported algorithm", func(identity *platform.AgentIdentity) { identity.SigningAlgorithms = []aep.SigningAlgorithm{"RS256"} }},
		{"invalid creation time", func(identity *platform.AgentIdentity) { identity.CreatedAt = "yesterday" }},
		{"invalid update time", func(identity *platform.AgentIdentity) { identity.UpdatedAt = "tomorrow" }},
		{"invalid document URL", func(identity *platform.AgentIdentity) { identity.DIDDocumentURL = "file:///tmp/did.json" }},
		{"wrong document origin", func(identity *platform.AgentIdentity) {
			identity.DIDDocumentURL = "https://other.example/.well-known/did.json"
		}},
		{"invalid DID encoding", func(identity *platform.AgentIdentity) {
			identity.AgentDID = "did:web:%ZZ"
			identity.KeyID = identity.AgentDID
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var lists, provisions atomic.Int32
			stub := newPlatformStub(t, nil, func(server *httptest.Server, w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != "/v1/aep/agent-identities" {
					return false
				}
				if r.Method == http.MethodPost {
					provisions.Add(1)
					w.WriteHeader(500)
					return true
				}
				lists.Add(1)
				identity := platformIdentity(server.URL)
				test.mutate(&identity)
				writePlatformJSON(t, w, platform.AgentIdentityListResponse{Count: "1", Total: "1", Data: []platform.AgentIdentity{identity}})
				return true
			})
			if _, err := stub.provider.GetOrCreateIdentity(context.Background(), IdentityRequest{ServiceDID: "did:web:service.example"}); err == nil {
				t.Fatal("invalid identity accepted")
			}
			if lists.Load() != 1 || provisions.Load() != 0 {
				t.Fatalf("lists=%d provisions=%d", lists.Load(), provisions.Load())
			}
		})
	}
}

// platformStub answers Platform discovery plus whatever the supplied handler covers.
type platformStub struct {
	provider *PlatformIdentityProvider
	server   *httptest.Server
}

func newPlatformStub(
	t *testing.T,
	options func(*PlatformIdentityProviderOptions),
	handler func(*httptest.Server, http.ResponseWriter, *http.Request) bool,
) *platformStub {
	t.Helper()
	stub := &platformStub{}
	stub.server = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if handler != nil && handler(stub.server, response, request) {
			return
		}
		if request.URL.Path == platform.WellKnownPath {
			writePlatformJSON(t, response, platformDiscovery(stub.server.URL))
			return
		}
		http.NotFound(response, request)
	}))
	t.Cleanup(stub.server.Close)

	providerOptions := PlatformIdentityProviderOptions{
		HTTPClient:     stub.server.Client(),
		IdempotencyKey: func() (string, error) { return "idempotency-1", nil },
		PlatformURL:    stub.server.URL,
	}
	if options != nil {
		options(&providerOptions)
	}
	provider, err := NewPlatformIdentityProvider(providerOptions)
	if err != nil {
		t.Fatal(err)
	}
	stub.provider = provider
	return stub
}

func TestNewPlatformIdentityProviderRejectsUnusableOptions(t *testing.T) {
	cases := map[string]PlatformIdentityProviderOptions{
		"missing URL":      {},
		"plaintext URL":    {PlatformURL: "http://platform.example"},
		"userinfo URL":     {PlatformURL: "https://user@platform.example"},
		"unparseable URL":  {PlatformURL: "://nonsense"},
		"negative timeout": {PlatformURL: "https://platform.example", RequestTimeout: -time.Second},
		"negative bytes":   {PlatformURL: "https://platform.example", MaximumResponseBytes: -1},
	}
	for name, options := range cases {
		if _, err := NewPlatformIdentityProvider(options); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	if _, err := NewPlatformIdentityProvider(PlatformIdentityProviderOptions{
		PlatformURL: "https://platform.example",
	}); err != nil {
		t.Fatalf("a usable configuration was refused: %v", err)
	}
	if _, err := NewPlatformIdentityProvider(PlatformIdentityProviderOptions{
		AllowInsecureLoopback: true, PlatformURL: "http://127.0.0.1:9443",
	}); err != nil {
		t.Fatalf("permitted loopback was refused: %v", err)
	}
}

func TestPlatformIdempotencyKeyIsValidated(t *testing.T) {
	for _, key := range []string{"", "   ", " key", "key\n"} {
		stub := newPlatformStub(t, func(options *PlatformIdentityProviderOptions) {
			options.IdempotencyKey = func() (string, error) { return key, nil }
		}, func(server *httptest.Server, response http.ResponseWriter, request *http.Request) bool {
			if request.URL.Path == "/v1/aep/agent-identities" && request.Method == http.MethodGet {
				writePlatformJSON(t, response, platform.AgentIdentityListResponse{
					Count: "0", Data: []platform.AgentIdentity{}, Total: "0",
				})
				return true
			}
			return false
		})
		if _, err := stub.provider.GetOrCreateIdentity(context.Background(), IdentityRequest{
			ServiceDID: "did:web:service.example",
		}); err == nil {
			t.Fatalf("a provider key of %q was accepted", key)
		}
	}
}

func TestPlatformIdempotencyKeyFailurePropagates(t *testing.T) {
	stub := newPlatformStub(t, func(options *PlatformIdentityProviderOptions) {
		options.IdempotencyKey = func() (string, error) { return "", errors.New("no entropy") }
	}, func(server *httptest.Server, response http.ResponseWriter, request *http.Request) bool {
		if request.URL.Path == "/v1/aep/agent-identities" && request.Method == http.MethodGet {
			writePlatformJSON(t, response, platform.AgentIdentityListResponse{
				Count: "0", Data: []platform.AgentIdentity{}, Total: "0",
			})
			return true
		}
		return false
	})
	if _, err := stub.provider.GetOrCreateIdentity(context.Background(), IdentityRequest{
		ServiceDID: "did:web:service.example",
	}); err == nil {
		t.Fatal("a failing key generator was ignored")
	}
}

func TestPlatformSignRejectsInvalidResponses(t *testing.T) {
	identityFor := func(server *httptest.Server) ServiceIdentity {
		return ServiceIdentity{
			AgentDID:       "did:web:" + encodedTestHost(server.URL) + ":agents:one",
			IdentityMethod: aep.IdentityMethodDIDWeb,
			Metadata: map[string]string{
				"agent_identity_id": "identity-1",
				"platform_url":      server.URL + "/",
				"status":            string(platform.ManagedAgentActive),
			},
			ServiceDID:        "did:web:service.example",
			SigningAlgorithms: []aep.SigningAlgorithm{aep.SigningAlgorithmES256},
		}
	}

	cases := map[string]func(*httptest.Server, http.ResponseWriter, *platform.SignRequest){
		"lifetime disagrees with the request": func(server *httptest.Server, response http.ResponseWriter, body *platform.SignRequest) {
			writePlatformJSON(t, response, platform.SignResponse{
				AgentDID: identityFor(server).AgentDID, ClientAssertion: "signed",
				ExpiresAt: time.Unix(1500, 0).UTC().Format(time.RFC3339),
				IssuedAt:  time.Unix(1000, 0).UTC().Format(time.RFC3339),
				JWTID:     body.JWTID, ServiceDID: body.ServiceDID, Status: platform.SignCompleted,
			})
		},
		"another Agent DID": func(server *httptest.Server, response http.ResponseWriter, body *platform.SignRequest) {
			writePlatformJSON(t, response, platform.SignResponse{
				AgentDID: "did:web:someone.else", ClientAssertion: "signed",
				ExpiresAt: time.Unix(1300, 0).UTC().Format(time.RFC3339),
				IssuedAt:  time.Unix(1000, 0).UTC().Format(time.RFC3339),
				JWTID:     body.JWTID, ServiceDID: body.ServiceDID, Status: platform.SignCompleted,
			})
		},
		"another jti": func(server *httptest.Server, response http.ResponseWriter, body *platform.SignRequest) {
			writePlatformJSON(t, response, platform.SignResponse{
				AgentDID: identityFor(server).AgentDID, ClientAssertion: "signed",
				ExpiresAt: time.Unix(1300, 0).UTC().Format(time.RFC3339),
				IssuedAt:  time.Unix(1000, 0).UTC().Format(time.RFC3339),
				JWTID:     "other-jti", ServiceDID: body.ServiceDID, Status: platform.SignCompleted,
			})
		},
		"empty assertion": func(server *httptest.Server, response http.ResponseWriter, body *platform.SignRequest) {
			writePlatformJSON(t, response, platform.SignResponse{
				AgentDID:  identityFor(server).AgentDID,
				ExpiresAt: time.Unix(1300, 0).UTC().Format(time.RFC3339),
				IssuedAt:  time.Unix(1000, 0).UTC().Format(time.RFC3339),
				JWTID:     body.JWTID, ServiceDID: body.ServiceDID, Status: platform.SignCompleted,
			})
		},
		"unparseable timestamps": func(server *httptest.Server, response http.ResponseWriter, body *platform.SignRequest) {
			writePlatformJSON(t, response, platform.SignResponse{
				AgentDID: identityFor(server).AgentDID, ClientAssertion: "signed",
				ExpiresAt: "soon", IssuedAt: "now",
				JWTID: body.JWTID, ServiceDID: body.ServiceDID, Status: platform.SignCompleted,
			})
		},
		"unregistered status": func(server *httptest.Server, response http.ResponseWriter, body *platform.SignRequest) {
			writePlatformJSON(t, response, platform.SignResponse{
				JWTID: body.JWTID, ServiceDID: body.ServiceDID, Status: "made-up",
			})
		},
		"pending without Accepted": func(server *httptest.Server, response http.ResponseWriter, body *platform.SignRequest) {
			writePlatformJSON(t, response, platform.SignResponse{
				RetryAfterSeconds: "5", Status: platform.SignPending,
			})
		},
	}

	for name, respond := range cases {
		stub := newPlatformStub(t, nil, func(server *httptest.Server, response http.ResponseWriter, request *http.Request) bool {
			if !strings.HasSuffix(request.URL.Path, "/sign") {
				return false
			}
			var body platform.SignRequest
			_ = json.NewDecoder(request.Body).Decode(&body)
			respond(server, response, &body)
			return true
		})
		identity := identityFor(stub.server)
		signer, err := stub.provider.SignerFor(context.Background(), identity)
		if err != nil {
			t.Fatalf("%s: signer unavailable: %v", name, err)
		}
		if _, err := signer(context.Background(), assertionClaims(identity), identity.SigningAlgorithms); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

func TestPlatformPendingSignStopsOnResolverFailure(t *testing.T) {
	denied := errors.New("approval denied")
	for _, mode := range []string{"denied", "cancelled", "cancelled without resolver error"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var signs, resolutions, keys atomic.Int32
			stub := newPlatformStub(t, func(options *PlatformIdentityProviderOptions) {
				options.IdempotencyKey = func() (string, error) {
					if keys.Add(1) == 1 {
						return "initial", nil
					}
					return "continuation", nil
				}
				options.PendingSignResolver = func(resolverContext context.Context, pending PlatformPendingSign) (map[string]json.RawMessage, error) {
					resolutions.Add(1)
					if resolverContext != ctx || string(pending.PlatformContext["handle"]) != `"approval-1"` {
						t.Fatal("resolver did not receive the caller context and approval handle")
					}
					if mode == "denied" {
						return nil, denied
					}
					cancel()
					if mode == "cancelled" {
						return nil, resolverContext.Err()
					}
					return pending.PlatformContext, nil
				}
			}, func(_ *httptest.Server, response http.ResponseWriter, request *http.Request) bool {
				if !strings.HasSuffix(request.URL.Path, "/sign") {
					return false
				}
				signs.Add(1)
				response.Header().Set("Content-Type", aep.MediaType)
				response.WriteHeader(http.StatusAccepted)
				writePlatformJSON(t, response, platform.SignResponse{
					PlatformContext:   map[string]json.RawMessage{"handle": json.RawMessage(`"approval-1"`)},
					RetryAfterSeconds: "1", Status: platform.SignPending,
				})
				return true
			})
			identity, err := stub.provider.serviceIdentity(platformIdentity(stub.server.URL))
			if err != nil {
				t.Fatal(err)
			}
			signer, err := stub.provider.SignerFor(ctx, identity)
			if err != nil {
				t.Fatal(err)
			}
			assertion, err := signer(ctx, assertionClaims(identity), identity.SigningAlgorithms)
			want := error(context.Canceled)
			if mode == "denied" {
				want = denied
			}
			if !errors.Is(err, want) || assertion != "" || signs.Load() != 1 || resolutions.Load() != 1 {
				t.Fatalf("assertion=%q error=%v signs=%d resolutions=%d", assertion, err, signs.Load(), resolutions.Load())
			}
		})
	}
}

func TestPlatformSignRejectsRetryAfterHeader(t *testing.T) {
	// PLT-SIGN-017: the pending contract carries retry_after_seconds in the body, never a header.
	stub := newPlatformStub(t, nil, func(server *httptest.Server, response http.ResponseWriter, request *http.Request) bool {
		if !strings.HasSuffix(request.URL.Path, "/sign") {
			return false
		}
		response.Header().Set("Retry-After", "5")
		response.Header().Set("Content-Type", aep.MediaType)
		response.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(response).Encode(platform.SignResponse{
			RetryAfterSeconds: "5", Status: platform.SignPending,
		})
		return true
	})
	identity := ServiceIdentity{
		AgentDID:       "did:web:" + encodedTestHost(stub.server.URL) + ":agents:one",
		IdentityMethod: aep.IdentityMethodDIDWeb,
		Metadata: map[string]string{
			"agent_identity_id": "identity-1",
			"platform_url":      stub.server.URL + "/",
			"status":            string(platform.ManagedAgentActive),
		},
		ServiceDID:        "did:web:service.example",
		SigningAlgorithms: []aep.SigningAlgorithm{aep.SigningAlgorithmES256},
	}
	signer, err := stub.provider.SignerFor(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer(context.Background(), assertionClaims(identity), identity.SigningAlgorithms); err == nil {
		t.Fatal("a Retry-After header was tolerated on the pending contract")
	}
}

func TestPlatformSignRejectsOutOfRangeRetryAfterSeconds(t *testing.T) {
	for _, seconds := range []string{"0", "301", "abc", ""} {
		stub := newPlatformStub(t, nil, func(server *httptest.Server, response http.ResponseWriter, request *http.Request) bool {
			if !strings.HasSuffix(request.URL.Path, "/sign") {
				return false
			}
			response.Header().Set("Content-Type", aep.MediaType)
			response.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(response).Encode(platform.SignResponse{
				RetryAfterSeconds: seconds, Status: platform.SignPending,
			})
			return true
		})
		identity := ServiceIdentity{
			AgentDID:       "did:web:" + encodedTestHost(stub.server.URL) + ":agents:one",
			IdentityMethod: aep.IdentityMethodDIDWeb,
			Metadata: map[string]string{
				"agent_identity_id": "identity-1",
				"platform_url":      stub.server.URL + "/",
				"status":            string(platform.ManagedAgentActive),
			},
			ServiceDID:        "did:web:service.example",
			SigningAlgorithms: []aep.SigningAlgorithm{aep.SigningAlgorithmES256},
		}
		signer, err := stub.provider.SignerFor(context.Background(), identity)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := signer(context.Background(), assertionClaims(identity), identity.SigningAlgorithms); err == nil {
			t.Fatalf("retry_after_seconds %q was accepted", seconds)
		}
	}
}

func TestPlatformCommandRejectsUnusableResponses(t *testing.T) {
	cases := map[string]func(http.ResponseWriter){
		"wrong media type": func(response http.ResponseWriter) {
			response.Header().Set("Content-Type", "text/plain")
			_, _ = response.Write([]byte("{}"))
		},
		"invalid JSON": func(response http.ResponseWriter) {
			response.Header().Set("Content-Type", aep.MediaType)
			_, _ = response.Write([]byte("{"))
		},
		"server error": func(response http.ResponseWriter) {
			response.Header().Set("Content-Type", aep.ProblemMediaType)
			response.WriteHeader(http.StatusInternalServerError)
			_, _ = response.Write([]byte(`{"code":"invalid_request","status":500,"title":"t","type":"urn:aep:error:invalid_request"}`))
		},
	}
	for name, respond := range cases {
		stub := newPlatformStub(t, nil, func(server *httptest.Server, response http.ResponseWriter, request *http.Request) bool {
			if request.URL.Path != "/v1/aep/agent-identities" {
				return false
			}
			respond(response)
			return true
		})
		if _, err := stub.provider.FindIdentityByServiceDID(context.Background(), "did:web:service.example"); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

func TestPlatformDiscoveryCacheLifecycle(t *testing.T) {
	var seconds atomic.Int64
	var redirects, documents, lists, authenticationCalls atomic.Int32
	const modified = "Mon, 31 Aug 2026 12:00:00 GMT"
	stub := newPlatformStub(t, func(options *PlatformIdentityProviderOptions) {
		options.Clock = func() time.Time { return time.Unix(seconds.Load(), 0) }
		options.Authorization = "Bearer platform-secret"
		options.AuthenticationHeaders = func(context.Context) (http.Header, error) {
			authenticationCalls.Add(1)
			return http.Header{"X-Platform-Key": {"secret"}}, nil
		}
	}, func(server *httptest.Server, w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/v1/aep/agent-identities" {
			lists.Add(1)
			if r.Header.Get("Authorization") != "Bearer platform-secret" || r.Header.Get("X-Platform-Key") != "secret" {
				t.Error("identity request omitted Platform authentication")
			}
			writePlatformJSON(t, w, platform.AgentIdentityListResponse{Count: "0", Total: "0", Data: []platform.AgentIdentity{}})
			return true
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-Platform-Key") != "" {
			t.Error("Platform credentials reached anonymous discovery")
		}
		if r.URL.Path == platform.WellKnownPath {
			redirects.Add(1)
			http.Redirect(w, r, "/discovery", http.StatusFound)
			return true
		}
		if r.URL.Path != "/discovery" {
			return false
		}
		switch documents.Add(1) {
		case 1, 4:
			if r.Header.Get("If-None-Match") != "" || r.Header.Get("If-Modified-Since") != "" {
				t.Error("uncached discovery sent validators")
			}
			w.Header().Set("Cache-Control", "max-age=10")
			w.Header().Set("ETag", `"one"`)
			w.Header().Set("Last-Modified", modified)
			writePlatformJSON(t, w, platformDiscovery(server.URL))
		case 2:
			if r.Header.Get("If-None-Match") != `"one"` || r.Header.Get("If-Modified-Since") != modified {
				t.Error("conditional discovery omitted validators")
			}
			w.Header().Set("Cache-Control", "max-age=20")
			w.Header().Set("ETag", `"two"`)
			w.Header().Set("Last-Modified", modified)
			w.WriteHeader(http.StatusNotModified)
		case 3:
			if r.Header.Get("If-None-Match") != `"two"` || r.Header.Get("If-Modified-Since") != modified {
				t.Error("304 validators were not retained")
			}
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusNotModified)
		default:
			t.Error("unexpected discovery request")
			w.WriteHeader(http.StatusInternalServerError)
		}
		return true
	})
	for _, step := range []struct {
		time    int64
		fetches int32
	}{{0, 1}, {9, 1}, {10, 2}, {29, 2}, {30, 3}, {30, 4}} {
		seconds.Store(step.time)
		if _, err := stub.provider.FindIdentityByServiceDID(context.Background(), "did:web:service.example"); err != nil {
			t.Fatal(err)
		}
		if documents.Load() != step.fetches {
			t.Fatalf("time=%d discovery requests=%d want=%d", step.time, documents.Load(), step.fetches)
		}
	}
	if redirects.Load() != 2 || lists.Load() != 6 || authenticationCalls.Load() != 6 {
		t.Fatalf("redirects=%d lists=%d authentication calls=%d", redirects.Load(), lists.Load(), authenticationCalls.Load())
	}
}

func TestPlatformDiscoveryFailureDoesNotReachIdentityEndpoints(t *testing.T) {
	for _, failure := range []string{"unexpected 304", "server error", "wrong media type", "oversized", "redirect loop", "cancelled"} {
		t.Run(failure, func(t *testing.T) {
			var requests, commands atomic.Int32
			stub := newPlatformStub(t, func(options *PlatformIdentityProviderOptions) {
				if failure == "oversized" {
					options.MaximumResponseBytes = 16
				}
			}, func(server *httptest.Server, w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != platform.WellKnownPath {
					commands.Add(1)
					w.WriteHeader(http.StatusInternalServerError)
					return true
				}
				requests.Add(1)
				switch failure {
				case "unexpected 304":
					w.WriteHeader(http.StatusNotModified)
				case "server error":
					w.WriteHeader(http.StatusServiceUnavailable)
				case "wrong media type":
					w.Header().Set("Content-Type", "text/plain")
					_, _ = w.Write([]byte(`{}`))
				case "redirect loop":
					http.Redirect(w, r, platform.WellKnownPath, http.StatusFound)
				default:
					writePlatformJSON(t, w, platformDiscovery(server.URL))
				}
				return true
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if failure == "cancelled" {
				cancel()
			}
			for range 2 {
				if _, err := stub.provider.GetOrCreateIdentity(ctx, IdentityRequest{ServiceDID: "did:web:service.example"}); err == nil {
					t.Fatal("discovery failure was accepted")
				} else if failure == "cancelled" && !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation was lost: %v", err)
				}
			}
			wantRequests := int32(2)
			if failure == "redirect loop" {
				wantRequests = 12
			} else if failure == "cancelled" {
				wantRequests = 0
			}
			if commands.Load() != 0 || requests.Load() != wantRequests {
				t.Fatalf("commands=%d discovery requests=%d want=%d", commands.Load(), requests.Load(), wantRequests)
			}
		})
	}
}

func TestPlatformDiscoveryRejectsUnusableDocuments(t *testing.T) {
	cases := map[string]func(*httptest.Server, http.ResponseWriter){
		"off-origin sign endpoint": func(server *httptest.Server, response http.ResponseWriter) {
			document := platformDiscovery(server.URL)
			document.Endpoints.Sign = "//evil.example/sign"
			writePlatformJSON(t, response, document)
		},
		"unresolved placeholder": func(server *httptest.Server, response http.ResponseWriter) {
			document := platformDiscovery(server.URL)
			document.Endpoints.Sign = "/v1/aep/{unknown}/sign"
			writePlatformJSON(t, response, document)
		},
		"relative endpoint": func(server *httptest.Server, response http.ResponseWriter) {
			document := platformDiscovery(server.URL)
			document.Endpoints.List = "v1/aep/agent-identities"
			writePlatformJSON(t, response, document)
		},
	}
	for name, respond := range cases {
		stub := newPlatformStub(t, nil, func(server *httptest.Server, response http.ResponseWriter, request *http.Request) bool {
			if request.URL.Path != platform.WellKnownPath {
				return false
			}
			respond(server, response)
			return true
		})
		if _, err := stub.provider.FindIdentityByServiceDID(context.Background(), "did:web:service.example"); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

func TestPlatformDiscoveryRejectsInvalidCapabilitiesBeforeAuthentication(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*platform.DiscoveryDocument)
	}{
		{"major version", func(d *platform.DiscoveryDocument) { d.AEPVersion = "2.0" }},
		{"missing name", func(d *platform.DiscoveryDocument) { d.Platform.Name = "" }},
		{"invalid DID", func(d *platform.DiscoveryDocument) { d.Platform.DID = "platform.example" }},
		{"verification flag without endpoint", func(d *platform.DiscoveryDocument) { d.Platform.HostedVerification = true }},
		{"verification endpoint without flag", func(d *platform.DiscoveryDocument) { d.Endpoints.HostedVerification = "/verify" }},
		{"missing DID placeholder", func(d *platform.DiscoveryDocument) { d.Identity.DIDURLTemplate = "https://platform.example/did.json" }},
		{"plaintext DID template", func(d *platform.DiscoveryDocument) {
			d.Identity.DIDURLTemplate = "http://platform.example/{agent_did_id}/did.json"
		}},
		{"missing did:web", func(d *platform.DiscoveryDocument) { d.Identity.DIDMethods = []string{"did:key"} }},
		{"unsupported algorithm", func(d *platform.DiscoveryDocument) { d.Signing.Algorithms = []aep.SigningAlgorithm{"HS256"} }},
		{"excessive lifetime", func(d *platform.DiscoveryDocument) { d.Signing.DefaultLifetimeSeconds = "301" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var authentication, commands atomic.Int32
			stub := newPlatformStub(t, func(options *PlatformIdentityProviderOptions) {
				options.AuthenticationHeaders = func(context.Context) (http.Header, error) {
					authentication.Add(1)
					return http.Header{"Authorization": {"Bearer secret"}}, nil
				}
			}, func(server *httptest.Server, w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != platform.WellKnownPath {
					commands.Add(1)
					w.WriteHeader(http.StatusInternalServerError)
					return true
				}
				document := platformDiscovery(server.URL)
				test.mutate(&document)
				writePlatformJSON(t, w, document)
				return true
			})
			if _, err := stub.provider.GetOrCreateIdentity(context.Background(), IdentityRequest{ServiceDID: "did:web:service.example"}); err == nil {
				t.Fatal("invalid capabilities accepted")
			}
			if authentication.Load() != 0 || commands.Load() != 0 {
				t.Fatalf("authentication=%d commands=%d", authentication.Load(), commands.Load())
			}
		})
	}
}

func TestPlatformDiscoveryRejectsCrossOriginRedirect(t *testing.T) {
	stub := newPlatformStub(t, nil, func(server *httptest.Server, response http.ResponseWriter, request *http.Request) bool {
		if request.URL.Path != platform.WellKnownPath {
			return false
		}
		http.Redirect(response, request, "https://evil.example/.well-known/aep-platform", http.StatusFound)
		return true
	})
	if _, err := stub.provider.FindIdentityByServiceDID(context.Background(), "did:web:service.example"); err == nil {
		t.Fatal("a cross-origin discovery redirect was followed")
	}
}

func TestPlatformDiscoveryRejectsMissingLocation(t *testing.T) {
	stub := newPlatformStub(t, nil, func(server *httptest.Server, response http.ResponseWriter, request *http.Request) bool {
		if request.URL.Path != platform.WellKnownPath {
			return false
		}
		response.WriteHeader(http.StatusFound)
		return true
	})
	if _, err := stub.provider.FindIdentityByServiceDID(context.Background(), "did:web:service.example"); err == nil {
		t.Fatal("a redirect without Location was followed")
	}
}

func TestPlatformIdentityRejectsUnusableRecords(t *testing.T) {
	cases := map[string]func(*httptest.Server) platform.AgentIdentity{
		"foreign Service": func(server *httptest.Server) platform.AgentIdentity {
			identity := platformIdentity(server.URL)
			identity.ServiceDID = "did:web:other.example"
			return identity
		},
		"inactive": func(server *httptest.Server) platform.AgentIdentity {
			identity := platformIdentity(server.URL)
			identity.Status = platform.ManagedAgentRevoked
			return identity
		},
		"key id that is not the Agent DID": func(server *httptest.Server) platform.AgentIdentity {
			identity := platformIdentity(server.URL)
			identity.KeyID = identity.AgentDID + "#key-1"
			return identity
		},
		"no signing algorithms": func(server *httptest.Server) platform.AgentIdentity {
			identity := platformIdentity(server.URL)
			identity.SigningAlgorithms = nil
			return identity
		},
		"non-DID agent": func(server *httptest.Server) platform.AgentIdentity {
			identity := platformIdentity(server.URL)
			identity.AgentDID = "agent.example"
			return identity
		},
	}
	for name, build := range cases {
		stub := newPlatformStub(t, nil, func(server *httptest.Server, response http.ResponseWriter, request *http.Request) bool {
			if request.URL.Path != "/v1/aep/agent-identities" || request.Method != http.MethodGet {
				return false
			}
			writePlatformJSON(t, response, platform.AgentIdentityListResponse{
				Count: "1", Data: []platform.AgentIdentity{build(server)}, Total: "1",
			})
			return true
		})
		identity, err := stub.provider.FindIdentityByServiceDID(context.Background(), "did:web:service.example")
		if err == nil && identity != nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

func TestPlatformErrorTypesRender(t *testing.T) {
	problem := aep.NewProblemDetails(aep.ErrorInvalidRequest, "Invalid request", http.StatusBadRequest)
	commandErr := &PlatformCommandError{Problem: &problem, Status: http.StatusBadRequest}
	if !strings.Contains(commandErr.Error(), "Invalid request") {
		t.Fatalf("unexpected command error text: %q", commandErr.Error())
	}
	bare := &PlatformCommandError{Status: http.StatusBadGateway}
	if !strings.Contains(bare.Error(), "502") {
		t.Fatalf("unexpected bare command error text: %q", bare.Error())
	}

	pendingErr := &PlatformSignPendingError{Pending: PlatformPendingSign{RetryAfterSeconds: 5}}
	if pendingErr.Error() == "" {
		t.Fatal("the pending error rendered as empty")
	}
}
