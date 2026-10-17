package platform

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	aep "github.com/aep-foundation/aep-go"
)

var errCollaborator = errors.New("collaborator failed")

type stubIdentityStore struct {
	IdentityStore
	findOrCreate   func(string, string, func() (IdentityRecord, error)) (IdentityRecord, bool, error)
	byAgentDID     func(string) (*IdentityRecord, error)
	byAgentDIDID   func(string) (*IdentityRecord, error)
	get            func(string) (*IdentityRecord, error)
	list           func(string, IdentityListQuery) (IdentityListResult, error)
	updateIdentity func(string, ManagedAgentStatus, time.Time) (*IdentityRecord, error)
}

func (store stubIdentityStore) FindOrCreateIdentity(_ context.Context, principal string, serviceDID string, create func() (IdentityRecord, error)) (IdentityRecord, bool, error) {
	if store.findOrCreate == nil {
		record, err := create()
		return record, true, err
	}
	return store.findOrCreate(principal, serviceDID, create)
}

func (store stubIdentityStore) FindIdentityByAgentDID(_ context.Context, agentDID string) (*IdentityRecord, error) {
	if store.byAgentDID == nil {
		return nil, nil
	}
	return store.byAgentDID(agentDID)
}

func (store stubIdentityStore) FindIdentityByAgentDIDID(_ context.Context, agentDIDID string) (*IdentityRecord, error) {
	if store.byAgentDIDID == nil {
		return nil, nil
	}
	return store.byAgentDIDID(agentDIDID)
}

func (store stubIdentityStore) GetIdentity(_ context.Context, agentIdentityID string) (*IdentityRecord, error) {
	if store.get == nil {
		return nil, nil
	}
	return store.get(agentIdentityID)
}

func (store stubIdentityStore) ListIdentities(_ context.Context, principal string, query IdentityListQuery) (IdentityListResult, error) {
	if store.list == nil {
		return IdentityListResult{}, nil
	}
	return store.list(principal, query)
}

func (store stubIdentityStore) UpdateIdentity(_ context.Context, agentIdentityID string, status ManagedAgentStatus, updatedAt time.Time) (*IdentityRecord, error) {
	if store.updateIdentity == nil {
		return nil, nil
	}
	return store.updateIdentity(agentIdentityID, status, updatedAt)
}

type stubAuthorizer struct {
	authorize func(AuthorizationRequest) (bool, error)
}

func (authorizer stubAuthorizer) Authorize(_ context.Context, request AuthorizationRequest, _ RequestContext) (bool, error) {
	return authorizer.authorize(request)
}

type stubLifecyclePolicy struct {
	canSign       func() (bool, error)
	canTransition func() (bool, error)
	canVerify     func() (bool, error)
}

func (policy stubLifecyclePolicy) CanSign(context.Context, IdentityRecord, RequestContext) (bool, error) {
	if policy.canSign == nil {
		return true, nil
	}
	return policy.canSign()
}

func (policy stubLifecyclePolicy) CanTransition(context.Context, IdentityRecord, ManagedAgentStatus, RequestContext) (bool, error) {
	if policy.canTransition == nil {
		return true, nil
	}
	return policy.canTransition()
}

func (policy stubLifecyclePolicy) CanVerify(context.Context, IdentityRecord, RequestContext) (bool, error) {
	if policy.canVerify == nil {
		return true, nil
	}
	return policy.canVerify()
}

type stubKeyStore struct {
	createKey             func(IdentityRecord) error
	didVerificationMethod func(IdentityRecord) (DIDVerificationMethod, error)
	sign                  func(IdentityRecord, aep.ClientAssertionClaims) (string, error)
	verificationKey       func(IdentityRecord) (any, error)
}

func (store stubKeyStore) CreateKey(_ context.Context, identity IdentityRecord) error {
	if store.createKey == nil {
		return nil
	}
	return store.createKey(identity)
}

func (store stubKeyStore) DIDVerificationMethod(_ context.Context, identity IdentityRecord) (DIDVerificationMethod, error) {
	if store.didVerificationMethod == nil {
		return DIDVerificationMethod{}, nil
	}
	return store.didVerificationMethod(identity)
}

func (store stubKeyStore) Sign(_ context.Context, identity IdentityRecord, claims aep.ClientAssertionClaims) (string, error) {
	if store.sign == nil {
		return "assertion", nil
	}
	return store.sign(identity, claims)
}

func (store stubKeyStore) VerificationKey(_ context.Context, identity IdentityRecord) (any, error) {
	if store.verificationKey == nil {
		return nil, nil
	}
	return store.verificationKey(identity)
}

type stubServiceDIDResolver struct {
	resolve func(string) (bool, error)
}

func (resolver stubServiceDIDResolver) ResolveServiceDID(_ context.Context, serviceDID string) (bool, error) {
	return resolver.resolve(serviceDID)
}

func cancelledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestNewRejectsEveryInvalidConfiguration(t *testing.T) {
	for _, test := range []struct {
		mutate func(*Options)
		name   string
	}{
		{name: "no authorizer", mutate: func(options *Options) { options.Authorizer = nil }},
		{name: "no key store", mutate: func(options *Options) { options.KeyStore = nil }},
		{name: "no Service DID resolver", mutate: func(options *Options) { options.ServiceDIDResolver = nil }},
		{name: "no DID host", mutate: func(options *Options) { options.DIDHost = "" }},
		{name: "no DID URL template", mutate: func(options *Options) { options.DIDURLTemplate = "" }},
		{name: "DID host with a path", mutate: func(options *Options) { options.DIDHost = "platform.example.com/agents" }},
		{name: "DID host with credentials", mutate: func(options *Options) { options.DIDHost = "user@platform.example.com" }},
		{name: "DID host with a query", mutate: func(options *Options) { options.DIDHost = "platform.example.com?x=1" }},
		{name: "no signing algorithms", mutate: func(options *Options) { options.SigningAlgorithms = nil }},
		{name: "duplicate signing algorithms", mutate: func(options *Options) {
			options.SigningAlgorithms = []aep.SigningAlgorithm{aep.SigningAlgorithmES256, aep.SigningAlgorithmES256}
		}},
		{name: "unsupported signing algorithm", mutate: func(options *Options) {
			options.SigningAlgorithms = []aep.SigningAlgorithm{"HS256"}
		}},
		{name: "negative maximum lifetime", mutate: func(options *Options) { options.MaximumLifetime = -time.Second }},
		{name: "maximum lifetime beyond the protocol ceiling", mutate: func(options *Options) {
			options.MaximumLifetime = aep.MaxAssertionLifetime + time.Second
		}},
		{name: "fractional maximum lifetime", mutate: func(options *Options) { options.MaximumLifetime = 1500 * time.Millisecond }},
		{name: "negative default lifetime", mutate: func(options *Options) { options.DefaultLifetime = -time.Second }},
		{name: "default lifetime beyond the local maximum", mutate: func(options *Options) {
			options.DefaultLifetime = 60 * time.Second
			options.MaximumLifetime = 30 * time.Second
		}},
		{name: "fractional default lifetime", mutate: func(options *Options) { options.DefaultLifetime = 1500 * time.Millisecond }},
		{name: "hosted verification without a replay store", mutate: func(options *Options) {
			options.HostedVerification = true
			options.Discovery.HostedVerificationEndpoint = "/v1/aep/verifications"
			options.ReplayStore = nil
		}},
		{name: "hosted verification endpoint without support", mutate: func(options *Options) {
			options.Discovery.HostedVerificationEndpoint = "/v1/aep/verifications"
		}},
		{name: "hosted verification without an endpoint", mutate: func(options *Options) {
			options.HostedVerification = true
			options.ReplayStore = NewMemoryReplayStore()
			options.Discovery.HostedVerificationEndpoint = ""
		}},
		{name: "relative endpoint base", mutate: func(options *Options) { options.Discovery.EndpointBase = "v1/aep" }},
		{name: "absolute lifecycle endpoint", mutate: func(options *Options) {
			options.Discovery.LifecycleEndpoint = "https://platform.example.com/v1/aep/agent-identities"
		}},
		{name: "list endpoint with a query", mutate: func(options *Options) { options.Discovery.ListEndpoint = "/v1/aep/list?x=1" }},
		{name: "provision endpoint with a fragment", mutate: func(options *Options) { options.Discovery.ProvisionEndpoint = "/v1/aep/provision#x" }},
		{name: "empty sign endpoint", mutate: func(options *Options) { options.Discovery.SignEndpoint = "" }},
		{name: "no Platform name", mutate: func(options *Options) { options.Discovery.PlatformName = "" }},
		{name: "Platform DID that is not a DID", mutate: func(options *Options) { options.Discovery.PlatformDID = "platform.example.com" }},
		{name: "DID URL template without a placeholder", mutate: func(options *Options) {
			options.DIDURLTemplate = "https://platform.example.com/agents/did.json"
		}},
		{name: "DID URL template with two placeholders", mutate: func(options *Options) {
			options.DIDURLTemplate = "https://platform.example.com/{agent_did_id}/{agent_did_id}/did.json"
		}},
		{name: "plaintext DID URL template", mutate: func(options *Options) {
			options.DIDURLTemplate = "http://platform.example.com/agents/{agent_did_id}/did.json"
		}},
		{name: "DID URL template with credentials", mutate: func(options *Options) {
			options.DIDURLTemplate = "https://user:secret@platform.example.com/agents/{agent_did_id}/did.json"
		}},
		{name: "DID URL template with a fragment", mutate: func(options *Options) {
			options.DIDURLTemplate = "https://platform.example.com/agents/{agent_did_id}/did.json#key"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			options, _, _ := testOptions(t, false)
			test.mutate(&options)
			if platform, err := New(options); err == nil {
				t.Fatalf("an invalid configuration was accepted: %#v", platform.Discovery().Body)
			}
		})
	}
}

func TestNewSuppliesItsOwnCollaborators(t *testing.T) {
	options, _, _ := testOptions(t, false)
	options.AgentDIDIDGenerator = nil
	options.Clock = nil
	options.Identifier = nil
	options.IdempotencyStore = nil
	options.IdentityStore = nil
	options.LifecyclePolicy = nil
	platform, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	if platform.clock == nil || platform.identityStore == nil || platform.idempotencyStore == nil || platform.lifecyclePolicy == nil {
		t.Fatal("a default collaborator was left unset")
	}
	first, err := platform.identifier()
	if err != nil || len(first) != 32 {
		t.Fatalf("unexpected generated identifier %q: %v", first, err)
	}
	second, err := platform.agentDIDIDGenerator()
	if err != nil || second == first {
		t.Fatalf("generated identifiers repeat: %q, %v", second, err)
	}
	identity := provisionedIdentity(t, platform, testServiceDID, "default-collaborators")
	if !strings.HasPrefix(identity.AgentIdentityID, "pai_") {
		t.Fatalf("unexpected identity identifier %q", identity.AgentIdentityID)
	}
}

func TestDIDURLTemplateValidationReportsItsOwnFailures(t *testing.T) {
	if err := validateDIDURLTemplate("", "agents", "https://platform.example.com/agents/{agent_did_id}/did.json"); err == nil {
		t.Fatal("an empty DID host was accepted")
	}
	if err := validateDIDURLTemplate("platform.example.com", "agents", "not a template"); err == nil {
		t.Fatal("an unrenderable template was accepted")
	}
	if err := validateDIDURLTemplate("platform.example.com", "agents", "https://platform.example.com/agents/{agent_did_id}/did.json"); err != nil {
		t.Fatalf("a consistent template was rejected: %v", err)
	}
}

func TestServiceScopedAgentDIDRequiresItsInputs(t *testing.T) {
	for _, test := range []struct{ host, id string }{
		{host: "", id: "abc"},
		{host: "platform.example.com", id: ""},
		{host: "platform.example.com/x", id: "abc"},
	} {
		if did, err := CreateServiceScopedAgentDID(test.host, "agents", test.id); err == nil {
			t.Fatalf("host %q and identifier %q produced %q", test.host, test.id, did)
		}
	}
	// An absent prefix falls back to the documented default, and a port is spelled the did:web way.
	did, err := CreateServiceScopedAgentDID("platform.example.com:8443", "", "abc")
	if err != nil || did != "did:web:platform.example.com%3A8443:agents:abc" {
		t.Fatalf("unexpected DID %q: %v", did, err)
	}
	nested, err := CreateServiceScopedAgentDID("platform.example.com", "/a//b/", "abc")
	if err != nil || nested != "did:web:platform.example.com:a:b:abc" {
		t.Fatalf("unexpected nested DID %q: %v", nested, err)
	}
}

func TestProvisioningSurfacesCollaboratorFailures(t *testing.T) {
	for _, test := range []struct {
		mutate func(*Options)
		name   string
	}{
		{name: "authorizer fails", mutate: func(options *Options) {
			options.Authorizer = stubAuthorizer{authorize: func(AuthorizationRequest) (bool, error) { return false, errCollaborator }}
		}},
		{name: "Service DID resolver fails", mutate: func(options *Options) {
			options.ServiceDIDResolver = stubServiceDIDResolver{resolve: func(string) (bool, error) { return false, errCollaborator }}
		}},
		{name: "identity store fails", mutate: func(options *Options) {
			options.IdentityStore = stubIdentityStore{findOrCreate: func(string, string, func() (IdentityRecord, error)) (IdentityRecord, bool, error) {
				return IdentityRecord{}, false, errCollaborator
			}}
		}},
		{name: "idempotency store fails", mutate: func(options *Options) {
			options.IdempotencyStore = stubIdempotencyStore{execute: func(IdempotencyInput, func() (StoredResponse, error)) (IdempotencyResult, error) {
				return IdempotencyResult{}, errCollaborator
			}}
		}},
		{name: "identity generator fails", mutate: func(options *Options) {
			options.Identifier = func() (string, error) { return "", errCollaborator }
		}},
		{name: "identity generator returns nothing", mutate: func(options *Options) {
			options.Identifier = func() (string, error) { return "", nil }
		}},
		{name: "DID identifier generator fails", mutate: func(options *Options) {
			options.AgentDIDIDGenerator = func() (string, error) { return "", errCollaborator }
		}},
		{name: "DID identifier generator returns nothing", mutate: func(options *Options) {
			options.AgentDIDIDGenerator = func() (string, error) { return "", nil }
		}},
		{name: "key creation fails", mutate: func(options *Options) {
			options.KeyStore = failingKeyStore{KeyStore: options.KeyStore}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			options, _, _ := testOptions(t, false)
			test.mutate(&options)
			platform, err := New(options)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := platform.Provision(context.Background(), ProvisionRequest{ServiceDID: testServiceDID}, testRequestContext("provision-failure")); err == nil {
				t.Fatal("a collaborator failure was swallowed")
			}
		})
	}
}

type stubIdempotencyStore struct {
	execute func(IdempotencyInput, func() (StoredResponse, error)) (IdempotencyResult, error)
}

func (store stubIdempotencyStore) ExecuteIdempotent(_ context.Context, input IdempotencyInput, execute func() (StoredResponse, error)) (IdempotencyResult, error) {
	return store.execute(input, execute)
}

func TestManagementOperationsSurfaceCollaboratorFailures(t *testing.T) {
	record := identityRecord(testAgentIdentityID, testAgentDIDID, testPrincipal, testServiceDID, testClock)
	failingGet := stubIdentityStore{get: func(string) (*IdentityRecord, error) { return nil, errCollaborator }}
	presentGet := stubIdentityStore{get: func(string) (*IdentityRecord, error) {
		copy := cloneIdentityRecord(record)
		return &copy, nil
	}}

	for _, test := range []struct {
		call   func(*Platform) error
		mutate func(*Options)
		name   string
	}{
		{
			name:   "get identity store fails",
			mutate: func(options *Options) { options.IdentityStore = failingGet },
			call: func(platform *Platform) error {
				_, err := platform.GetIdentity(context.Background(), testAgentIdentityID, testRequestContext("get"))
				return err
			},
		},
		{
			name: "get authorizer fails",
			mutate: func(options *Options) {
				options.IdentityStore = presentGet
				options.Authorizer = stubAuthorizer{authorize: func(AuthorizationRequest) (bool, error) { return false, errCollaborator }}
			},
			call: func(platform *Platform) error {
				_, err := platform.GetIdentity(context.Background(), testAgentIdentityID, testRequestContext("get"))
				return err
			},
		},
		{
			name: "list authorizer fails",
			mutate: func(options *Options) {
				options.Authorizer = stubAuthorizer{authorize: func(AuthorizationRequest) (bool, error) { return false, errCollaborator }}
			},
			call: func(platform *Platform) error {
				_, err := platform.List(context.Background(), IdentityListQuery{}, testRequestContext("list"))
				return err
			},
		},
		{
			name: "list identity store fails",
			mutate: func(options *Options) {
				options.IdentityStore = stubIdentityStore{list: func(string, IdentityListQuery) (IdentityListResult, error) {
					return IdentityListResult{}, errCollaborator
				}}
			},
			call: func(platform *Platform) error {
				_, err := platform.List(context.Background(), IdentityListQuery{}, testRequestContext("list"))
				return err
			},
		},
		{
			name:   "update identity store read fails",
			mutate: func(options *Options) { options.IdentityStore = failingGet },
			call: func(platform *Platform) error {
				_, err := platform.UpdateIdentity(context.Background(), testAgentIdentityID, LifecycleRequest{Status: ManagedAgentRevoked}, testRequestContext("update"))
				return err
			},
		},
		{
			name: "update lifecycle policy fails",
			mutate: func(options *Options) {
				options.IdentityStore = presentGet
				options.LifecyclePolicy = stubLifecyclePolicy{canTransition: func() (bool, error) { return false, errCollaborator }}
			},
			call: func(platform *Platform) error {
				_, err := platform.UpdateIdentity(context.Background(), testAgentIdentityID, LifecycleRequest{Status: ManagedAgentRevoked}, testRequestContext("update"))
				return err
			},
		},
		{
			name: "update identity store write fails",
			mutate: func(options *Options) {
				options.IdentityStore = stubIdentityStore{
					get: presentGet.get,
					updateIdentity: func(string, ManagedAgentStatus, time.Time) (*IdentityRecord, error) {
						return nil, errCollaborator
					},
				}
			},
			call: func(platform *Platform) error {
				_, err := platform.UpdateIdentity(context.Background(), testAgentIdentityID, LifecycleRequest{Status: ManagedAgentRevoked}, testRequestContext("update"))
				return err
			},
		},
		{
			name:   "sign identity store fails",
			mutate: func(options *Options) { options.IdentityStore = failingGet },
			call: func(platform *Platform) error {
				_, err := platform.Sign(context.Background(), testAgentIdentityID, SignRequest{
					JWTID: "j", Operation: aep.AssertionStatus, ServiceDID: testServiceDID,
				}, testRequestContext("sign"))
				return err
			},
		},
		{
			name: "sign lifecycle policy fails",
			mutate: func(options *Options) {
				options.IdentityStore = presentGet
				options.LifecyclePolicy = stubLifecyclePolicy{canSign: func() (bool, error) { return false, errCollaborator }}
			},
			call: func(platform *Platform) error {
				_, err := platform.Sign(context.Background(), testAgentIdentityID, SignRequest{
					JWTID: "j", Operation: aep.AssertionStatus, ServiceDID: testServiceDID,
				}, testRequestContext("sign"))
				return err
			},
		},
		{
			name: "sign key store fails",
			mutate: func(options *Options) {
				options.IdentityStore = presentGet
				options.KeyStore = stubKeyStore{sign: func(IdentityRecord, aep.ClientAssertionClaims) (string, error) { return "", errCollaborator }}
			},
			call: func(platform *Platform) error {
				_, err := platform.Sign(context.Background(), testAgentIdentityID, SignRequest{
					JWTID: "j", Operation: aep.AssertionStatus, ServiceDID: testServiceDID,
				}, testRequestContext("sign"))
				return err
			},
		},
		{
			name: "DID document store fails",
			mutate: func(options *Options) {
				options.IdentityStore = stubIdentityStore{byAgentDIDID: func(string) (*IdentityRecord, error) { return nil, errCollaborator }}
			},
			call: func(platform *Platform) error {
				_, err := platform.GetDIDDocument(context.Background(), testAgentDIDID)
				return err
			},
		},
		{
			name: "DID document key store fails",
			mutate: func(options *Options) {
				options.IdentityStore = stubIdentityStore{byAgentDIDID: func(string) (*IdentityRecord, error) {
					copy := cloneIdentityRecord(record)
					return &copy, nil
				}}
				options.KeyStore = stubKeyStore{didVerificationMethod: func(IdentityRecord) (DIDVerificationMethod, error) {
					return DIDVerificationMethod{}, errCollaborator
				}}
			},
			call: func(platform *Platform) error {
				_, err := platform.GetDIDDocument(context.Background(), testAgentDIDID)
				return err
			},
		},
		{
			name: "DID document verification method does not match",
			mutate: func(options *Options) {
				options.IdentityStore = stubIdentityStore{byAgentDIDID: func(string) (*IdentityRecord, error) {
					copy := cloneIdentityRecord(record)
					return &copy, nil
				}}
				options.KeyStore = stubKeyStore{didVerificationMethod: func(identity IdentityRecord) (DIDVerificationMethod, error) {
					return DIDVerificationMethod{Controller: "did:web:attacker.example", ID: identity.KeyID, PublicKeyJWK: json.RawMessage(`{}`), Type: "JsonWebKey2020"}, nil
				}}
			},
			call: func(platform *Platform) error {
				_, err := platform.GetDIDDocument(context.Background(), testAgentDIDID)
				return err
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			options, _, _ := testOptions(t, false)
			test.mutate(&options)
			platform, err := New(options)
			if err != nil {
				t.Fatal(err)
			}
			if err := test.call(platform); err == nil {
				t.Fatal("a collaborator failure was swallowed")
			}
		})
	}
}

// A lifecycle update races an identity that disappears between the read and the write.
func TestUpdateIdentityHandlesAVanishedRecord(t *testing.T) {
	record := identityRecord(testAgentIdentityID, testAgentDIDID, testPrincipal, testServiceDID, testClock)
	options, _, _ := testOptions(t, false)
	options.IdentityStore = stubIdentityStore{
		get: func(string) (*IdentityRecord, error) {
			copy := cloneIdentityRecord(record)
			return &copy, nil
		},
		updateIdentity: func(string, ManagedAgentStatus, time.Time) (*IdentityRecord, error) { return nil, nil },
	}
	platform, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	result, err := platform.UpdateIdentity(context.Background(), testAgentIdentityID, LifecycleRequest{Status: ManagedAgentRevoked}, testRequestContext("update"))
	if err != nil || result.Problem == nil || result.Status != http.StatusNotFound || result.Problem.Code != aep.ErrorNotRecognized {
		t.Fatalf("a vanished record answered %#v, %v", result, err)
	}
}

// A request context without a clock reading falls back to the Platform clock.
func TestSigningAndVerificationFallBackToThePlatformClock(t *testing.T) {
	platform, _, _ := newTestPlatform(t, true)
	identity := provisionedIdentity(t, platform, testServiceDID, "provision-clock")
	signed, err := platform.Sign(context.Background(), identity.AgentIdentityID, SignRequest{
		JWTID: "jti-clock", Operation: aep.AssertionStatus, ServiceDID: testServiceDID,
	}, RequestContext{IdempotencyKey: "sign-clock", Principal: testPrincipal})
	if err != nil || signed.Problem != nil {
		t.Fatalf("signing without a request clock failed: %#v, %v", signed, err)
	}
	if signed.Body.IssuedAt != testClock.UTC().Format(time.RFC3339) {
		t.Fatalf("the Platform clock was not used: %q", signed.Body.IssuedAt)
	}
	verified, err := platform.Verify(context.Background(), VerificationRequest{
		ClientAssertion: signed.Body.ClientAssertion, Operation: aep.AssertionStatus, ServiceDID: testServiceDID,
	}, RequestContext{IdempotencyKey: "verify-clock", Principal: testPrincipal})
	if err != nil || !verified.Body.Verified {
		t.Fatalf("verification without a request clock failed: %#v, %v", verified, err)
	}
}

func TestVerificationSurfacesCollaboratorFailuresAndRejectsMalformedAssertions(t *testing.T) {
	platform, _, _ := newTestPlatform(t, true)
	identity := provisionedIdentity(t, platform, testServiceDID, "provision-verify-edges")
	signed, err := platform.Sign(context.Background(), identity.AgentIdentityID, SignRequest{
		JWTID: "jti-verify-edges", Operation: aep.AssertionStatus, ServiceDID: testServiceDID,
	}, testRequestContext("sign-verify-edges"))
	if err != nil || signed.Problem != nil {
		t.Fatalf("signing failed: %#v, %v", signed, err)
	}

	// An assertion whose issuer, subject, and key identifier disagree never reaches the store.
	for _, claims := range []map[string]any{
		{"sub": identity.AgentDID},
		{"iss": "", "sub": ""},
		{"iss": 7, "sub": identity.AgentDID},
		{"iss": identity.AgentDID, "sub": "did:web:other.example"},
		{"iss": identity.AgentDID},
	} {
		header := map[string]any{"alg": "ES256", "kid": identity.AgentDID, "typ": "JWT"}
		result, verifyErr := platform.Verify(context.Background(), VerificationRequest{
			ClientAssertion: unsignedJWT(header, claims), Operation: aep.AssertionStatus, ServiceDID: testServiceDID,
		}, testRequestContext("verify-claims"))
		if verifyErr != nil || result.Body.Verified {
			t.Fatalf("a malformed assertion was recognized: %#v, %v", result, verifyErr)
		}
	}
	// PLT-SIGN-022: a fragmented key identifier is not a Platform-hosted identity.
	fragmented := unsignedJWT(
		map[string]any{"alg": "ES256", "kid": identity.AgentDID + "#key-1", "typ": "JWT"},
		map[string]any{"iss": identity.AgentDID, "sub": identity.AgentDID},
	)
	if result, verifyErr := platform.Verify(context.Background(), VerificationRequest{
		ClientAssertion: fragmented, Operation: aep.AssertionStatus, ServiceDID: testServiceDID,
	}, testRequestContext("verify-fragment")); verifyErr != nil || result.Body.Verified {
		t.Fatalf("a fragmented kid was recognized: %#v, %v", result, verifyErr)
	}

	record := identityRecord(testAgentIdentityID, testAgentDIDID, testPrincipal, testServiceDID, testClock)
	present := func(string) (*IdentityRecord, error) {
		copy := cloneIdentityRecord(record)
		return &copy, nil
	}
	assertion := unsignedJWT(
		map[string]any{"alg": "ES256", "kid": record.AgentDID, "typ": "JWT"},
		map[string]any{"iss": record.AgentDID, "sub": record.AgentDID},
	)
	for _, test := range []struct {
		mutate func(*Options)
		name   string
	}{
		{name: "identity store fails", mutate: func(options *Options) {
			options.IdentityStore = stubIdentityStore{byAgentDID: func(string) (*IdentityRecord, error) { return nil, errCollaborator }}
		}},
		{name: "authorizer fails", mutate: func(options *Options) {
			options.IdentityStore = stubIdentityStore{byAgentDID: present}
			options.Authorizer = stubAuthorizer{authorize: func(AuthorizationRequest) (bool, error) { return false, errCollaborator }}
		}},
		{name: "lifecycle policy fails", mutate: func(options *Options) {
			options.IdentityStore = stubIdentityStore{byAgentDID: present}
			options.LifecyclePolicy = stubLifecyclePolicy{canVerify: func() (bool, error) { return false, errCollaborator }}
		}},
		{name: "key store fails", mutate: func(options *Options) {
			options.IdentityStore = stubIdentityStore{byAgentDID: present}
			options.KeyStore = stubKeyStore{verificationKey: func(IdentityRecord) (any, error) { return nil, errCollaborator }}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			options, _, _ := testOptions(t, true)
			test.mutate(&options)
			instance, newErr := New(options)
			if newErr != nil {
				t.Fatal(newErr)
			}
			if _, err := instance.Verify(context.Background(), VerificationRequest{
				ClientAssertion: assertion, Operation: aep.AssertionStatus, ServiceDID: testServiceDID,
			}, testRequestContext("verify-failure")); err == nil {
				t.Fatal("a collaborator failure was swallowed")
			}
		})
	}

	// A refusing authorizer or policy is an unrecognized answer, not an error.
	for _, test := range []struct {
		mutate func(*Options)
		name   string
	}{
		{name: "authorizer refuses", mutate: func(options *Options) {
			options.IdentityStore = stubIdentityStore{byAgentDID: present}
			options.Authorizer = stubAuthorizer{authorize: func(AuthorizationRequest) (bool, error) { return false, nil }}
		}},
		{name: "policy refuses", mutate: func(options *Options) {
			options.IdentityStore = stubIdentityStore{byAgentDID: present}
			options.LifecyclePolicy = stubLifecyclePolicy{canVerify: func() (bool, error) { return false, nil }}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			options, _, _ := testOptions(t, true)
			test.mutate(&options)
			instance, newErr := New(options)
			if newErr != nil {
				t.Fatal(newErr)
			}
			result, err := instance.Verify(context.Background(), VerificationRequest{
				ClientAssertion: assertion, Operation: aep.AssertionStatus, ServiceDID: testServiceDID,
			}, testRequestContext("verify-refused"))
			if err != nil || result.Problem != nil || result.Body.Verified || result.Body.Reason != "not_recognized" {
				t.Fatalf("a refusal did not answer not_recognized: %#v, %v", result, err)
			}
		})
	}

	// The replay store is consulted, and its failure surfaces.
	options, _, _ := testOptions(t, true)
	options.ReplayStore = stubReplayStore{consume: func(string, time.Time) (bool, error) { return false, errCollaborator }}
	replayFailure, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	live := provisionedIdentity(t, replayFailure, testServiceDID, "provision-replay")
	liveAssertion, err := replayFailure.Sign(context.Background(), live.AgentIdentityID, SignRequest{
		JWTID: "jti-replay", Operation: aep.AssertionStatus, ServiceDID: testServiceDID,
	}, testRequestContext("sign-replay"))
	if err != nil || liveAssertion.Problem != nil {
		t.Fatalf("signing failed: %#v, %v", liveAssertion, err)
	}
	if _, err := replayFailure.Verify(context.Background(), VerificationRequest{
		ClientAssertion: liveAssertion.Body.ClientAssertion, Operation: aep.AssertionStatus, ServiceDID: testServiceDID,
	}, testRequestContext("verify-replay")); err == nil {
		t.Fatal("a replay store failure was swallowed")
	}
}

type stubReplayStore struct {
	consume func(string, time.Time) (bool, error)
}

func (store stubReplayStore) ConsumeReplay(_ context.Context, key string, expiresAt time.Time) (bool, error) {
	return store.consume(key, expiresAt)
}

func unsignedJWT(header map[string]any, claims map[string]any) string {
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	encode := base64.RawURLEncoding.EncodeToString
	return encode(headerJSON) + "." + encode(claimsJSON) + ".signature"
}

func TestSignHandlerFailureAndCompletedPassthrough(t *testing.T) {
	failing, _, _ := newTestPlatformWithHandler(t, func(context.Context, SignHandlerInput, RequestContext) (*Result[SignResponse], error) {
		return nil, errCollaborator
	})
	identity := provisionedIdentity(t, failing, testServiceDID, "provision-handler-failure")
	if _, err := failing.Sign(context.Background(), identity.AgentIdentityID, SignRequest{
		JWTID: "jti-handler-failure", Operation: aep.AssertionStatus, ServiceDID: testServiceDID,
	}, testRequestContext("handler-failure")); err == nil {
		t.Fatal("a sign handler failure was swallowed")
	}

	// A handler that declines to answer hands the request back to the Platform's own signer.
	declining, _, _ := newTestPlatformWithHandler(t, func(context.Context, SignHandlerInput, RequestContext) (*Result[SignResponse], error) {
		return nil, nil
	})
	declined := provisionedIdentity(t, declining, testServiceDID, "provision-declined")
	result, err := declining.Sign(context.Background(), declined.AgentIdentityID, SignRequest{
		JWTID: "jti-declined", Operation: aep.AssertionStatus, ServiceDID: testServiceDID,
	}, testRequestContext("handler-declined"))
	if err != nil || result.Problem != nil || result.Body.Status != SignCompleted || result.Body.ClientAssertion == "" {
		t.Fatalf("a declining handler did not fall through: %#v, %v", result, err)
	}

	// A well-formed completed response from a handler is returned unchanged.
	issuedAt := testClock.UTC().Format(time.RFC3339)
	expiresAt := testClock.Add(time.Minute).UTC().Format(time.RFC3339)
	completing, _, _ := newTestPlatformWithHandler(t, func(_ context.Context, input SignHandlerInput, _ RequestContext) (*Result[SignResponse], error) {
		return &Result[SignResponse]{
			Body: SignResponse{
				AgentDID: input.Identity.AgentDID, ClientAssertion: "handler.assertion", ExpiresAt: expiresAt,
				IssuedAt: issuedAt, JWTID: input.Request.JWTID, ServiceDID: input.Request.ServiceDID, Status: SignCompleted,
			},
			ContentType: aep.MediaType, Status: http.StatusOK,
		}, nil
	})
	handled := provisionedIdentity(t, completing, testServiceDID, "provision-completed")
	passed, err := completing.Sign(context.Background(), handled.AgentIdentityID, SignRequest{
		JWTID: "jti-completed", Operation: aep.AssertionStatus, ServiceDID: testServiceDID,
	}, testRequestContext("handler-completed"))
	if err != nil || passed.Problem != nil || passed.Body.ClientAssertion != "handler.assertion" {
		t.Fatalf("a valid completed handler response was not returned: %#v, %v", passed, err)
	}

	// A handler answering for a different identity or request is refused.
	for _, mutate := range []func(*SignResponse){
		func(body *SignResponse) { body.AgentDID = "did:web:attacker.example" },
		func(body *SignResponse) { body.JWTID = "another-jti" },
		func(body *SignResponse) { body.ServiceDID = "did:web:other.service.example" },
		func(body *SignResponse) { body.ClientAssertion = "" },
		func(body *SignResponse) { body.IssuedAt = "not a timestamp" },
		func(body *SignResponse) { body.ExpiresAt = "not a timestamp" },
		func(body *SignResponse) { body.ExpiresAt = body.IssuedAt },
		func(body *SignResponse) { body.ExpiresAt = testClock.Add(time.Hour).UTC().Format(time.RFC3339) },
		func(body *SignResponse) { body.Status = "unknown" },
	} {
		apply := mutate
		instance, _, _ := newTestPlatformWithHandler(t, func(_ context.Context, input SignHandlerInput, _ RequestContext) (*Result[SignResponse], error) {
			body := SignResponse{
				AgentDID: input.Identity.AgentDID, ClientAssertion: "handler.assertion", ExpiresAt: expiresAt,
				IssuedAt: issuedAt, JWTID: input.Request.JWTID, ServiceDID: input.Request.ServiceDID, Status: SignCompleted,
			}
			apply(&body)
			return &Result[SignResponse]{Body: body, ContentType: aep.MediaType, Status: http.StatusOK}, nil
		})
		mismatched := provisionedIdentity(t, instance, testServiceDID, "provision-mismatch")
		if _, err := instance.Sign(context.Background(), mismatched.AgentIdentityID, SignRequest{
			JWTID: "jti-mismatch", Operation: aep.AssertionStatus, ServiceDID: testServiceDID,
		}, testRequestContext("handler-mismatch")); err == nil {
			t.Fatal("a mismatched handler response was accepted")
		}
	}

	// A well-formed Problem from a handler is returned as-is.
	refusing, _, _ := newTestPlatformWithHandler(t, func(context.Context, SignHandlerInput, RequestContext) (*Result[SignResponse], error) {
		problem := aep.NewProblemDetails(aep.ErrorRateLimited, "Rate limited", http.StatusTooManyRequests)
		return &Result[SignResponse]{ContentType: aep.ProblemMediaType, Problem: &problem, Status: http.StatusTooManyRequests}, nil
	})
	limited := provisionedIdentity(t, refusing, testServiceDID, "provision-limited")
	refused, err := refusing.Sign(context.Background(), limited.AgentIdentityID, SignRequest{
		JWTID: "jti-limited", Operation: aep.AssertionStatus, ServiceDID: testServiceDID,
	}, testRequestContext("handler-limited"))
	if err != nil || refused.Problem == nil || refused.Problem.Code != aep.ErrorRateLimited || refused.Status != http.StatusTooManyRequests {
		t.Fatalf("a handler Problem was not returned: %#v, %v", refused, err)
	}
}

func TestCanonicalPositiveIntegerRejectsOverflow(t *testing.T) {
	if _, ok := canonicalPositiveInteger("99999999999999999999"); ok {
		t.Fatal("a value beyond int64 was accepted")
	}
	for _, value := range []string{"", "0", "+1", "-1", "1a", " 1", "1 "} {
		if _, ok := canonicalPositiveInteger(value); ok {
			t.Fatalf("%q was accepted", value)
		}
	}
	if parsed, ok := canonicalPositiveInteger("300"); !ok || parsed != 300 {
		t.Fatalf("300 parsed as %d, %v", parsed, ok)
	}
}

func TestStoreResultRejectsAnUnencodableBody(t *testing.T) {
	if _, err := storeResult(Result[chan int]{Body: make(chan int), ContentType: aep.MediaType}); err == nil {
		t.Fatal("an unencodable body was stored")
	}
	if _, err := restoreResult[AgentIdentity](StoredResponse{Body: json.RawMessage(`{`), ContentType: aep.MediaType}); err == nil {
		t.Fatal("a corrupt stored body was restored")
	}
	if _, err := restoreResult[AgentIdentity](StoredResponse{Body: json.RawMessage(`{`), ContentType: aep.ProblemMediaType}); err == nil {
		t.Fatal("a corrupt stored Problem was restored")
	}
	if cloneHeader(nil) != nil {
		t.Fatal("an absent header set became present")
	}
}

func TestMemoryStoresHonourCancellation(t *testing.T) {
	identities := NewMemoryIdentityStore()
	record := identityRecord(testAgentIdentityID, testAgentDIDID, testPrincipal, testServiceDID, testClock)
	create := func() (IdentityRecord, error) { return cloneIdentityRecord(record), nil }
	for name, call := range map[string]func(context.Context) error{
		"find or create": func(ctx context.Context) error {
			_, _, err := identities.FindOrCreateIdentity(ctx, testPrincipal, testServiceDID, create)
			return err
		},
		"by agent DID": func(ctx context.Context) error {
			_, err := identities.FindIdentityByAgentDID(ctx, record.AgentDID)
			return err
		},
		"by agent DID identifier": func(ctx context.Context) error {
			_, err := identities.FindIdentityByAgentDIDID(ctx, record.AgentDIDID)
			return err
		},
		"get": func(ctx context.Context) error {
			_, err := identities.GetIdentity(ctx, record.AgentIdentityID)
			return err
		},
		"list": func(ctx context.Context) error {
			_, err := identities.ListIdentities(ctx, testPrincipal, IdentityListQuery{})
			return err
		},
		"update": func(ctx context.Context) error {
			_, err := identities.UpdateIdentity(ctx, record.AgentIdentityID, ManagedAgentRevoked, testClock)
			return err
		},
	} {
		if err := call(cancelledContext()); err == nil {
			t.Fatalf("%s ignored a cancelled context", name)
		}
	}

	idempotency := NewMemoryIdempotencyStore()
	if _, err := idempotency.ExecuteIdempotent(cancelledContext(), IdempotencyInput{
		IdempotencyKey: "k", Operation: IdempotentProvision, Principal: testPrincipal, RequestHash: "h",
	}, func() (StoredResponse, error) { return StoredResponse{}, nil }); err == nil {
		t.Fatal("the idempotency store ignored a cancelled context")
	}
	replay := NewMemoryReplayStore()
	if _, err := replay.ConsumeReplay(cancelledContext(), "k", testClock.Add(time.Hour)); err == nil {
		t.Fatal("the replay store ignored a cancelled context")
	}
}

func TestMemoryIdentityStoreRejectsRecordsOutsideTheRequestedScope(t *testing.T) {
	store := NewMemoryIdentityStore()
	if _, _, err := store.FindOrCreateIdentity(context.Background(), testPrincipal, testServiceDID, func() (IdentityRecord, error) {
		return identityRecord(testAgentIdentityID, testAgentDIDID, "owner-2", testServiceDID, testClock), nil
	}); err == nil {
		t.Fatal("a record for another principal was stored")
	}
	if _, _, err := store.FindOrCreateIdentity(context.Background(), testPrincipal, testServiceDID, func() (IdentityRecord, error) {
		return identityRecord(testAgentIdentityID, testAgentDIDID, testPrincipal, "did:web:other.service.example", testClock), nil
	}); err == nil {
		t.Fatal("a record for another Service was stored")
	}
}

func TestMemoryIdentityStoreOrdersByCreationTime(t *testing.T) {
	store := NewMemoryIdentityStore()
	for index, created := range []time.Time{testClock.Add(2 * time.Minute), testClock, testClock.Add(time.Minute)} {
		record := identityRecord(
			"pai_"+string(rune('a'+index)), "did"+string(rune('a'+index)), testPrincipal,
			"did:web:service"+string(rune('a'+index))+".example", created,
		)
		if _, _, err := store.FindOrCreateIdentity(context.Background(), testPrincipal, record.ServiceDID, func() (IdentityRecord, error) {
			return record, nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	ascending, err := store.ListIdentities(context.Background(), testPrincipal, IdentityListQuery{})
	if err != nil || len(ascending.Identities) != 3 || ascending.Identities[0].AgentIdentityID != "pai_b" || ascending.Identities[2].AgentIdentityID != "pai_a" {
		t.Fatalf("ascending order was wrong: %#v, %v", ascending.Identities, err)
	}
	descending, err := store.ListIdentities(context.Background(), testPrincipal, IdentityListQuery{Descending: true})
	if err != nil || descending.Identities[0].AgentIdentityID != "pai_a" || descending.Identities[2].AgentIdentityID != "pai_b" {
		t.Fatalf("descending order was wrong: %#v, %v", descending.Identities, err)
	}
	limited, err := store.ListIdentities(context.Background(), testPrincipal, IdentityListQuery{Limit: 2})
	if err != nil || len(limited.Identities) != 2 || limited.Total != 3 {
		t.Fatalf("limit was not applied after ordering: %#v, %v", limited, err)
	}
}

func TestMemoryReplayStoreEvictsExpiredKeys(t *testing.T) {
	store := NewMemoryReplayStore()
	if consumed, err := store.ConsumeReplay(context.Background(), "expiring", time.Now().Add(20*time.Millisecond)); err != nil || !consumed {
		t.Fatalf("the first consumption failed: %v, %v", consumed, err)
	}
	if consumed, err := store.ConsumeReplay(context.Background(), "expiring", time.Now().Add(20*time.Millisecond)); err != nil || consumed {
		t.Fatalf("an immediate replay was accepted: %v, %v", consumed, err)
	}
	if consumed, err := store.ConsumeReplay(context.Background(), "already-expired", time.Now().Add(-time.Minute)); err != nil || consumed {
		t.Fatalf("an already-expired record was consumed: %v, %v", consumed, err)
	}
	time.Sleep(30 * time.Millisecond)
	if consumed, err := store.ConsumeReplay(context.Background(), "later", time.Now().Add(time.Minute)); err != nil || !consumed {
		t.Fatalf("a later record was refused: %v, %v", consumed, err)
	}
}

func TestMemoryStoresSerializeConcurrentCallersOnOneKey(t *testing.T) {
	identities := NewMemoryIdentityStore()
	record := identityRecord(testAgentIdentityID, testAgentDIDID, testPrincipal, testServiceDID, testClock)
	entered := make(chan struct{})
	release := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(1)
	go func() {
		defer wait.Done()
		_, _, _ = identities.FindOrCreateIdentity(context.Background(), testPrincipal, testServiceDID, func() (IdentityRecord, error) {
			close(entered)
			<-release
			return cloneIdentityRecord(record), nil
		})
	}()
	<-entered
	cancelled, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, _, err := identities.FindOrCreateIdentity(cancelled, testPrincipal, testServiceDID, func() (IdentityRecord, error) {
		return cloneIdentityRecord(record), nil
	}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a waiting creator did not give up: %v", err)
	}
	queued := make(chan string, 1)
	go func() {
		result, _, _ := identities.FindOrCreateIdentity(context.Background(), testPrincipal, testServiceDID, func() (IdentityRecord, error) {
			return IdentityRecord{}, errors.New("the queued caller created a second identity")
		})
		queued <- result.AgentIdentityID
	}()
	time.Sleep(10 * time.Millisecond)
	close(release)
	if identityID := <-queued; identityID != testAgentIdentityID {
		t.Fatalf("the queued caller did not observe the created record: %q", identityID)
	}
	wait.Wait()

	idempotency := NewMemoryIdempotencyStore()
	input := IdempotencyInput{IdempotencyKey: "k", Operation: IdempotentSign, Principal: testPrincipal, RequestHash: "h"}
	busy := make(chan struct{})
	finish := make(chan struct{})
	wait.Add(1)
	go func() {
		defer wait.Done()
		_, _ = idempotency.ExecuteIdempotent(context.Background(), input, func() (StoredResponse, error) {
			close(busy)
			<-finish
			return StoredResponse{Body: json.RawMessage(`{}`), ContentType: aep.MediaType, Status: http.StatusOK}, nil
		})
	}()
	<-busy
	idempotencyDeadline, cancelIdempotency := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelIdempotency()
	if _, err := idempotency.ExecuteIdempotent(idempotencyDeadline, input, func() (StoredResponse, error) {
		return StoredResponse{}, nil
	}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a waiting idempotency caller did not give up: %v", err)
	}
	replayed := make(chan IdempotencyState, 1)
	go func() {
		result, _ := idempotency.ExecuteIdempotent(context.Background(), input, func() (StoredResponse, error) {
			return StoredResponse{}, errors.New("the queued caller executed twice")
		})
		replayed <- result.State
	}()
	time.Sleep(10 * time.Millisecond)
	close(finish)
	if state := <-replayed; state != IdempotencyReplayed {
		t.Fatalf("the queued caller did not replay the stored response: %q", state)
	}
	wait.Wait()
}

// A clock that never advanced would mint identities with no creation time, so the record validator
// refuses them rather than storing something no lifecycle answer could describe.
func TestProvisioningRefusesIdentitiesFromAStoppedClock(t *testing.T) {
	options, _, _ := testOptions(t, false)
	options.Clock = func() time.Time { return time.Time{} }
	platform, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := platform.Provision(context.Background(), ProvisionRequest{ServiceDID: testServiceDID}, testRequestContext("provision-stopped-clock")); err == nil {
		t.Fatal("an identity with no creation time was provisioned")
	}
}
