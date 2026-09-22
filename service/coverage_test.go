package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	aep "github.com/aep-foundation/aep-go"
)

var errStore = errors.New("store failed")

type stubEnrollmentStore struct {
	find          func(string) (*EnrollmentRecord, error)
	findOrCreate  func(string, func() (EnrollmentRecord, error)) (EnrollmentRecord, bool, error)
	saveEnrolment func(EnrollmentRecord) (EnrollmentRecord, error)
}

func (store stubEnrollmentStore) FindEnrollment(_ context.Context, agentDID string) (*EnrollmentRecord, error) {
	if store.find == nil {
		return nil, nil
	}
	return store.find(agentDID)
}

func (store stubEnrollmentStore) FindOrCreateEnrollment(_ context.Context, agentDID string, create func() (EnrollmentRecord, error)) (EnrollmentRecord, bool, error) {
	if store.findOrCreate == nil {
		record, err := create()
		return record, true, err
	}
	return store.findOrCreate(agentDID, create)
}

func (store stubEnrollmentStore) SaveEnrollment(_ context.Context, record EnrollmentRecord) (EnrollmentRecord, error) {
	if store.saveEnrolment == nil {
		return record, nil
	}
	return store.saveEnrolment(record)
}

type stubReplayStore struct {
	consume func(ReplayRecord, int64) (bool, error)
}

func (store stubReplayStore) ConsumeReplay(_ context.Context, record ReplayRecord, now int64) (bool, error) {
	return store.consume(record, now)
}

type stubIdempotencyStore struct {
	execute func(IdempotencyInput, func() (StoredResponse, error)) (IdempotencyResult, error)
}

func (store stubIdempotencyStore) ExecuteIdempotent(_ context.Context, input IdempotencyInput, execute func() (StoredResponse, error)) (IdempotencyResult, error) {
	return store.execute(input, execute)
}

type stubCredentialStore struct {
	authenticate func(aep.GrantType, CredentialAuthenticationInput) (*CredentialMatch, error)
	detect       func(aep.GrantType, CredentialAuthenticationInput) (bool, error)
	revoke       func(string, aep.GrantType, string, time.Time) error
	revokeAll    func(string, aep.GrantType, time.Time) error
	save         func(ServiceCredentialRecord) error
}

func (store stubCredentialStore) AuthenticateCredential(_ context.Context, grantType aep.GrantType, input CredentialAuthenticationInput) (*CredentialMatch, error) {
	if store.authenticate == nil {
		return nil, nil
	}
	return store.authenticate(grantType, input)
}

func (store stubCredentialStore) HasCredentialPresentation(_ context.Context, grantType aep.GrantType, input CredentialAuthenticationInput) (bool, error) {
	if store.detect == nil {
		return false, nil
	}
	return store.detect(grantType, input)
}

func (store stubCredentialStore) RevokeCredential(_ context.Context, agentDID string, grantType aep.GrantType, credentialID string, revokedAt time.Time) error {
	if store.revoke == nil {
		return nil
	}
	return store.revoke(agentDID, grantType, credentialID, revokedAt)
}

func (store stubCredentialStore) RevokeGrantType(_ context.Context, agentDID string, grantType aep.GrantType, revokedAt time.Time) error {
	if store.revokeAll == nil {
		return nil
	}
	return store.revokeAll(agentDID, grantType, revokedAt)
}

func (store stubCredentialStore) SaveCredential(_ context.Context, record ServiceCredentialRecord) error {
	if store.save == nil {
		return nil
	}
	return store.save(record)
}

func cancelledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestNewRejectsEveryInvalidOption(t *testing.T) {
	verifier := func(context.Context, string, AssertionVerificationContext) (aep.ClientAssertionClaims, error) {
		return aep.ClientAssertionClaims{}, nil
	}
	base := func() Options {
		return Options{
			IdentityMethods: []aep.IdentityMethod{aep.IdentityMethodDIDWeb},
			ServiceDID:      "did:web:service.example",
			Verifier:        verifier,
		}
	}
	for _, test := range []struct {
		mutate func(*Options)
		name   string
	}{
		{name: "missing Service DID", mutate: func(options *Options) { options.ServiceDID = "" }},
		{name: "missing verifier", mutate: func(options *Options) { options.Verifier = nil }},
		{name: "no identity methods", mutate: func(options *Options) { options.IdentityMethods = nil }},
		{name: "duplicate identity methods", mutate: func(options *Options) {
			options.IdentityMethods = []aep.IdentityMethod{aep.IdentityMethodDIDWeb, aep.IdentityMethodDIDWeb}
		}},
		{name: "signing algorithms without EdDSA", mutate: func(options *Options) {
			options.SigningAlgorithms = []aep.SigningAlgorithm{aep.SigningAlgorithmES256}
		}},
		{name: "signing algorithms without ES256", mutate: func(options *Options) {
			options.SigningAlgorithms = []aep.SigningAlgorithm{aep.SigningAlgorithmEdDSA}
		}},
		{name: "duplicate signing algorithms", mutate: func(options *Options) {
			options.SigningAlgorithms = []aep.SigningAlgorithm{aep.SigningAlgorithmEdDSA, aep.SigningAlgorithmES256, aep.SigningAlgorithmES256}
		}},
		{name: "grant type without an identifier", mutate: func(options *Options) {
			options.GrantTypes = []GrantTypeDefinition{{Handler: &testGrantHandler{}}}
		}},
		{name: "grant type without a handler", mutate: func(options *Options) {
			options.GrantTypes = []GrantTypeDefinition{{GrantType: "custom-session"}}
		}},
		{name: "duplicate grant types", mutate: func(options *Options) {
			options.GrantTypes = []GrantTypeDefinition{
				{GrantType: "custom-session", Handler: &testGrantHandler{}},
				{GrantType: "custom-session", Handler: &testGrantHandler{}},
			}
		}},
		{name: "duplicate authentication methods", mutate: func(options *Options) {
			options.AuthenticationMethods = []aep.AuthenticationMethod{aep.AuthenticationMethodJWT, aep.AuthenticationMethodJWT}
		}},
		{name: "authentication method without a credential authenticator", mutate: func(options *Options) {
			options.AuthenticationMethods = []aep.AuthenticationMethod{"plain-session"}
			options.GrantTypes = []GrantTypeDefinition{{GrantType: "plain-session", Handler: plainGrantHandler{}}}
		}},
		{name: "relative endpoint base", mutate: func(options *Options) { options.EndpointBase = "aep" }},
		{name: "protocol-relative endpoint base", mutate: func(options *Options) { options.EndpointBase = "//aep" }},
		{name: "Service DID the Inspect schema rejects", mutate: func(options *Options) { options.ServiceDID = "not-a-did" }},
		{name: "clock skew beyond the recommendation", mutate: func(options *Options) {
			options.ClientAssertion.ClockSkew = durationPointer(time.Minute)
		}},
		{name: "assertion lifetime beyond the maximum", mutate: func(options *Options) {
			options.ClientAssertion.MaximumLifetime = time.Hour
		}},
		{name: "negative claim value limits", mutate: func(options *Options) {
			options.ClaimValueLimits = &ClaimValueLimits{MaxEncodedBytes: -1}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := base()
			test.mutate(&options)
			if service, err := New(options); err == nil {
				t.Fatalf("invalid options were accepted: %#v", service)
			}
		})
	}
}

type plainGrantHandler struct{}

func (plainGrantHandler) Grant(context.Context, aep.GrantRequest, GrantContext) (json.RawMessage, error) {
	return json.RawMessage(`{"credential_id":"credential-1"}`), nil
}

func (plainGrantHandler) Revoke(context.Context, aep.RevokeRequest, RevokeContext) error {
	return nil
}

func TestNewAcceptsFullyPopulatedOptions(t *testing.T) {
	service, err := New(Options{
		Claims:           &aep.InspectClaims{Optional: []aep.ClaimName{aep.ClaimPersonUsername}, Preferred: []aep.ClaimName{aep.ClaimContactMobile}, Required: []aep.ClaimName{aep.ClaimContactEmail}},
		ClaimValueLimits: &ClaimValueLimits{MaxEncodedBytes: 1024, MaxMemberCount: 4, MaxObjectDepth: 3, MaxStringLength: 64},
		EndpointBase:     "/identity",
		Extensions:       []string{"https://example.com/aep-extension"},
		GrantTypes: []GrantTypeDefinition{{
			Config:    aep.GrantTypeConfig{Additional: aep.AdditionalMembers{"scopes_supported": json.RawMessage(`["read"]`)}, SupportsPerCredentialRevoke: "true"},
			GrantType: "custom-session", Handler: &testGrantHandler{},
		}},
		IdentityMethods: []aep.IdentityMethod{aep.IdentityMethodDIDWeb},
		OpenAPI: &aep.OpenAPIReference{
			PathMatching: aep.OpenAPIPathMatching{TrailingSlash: "strict"},
			URL:          "https://service.example/openapi.json",
		},
		ServiceDID: "did:web:service.example",
		Verifier: func(context.Context, string, AssertionVerificationContext) (aep.ClientAssertionClaims, error) {
			return aep.ClientAssertionClaims{}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	document, err := service.InspectDocument()
	if err != nil {
		t.Fatal(err)
	}
	if document.Extensions == nil || len(document.Extensions.Supported) != 1 {
		t.Fatalf("extensions were dropped: %#v", document.Extensions)
	}
	if document.HTTP.OpenAPI == nil || document.HTTP.OpenAPI.URL != "https://service.example/openapi.json" || document.HTTP.OpenAPI.PathMatching.TrailingSlash != "strict" {
		t.Fatalf("the OpenAPI reference was dropped: %#v", document.HTTP.OpenAPI)
	}
	if document.HTTP.EndpointBase != "/identity/" {
		t.Fatalf("the endpoint base was not normalized: %q", document.HTTP.EndpointBase)
	}
	if document.Claims == nil || len(document.Claims.Required) != 1 || len(document.Claims.Preferred) != 1 || len(document.Claims.Optional) != 1 {
		t.Fatalf("the claims catalog was dropped: %#v", document.Claims)
	}
	if _, found := document.Commands.GrantTypesConfig["custom-session"]; !found {
		t.Fatalf("the grant type configuration was dropped: %#v", document.Commands.GrantTypesConfig)
	}

	// The returned document is a deep copy, so a caller cannot reach back into the Service.
	document.Service.DID = "did:web:attacker.example"
	document.Identity.Methods[0] = "did:key"
	again, err := service.InspectDocument()
	if err != nil || again.Service.DID != "did:web:service.example" || again.Identity.Methods[0] != aep.IdentityMethodDIDWeb {
		t.Fatalf("the advertised document is aliased: %#v, %v", again, err)
	}
}

func TestNewGeneratesIdentifiersWhenNoProviderIsConfigured(t *testing.T) {
	service, err := New(Options{
		IdentityMethods: []aep.IdentityMethod{aep.IdentityMethodDIDWeb},
		ServiceDID:      "did:web:service.example",
		Verifier: func(context.Context, string, AssertionVerificationContext) (aep.ClientAssertionClaims, error) {
			return aep.ClientAssertionClaims{}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.identifier()
	if err != nil || len(first) != 32 {
		t.Fatalf("unexpected generated identifier %q: %v", first, err)
	}
	second, err := service.identifier()
	if err != nil || second == first {
		t.Fatalf("generated identifiers repeat: %q, %v", second, err)
	}
	if service.clock == nil || service.enrollmentPolicy == nil || service.enrollmentStore == nil || service.idempotencyStore == nil || service.replayStore == nil {
		t.Fatal("a default collaborator was left unset")
	}
}

func TestEnrollPropagatesCollaboratorFailures(t *testing.T) {
	enrollBody := []byte(`{"agent_did":"did:web:agent.example"}`)
	for _, test := range []struct {
		name    string
		options Options
	}{
		{name: "enrollment policy fails", options: Options{EnrollmentPolicy: testEnrollmentPolicy(func(aep.EnrollRequest, EnrollmentPolicyContext) (EnrollmentDecision, error) {
			return EnrollmentDecision{}, errStore
		})}},
		{name: "enrollment store fails", options: Options{EnrollmentStore: stubEnrollmentStore{
			findOrCreate: func(string, func() (EnrollmentRecord, error)) (EnrollmentRecord, bool, error) {
				return EnrollmentRecord{}, false, errStore
			},
		}}},
		{name: "idempotency store fails", options: Options{IdempotencyStore: stubIdempotencyStore{
			execute: func(IdempotencyInput, func() (StoredResponse, error)) (IdempotencyResult, error) {
				return IdempotencyResult{}, errStore
			},
		}}},
		{name: "replay store fails", options: Options{ReplayStore: stubReplayStore{
			consume: func(ReplayRecord, int64) (bool, error) { return false, errStore },
		}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := test.options
			service := newTestService(t, options)
			if _, err := service.Enroll(context.Background(), enrollBody, commandOptions(aep.AssertionEnroll, "enroll-failure", "enroll-failure")); err == nil {
				t.Fatal("a collaborator failure was swallowed")
			}
		})
	}

	failingIdentifier := newTestService(t, Options{})
	failingIdentifier.identifier = func() (string, error) { return "", errStore }
	if _, err := failingIdentifier.Enroll(context.Background(), enrollBody, commandOptions(aep.AssertionEnroll, "enroll-failed-id", "enroll-failed-id")); !errors.Is(err, errStore) {
		t.Fatalf("a failing enrollment identifier was accepted: %v", err)
	}

	empty := newTestService(t, Options{})
	empty.identifier = func() (string, error) { return "", nil }
	if _, err := empty.Enroll(context.Background(), enrollBody, commandOptions(aep.AssertionEnroll, "enroll-empty-id", "enroll-empty-id")); err == nil || !strings.Contains(err.Error(), "empty identifier") {
		t.Fatalf("an empty enrollment identifier was accepted: %v", err)
	}

	refused := newTestService(t, Options{ReplayStore: stubReplayStore{
		consume: func(ReplayRecord, int64) (bool, error) { return false, nil },
	}})
	result, err := refused.Enroll(context.Background(), enrollBody, commandOptions(aep.AssertionEnroll, "enroll-refused", "enroll-refused"))
	if err != nil || result.Problem == nil || result.Problem.Code != aep.ErrorNotRecognized {
		t.Fatalf("a refused replay record was accepted: %#v, %v", result, err)
	}
}

func TestEnrollReportsLifecycleStateFromAnExternalStore(t *testing.T) {
	service := newTestService(t, Options{EnrollmentStore: stubEnrollmentStore{
		findOrCreate: func(agentDID string, _ func() (EnrollmentRecord, error)) (EnrollmentRecord, bool, error) {
			record := activeEnrollment(agentDID)
			record.OwnerActionRequired = true
			record.Status = aep.AgentPending
			record.RequirementsPending = []string{"contact.email"}
			record.VerificationPending = []string{"domain-control"}
			return record, false, nil
		},
	}})
	result, err := service.Enroll(context.Background(), []byte(`{"agent_did":"did:web:agent.example"}`), commandOptions(aep.AssertionEnroll, "enroll-pending", "enroll-pending"))
	if err != nil || result.Problem != nil || result.Body.Status != aep.AgentPending {
		t.Fatalf("unexpected pending enrollment: %#v, %v", result, err)
	}
	if result.Body.OwnerActionRequired == nil || *result.Body.OwnerActionRequired != "true" {
		t.Fatalf("owner_action_required was %#v", result.Body.OwnerActionRequired)
	}
	if len(result.Body.VerificationPending) != 1 || len(result.Body.RequirementsPending) != 1 {
		t.Fatalf("pending lists were dropped: %#v", result.Body)
	}

	unknown := newTestService(t, Options{EnrollmentStore: stubEnrollmentStore{
		findOrCreate: func(agentDID string, _ func() (EnrollmentRecord, error)) (EnrollmentRecord, bool, error) {
			record := activeEnrollment(agentDID)
			record.Status = "archived"
			return record, false, nil
		},
	}})
	failed, err := unknown.Enroll(context.Background(), []byte(`{"agent_did":"did:web:agent.example"}`), commandOptions(aep.AssertionEnroll, "enroll-unknown", "enroll-unknown"))
	if err != nil || failed.Problem == nil || failed.Problem.Code != aep.ErrorEnrollmentFailed {
		t.Fatalf("an unrepresentable lifecycle state was reported as success: %#v, %v", failed, err)
	}
}

func TestStatusReportsLifecycleDetailAndStoreFailures(t *testing.T) {
	service := newTestService(t, Options{EnrollmentStore: stubEnrollmentStore{
		find: func(agentDID string) (*EnrollmentRecord, error) {
			record := activeEnrollment(agentDID)
			record.OwnerActionRequired = true
			record.Status = aep.AgentSuspended
			record.RequirementsPending = []string{"contact.email"}
			record.VerificationPending = []string{"domain-control"}
			return &record, nil
		},
	}})
	result, err := service.Status(context.Background(), commandOptions(aep.AssertionStatus, "status-detail", ""))
	if err != nil || result.Problem != nil || result.Body.Status != aep.AgentSuspended {
		t.Fatalf("unexpected status: %#v, %v", result, err)
	}
	if result.Body.OwnerActionRequired == nil || *result.Body.OwnerActionRequired != "true" || result.Body.Since == "" {
		t.Fatalf("status detail was dropped: %#v", result.Body)
	}

	failing := newTestService(t, Options{EnrollmentStore: stubEnrollmentStore{
		find: func(string) (*EnrollmentRecord, error) { return nil, errStore },
	}})
	if _, err := failing.Status(context.Background(), commandOptions(aep.AssertionStatus, "status-failure", "")); err == nil {
		t.Fatal("a store failure was swallowed")
	}

	unknown := newTestService(t, Options{})
	missing, err := unknown.Status(context.Background(), commandOptions(aep.AssertionStatus, "status-unknown", ""))
	if err != nil || missing.Problem == nil || missing.Problem.Code != aep.ErrorNotRecognized {
		t.Fatalf("an unknown Agent was not rejected: %#v, %v", missing, err)
	}

	anonymous, err := unknown.Status(context.Background(), CommandOptions{})
	if err != nil || anonymous.Problem == nil || anonymous.Problem.Code != aep.ErrorNotRecognized {
		t.Fatalf("an anonymous Status was accepted: %#v, %v", anonymous, err)
	}
}

func TestGrantAndRevokePropagateHandlerFailures(t *testing.T) {
	grantFailure := newTestService(t, Options{GrantTypes: []GrantTypeDefinition{{GrantType: "custom-session", Handler: &testGrantHandler{
		grant: func(aep.GrantRequest, GrantContext) (json.RawMessage, error) { return nil, errStore },
	}}}})
	seedEnrollment(t, grantFailure.enrollmentStore)
	if _, err := grantFailure.Grant(context.Background(), []byte(`{"grant_type":"custom-session"}`), commandOptions(aep.AssertionGrant, "grant-failure", "grant-failure")); err == nil {
		t.Fatal("a Grant handler failure was swallowed")
	}

	revokeFailure := newTestService(t, Options{GrantTypes: []GrantTypeDefinition{{GrantType: "custom-session", Handler: &testGrantHandler{
		revoke: func(aep.RevokeRequest, RevokeContext) error { return errStore },
	}}}})
	seedEnrollment(t, revokeFailure.enrollmentStore)
	if _, err := revokeFailure.Revoke(context.Background(), []byte(`{"grant_type":"custom-session"}`), commandOptions(aep.AssertionRevoke, "revoke-failure", "revoke-failure")); err == nil {
		t.Fatal("a Revoke handler failure was swallowed")
	}
	if _, err := revokeFailure.Revoke(context.Background(), []byte(`{"all_grant_types":"true"}`), commandOptions(aep.AssertionRevoke, "revoke-all-failure", "revoke-all-failure")); err == nil {
		t.Fatal("a bulk Revoke handler failure was swallowed")
	}

	unenrolled := newTestService(t, Options{GrantTypes: []GrantTypeDefinition{{GrantType: "custom-session", Handler: &testGrantHandler{}}}})
	revoke, err := unenrolled.Revoke(context.Background(), []byte(`{"grant_type":"custom-session"}`), commandOptions(aep.AssertionRevoke, "revoke-unenrolled", "revoke-unenrolled"))
	if err != nil || revoke.Problem == nil || revoke.Problem.Code != aep.ErrorNotRecognized {
		t.Fatalf("Revoke before Enroll was accepted: %#v, %v", revoke, err)
	}

	anonymous := newTestService(t, Options{GrantTypes: []GrantTypeDefinition{{GrantType: "custom-session", Handler: &testGrantHandler{}}}})
	for _, body := range []string{`{"grant_type":"custom-session"}`} {
		grant, grantErr := anonymous.Grant(context.Background(), []byte(body), CommandOptions{IdempotencyKey: "anonymous"})
		if grantErr != nil || grant.Problem == nil || grant.Problem.Code != aep.ErrorNotRecognized {
			t.Fatalf("an anonymous Grant was accepted: %#v, %v", grant, grantErr)
		}
		revokeResult, revokeErr := anonymous.Revoke(context.Background(), []byte(body), CommandOptions{IdempotencyKey: "anonymous"})
		if revokeErr != nil || revokeResult.Problem == nil || revokeResult.Problem.Code != aep.ErrorNotRecognized {
			t.Fatalf("an anonymous Revoke was accepted: %#v, %v", revokeResult, revokeErr)
		}
		enroll, enrollErr := anonymous.Enroll(context.Background(), []byte(`{"agent_did":"did:web:agent.example"}`), CommandOptions{IdempotencyKey: "anonymous"})
		if enrollErr != nil || enroll.Problem == nil || enroll.Problem.Code != aep.ErrorNotRecognized {
			t.Fatalf("an anonymous Enroll was accepted: %#v, %v", enroll, enrollErr)
		}
	}

	malformed := newTestService(t, Options{GrantTypes: []GrantTypeDefinition{{GrantType: "custom-session", Handler: &testGrantHandler{}}}})
	seedEnrollment(t, malformed.enrollmentStore)
	badGrant, err := malformed.Grant(context.Background(), []byte(`{`), commandOptions(aep.AssertionGrant, "grant-malformed", "grant-malformed"))
	if err != nil || badGrant.Problem == nil || badGrant.Problem.Code != aep.ErrorInvalidRequest {
		t.Fatalf("a malformed Grant body was accepted: %#v, %v", badGrant, err)
	}
	badRevoke, err := malformed.Revoke(context.Background(), []byte(`{`), commandOptions(aep.AssertionRevoke, "revoke-malformed", "revoke-malformed"))
	if err != nil || badRevoke.Problem == nil || badRevoke.Problem.Code != aep.ErrorInvalidRequest {
		t.Fatalf("a malformed Revoke body was accepted: %#v, %v", badRevoke, err)
	}
}

func TestGrantReportsStoreFailuresAndInvalidCredentials(t *testing.T) {
	failing := newTestService(t, Options{
		EnrollmentStore: stubEnrollmentStore{find: func(string) (*EnrollmentRecord, error) { return nil, errStore }},
		GrantTypes:      []GrantTypeDefinition{{GrantType: "custom-session", Handler: &testGrantHandler{}}},
	})
	if _, err := failing.Grant(context.Background(), []byte(`{"grant_type":"custom-session"}`), commandOptions(aep.AssertionGrant, "grant-store", "grant-store")); err == nil {
		t.Fatal("a store failure during Grant was swallowed")
	}
	if _, err := failing.Revoke(context.Background(), []byte(`{"grant_type":"custom-session"}`), commandOptions(aep.AssertionRevoke, "revoke-store", "revoke-store")); err == nil {
		t.Fatal("a store failure during Revoke was swallowed")
	}

	for _, credential := range []string{`[]`, `null`, `"text"`, `{}`, `{"credential_id":""}`, `{"credential_id":7}`} {
		service := newTestService(t, Options{GrantTypes: []GrantTypeDefinition{{GrantType: "custom-session", Handler: &testGrantHandler{
			grant: func(aep.GrantRequest, GrantContext) (json.RawMessage, error) { return json.RawMessage(credential), nil },
		}}}})
		seedEnrollment(t, service.enrollmentStore)
		if _, err := service.Grant(context.Background(), []byte(`{"grant_type":"custom-session"}`), commandOptions(aep.AssertionGrant, "grant-"+credential, "grant-"+credential)); err == nil {
			t.Fatalf("Grant accepted the credential object %s", credential)
		}
	}
}

func TestAuthenticateAssertionRejectsUnusableExpiry(t *testing.T) {
	service := newTestService(t, Options{Verifier: nil})
	service.verifier = func(context.Context, string, AssertionVerificationContext) (aep.ClientAssertionClaims, error) {
		return aep.ClientAssertionClaims{
			Audience: "did:web:service.example", ExpiresAt: 1 << 62, IssuedAt: testNow.Unix(), Issuer: "did:web:agent.example",
			JWTID: "overflow", Operation: aep.AssertionStatus, Subject: "did:web:agent.example",
		}, nil
	}
	result, err := service.Status(context.Background(), CommandOptions{ClientAssertion: assertion(aep.AssertionStatus, "overflow", "")})
	if err != nil || result.Problem == nil || result.Problem.Code != aep.ErrorNotRecognized {
		t.Fatalf("an unusable expiry was accepted: %#v, %v", result, err)
	}

	verifierFailure := newTestService(t, Options{})
	verifierFailure.verifier = func(context.Context, string, AssertionVerificationContext) (aep.ClientAssertionClaims, error) {
		return aep.ClientAssertionClaims{}, errStore
	}
	rejected, err := verifierFailure.Status(context.Background(), CommandOptions{ClientAssertion: "opaque"})
	if err != nil || rejected.Problem == nil || rejected.Problem.Code != aep.ErrorNotRecognized {
		t.Fatalf("CORE-CA-024 did not collapse a verifier failure: %#v, %v", rejected, err)
	}

	undecodable := newTestService(t, Options{})
	undecodable.verifier = func(context.Context, string, AssertionVerificationContext) (aep.ClientAssertionClaims, error) {
		return aep.ClientAssertionClaims{
			Audience: "did:web:service.example", ExpiresAt: testNow.Add(time.Minute).Unix(), IssuedAt: testNow.Unix(),
			Issuer: "did:web:agent.example", JWTID: "undecodable", Operation: aep.AssertionStatus, Subject: "did:web:agent.example",
		}, nil
	}
	opaque, err := undecodable.Status(context.Background(), CommandOptions{ClientAssertion: "not.a.jwt"})
	if err != nil || opaque.Problem == nil || opaque.Problem.Code != aep.ErrorNotRecognized {
		t.Fatalf("an undecodable assertion was accepted: %#v, %v", opaque, err)
	}
}

func TestIdentityMethodParsesOnlyWellFormedDIDs(t *testing.T) {
	for _, test := range []struct {
		did    string
		method aep.IdentityMethod
	}{
		{did: "did:web:service.example", method: "did:web"},
		{did: "did:key:z6Mk", method: "did:key"},
		{did: "did:web:service.example:path:more", method: "did:web"},
		{did: "did:web:", method: "did:web"},
		{did: "did:web", method: ""},
		{did: "web:service.example:x", method: ""},
		{did: "did::service.example", method: ""},
		{did: "", method: ""},
	} {
		if method := identityMethod(test.did); method != test.method {
			t.Fatalf("identityMethod(%q) was %q, expected %q", test.did, method, test.method)
		}
	}
}

func TestStoredResultRoundTripsProblemsAndBodies(t *testing.T) {
	problem := problemResult[aep.RevokeResponse](aep.ErrorNotRecognized, "Not recognized", http.StatusUnauthorized)
	stored, err := storeResult(problem, testNow)
	if err != nil || stored.ContentType != aep.ProblemMediaType || stored.Headers.Get("WWW-Authenticate") == "" {
		t.Fatalf("a Problem result did not survive storage: %#v, %v", stored, err)
	}
	restored, err := parseStoredResult(stored, aep.ParseRevokeResponse)
	if err != nil || restored.Problem == nil || restored.Problem.Code != aep.ErrorNotRecognized || restored.Headers.Get("WWW-Authenticate") == "" {
		t.Fatalf("a stored Problem did not restore: %#v, %v", restored, err)
	}

	if _, err := parseStoredResult(StoredResponse{Body: json.RawMessage(`{`), ContentType: aep.ProblemMediaType}, aep.ParseRevokeResponse); err == nil {
		t.Fatal("a corrupt stored Problem was restored")
	}
	if _, err := parseStoredResult(StoredResponse{Body: json.RawMessage(`{"unexpected":1}`), ContentType: aep.MediaType}, aep.ParseRevokeResponse); err == nil {
		t.Fatal("a corrupt stored body was restored")
	}
	if _, err := storeResult(Result[chan int]{Body: make(chan int), ContentType: aep.MediaType}, testNow); err == nil {
		t.Fatal("an unencodable body was stored")
	}
	if _, err := executeIdempotent(newTestService(t, Options{}), context.Background(), "did:web:agent.example", IdempotentEnroll, "key", make(chan int), aep.ParseRevokeResponse, func() (Result[aep.RevokeResponse], error) {
		return Result[aep.RevokeResponse]{}, nil
	}); err == nil {
		t.Fatal("an unencodable request was fingerprinted")
	}
}

func TestRequirementsUnmetErrorDescribesItself(t *testing.T) {
	if message := (requirementsUnmetError{}).Error(); !strings.Contains(message, "requirements") {
		t.Fatalf("unexpected message: %q", message)
	}
}

func TestClaimValueLimitsAreResolvedAndEnforced(t *testing.T) {
	defaults := DefaultClaimValueLimits()
	if defaults.MaxEncodedBytes == 0 || defaults.MaxMemberCount == 0 || defaults.MaxObjectDepth == 0 || defaults.MaxStringLength == 0 {
		t.Fatalf("the default limits are incomplete: %#v", defaults)
	}
	for _, configured := range []ClaimValueLimits{
		{MaxEncodedBytes: 1}, {MaxMemberCount: 1}, {MaxObjectDepth: 1}, {MaxStringLength: 1},
	} {
		resolved, err := resolveClaimValueLimits(&configured)
		if err != nil {
			t.Fatal(err)
		}
		if resolved == defaults {
			t.Fatalf("a configured override was ignored: %#v", configured)
		}
	}
	for _, configured := range []ClaimValueLimits{
		{MaxEncodedBytes: -1}, {MaxMemberCount: -1}, {MaxObjectDepth: -1}, {MaxStringLength: -1},
	} {
		if _, err := resolveClaimValueLimits(&configured); err == nil {
			t.Fatalf("a negative limit was accepted: %#v", configured)
		}
	}

	limits := ClaimValueLimits{MaxEncodedBytes: 4096, MaxMemberCount: 4, MaxObjectDepth: 3, MaxStringLength: 16}
	if !claimValuesWithinLimits(nil, limits) {
		t.Fatal("absent claim values were rejected")
	}
	for _, test := range []struct {
		document string
		within   bool
	}{
		{document: `{"contact.email":"a@b.com"}`, within: true},
		{document: `{"x":[1,true,null,"short"]}`, within: true},
		{document: `{"x":"01234567890123456"}`},
		{document: `{"01234567890123456":"short"}`},
		{document: `{"a":1,"b":2,"c":3,"d":4,"e":5}`},
		{document: `{"a":{"b":{"c":{"d":"deep"}}}}`},
		{document: `{"a":[[[["deep"]]]]}`},
	} {
		values, err := aep.ParseClaimValues([]byte(test.document))
		if err != nil {
			t.Fatalf("%s: %v", test.document, err)
		}
		if within := claimValuesWithinLimits(&values, limits); within != test.within {
			t.Fatalf("%s was %v, expected %v", test.document, within, test.within)
		}
	}
	if claimValuesWithinLimits(&aep.ClaimValues{Additional: aep.AdditionalMembers{"x": json.RawMessage(`"tiny"`)}}, ClaimValueLimits{MaxEncodedBytes: 1}) {
		t.Fatal("an oversized encoding was accepted")
	}

	// The default arm guards against a decoder that yields a type JSON cannot produce.
	members := 0
	if claimValueWithinLimits(struct{}{}, 1, limits, &members) {
		t.Fatal("an unrepresentable claim value was accepted")
	}
}

func TestCloneClaimValuesPreservesAndIsolatesValues(t *testing.T) {
	if clone, err := cloneClaimValues(nil); err != nil || clone != nil {
		t.Fatalf("a nil claim set did not clone: %#v, %v", clone, err)
	}
	values, err := aep.ParseClaimValues([]byte(`{"contact.email":"agent@example.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	clone, err := cloneClaimValues(&values)
	if err != nil || clone.ContactEmail == nil || *clone.ContactEmail != "agent@example.com" {
		t.Fatalf("claim values were not cloned: %#v, %v", clone, err)
	}
	if clone.ContactEmail == values.ContactEmail {
		t.Fatal("the clone aliases the original")
	}
	if _, err := cloneClaimValues(&aep.ClaimValues{Additional: aep.AdditionalMembers{"contact.email": json.RawMessage(`7`)}}); err == nil {
		t.Fatal("an invalid claim value cloned successfully")
	}
}

func TestStoredCredentialGrantTypesValidateTheirConfiguration(t *testing.T) {
	issue := func(context.Context, aep.GrantRequest, GrantContext) (aep.APIKeyGrantResponse, error) {
		return aep.APIKeyGrantResponse{}, nil
	}
	store := NewMemoryServiceCredentialStore()
	if _, err := StoredAPIKeyGrantType(StoredCredentialGrantTypeOptions[aep.APIKeyGrantResponse]{Store: store}); err == nil {
		t.Fatal("a stored grant type without an issuer was accepted")
	}
	if _, err := StoredAPIKeyGrantType(StoredCredentialGrantTypeOptions[aep.APIKeyGrantResponse]{Issue: issue}); err == nil {
		t.Fatal("a stored grant type without a store was accepted")
	}
	for _, headerNames := range []string{`7`, `null`, `["not a field name!"]`, `["X-Api-Key","x-api-key"]`, `[""]`} {
		if _, err := StoredAPIKeyGrantType(StoredCredentialGrantTypeOptions[aep.APIKeyGrantResponse]{
			Config: aep.GrantTypeConfig{Additional: aep.AdditionalMembers{"header_names": json.RawMessage(headerNames)}},
			Issue:  issue, Store: store,
		}); err == nil {
			t.Fatalf("header_names %s was accepted", headerNames)
		}
	}
	definition, err := StoredBasicGrantType(StoredCredentialGrantTypeOptions[aep.BasicGrantResponse]{
		Issue: func(context.Context, aep.GrantRequest, GrantContext) (aep.BasicGrantResponse, error) {
			return aep.BasicGrantResponse{}, nil
		},
		Store: store,
	})
	if err != nil || definition.Config.SupportsPerCredentialRevoke != "true" {
		t.Fatalf("a stored grant type did not advertise per-credential Revoke: %#v, %v", definition, err)
	}
}

func TestStoredCredentialHandlerRejectsUnusableIssuance(t *testing.T) {
	expiry := testNow.Add(time.Hour).UTC().Format(time.RFC3339)
	for _, test := range []struct {
		issue func() (aep.OAuthBearerGrantResponse, error)
		name  string
		save  func(ServiceCredentialRecord) error
	}{
		{name: "issuer fails", issue: func() (aep.OAuthBearerGrantResponse, error) { return aep.OAuthBearerGrantResponse{}, errStore }},
		{name: "credential fails validation", issue: func() (aep.OAuthBearerGrantResponse, error) {
			return aep.OAuthBearerGrantResponse{AccessToken: "token", CredentialID: "credential-1", ExpiresAt: expiry}, nil
		}},
		{name: "credential expires before issuance", issue: func() (aep.OAuthBearerGrantResponse, error) {
			return aep.OAuthBearerGrantResponse{
				AccessToken: "token", CredentialID: "credential-1", ExpiresAt: testNow.Add(-time.Hour).UTC().Format(time.RFC3339), TokenType: "Bearer",
			}, nil
		}},
		{name: "store fails", save: func(ServiceCredentialRecord) error { return errStore }},
	} {
		t.Run(test.name, func(t *testing.T) {
			issue := test.issue
			if issue == nil {
				issue = func() (aep.OAuthBearerGrantResponse, error) {
					return aep.OAuthBearerGrantResponse{AccessToken: "token", CredentialID: "credential-1", ExpiresAt: expiry, TokenType: "Bearer"}, nil
				}
			}
			definition, err := StoredOAuthBearerGrantType(StoredCredentialGrantTypeOptions[aep.OAuthBearerGrantResponse]{
				Issue: func(context.Context, aep.GrantRequest, GrantContext) (aep.OAuthBearerGrantResponse, error) {
					return issue()
				},
				Store: stubCredentialStore{save: test.save},
			})
			if err != nil {
				t.Fatal(err)
			}
			service := newTestService(t, Options{GrantTypes: []GrantTypeDefinition{definition}})
			seedEnrollment(t, service.enrollmentStore)
			if _, err := service.Grant(context.Background(), []byte(`{"grant_type":"oauth-bearer"}`), commandOptions(aep.AssertionGrant, "grant-"+test.name, "grant-"+test.name)); err == nil {
				t.Fatalf("unusable issuance was accepted for %s", test.name)
			}
		})
	}
}

func TestStoredCredentialHandlerValidatesStoreResponses(t *testing.T) {
	expiry := testNow.Add(time.Hour)
	for _, test := range []struct {
		match *CredentialMatch
		name  string
	}{
		{name: "no Agent", match: &CredentialMatch{CredentialID: "credential-1", ExpiresAt: expiry, GrantType: aep.GrantTypeOAuthBearer}},
		{name: "no credential identifier", match: &CredentialMatch{AgentDID: "did:web:agent.example", ExpiresAt: expiry, GrantType: aep.GrantTypeOAuthBearer}},
		{name: "already expired", match: &CredentialMatch{AgentDID: "did:web:agent.example", CredentialID: "credential-1", ExpiresAt: testNow, GrantType: aep.GrantTypeOAuthBearer}},
		{name: "another grant type", match: &CredentialMatch{AgentDID: "did:web:agent.example", CredentialID: "credential-1", ExpiresAt: expiry, GrantType: aep.GrantTypeAPIKey}},
	} {
		t.Run(test.name, func(t *testing.T) {
			definition, err := StoredOAuthBearerGrantType(StoredCredentialGrantTypeOptions[aep.OAuthBearerGrantResponse]{
				Issue: func(context.Context, aep.GrantRequest, GrantContext) (aep.OAuthBearerGrantResponse, error) {
					return aep.OAuthBearerGrantResponse{}, nil
				},
				Store: stubCredentialStore{authenticate: func(aep.GrantType, CredentialAuthenticationInput) (*CredentialMatch, error) {
					return test.match, nil
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			service := newTestService(t, Options{
				AuthenticationMethods: []aep.AuthenticationMethod{aep.AuthenticationMethod(aep.GrantTypeOAuthBearer)},
				GrantTypes:            []GrantTypeDefinition{definition},
			})
			seedEnrollment(t, service.enrollmentStore)
			if _, err := service.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{
				Headers: http.Header{"Authorization": {"Bearer token"}}, Method: http.MethodGet, URL: mustURL(t, "https://service.example/private"),
			}); err == nil {
				t.Fatalf("an invalid credential match was accepted for %s", test.name)
			}
		})
	}

	failing, err := StoredOAuthBearerGrantType(StoredCredentialGrantTypeOptions[aep.OAuthBearerGrantResponse]{
		Issue: func(context.Context, aep.GrantRequest, GrantContext) (aep.OAuthBearerGrantResponse, error) {
			return aep.OAuthBearerGrantResponse{}, nil
		},
		Store: stubCredentialStore{
			authenticate: func(aep.GrantType, CredentialAuthenticationInput) (*CredentialMatch, error) { return nil, errStore },
			detect:       func(aep.GrantType, CredentialAuthenticationInput) (bool, error) { return false, errStore },
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	service := newTestService(t, Options{
		AuthenticationMethods: []aep.AuthenticationMethod{aep.AuthenticationMethod(aep.GrantTypeOAuthBearer)},
		GrantTypes:            []GrantTypeDefinition{failing},
	})
	if _, err := service.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{
		Headers: http.Header{"Authorization": {"Bearer token"}}, Method: http.MethodGet, URL: mustURL(t, "https://service.example/private"),
	}); err == nil {
		t.Fatal("a credential store failure was swallowed")
	}
}

func TestAuthenticateProtectedResourceRejectsMalformedPrincipals(t *testing.T) {
	valid := AuthenticatedPrincipal{
		AgentDID: "did:web:agent.example", AuthenticationKind: AuthenticationKindSessionCredential,
		AuthenticationMethod: "custom-session", CredentialID: "credential-1", GrantType: "custom-session",
	}
	for _, test := range []struct {
		mutate func(*AuthenticatedPrincipal)
		name   string
	}{
		{name: "no Agent", mutate: func(principal *AuthenticatedPrincipal) { principal.AgentDID = "" }},
		{name: "another method", mutate: func(principal *AuthenticatedPrincipal) { principal.AuthenticationMethod = "other-session" }},
		{name: "wrong kind", mutate: func(principal *AuthenticatedPrincipal) { principal.AuthenticationKind = AuthenticationKindJWT }},
		{name: "another grant type", mutate: func(principal *AuthenticatedPrincipal) { principal.GrantType = "other-session" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			principal := valid
			test.mutate(&principal)
			service := newTestService(t, Options{
				AuthenticationMethods: []aep.AuthenticationMethod{"custom-session"},
				GrantTypes: []GrantTypeDefinition{{GrantType: "custom-session", Handler: &testGrantHandler{
					authenticate: func(CredentialAuthenticationInput) (*AuthenticatedPrincipal, error) { return &principal, nil },
				}}},
			})
			seedEnrollment(t, service.enrollmentStore)
			if _, err := service.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{
				Headers: http.Header{"Authorization": {"Bearer token"}}, Method: http.MethodGet, URL: mustURL(t, "https://service.example/private"),
			}); err == nil {
				t.Fatalf("an invalid principal was accepted for %s", test.name)
			}
		})
	}

	inactive := newTestService(t, Options{
		AuthenticationMethods: []aep.AuthenticationMethod{aep.AuthenticationMethodJWT, "custom-session"},
		EnrollmentStore: stubEnrollmentStore{find: func(agentDID string) (*EnrollmentRecord, error) {
			record := activeEnrollment(agentDID)
			record.Status = aep.AgentSuspended
			return &record, nil
		}},
		GrantTypes: []GrantTypeDefinition{{GrantType: "custom-session", Handler: &testGrantHandler{
			authenticate: func(CredentialAuthenticationInput) (*AuthenticatedPrincipal, error) {
				principal := valid
				return &principal, nil
			},
		}}},
	})
	resource := mustURL(t, "https://service.example/private")
	session, err := inactive.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{
		Headers: http.Header{"Authorization": {"Bearer token"}}, Method: http.MethodGet, URL: resource,
	})
	if err != nil || session.Authenticated || session.Response.Body.Code != aep.ErrorNotRecognized {
		t.Fatalf("a suspended identity authenticated with a session credential: %#v, %v", session, err)
	}
	jwt, err := inactive.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{
		Headers: http.Header{"Authorization": {"AEP " + assertion(aep.AssertionAuthenticate, "suspended-jwt", resource.String())}},
		Method:  http.MethodGet, URL: resource,
	})
	if err != nil || jwt.Authenticated || jwt.Response.Body.Code != aep.ErrorNotRecognized {
		t.Fatalf("a suspended identity authenticated with an assertion: %#v, %v", jwt, err)
	}

	failing := newTestService(t, Options{
		AuthenticationMethods: []aep.AuthenticationMethod{aep.AuthenticationMethodJWT, "custom-session"},
		EnrollmentStore:       stubEnrollmentStore{find: func(string) (*EnrollmentRecord, error) { return nil, errStore }},
		GrantTypes: []GrantTypeDefinition{{GrantType: "custom-session", Handler: &testGrantHandler{
			authenticate: func(CredentialAuthenticationInput) (*AuthenticatedPrincipal, error) {
				principal := valid
				return &principal, nil
			},
		}}},
	})
	if _, err := failing.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{
		Headers: http.Header{"Authorization": {"Bearer token"}}, Method: http.MethodGet, URL: resource,
	}); err == nil {
		t.Fatal("an enrollment store failure was swallowed during session authentication")
	}
	if _, err := failing.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{
		Headers: http.Header{"Authorization": {"AEP " + assertion(aep.AssertionAuthenticate, "store-failure", resource.String())}},
		Method:  http.MethodGet, URL: resource,
	}); err == nil {
		t.Fatal("an enrollment store failure was swallowed during assertion authentication")
	}
}

func TestMemoryServiceCredentialStoreGuardsIssuanceAndRevocation(t *testing.T) {
	store := NewMemoryServiceCredentialStore()
	expiry := testNow.Add(time.Hour)
	record := func(credentialID string, token string) ServiceCredentialRecord {
		return ServiceCredentialRecord{
			AgentDID: "did:web:agent.example", CreatedAt: testNow,
			Credential: aep.OAuthBearerGrantResponse{
				AccessToken: token, CredentialID: credentialID, ExpiresAt: expiry.UTC().Format(time.RFC3339), TokenType: "Bearer",
			},
			CredentialID: credentialID, ExpiresAt: expiry, GrantType: aep.GrantTypeOAuthBearer,
		}
	}
	if err := store.SaveCredential(context.Background(), record("credential-1", "token-1")); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveCredential(context.Background(), record("credential-1", "token-2")); err == nil {
		t.Fatal("a reassigned credential identifier was accepted")
	}
	if err := store.SaveCredential(context.Background(), record("credential-2", "token-1")); err == nil {
		t.Fatal("a reissued credential secret was accepted")
	}
	if err := store.SaveCredential(cancelledContext(), record("credential-3", "token-3")); err == nil {
		t.Fatal("a cancelled context still wrote a credential")
	}

	mismatched := record("credential-4", "token-4")
	mismatched.ExpiresAt = expiry.Add(time.Minute)
	if err := store.SaveCredential(context.Background(), mismatched); err == nil {
		t.Fatal("a record whose expiry disagrees with its credential was accepted")
	}
	incomplete := record("credential-5", "token-5")
	incomplete.AgentDID = ""
	if err := store.SaveCredential(context.Background(), incomplete); err == nil {
		t.Fatal("a record without an Agent was accepted")
	}
	invalid := record("credential-6", "token-6")
	invalid.Credential = aep.OAuthBearerGrantResponse{CredentialID: "credential-6"}
	if err := store.SaveCredential(context.Background(), invalid); err == nil {
		t.Fatal("an invalid credential was accepted")
	}
	foreign := record("credential-7", "token-7")
	foreign.Credential = aep.APIKeyGrantResponse{
		APIKey: "key", CredentialID: "credential-7", ExpiresAt: expiry.UTC().Format(time.RFC3339), Header: "x-api-key",
	}
	if err := store.SaveCredential(context.Background(), foreign); err == nil {
		t.Fatal("a credential of another grant type was accepted")
	}

	input := CredentialAuthenticationInput{Headers: http.Header{"Authorization": {"Bearer token-1"}}, Now: testNow}
	match, err := store.AuthenticateCredential(context.Background(), aep.GrantTypeOAuthBearer, input)
	if err != nil || match == nil || match.CredentialID != "credential-1" {
		t.Fatalf("the stored credential did not authenticate: %#v, %v", match, err)
	}
	if _, err := store.AuthenticateCredential(cancelledContext(), aep.GrantTypeOAuthBearer, input); err == nil {
		t.Fatal("a cancelled context still authenticated")
	}
	if _, err := store.HasCredentialPresentation(cancelledContext(), aep.GrantTypeOAuthBearer, input); err == nil {
		t.Fatal("a cancelled context still probed for a presentation")
	}
	detected, err := store.HasCredentialPresentation(context.Background(), aep.GrantTypeOAuthBearer, input)
	if err != nil || !detected {
		t.Fatalf("a bearer presentation went undetected: %v, %v", detected, err)
	}

	if err := store.RevokeCredential(context.Background(), "did:web:agent.example", aep.GrantTypeOAuthBearer, "credential-1", time.Time{}); err == nil {
		t.Fatal("revocation without a time was accepted")
	}
	if err := store.RevokeGrantType(context.Background(), "did:web:agent.example", aep.GrantTypeOAuthBearer, time.Time{}); err == nil {
		t.Fatal("bulk revocation without a time was accepted")
	}
	if err := store.RevokeCredential(cancelledContext(), "did:web:agent.example", aep.GrantTypeOAuthBearer, "credential-1", testNow); err == nil {
		t.Fatal("a cancelled context still revoked")
	}
	if err := store.RevokeGrantType(cancelledContext(), "did:web:agent.example", aep.GrantTypeOAuthBearer, testNow); err == nil {
		t.Fatal("a cancelled context still bulk-revoked")
	}
	if err := store.RevokeCredential(context.Background(), "did:web:attacker.example", aep.GrantTypeOAuthBearer, "credential-1", testNow); err != nil {
		t.Fatal(err)
	}
	if match, err := store.AuthenticateCredential(context.Background(), aep.GrantTypeOAuthBearer, input); err != nil || match == nil {
		t.Fatalf("another Agent revoked a credential it does not hold: %#v, %v", match, err)
	}
	if err := store.RevokeGrantType(context.Background(), "did:web:agent.example", aep.GrantTypeOAuthBearer, testNow); err != nil {
		t.Fatal(err)
	}
	if match, err := store.AuthenticateCredential(context.Background(), aep.GrantTypeOAuthBearer, input); err != nil || match != nil {
		t.Fatalf("a revoked credential still authenticated: %#v, %v", match, err)
	}
}

func TestMemoryServiceCredentialStoreStoresBasicCredentials(t *testing.T) {
	store := NewMemoryServiceCredentialStore()
	expiry := testNow.Add(time.Hour)
	credential := aep.BasicGrantResponse{
		CredentialID: "credential-1", ExpiresAt: expiry.UTC().Format(time.RFC3339), Password: "secret", Username: "agent",
	}
	if err := store.SaveCredential(context.Background(), ServiceCredentialRecord{
		AgentDID: "did:web:agent.example", CreatedAt: testNow, Credential: credential,
		CredentialID: "credential-1", ExpiresAt: expiry, GrantType: aep.GrantTypeBasic,
	}); err != nil {
		t.Fatal(err)
	}
	input := CredentialAuthenticationInput{Headers: http.Header{"Authorization": {"Basic YWdlbnQ6c2VjcmV0"}}, Now: testNow}
	match, err := store.AuthenticateCredential(context.Background(), aep.GrantTypeBasic, input)
	if err != nil || match == nil || match.CredentialID != "credential-1" {
		t.Fatalf("the Basic credential did not authenticate: %#v, %v", match, err)
	}
	wrong := CredentialAuthenticationInput{Headers: http.Header{"Authorization": {"Basic YWdlbnQ6d3Jvbmc="}}, Now: testNow}
	if match, err := store.AuthenticateCredential(context.Background(), aep.GrantTypeBasic, wrong); err != nil || match != nil {
		t.Fatalf("a wrong Basic password authenticated: %#v, %v", match, err)
	}
	bearer := CredentialAuthenticationInput{Headers: http.Header{"Authorization": {"Bearer YWdlbnQ6c2VjcmV0"}}, Now: testNow}
	if match, err := store.AuthenticateCredential(context.Background(), aep.GrantTypeBasic, bearer); err != nil || match != nil {
		t.Fatalf("a Basic credential authenticated under another scheme: %#v, %v", match, err)
	}
	none := CredentialAuthenticationInput{Headers: http.Header{}, Now: testNow}
	if match, err := store.AuthenticateCredential(context.Background(), aep.GrantTypeBasic, none); err != nil || match != nil {
		t.Fatalf("an absent presentation authenticated: %#v, %v", match, err)
	}
	if detected, err := store.HasCredentialPresentation(context.Background(), aep.GrantTypeAPIKey, none); err != nil || detected {
		t.Fatalf("an API-key presentation was detected without one: %v, %v", detected, err)
	}
}

func TestStoredCredentialHandlerRevokesByCredentialAndGrantType(t *testing.T) {
	var calls []string
	definition, err := StoredBasicGrantType(StoredCredentialGrantTypeOptions[aep.BasicGrantResponse]{
		Issue: func(context.Context, aep.GrantRequest, GrantContext) (aep.BasicGrantResponse, error) {
			return aep.BasicGrantResponse{}, nil
		},
		Store: stubCredentialStore{
			revoke: func(_ string, _ aep.GrantType, credentialID string, _ time.Time) error {
				calls = append(calls, "credential:"+credentialID)
				return nil
			},
			revokeAll: func(string, aep.GrantType, time.Time) error {
				calls = append(calls, "grant-type")
				return nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	service := newTestService(t, Options{GrantTypes: []GrantTypeDefinition{definition}})
	seedEnrollment(t, service.enrollmentStore)
	if _, err := service.Revoke(context.Background(), []byte(`{"grant_type":"basic","credential_id":"credential-1"}`), commandOptions(aep.AssertionRevoke, "revoke-one", "revoke-one")); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Revoke(context.Background(), []byte(`{"grant_type":"basic"}`), commandOptions(aep.AssertionRevoke, "revoke-type", "revoke-type")); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || calls[0] != "credential:credential-1" || calls[1] != "grant-type" {
		t.Fatalf("unexpected revocation calls: %v", calls)
	}
}

func TestBuiltInCredentialMetadataRequiresAKnownShape(t *testing.T) {
	if _, _, err := builtInCredentialMetadata(nil); err == nil {
		t.Fatal("an unknown credential shape was accepted")
	}
	if _, err := serviceCredentialRecord("", aep.BasicGrantResponse{}, testNow); err == nil {
		t.Fatal("a record without an Agent was built")
	}
	if _, err := serviceCredentialRecord("did:web:agent.example", aep.BasicGrantResponse{}, time.Time{}); err == nil {
		t.Fatal("a record without an issuance time was built")
	}
	if _, err := serviceCredentialRecord("did:web:agent.example", aep.BasicGrantResponse{ExpiresAt: "not a timestamp"}, testNow); err == nil {
		t.Fatal("a record with an unparseable expiry was built")
	}
	if _, err := memoryCredentialRecord(ServiceCredentialRecord{}); err == nil {
		t.Fatal("an empty credential record was stored")
	}
}

func TestHTTPHandlerConstructionAndDispatchEdges(t *testing.T) {
	service := newTestService(t, Options{})
	if _, err := NewHTTPHandler(nil, HTTPHandlerOptions{}); err == nil {
		t.Fatal("a handler without a Service was built")
	}
	if _, err := NewHTTPHandler(service, HTTPHandlerOptions{MaximumRequestBodyBytes: -1}); err == nil {
		t.Fatal("a negative body limit was accepted")
	}
	for _, cacheControl := range []string{"   ", "public\r\nX-Injected: 1"} {
		if _, err := NewHTTPHandler(service, HTTPHandlerOptions{InspectCacheControl: cacheControl}); err == nil {
			t.Fatalf("an unsafe Cache-Control value was accepted: %q", cacheControl)
		}
	}
	custom, err := NewHTTPHandler(service, HTTPHandlerOptions{InspectCacheControl: "no-store"})
	if err != nil {
		t.Fatal(err)
	}
	if recorder := serveRequest(custom, http.MethodGet, aep.WellKnownPath, "", nil); recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("the configured Cache-Control was ignored: %q", recorder.Header().Get("Cache-Control"))
	}
	if recorder := serveRequest(custom, http.MethodGet, aep.WellKnownPath, "", http.Header{"If-None-Match": {"*"}}); recorder.Code != http.StatusNotModified {
		t.Fatalf("a wildcard If-None-Match returned %d", recorder.Code)
	}
	etag := serveRequest(custom, http.MethodGet, aep.WellKnownPath, "", nil).Header().Get("ETag")
	if recorder := serveRequest(custom, http.MethodGet, aep.WellKnownPath, "", http.Header{"If-None-Match": {`"other", W/` + etag}}); recorder.Code != http.StatusNotModified {
		t.Fatalf("a weak ETag in a list returned %d", recorder.Code)
	}
	if recorder := serveRequest(custom, http.MethodGet, aep.WellKnownPath, "", http.Header{"If-None-Match": {`"other"`}}); recorder.Code != http.StatusOK {
		t.Fatalf("a non-matching ETag returned %d", recorder.Code)
	}

	var nilHandler *HTTPHandler
	if recorder := serveRequest(nilHandler, http.MethodGet, aep.WellKnownPath, "", nil); recorder.Code != http.StatusInternalServerError {
		t.Fatalf("a nil handler returned %d", recorder.Code)
	}
	if recorder := serveRequest(&HTTPHandler{}, http.MethodGet, aep.WellKnownPath, "", nil); recorder.Code != http.StatusInternalServerError {
		t.Fatalf("a handler without a Service returned %d", recorder.Code)
	}
	if recorder := serveRequest(custom, http.MethodGet, "/absent", "", nil); recorder.Code != http.StatusNotFound {
		t.Fatalf("an unknown path returned %d", recorder.Code)
	}

	limited, err := NewHTTPHandler(service, HTTPHandlerOptions{MaximumRequestBodyBytes: 8})
	if err != nil {
		t.Fatal(err)
	}
	oversized := serveRequest(limited, http.MethodPost, "/aep/enroll", strings.Repeat("x", 64), commandHeaders("", "oversized"))
	if oversized.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("an oversized body returned %d", oversized.Code)
	}
}

func TestCommandAssertionAcceptsOnlyASingleAEPCarrier(t *testing.T) {
	for _, test := range []struct {
		expected string
		header   http.Header
		name     string
	}{
		{name: "single AEP value", header: http.Header{"Authorization": {"AEP token"}}, expected: "token"},
		{name: "lowercase scheme", header: http.Header{"Authorization": {"aep token"}}, expected: "token"},
		{name: "repeated field lines", header: http.Header{"Authorization": {"AEP one", "AEP two"}}},
		{name: "another scheme", header: http.Header{"Authorization": {"Bearer token"}}},
		{name: "unparseable value", header: http.Header{"Authorization": {"AEP"}}},
		{name: "absent", header: http.Header{}},
	} {
		if value := commandAssertion(test.header); value != test.expected {
			t.Fatalf("%s produced %q, expected %q", test.name, value, test.expected)
		}
	}
}

func TestProtectedResourceMiddlewareHandlesDegenerateConfigurations(t *testing.T) {
	if _, err := NewProtectedResourceMiddleware(nil, "https://service.example"); err == nil {
		t.Fatal("middleware without a Service was built")
	}
	service := newTestService(t, Options{AuthenticationMethods: []aep.AuthenticationMethod{aep.AuthenticationMethodJWT}})
	middleware, err := NewProtectedResourceMiddleware(service, "https://service.example")
	if err != nil {
		t.Fatal(err)
	}
	recorder := serveRequest(middleware(nil), http.MethodGet, "/private", "", http.Header{})
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("an anonymous request returned %d", recorder.Code)
	}
	seedEnrollment(t, service.enrollmentStore)
	authenticated := serveRequest(middleware(nil), http.MethodGet, "/private", "", http.Header{
		"Authorization": {"AEP " + assertion(aep.AssertionAuthenticate, "middleware-notfound", "https://service.example/private")},
	})
	if authenticated.Code != http.StatusNotFound {
		t.Fatalf("the default next handler returned %d", authenticated.Code)
	}

	loopback := newTestService(t, Options{ClientAssertion: ClientAssertionOptions{AllowInsecureLoopback: true}})
	if _, err := NewProtectedResourceMiddleware(loopback, "http://127.0.0.1:8080"); err != nil {
		t.Fatalf("a permitted loopback origin was refused: %v", err)
	}
}

func TestPrincipalFromContextIsolatesItsScopes(t *testing.T) {
	if _, found := PrincipalFromContext(context.Background()); found {
		t.Fatal("a principal was found in an empty context")
	}
	principal := AuthenticatedPrincipal{AgentDID: "did:web:agent.example", Scopes: []string{"read"}}
	ctx := context.WithValue(context.Background(), principalContextKey{}, clonePrincipal(principal))
	first, found := PrincipalFromContext(ctx)
	if !found || len(first.Scopes) != 1 {
		t.Fatalf("unexpected principal: %#v, %v", first, found)
	}
	first.Scopes[0] = "write"
	second, _ := PrincipalFromContext(ctx)
	if second.Scopes[0] != "read" {
		t.Fatal("the stored principal's scopes are aliased")
	}
	principal.Scopes[0] = "write"
	third, _ := PrincipalFromContext(ctx)
	if third.Scopes[0] != "read" {
		t.Fatal("the stored principal aliases the caller's slice")
	}
}

func TestResponseWritersFailSafely(t *testing.T) {
	unencodable := httptestRecorder()
	writeServiceResult(unencodable, Result[chan int]{Body: make(chan int), ContentType: aep.MediaType, Status: http.StatusOK}, nil)
	if unencodable.Code != http.StatusInternalServerError {
		t.Fatalf("an unencodable body returned %d", unencodable.Code)
	}
	failed := httptestRecorder()
	writeServiceResult(failed, Result[aep.RevokeResponse]{}, errStore)
	if failed.Code != http.StatusInternalServerError {
		t.Fatalf("a failed command returned %d", failed.Code)
	}
	missing := httptestRecorder()
	writeProblemResponse(missing, nil)
	if missing.Code != http.StatusInternalServerError {
		t.Fatalf("an absent Problem returned %d", missing.Code)
	}

	// Result headers reach the response, but never the framing fields the writer owns.
	headers := httptestRecorder()
	writeServiceResult(headers, Result[aep.RevokeResponse]{
		ContentType: aep.MediaType,
		Headers:     http.Header{"Content-Length": {"999"}, "Content-Type": {"text/plain"}, "Retry-After": {"30"}},
		Status:      http.StatusOK,
	}, nil)
	if headers.Header().Get("Content-Type") != aep.MediaType || headers.Header().Get("Content-Length") != "2" {
		t.Fatalf("a result header overwrote the response framing: %v", headers.Header())
	}
	if headers.Header().Get("Retry-After") != "30" || headers.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected response headers: %v", headers.Header())
	}
	problem := httptestRecorder()
	writeProblemResponse(problem, &ProblemResponse{
		Body: aep.NewProblemDetails(aep.ErrorNotRecognized, "Not recognized", http.StatusUnauthorized), ContentType: aep.ProblemMediaType,
		Headers: http.Header{"Content-Length": {"999"}, "WWW-Authenticate": {"AEP"}}, Status: http.StatusUnauthorized,
	})
	if problem.Header().Get("Content-Length") == "999" || problem.Header().Get("WWW-Authenticate") != "AEP" {
		t.Fatalf("unexpected Problem headers: %v", problem.Header())
	}
}

func TestReadRequestBodyToleratesAnAbsentBody(t *testing.T) {
	request := &http.Request{Method: http.MethodPost, URL: &url.URL{Path: "/aep/enroll"}}
	body, err := readRequestBody(httptestRecorder(), request, DefaultMaximumRequestBodyBytes)
	if err != nil || body != nil {
		t.Fatalf("an absent body produced %q, %v", body, err)
	}
}

func TestMemoryEnrollmentStoreRejectsInvalidUsage(t *testing.T) {
	store := NewMemoryEnrollmentStore()
	if _, _, err := store.FindOrCreateEnrollment(context.Background(), "", func() (EnrollmentRecord, error) {
		return EnrollmentRecord{}, nil
	}); err == nil {
		t.Fatal("an empty Agent DID was accepted")
	}
	if _, _, err := store.FindOrCreateEnrollment(context.Background(), "did:web:agent.example", nil); err == nil {
		t.Fatal("a missing create function was accepted")
	}
	if _, _, err := store.FindOrCreateEnrollment(cancelledContext(), "did:web:agent.example", func() (EnrollmentRecord, error) {
		return activeEnrollment("did:web:agent.example"), nil
	}); err == nil {
		t.Fatal("a cancelled context still created a record")
	}
	if _, _, err := store.FindOrCreateEnrollment(context.Background(), "did:web:agent.example", func() (EnrollmentRecord, error) {
		return EnrollmentRecord{}, errStore
	}); err == nil {
		t.Fatal("a failing create function was swallowed")
	}
	if _, _, err := store.FindOrCreateEnrollment(context.Background(), "did:web:agent.example", func() (EnrollmentRecord, error) {
		return activeEnrollment("did:web:attacker.example"), nil
	}); err == nil {
		t.Fatal("a record for another Agent was stored")
	}
	if _, err := store.FindEnrollment(cancelledContext(), "did:web:agent.example"); err == nil {
		t.Fatal("a cancelled context still read a record")
	}
	if record, err := store.FindEnrollment(context.Background(), "did:web:absent.example"); err != nil || record != nil {
		t.Fatalf("an absent record produced %#v, %v", record, err)
	}

	for _, mutate := range []func(*EnrollmentRecord){
		func(record *EnrollmentRecord) { record.AgentDID = "" },
		func(record *EnrollmentRecord) { record.EnrollmentID = "" },
		func(record *EnrollmentRecord) { record.CreatedAt = time.Time{} },
		func(record *EnrollmentRecord) { record.Since = time.Time{} },
		func(record *EnrollmentRecord) { record.UpdatedAt = time.Time{} },
		func(record *EnrollmentRecord) { record.Status = "archived" },
	} {
		record := activeEnrollment("did:web:agent.example")
		mutate(&record)
		if _, err := store.SaveEnrollment(context.Background(), record); err == nil {
			t.Fatalf("an invalid record was saved: %#v", record)
		}
	}
	if _, err := store.SaveEnrollment(cancelledContext(), activeEnrollment("did:web:agent.example")); err == nil {
		t.Fatal("a cancelled context still saved a record")
	}

	claims, err := aep.ParseClaimValues([]byte(`{"contact.email":"agent@example.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	withClaims := activeEnrollment("did:web:claims.example")
	withClaims.Claims = &claims
	saved, err := store.SaveEnrollment(context.Background(), withClaims)
	if err != nil || saved.Claims == nil || saved.Claims == withClaims.Claims {
		t.Fatalf("claim values were not copied: %#v, %v", saved, err)
	}
	if _, err := cloneEnrollment(EnrollmentRecord{Claims: &aep.ClaimValues{Additional: aep.AdditionalMembers{"contact.email": json.RawMessage(`7`)}}}); err == nil {
		t.Fatal("an invalid claim set cloned successfully")
	}
}

func TestMemoryReplayStoreRejectsUnusableRecords(t *testing.T) {
	store := NewMemoryReplayStore()
	if _, err := store.ConsumeReplay(cancelledContext(), ReplayRecord{ExpiresAt: 1, JWTID: "j", Subject: "s"}, 0); err == nil {
		t.Fatal("a cancelled context still consumed a record")
	}
	for _, record := range []ReplayRecord{
		{ExpiresAt: 1, JWTID: "j"},
		{ExpiresAt: 1, Subject: "s"},
		{JWTID: "j", Subject: "s"},
	} {
		if _, err := store.ConsumeReplay(context.Background(), record, 0); err == nil {
			t.Fatalf("an unusable replay record was accepted: %#v", record)
		}
	}
}

func TestMemoryIdempotencyStoreRejectsInvalidInput(t *testing.T) {
	store := NewMemoryIdempotencyStore()
	valid := IdempotencyInput{AgentDID: "did:web:agent.example", Command: IdempotentEnroll, IdempotencyKey: "key", RequestHash: "sha256:abc"}
	execute := func() (StoredResponse, error) {
		return StoredResponse{Body: json.RawMessage(`{}`), ContentType: aep.MediaType, Status: http.StatusOK}, nil
	}
	for _, mutate := range []func(*IdempotencyInput){
		func(input *IdempotencyInput) { input.AgentDID = "" },
		func(input *IdempotencyInput) { input.Command = "" },
		func(input *IdempotencyInput) { input.IdempotencyKey = "" },
		func(input *IdempotencyInput) { input.RequestHash = "" },
	} {
		input := valid
		mutate(&input)
		if _, err := store.ExecuteIdempotent(context.Background(), input, execute); err == nil {
			t.Fatalf("invalid idempotency input was accepted: %#v", input)
		}
	}
	if _, err := store.ExecuteIdempotent(context.Background(), valid, nil); err == nil {
		t.Fatal("a missing execute function was accepted")
	}
	if _, err := store.ExecuteIdempotent(context.Background(), valid, func() (StoredResponse, error) {
		return StoredResponse{}, errStore
	}); err == nil {
		t.Fatal("a failing execution was recorded")
	}
	created, err := store.ExecuteIdempotent(context.Background(), valid, execute)
	if err != nil || created.State != IdempotencyCreated || created.Response.CreatedAt.IsZero() {
		t.Fatalf("an execution without a timestamp was not stamped: %#v, %v", created, err)
	}
	conflicting := valid
	conflicting.Command = IdempotentGrant
	conflict, err := store.ExecuteIdempotent(context.Background(), conflicting, execute)
	if err != nil || conflict.State != IdempotencyConflict {
		t.Fatalf("a cross-command reuse was not a conflict: %#v, %v", conflict, err)
	}
}

func TestCloneHeaderPreservesAbsence(t *testing.T) {
	if cloneHeader(nil) != nil {
		t.Fatal("an absent header set became present")
	}
	source := http.Header{"Retry-After": {"30"}}
	clone := cloneHeader(source)
	clone.Set("Retry-After", "60")
	if source.Get("Retry-After") != "30" {
		t.Fatal("the cloned header aliases its source")
	}
}

func TestStaticEnrollmentPolicyDefaultsAndIsolatesItsDecision(t *testing.T) {
	decision := EnrollmentDecision{RequirementsPending: []string{"contact.email"}, VerificationPending: []string{"domain-control"}}
	policy := NewStaticEnrollmentPolicy(decision)
	first, err := policy.DecideEnrollment(context.Background(), aep.EnrollRequest{}, EnrollmentPolicyContext{Now: testNow})
	if err != nil || first.Status != aep.EnrollmentActive {
		t.Fatalf("unexpected decision: %#v, %v", first, err)
	}
	first.RequirementsPending[0] = "mutated"
	second, err := policy.DecideEnrollment(context.Background(), aep.EnrollRequest{}, EnrollmentPolicyContext{Now: testNow})
	if err != nil || second.RequirementsPending[0] != "contact.email" {
		t.Fatalf("the static decision is aliased: %#v, %v", second, err)
	}
}

func TestDIDWebAssertionVerifierRejectsUnusableAssertions(t *testing.T) {
	verify := NewDIDWebAssertionVerifier(DIDWebVerifierOptions{})
	for _, test := range []struct {
		assertion string
		name      string
	}{
		{name: "not a JWT", assertion: "opaque"},
		{name: "no issuer", assertion: customAssertion(defaultHeader(), map[string]any{"sub": "did:web:agent.example"})},
		{name: "empty issuer", assertion: customAssertion(defaultHeader(), map[string]any{"iss": ""})},
		{name: "non-string issuer", assertion: customAssertion(defaultHeader(), map[string]any{"iss": 7})},
		{name: "no key identifier", assertion: customAssertion(map[string]any{"alg": "EdDSA", "typ": "JWT"}, defaultClaims(aep.AssertionStatus, "no-kid"))},
		{name: "empty key identifier", assertion: customAssertion(map[string]any{"alg": "EdDSA", "kid": "", "typ": "JWT"}, defaultClaims(aep.AssertionStatus, "empty-kid"))},
		{name: "unresolvable DID", assertion: customAssertion(defaultHeader(), defaultClaims(aep.AssertionStatus, "unresolvable"))},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := verify(context.Background(), test.assertion, AssertionVerificationContext{
				ServiceDID: "did:web:service.example", SigningAlgorithms: []aep.SigningAlgorithm{aep.SigningAlgorithmEdDSA},
			}); err == nil {
				t.Fatal("an unusable assertion was verified")
			}
		})
	}
}

func httptestRecorder() *httptest.ResponseRecorder {
	return httptest.NewRecorder()
}
