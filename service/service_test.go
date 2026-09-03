package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	aep "github.com/aep-foundation/aep-go"
)

var testNow = time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)

func TestServiceCommandsAndIdempotency(t *testing.T) {
	var policyCalls atomic.Int32
	var grantCalls atomic.Int32
	handler := &testGrantHandler{
		grant: func(aep.GrantRequest, GrantContext) (json.RawMessage, error) {
			grantCalls.Add(1)
			return json.RawMessage(`{"access_token":"secret","credential_id":"credential-1"}`), nil
		},
	}
	service := newTestService(t, Options{
		Claims: &aep.InspectClaims{Required: []aep.ClaimName{aep.ClaimContactEmail}},
		EnrollmentPolicy: testEnrollmentPolicy(func(aep.EnrollRequest, EnrollmentPolicyContext) (EnrollmentDecision, error) {
			policyCalls.Add(1)
			return EnrollmentDecision{Status: aep.EnrollmentActive}, nil
		}),
		GrantTypes: []GrantTypeDefinition{{GrantType: "custom-session", Handler: handler}},
	})

	missing, err := service.Enroll(context.Background(), []byte(`{"agent_did":"did:web:agent.example"}`), commandOptions(aep.AssertionEnroll, "missing", "enroll-missing"))
	if err != nil || missing.Problem == nil || missing.Problem.Code != aep.ErrorRequirementsUnmet || policyCalls.Load() != 0 {
		t.Fatalf("unexpected missing-claims result: %#v, %v", missing, err)
	}

	enrollBody := []byte(`{"agent_did":"did:web:agent.example","claims":{"contact.email":"agent@example.com"}}`)
	enrolled, err := service.Enroll(context.Background(), enrollBody, commandOptions(aep.AssertionEnroll, "enroll-1", "enroll-key"))
	if err != nil || enrolled.Problem != nil || enrolled.Body.Status != aep.AgentActive || policyCalls.Load() != 1 {
		t.Fatalf("unexpected enrollment result: %#v, %v", enrolled, err)
	}
	repeated, err := service.Enroll(context.Background(), enrollBody, commandOptions(aep.AssertionEnroll, "enroll-2", "another-key"))
	if err != nil || repeated.Body.Status != aep.AgentActive || policyCalls.Load() != 1 {
		t.Fatalf("existing enrollment was not stable: %#v, %v", repeated, err)
	}

	status, err := service.Status(context.Background(), commandOptions(aep.AssertionStatus, "status-1", ""))
	if err != nil || status.Body.Status != aep.AgentActive || status.Body.Since == "" {
		t.Fatalf("unexpected status result: %#v, %v", status, err)
	}

	grantBody := []byte(`{"grant_type":"custom-session"}`)
	granted, err := service.Grant(context.Background(), grantBody, commandOptions(aep.AssertionGrant, "grant-1", "grant-key"))
	if err != nil || granted.Problem != nil || grantCalls.Load() != 1 {
		t.Fatalf("unexpected Grant result: %#v, %v", granted, err)
	}
	replayed, err := service.Grant(context.Background(), grantBody, commandOptions(aep.AssertionGrant, "grant-2", "grant-key"))
	if err != nil || replayed.Problem != nil || grantCalls.Load() != 1 || string(replayed.Body) != string(granted.Body) {
		t.Fatalf("Grant was not replayed: %#v, %v", replayed, err)
	}

	conflict, err := service.Revoke(context.Background(), []byte(`{"grant_type":"custom-session"}`), commandOptions(aep.AssertionRevoke, "revoke-1", "grant-key"))
	if err != nil || conflict.Problem == nil || conflict.Problem.Code != aep.ErrorIdempotencyConflict {
		t.Fatalf("cross-command idempotency conflict was not rejected: %#v, %v", conflict, err)
	}
}

func TestServiceRestrictsInitialEnrollmentStatus(t *testing.T) {
	for _, test := range []struct {
		status aep.EnrollmentStatus
		valid  bool
	}{
		{status: aep.EnrollmentActive, valid: true},
		{status: aep.EnrollmentPending, valid: true},
		{status: aep.EnrollmentRejected, valid: true},
		{status: aep.EnrollmentStatus(aep.AgentSuspended)},
		{status: aep.EnrollmentStatus(aep.AgentTerminated)},
		{status: aep.EnrollmentStatus(aep.AgentUnavailable)},
		{status: "unknown"},
	} {
		t.Run(string(test.status), func(t *testing.T) {
			instance := newTestService(t, Options{
				EnrollmentPolicy: testEnrollmentPolicy(func(aep.EnrollRequest, EnrollmentPolicyContext) (EnrollmentDecision, error) {
					return EnrollmentDecision{Status: test.status}, nil
				}),
			})
			result, err := instance.Enroll(context.Background(), []byte(`{"agent_did":"did:web:agent.example"}`), commandOptions(aep.AssertionEnroll, "initial-status", "initial-status"))
			if test.valid && (err != nil || result.Body.Status != aep.AgentStatus(test.status)) {
				t.Fatalf("valid initial enrollment status was rejected: %#v, %v", result, err)
			}
			if !test.valid && (err == nil || !strings.Contains(err.Error(), "invalid initial status")) {
				t.Fatalf("invalid initial enrollment status was accepted: %#v, %v", result, err)
			}
		})
	}
}

func TestMemoryEnrollmentStoreFindOrCreateIsAtomic(t *testing.T) {
	store := NewMemoryEnrollmentStore()
	start := make(chan struct{})
	var calls atomic.Int32
	results := make(chan EnrollmentRecord, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			record, _, err := store.FindOrCreateEnrollment(context.Background(), "did:web:agent.example", func() (EnrollmentRecord, error) {
				calls.Add(1)
				<-start
				return activeEnrollment("did:web:agent.example"), nil
			})
			if err != nil {
				t.Errorf("FindOrCreateEnrollment failed: %v", err)
				return
			}
			results <- record
		}()
	}
	for calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	close(start)
	wait.Wait()
	close(results)
	if calls.Load() != 1 {
		t.Fatalf("create ran %d times", calls.Load())
	}
	for record := range results {
		if record.EnrollmentID != "enrollment-1" {
			t.Fatalf("unexpected enrollment: %#v", record)
		}
	}
}

func TestMemoryEnrollmentStoreSavesLifecycleStateWithoutAliasing(t *testing.T) {
	store := NewMemoryEnrollmentStore()
	record := activeEnrollment("did:web:agent.example")
	record.Status = aep.AgentPending
	record.RequirementsPending = []string{"approval"}
	saved, err := store.SaveEnrollment(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	saved.RequirementsPending[0] = "mutated"
	found, err := store.FindEnrollment(context.Background(), record.AgentDID)
	if err != nil || found == nil || found.RequirementsPending[0] != "approval" {
		t.Fatalf("stored enrollment was aliased: %#v, %v", found, err)
	}
}

func TestServiceRejectsInvalidAssertionsBeforeRequestDetails(t *testing.T) {
	service := newTestService(t, Options{})
	result, err := service.Enroll(context.Background(), []byte(`not-json`), CommandOptions{ClientAssertion: "not-a-jwt"})
	if err != nil || result.Problem == nil || result.Problem.Code != aep.ErrorNotRecognized || result.Headers.Get("WWW-Authenticate") == "" {
		t.Fatalf("invalid assertion leaked request validation: %#v, %v", result, err)
	}
}

func TestServiceRejectsExpirationBoundaryFromCustomVerifier(t *testing.T) {
	boundary := testNow.Add(90 * time.Second)
	clockSkew := 30 * time.Second
	claims := aep.ClientAssertionClaims{
		Audience: "did:web:service.example", ExpiresAt: boundary.Add(-30 * time.Second).Unix(),
		IssuedAt: testNow.Unix(), Issuer: "did:web:agent.example", JWTID: "expiration-boundary",
		Operation: aep.AssertionStatus, Subject: "did:web:agent.example",
	}
	service, err := New(Options{
		ClientAssertion: ClientAssertionOptions{ClockSkew: &clockSkew},
		Clock:           func() time.Time { return boundary },
		IdentityMethods: []aep.IdentityMethod{aep.IdentityMethodDIDWeb},
		ServiceDID:      claims.Audience,
		Verifier: func(context.Context, string, AssertionVerificationContext) (aep.ClientAssertionClaims, error) {
			return claims, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Status(context.Background(), CommandOptions{
		ClientAssertion: assertion(aep.AssertionStatus, claims.JWTID, ""),
	})
	if err != nil || result.Problem == nil || result.Problem.Code != aep.ErrorNotRecognized {
		t.Fatalf("assertion was accepted at the expiration boundary: %#v, %v", result, err)
	}
}

func TestServiceGrantAndRevokeFailures(t *testing.T) {
	var revoked []aep.GrantType
	first := &testGrantHandler{revoke: func(_ aep.RevokeRequest, context RevokeContext) error {
		revoked = append(revoked, context.GrantType)
		return nil
	}}
	second := &testGrantHandler{revoke: func(_ aep.RevokeRequest, context RevokeContext) error {
		revoked = append(revoked, context.GrantType)
		return nil
	}}
	service := newTestService(t, Options{GrantTypes: []GrantTypeDefinition{
		{GrantType: "zeta", Handler: first}, {GrantType: "alpha", Handler: second},
	}})
	seedEnrollment(t, service.enrollmentStore)

	unsupported, err := service.Grant(context.Background(), []byte(`{"grant_type":"unknown"}`), commandOptions(aep.AssertionGrant, "grant-unsupported", "grant-unsupported"))
	if err != nil || unsupported.Problem == nil || unsupported.Problem.Code != aep.ErrorUnsupportedGrantType {
		t.Fatalf("unsupported Grant Type was not rejected: %#v, %v", unsupported, err)
	}
	targeted, err := service.Revoke(context.Background(), []byte(`{"credential_id":"credential-1","grant_type":"alpha"}`), commandOptions(aep.AssertionRevoke, "revoke-targeted", "revoke-targeted"))
	if err != nil || targeted.Problem == nil || targeted.Problem.Code != aep.ErrorInvalidRequest {
		t.Fatalf("unadvertised targeted Revoke was accepted: %#v, %v", targeted, err)
	}
	all, err := service.Revoke(context.Background(), []byte(`{"all_grant_types":"true"}`), commandOptions(aep.AssertionRevoke, "revoke-all", "revoke-all"))
	if err != nil || all.Problem != nil || len(revoked) != 2 || revoked[0] != "alpha" || revoked[1] != "zeta" {
		t.Fatalf("all-grant-types Revoke was not deterministic: %#v, %v, %v", all, revoked, err)
	}
}

func TestServiceRepresentsExtendedLifecycleStates(t *testing.T) {
	store := NewMemoryEnrollmentStore()
	record := activeEnrollment("did:web:agent.example")
	record.Status = aep.AgentSuspended
	record.Since = testNow.Add(-time.Hour)
	if _, err := store.SaveEnrollment(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	service := newTestService(t, Options{
		EnrollmentStore: store,
		GrantTypes:      []GrantTypeDefinition{{GrantType: "custom-session", Handler: &testGrantHandler{}}},
	})
	status, err := service.Status(context.Background(), commandOptions(aep.AssertionStatus, "status-suspended", ""))
	if err != nil || status.Problem != nil || status.Body.Status != aep.AgentSuspended || status.Body.Since != record.Since.Format(time.RFC3339) {
		t.Fatalf("suspended status was not represented: %#v, %v", status, err)
	}
	grant, err := service.Grant(context.Background(), []byte(`{"grant_type":"custom-session"}`), commandOptions(aep.AssertionGrant, "grant-suspended", "grant-suspended"))
	if err != nil || grant.Problem == nil || grant.Problem.Code != aep.ErrorIdentitySuspended {
		t.Fatalf("suspended Grant returned the wrong result: %#v, %v", grant, err)
	}
}

func TestServiceMapsEveryNonActiveLifecycleState(t *testing.T) {
	tests := []struct {
		status    aep.AgentStatus
		grantCode aep.ErrorCode
	}{
		{status: aep.AgentPending, grantCode: aep.ErrorVerificationPending},
		{status: aep.AgentRejected, grantCode: aep.ErrorEnrollmentFailed},
		{status: aep.AgentSuspended, grantCode: aep.ErrorIdentitySuspended},
		{status: aep.AgentTerminated, grantCode: aep.ErrorIdentityTerminated},
		{status: aep.AgentUnavailable, grantCode: aep.ErrorIdentityUnavailable},
	}
	for index, test := range tests {
		store := NewMemoryEnrollmentStore()
		record := activeEnrollment("did:web:agent.example")
		record.Status = test.status
		if _, err := store.SaveEnrollment(context.Background(), record); err != nil {
			t.Fatal(err)
		}
		service := newTestService(t, Options{
			EnrollmentStore: store,
			GrantTypes:      []GrantTypeDefinition{{GrantType: "custom-session", Handler: &testGrantHandler{}}},
		})
		suffix := string(rune('a' + index))
		enrolled, err := service.Enroll(context.Background(), []byte(`{"agent_did":"did:web:agent.example"}`), commandOptions(aep.AssertionEnroll, "enroll-lifecycle-"+suffix, "enroll-lifecycle-"+suffix))
		if err != nil {
			t.Fatal(err)
		}
		if enrolled.Status != http.StatusOK || enrolled.Problem != nil || enrolled.Body.Status != test.status {
			t.Fatalf("unexpected %s Enroll result: %#v", test.status, enrolled)
		}
		granted, err := service.Grant(context.Background(), []byte(`{"grant_type":"custom-session"}`), commandOptions(aep.AssertionGrant, "grant-lifecycle-"+suffix, "grant-lifecycle-"+suffix))
		if err != nil || granted.Problem == nil || granted.Problem.Code != test.grantCode {
			t.Fatalf("unexpected %s Grant problem: %#v, %v", test.status, granted, err)
		}
	}
}

func TestMemoryIdempotencyStoreSerializesConcurrentExecution(t *testing.T) {
	store := NewMemoryIdempotencyStore()
	input := IdempotencyInput{AgentDID: "did:web:agent.example", Command: IdempotentEnroll, IdempotencyKey: "key", RequestHash: "sha256:digest"}
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	results := make(chan IdempotencyResult, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := store.ExecuteIdempotent(context.Background(), input, func() (StoredResponse, error) {
				if calls.Add(1) == 1 {
					close(started)
				}
				<-release
				return StoredResponse{Body: json.RawMessage(`{}`), ContentType: aep.MediaType, Status: http.StatusOK}, nil
			})
			if err != nil {
				t.Errorf("ExecuteIdempotent failed: %v", err)
				return
			}
			results <- result
		}()
	}
	<-started
	close(release)
	wait.Wait()
	close(results)
	states := map[IdempotencyState]int{}
	for result := range results {
		states[result.State]++
	}
	if calls.Load() != 1 || states[IdempotencyCreated] != 1 || states[IdempotencyReplayed] != 1 {
		t.Fatalf("idempotent execution was not serialized: calls=%d states=%v", calls.Load(), states)
	}
}

func TestServiceRejectsGrantResponseWithoutCredentialID(t *testing.T) {
	service := newTestService(t, Options{GrantTypes: []GrantTypeDefinition{{
		GrantType: "custom-session",
		Handler: &testGrantHandler{grant: func(aep.GrantRequest, GrantContext) (json.RawMessage, error) {
			return json.RawMessage(`{"access_token":"secret"}`), nil
		}},
	}}})
	seedEnrollment(t, service.enrollmentStore)
	if _, err := service.Grant(context.Background(), []byte(`{"grant_type":"custom-session"}`), commandOptions(aep.AssertionGrant, "grant-invalid", "grant-invalid")); err == nil {
		t.Fatal("Grant response without credential_id was accepted")
	}
}

func TestProtectedResourceAuthentication(t *testing.T) {
	handler := &testGrantHandler{
		authenticate: func(input CredentialAuthenticationInput) (*AuthenticatedPrincipal, error) {
			if input.Headers.Get("Authorization") != "Bearer valid" {
				return nil, nil
			}
			return &AuthenticatedPrincipal{
				AgentDID: "did:web:agent.example", AuthenticationKind: AuthenticationKindSessionCredential,
				AuthenticationMethod: "custom-session", CredentialID: "credential-1", GrantType: "custom-session", Scopes: []string{"read"},
			}, nil
		},
		hasPresentation: func(input CredentialAuthenticationInput) (bool, error) {
			return input.Headers.Get("Authorization") != "", nil
		},
	}
	service := newTestService(t, Options{
		AuthenticationMethods: []aep.AuthenticationMethod{aep.AuthenticationMethodJWT, "custom-session"},
		GrantTypes:            []GrantTypeDefinition{{GrantType: "custom-session", Handler: handler}},
	})
	seedEnrollment(t, service.enrollmentStore)
	resource := mustURL(t, "https://service.example/private")

	missing, err := service.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{Headers: http.Header{}, Method: http.MethodGet, URL: resource})
	if err != nil || missing.Authenticated || missing.Response == nil || missing.Response.Body.Code != aep.ErrorAuthenticationRequired || missing.Response.Headers.Get("WWW-Authenticate") == "" {
		t.Fatalf("unexpected missing-authentication result: %#v, %v", missing, err)
	}

	jwt, err := service.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{
		Headers: http.Header{"Authorization": []string{"AEP " + assertion(aep.AssertionAuthenticate, "authenticate-1", resource.String())}}, Method: http.MethodGet, URL: resource,
	})
	if err != nil || !jwt.Authenticated || jwt.Principal == nil || jwt.Principal.AuthenticationKind != AuthenticationKindJWT {
		t.Fatalf("unexpected JWT authentication result: %#v, %v", jwt, err)
	}
	replay, err := service.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{
		Headers: http.Header{"Authorization": []string{"AEP " + assertion(aep.AssertionAuthenticate, "authenticate-1", resource.String())}}, Method: http.MethodGet, URL: resource,
	})
	if err != nil || replay.Authenticated || replay.Response == nil || replay.Response.Body.Code != aep.ErrorNotRecognized {
		t.Fatalf("replayed assertion was accepted: %#v, %v", replay, err)
	}

	session, err := service.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{
		Headers: http.Header{"AEP-Authorization": []string{"Bearer valid"}, "Authorization": []string{"Payment orthogonal"}}, Method: http.MethodPost, URL: resource,
	})
	if err != nil || !session.Authenticated || session.Principal == nil || session.Principal.CredentialID != "credential-1" {
		t.Fatalf("dedicated session credential did not compose with payment: %#v, %v", session, err)
	}
	ambiguous, err := service.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{
		Headers: http.Header{"AEP-Authorization": []string{"Bearer valid"}, "Authorization": []string{"Basic other"}}, Method: http.MethodGet, URL: resource,
	})
	if err != nil || ambiguous.Authenticated || ambiguous.Response == nil || ambiguous.Response.Body.Code != aep.ErrorNotRecognized {
		t.Fatalf("ambiguous credential carriers were accepted: %#v, %v", ambiguous, err)
	}
}

func TestProtectedResourceAuthenticationRejectsUnsupportedAndDuplicatePresentations(t *testing.T) {
	service := newTestService(t, Options{})
	resource := mustURL(t, "https://service.example/private")
	unsupported, err := service.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{
		Headers: http.Header{"Authorization": []string{"AEP " + assertion(aep.AssertionAuthenticate, "unsupported-jwt", resource.String())}}, URL: resource,
	})
	if err != nil || unsupported.Authenticated || unsupported.Response == nil || unsupported.Response.Body.Code != aep.ErrorUnsupportedAuthenticationMethod {
		t.Fatalf("unsupported JWT method returned the wrong result: %#v, %v", unsupported, err)
	}
	duplicate, err := service.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{
		Headers: http.Header{"AEP-Authorization": []string{"Bearer first", "Bearer second"}}, URL: resource,
	})
	if err != nil || duplicate.Authenticated || duplicate.Response == nil || duplicate.Response.Body.Code != aep.ErrorNotRecognized {
		t.Fatalf("duplicate dedicated presentations were accepted: %#v, %v", duplicate, err)
	}
}

func TestNewRejectsCapabilityMisconfiguration(t *testing.T) {
	_, err := New(Options{
		AuthenticationMethods: []aep.AuthenticationMethod{"custom-session"},
		IdentityMethods:       []aep.IdentityMethod{aep.IdentityMethodDIDWeb},
		ServiceDID:            "did:web:service.example",
		Verifier: func(context.Context, string, AssertionVerificationContext) (aep.ClientAssertionClaims, error) {
			return aep.ClientAssertionClaims{}, nil
		},
	})
	if err == nil {
		t.Fatal("authentication method without a matching Grant Type was accepted")
	}
}

func TestNewAcceptsExplicitZeroClockSkew(t *testing.T) {
	zero := time.Duration(0)
	service := newTestService(t, Options{ClientAssertion: ClientAssertionOptions{ClockSkew: &zero}})
	if service.clientAssertion.ClockSkew != 0 {
		t.Fatalf("explicit zero clock skew became %s", service.clientAssertion.ClockSkew)
	}
}

func TestDIDWebAssertionVerifierUsesResolvedPublicKey(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var did string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/.well-known/did.json" {
			http.NotFound(response, request)
			return
		}
		response.Header().Set("Content-Type", "application/did+json")
		_ = json.NewEncoder(response).Encode(map[string]any{
			"id": did,
			"verificationMethod": []any{map[string]any{
				"id": did + "#key-1", "publicKeyJwk": map[string]any{
					"crv": "Ed25519", "kty": "OKP", "x": base64.RawURLEncoding.EncodeToString(publicKey),
				},
			}},
		})
	}))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "http://")
	did = "did:web:" + strings.ReplaceAll(host, ":", "%3A")
	claims := aep.ClientAssertionClaims{
		Audience: "did:web:service.example", ExpiresAt: testNow.Add(time.Minute).Unix(), IssuedAt: testNow.Unix(),
		Issuer: did, JWTID: "did-web-real", Operation: aep.AssertionStatus, Subject: did,
	}
	token, err := aep.SignClientAssertion(claims, aep.SignClientAssertionOptions{
		Algorithm: aep.SigningAlgorithmEdDSA, AllowInsecureLoopback: true, Key: privateKey, KeyID: did + "#key-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier := NewDIDWebAssertionVerifier(DIDWebVerifierOptions{HTTPClient: server.Client()})
	verified, err := verifier(context.Background(), token, AssertionVerificationContext{
		AllowInsecureLoopback: true, ClockTolerance: aep.RecommendedClockSkew, CurrentTime: testNow,
		Operation: aep.AssertionStatus, ServiceDID: claims.Audience, SigningAlgorithms: []aep.SigningAlgorithm{aep.SigningAlgorithmEdDSA},
	})
	if err != nil || verified.Subject != did {
		t.Fatalf("real did:web assertion verification failed: %#v, %v", verified, err)
	}
}

func TestServiceInspectReflectsConfiguredCapabilities(t *testing.T) {
	handler := &testGrantHandler{}
	service := newTestService(t, Options{
		AuthenticationMethods: []aep.AuthenticationMethod{"custom-session"},
		EndpointBase:          "/identity",
		GrantTypes:            []GrantTypeDefinition{{GrantType: "custom-session", Handler: handler}},
	})
	document, err := service.InspectDocument()
	if err != nil {
		t.Fatal(err)
	}
	if document.HTTP.EndpointBase != "/identity/" || !containsCommand(document.Commands.Supported, aep.CommandGrant) || len(document.Authentication.Methods) != 1 {
		t.Fatalf("unexpected Inspect document: %#v", document)
	}
}

type testEnrollmentPolicy func(aep.EnrollRequest, EnrollmentPolicyContext) (EnrollmentDecision, error)

func (policy testEnrollmentPolicy) DecideEnrollment(_ context.Context, request aep.EnrollRequest, context EnrollmentPolicyContext) (EnrollmentDecision, error) {
	return policy(request, context)
}

type testGrantHandler struct {
	authenticate    func(CredentialAuthenticationInput) (*AuthenticatedPrincipal, error)
	grant           func(aep.GrantRequest, GrantContext) (json.RawMessage, error)
	hasPresentation func(CredentialAuthenticationInput) (bool, error)
	revoke          func(aep.RevokeRequest, RevokeContext) error
}

func (handler *testGrantHandler) Grant(_ context.Context, request aep.GrantRequest, context GrantContext) (json.RawMessage, error) {
	if handler.grant == nil {
		return json.RawMessage(`{"credential_id":"credential-1"}`), nil
	}
	return handler.grant(request, context)
}

func (handler *testGrantHandler) Revoke(_ context.Context, request aep.RevokeRequest, context RevokeContext) error {
	if handler.revoke == nil {
		return nil
	}
	return handler.revoke(request, context)
}

func (handler *testGrantHandler) AuthenticateCredential(_ context.Context, input CredentialAuthenticationInput) (*AuthenticatedPrincipal, error) {
	if handler.authenticate == nil {
		return nil, nil
	}
	return handler.authenticate(input)
}

func (handler *testGrantHandler) HasCredentialPresentation(_ context.Context, input CredentialAuthenticationInput) (bool, error) {
	if handler.hasPresentation == nil {
		return false, nil
	}
	return handler.hasPresentation(input)
}

func newTestService(t *testing.T, options Options) *Service {
	t.Helper()
	options.Clock = func() time.Time { return testNow }
	options.Identifier = func() (string, error) { return "enrollment-1", nil }
	options.IdentityMethods = []aep.IdentityMethod{aep.IdentityMethodDIDWeb}
	options.ServiceDID = "did:web:service.example"
	options.Verifier = func(_ context.Context, token string, _ AssertionVerificationContext) (aep.ClientAssertionClaims, error) {
		decoded, err := aep.DecodeJWTUnverified(token)
		if err != nil {
			return aep.ClientAssertionClaims{}, err
		}
		data, err := json.Marshal(decoded.Payload)
		if err != nil {
			return aep.ClientAssertionClaims{}, err
		}
		return aep.ParseClientAssertionClaims(data)
	}
	service, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func commandOptions(operation aep.AssertionOperation, jti string, idempotencyKey string) CommandOptions {
	return CommandOptions{ClientAssertion: assertion(operation, jti, ""), IdempotencyKey: idempotencyKey}
}

func assertion(operation aep.AssertionOperation, jti string, resource string) string {
	claims := aep.ClientAssertionClaims{
		Audience: "did:web:service.example", ExpiresAt: testNow.Add(time.Minute).Unix(), IssuedAt: testNow.Unix(),
		Issuer: "did:web:agent.example", JWTID: jti, Operation: operation, Resource: resource, Subject: "did:web:agent.example",
	}
	header, _ := json.Marshal(map[string]string{"alg": "EdDSA", "kid": "did:web:agent.example#key-1", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func seedEnrollment(t *testing.T, store EnrollmentStore) {
	t.Helper()
	if _, _, err := store.FindOrCreateEnrollment(context.Background(), "did:web:agent.example", func() (EnrollmentRecord, error) {
		return activeEnrollment("did:web:agent.example"), nil
	}); err != nil {
		t.Fatal(err)
	}
}

func activeEnrollment(agentDID string) EnrollmentRecord {
	return EnrollmentRecord{
		AgentDID: agentDID, CreatedAt: testNow, EnrollmentID: "enrollment-1", Since: testNow, Status: aep.AgentActive, UpdatedAt: testNow,
	}
}

func mustURL(t *testing.T, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func containsCommand(commands []aep.Command, command aep.Command) bool {
	for _, candidate := range commands {
		if candidate == command {
			return true
		}
	}
	return false
}
