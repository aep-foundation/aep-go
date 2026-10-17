package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	aep "github.com/aep-foundation/aep-go"
)

// customAssertion renders an unsigned assertion from an explicit JOSE header and claim set. The
// test verifier installed by newTestService parses the payload without checking the signature, so
// these vectors exercise the Service-side checks in validAssertion rather than the JWS layer.
func customAssertion(header map[string]any, claims map[string]any) string {
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON) + ".signature"
}

func TestProtectedResourceClassifiesBuiltInCredentialPresentations(t *testing.T) {
	bearer, err := StoredOAuthBearerGrantType(StoredCredentialGrantTypeOptions[aep.OAuthBearerGrantResponse]{
		Store: NewMemoryServiceCredentialStore(),
		Issue: func(context.Context, aep.GrantRequest, GrantContext) (aep.OAuthBearerGrantResponse, error) {
			t.Fatal("authentication unexpectedly issued a credential")
			return aep.OAuthBearerGrantResponse{}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	jwt := newTestService(t, Options{AuthenticationMethods: []aep.AuthenticationMethod{aep.AuthenticationMethodJWT}})
	oauth := newTestService(t, Options{AuthenticationMethods: []aep.AuthenticationMethod{aep.AuthenticationMethod(aep.GrantTypeOAuthBearer)}, GrantTypes: []GrantTypeDefinition{bearer}})
	for _, test := range []struct {
		name, value string
		instance    *Service
		code        aep.ErrorCode
	}{
		{"unsupported bearer", "Bearer token", jwt, aep.ErrorUnsupportedAuthenticationMethod},
		{"unsupported basic", "Basic dTpw", jwt, aep.ErrorUnsupportedAuthenticationMethod},
		{"malformed bearer", "Bearer bad token", oauth, aep.ErrorNotRecognized},
		{"empty bearer", "Bearer", oauth, aep.ErrorNotRecognized},
		{"unknown bearer", "Bearer token", oauth, aep.ErrorNotRecognized},
		{"empty assertion", "AEP", jwt, aep.ErrorNotRecognized},
		{"unrelated payment", "Payment token", jwt, aep.ErrorAuthenticationRequired},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, header := range []string{"Authorization", "aep-authorization"} {
				if test.value == "Payment token" && header != "Authorization" {
					continue
				}
				result, err := test.instance.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{Headers: http.Header{header: {test.value}}, Method: http.MethodGet, URL: mustURL(t, "https://service.example/private")})
				if err != nil || result.Authenticated || result.Response == nil || result.Response.Body.Code != test.code {
					t.Fatalf("%s: %#v, %v", header, result, err)
				}
			}
		})
	}
}

func defaultHeader() map[string]any {
	return map[string]any{"alg": "EdDSA", "kid": "did:web:agent.example#key-1", "typ": "JWT"}
}

func defaultClaims(operation aep.AssertionOperation, jti string) map[string]any {
	return map[string]any{
		"aud": "did:web:service.example", "exp": testNow.Add(time.Minute).Unix(), "iat": testNow.Unix(),
		"iss": "did:web:agent.example", "jti": jti, "op": string(operation), "sub": "did:web:agent.example",
	}
}

// CORE-PR-014, CORE-PR-016, CORE-PR-038 and APK-PRS-002: a request that carries no AEP credential
// is anonymous to the AEP layer, whatever else its Authorization field holds, so it receives the
// authentication_required challenge rather than the non-disclosing not_recognized answer reserved
// for credentials the Service saw and could not accept.
func TestProtectedResourceSeparatesMissingCredentialsFromRejectedOnes(t *testing.T) {
	service := newTestService(t, Options{
		AuthenticationMethods: []aep.AuthenticationMethod{aep.AuthenticationMethodJWT, "custom-session"},
		GrantTypes: []GrantTypeDefinition{{GrantType: "custom-session", Handler: &testGrantHandler{
			hasPresentation: func(input CredentialAuthenticationInput) (bool, error) {
				return strings.HasPrefix(input.Headers.Get("Authorization"), "Bearer "), nil
			},
		}}},
	})
	seedEnrollment(t, service.enrollmentStore)
	resource := mustURL(t, "https://service.example/private")

	for _, test := range []struct {
		code    aep.ErrorCode
		headers http.Header
		name    string
	}{
		{code: aep.ErrorAuthenticationRequired, headers: http.Header{}, name: "no authorization at all"},
		{code: aep.ErrorAuthenticationRequired, headers: http.Header{"Authorization": {"Payment orthogonal"}}, name: "unrelated payment carrier"},
		{code: aep.ErrorAuthenticationRequired, headers: http.Header{"X-Api-Key": {"key-in-an-unissued-header"}}, name: "api key outside an issued header"},
		{code: aep.ErrorNotRecognized, headers: http.Header{"Authorization": {"AEP not-a-jwt"}}, name: "malformed AEP assertion"},
		{code: aep.ErrorNotRecognized, headers: http.Header{"Authorization": {"aep \x01"}}, name: "unparseable AEP field value"},
		{code: aep.ErrorNotRecognized, headers: http.Header{"Authorization": {"Bearer unknown"}}, name: "unknown session credential"},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := service.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{
				Headers: test.headers, Method: http.MethodGet, URL: resource,
			})
			if err != nil || result.Authenticated || result.Response == nil || result.Response.Body.Code != test.code {
				t.Fatalf("expected %s, got %#v, %v", test.code, result.Response, err)
			}
			challenge := result.Response.Headers.Get("WWW-Authenticate")
			if !strings.HasPrefix(challenge, "AEP ") || !strings.Contains(challenge, `service_did="did:web:service.example"`) || !strings.Contains(challenge, `inspect="`) {
				t.Fatalf("CORE-PR-024 challenge was incomplete: %q", challenge)
			}
		})
	}
}

// CORE-ERR-007: a not_recognized response must not disclose lifecycle detail.
func TestProtectedResourceChallengeOmitsLifecycleFields(t *testing.T) {
	service := newTestService(t, Options{AuthenticationMethods: []aep.AuthenticationMethod{aep.AuthenticationMethodJWT}})
	resource := mustURL(t, "https://service.example/private")
	result, err := service.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{
		Headers: http.Header{"Authorization": {"AEP " + assertion(aep.AssertionAuthenticate, "unknown-agent", resource.String())}},
		Method:  http.MethodGet, URL: resource,
	})
	if err != nil || result.Response == nil || result.Response.Body.Code != aep.ErrorNotRecognized {
		t.Fatalf("unknown Agent was not rejected: %#v, %v", result, err)
	}
	problem := result.Response.Body
	if problem.OwnerActionRequired != nil || len(problem.VerificationPending) != 0 || len(problem.RequirementsPending) != 0 {
		t.Fatalf("not_recognized leaked lifecycle detail: %#v", problem)
	}
	if problem.Type != "urn:aep:error:not_recognized" || problem.Title == "" || problem.Status != http.StatusUnauthorized {
		t.Fatalf("CORE-ERR-001..003 problem shape is wrong: %#v", problem)
	}
}

// CORE-PR-012, CORE-PR-013, CORE-PR-018 and CORE-PR-019: the Service never chooses between two
// AEP-recognized credentials, and an invalid dedicated credential fails closed.
func TestProtectedResourceRejectsCredentialSmuggling(t *testing.T) {
	service := newTestService(t, Options{
		AuthenticationMethods: []aep.AuthenticationMethod{aep.AuthenticationMethodJWT, "custom-session"},
		GrantTypes: []GrantTypeDefinition{{GrantType: "custom-session", Handler: &testGrantHandler{
			authenticate: func(input CredentialAuthenticationInput) (*AuthenticatedPrincipal, error) {
				if input.Headers.Get("Authorization") != "Bearer valid" {
					return nil, nil
				}
				return &AuthenticatedPrincipal{
					AgentDID: "did:web:agent.example", AuthenticationKind: AuthenticationKindSessionCredential,
					AuthenticationMethod: "custom-session", CredentialID: "credential-1", GrantType: "custom-session",
				}, nil
			},
		}}},
	})
	seedEnrollment(t, service.enrollmentStore)
	resource := mustURL(t, "https://service.example/private")

	for _, test := range []struct {
		headers http.Header
		name    string
	}{
		{headers: http.Header{"Aep-Authorization": {"Bearer valid"}, "Authorization": {"Bearer valid"}}, name: "both carriers recognized"},
		{headers: http.Header{"Aep-Authorization": {"Bearer valid, Bearer other"}}, name: "combined dedicated value"},
		{headers: http.Header{"Aep-Authorization": {"Payment orthogonal"}, "Authorization": {"Bearer valid"}}, name: "invalid dedicated does not fall back"},
		{headers: http.Header{"Authorization": {"Bearer valid", "Basic other"}}, name: "repeated standard field lines"},
		{headers: http.Header{"Authorization": {"Payment orthogonal", "Bearer valid"}}, name: "recognized value beside an unrelated one"},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := service.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{
				Headers: test.headers, Method: http.MethodGet, URL: resource,
			})
			if err != nil || result.Authenticated || result.Response == nil || result.Response.Body.Code != aep.ErrorNotRecognized {
				t.Fatalf("ambiguous presentation was not rejected: %#v, %v", result, err)
			}
		})
	}
}

// CORE-PR-015: the dedicated carrier authenticates without the AEP layer consuming or rewriting an
// unrelated Authorization credential the application still needs.
func TestProtectedResourceLeavesUnrelatedAuthorizationIntact(t *testing.T) {
	service := newTestService(t, Options{
		AuthenticationMethods: []aep.AuthenticationMethod{"custom-session"},
		GrantTypes: []GrantTypeDefinition{{GrantType: "custom-session", Handler: &testGrantHandler{
			authenticate: func(input CredentialAuthenticationInput) (*AuthenticatedPrincipal, error) {
				if input.Headers.Get("Authorization") != "Bearer valid" {
					return nil, nil
				}
				return &AuthenticatedPrincipal{
					AgentDID: "did:web:agent.example", AuthenticationKind: AuthenticationKindSessionCredential,
					AuthenticationMethod: "custom-session", CredentialID: "credential-1", GrantType: "custom-session",
				}, nil
			},
		}}},
	})
	seedEnrollment(t, service.enrollmentStore)
	middleware, err := NewProtectedResourceMiddleware(service, "https://service.example")
	if err != nil {
		t.Fatal(err)
	}
	var observed string
	next := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		observed = request.Header.Get("Authorization")
		response.WriteHeader(http.StatusNoContent)
	})
	recorder := serveRequest(middleware(next), http.MethodGet, "/private", "", http.Header{
		"Aep-Authorization": {"Bearer valid"}, "Authorization": {"Payment orthogonal"},
	})
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("dedicated carrier did not authenticate: %d %s", recorder.Code, recorder.Body.String())
	}
	if observed != "Payment orthogonal" {
		t.Fatalf("the AEP layer rewrote an unrelated Authorization credential: %q", observed)
	}
}

// RFC 9110 Section 9.3.2 requires a HEAD response wherever GET is answered, with identical header
// fields, and CORE-HTTP-002 keeps every other method off the binding.
func TestHTTPHandlerAnswersHeadWhereverItAnswersGet(t *testing.T) {
	service := newTestService(t, Options{})
	handler, err := NewHTTPHandler(service, HTTPHandlerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{aep.WellKnownPath, "/aep/status"} {
		get := serveRequest(handler, http.MethodGet, target, "", nil)
		head := serveRequest(handler, http.MethodHead, target, "", nil)
		if head.Code != get.Code {
			t.Fatalf("HEAD %s returned %d where GET returned %d", target, head.Code, get.Code)
		}
		for _, field := range []string{"Cache-Control", "Content-Length", "Content-Type", "ETag", "WWW-Authenticate"} {
			if head.Header().Get(field) != get.Header().Get(field) {
				t.Fatalf("HEAD %s %s was %q, GET was %q", target, field, head.Header().Get(field), get.Header().Get(field))
			}
		}
	}
	for _, test := range []struct {
		allow  string
		method string
		target string
	}{
		{allow: "GET, HEAD", method: http.MethodDelete, target: aep.WellKnownPath},
		{allow: "GET, HEAD", method: http.MethodPost, target: "/aep/status"},
		{allow: http.MethodPost, method: http.MethodGet, target: "/aep/enroll"},
		{allow: http.MethodPost, method: http.MethodHead, target: "/aep/enroll"},
	} {
		recorder := serveRequest(handler, test.method, test.target, "", nil)
		if recorder.Code != http.StatusMethodNotAllowed || recorder.Header().Get("Allow") != test.allow {
			t.Fatalf("%s %s returned %d with Allow %q", test.method, test.target, recorder.Code, recorder.Header().Get("Allow"))
		}
	}
}

// CORE-IDP-001, CORE-IDP-003 and CORE-IDP-009 govern the Idempotency-Key header on the
// state-mutating commands.
func TestCommandsRequireAUsableIdempotencyKey(t *testing.T) {
	service := newTestService(t, Options{GrantTypes: []GrantTypeDefinition{{GrantType: "custom-session", Handler: &testGrantHandler{}}}})
	seedEnrollment(t, service.enrollmentStore)
	for _, key := range []string{"", "   ", "\t"} {
		enroll, err := service.Enroll(context.Background(), []byte(`{"agent_did":"did:web:agent.example"}`), CommandOptions{
			ClientAssertion: assertion(aep.AssertionEnroll, "enroll-"+key, ""), IdempotencyKey: key,
		})
		if err != nil || enroll.Problem == nil || enroll.Problem.Code != aep.ErrorInvalidRequest || enroll.Status != http.StatusBadRequest {
			t.Fatalf("Enroll accepted idempotency key %q: %#v, %v", key, enroll, err)
		}
		grant, err := service.Grant(context.Background(), []byte(`{"grant_type":"custom-session"}`), CommandOptions{
			ClientAssertion: assertion(aep.AssertionGrant, "grant-"+key, ""), IdempotencyKey: key,
		})
		if err != nil || grant.Problem == nil || grant.Problem.Code != aep.ErrorInvalidRequest {
			t.Fatalf("Grant accepted idempotency key %q: %#v, %v", key, grant, err)
		}
		revoke, err := service.Revoke(context.Background(), []byte(`{"grant_type":"custom-session"}`), CommandOptions{
			ClientAssertion: assertion(aep.AssertionRevoke, "revoke-"+key, ""), IdempotencyKey: key,
		})
		if err != nil || revoke.Problem == nil || revoke.Problem.Code != aep.ErrorInvalidRequest {
			t.Fatalf("Revoke accepted idempotency key %q: %#v, %v", key, revoke, err)
		}
	}

	mismatch, err := service.Enroll(context.Background(), []byte(`{"agent_did":"did:web:agent.example","idempotency_key":"body-key"}`), CommandOptions{
		ClientAssertion: assertion(aep.AssertionEnroll, "enroll-mismatch", ""), IdempotencyKey: "header-key",
	})
	if err != nil || mismatch.Problem == nil || mismatch.Problem.Code != aep.ErrorInvalidRequest {
		t.Fatalf("CORE-IDP-009 mismatch was accepted: %#v, %v", mismatch, err)
	}
	matched, err := service.Enroll(context.Background(), []byte(`{"agent_did":"did:web:agent.example","idempotency_key":"agreed-key"}`), CommandOptions{
		ClientAssertion: assertion(aep.AssertionEnroll, "enroll-matched", ""), IdempotencyKey: "agreed-key",
	})
	if err != nil || matched.Problem != nil {
		t.Fatalf("CORE-IDP-009 agreement was rejected: %#v, %v", matched, err)
	}
}

// CORE-IDP-004: the response bound to (agent_did, Idempotency-Key) survives for at least an hour.
func TestIdempotencyRecordsSurviveTheRequiredWindow(t *testing.T) {
	now := testNow
	store := newMemoryIdempotencyStore(func() time.Time { return now })
	input := IdempotencyInput{AgentDID: "did:web:agent.example", Command: IdempotentEnroll, IdempotencyKey: "key", RequestHash: "sha256:abc"}
	execute := func() (StoredResponse, error) {
		return StoredResponse{Body: json.RawMessage(`{}`), ContentType: aep.MediaType, CreatedAt: now, Status: http.StatusOK}, nil
	}
	if _, err := store.ExecuteIdempotent(context.Background(), input, execute); err != nil {
		t.Fatal(err)
	}
	now = testNow.Add(time.Hour - time.Second)
	replayed, err := store.ExecuteIdempotent(context.Background(), input, func() (StoredResponse, error) {
		t.Fatal("the cached response was discarded inside the one-hour window")
		return StoredResponse{}, nil
	})
	if err != nil || replayed.State != IdempotencyReplayed {
		t.Fatalf("unexpected replay state: %#v, %v", replayed, err)
	}
	now = testNow.Add(2 * time.Hour)
	expired, err := store.ExecuteIdempotent(context.Background(), input, execute)
	if err != nil || expired.State != IdempotencyCreated {
		t.Fatalf("an expired record was still replayed: %#v, %v", expired, err)
	}
}

// CORE-CA-013, CORE-PR-002 and CORE-PR-003: an operation is valid only at its own target.
func TestAssertionOperationsAreBoundToTheirTarget(t *testing.T) {
	service := newTestService(t, Options{AuthenticationMethods: []aep.AuthenticationMethod{aep.AuthenticationMethodJWT}})
	seedEnrollment(t, service.enrollmentStore)
	resource := mustURL(t, "https://service.example/private")

	for index, operation := range []aep.AssertionOperation{aep.AssertionEnroll, aep.AssertionGrant, aep.AssertionRevoke, aep.AssertionStatus} {
		result, err := service.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{
			Headers: http.Header{"Authorization": {"AEP " + assertion(operation, "substituted-"+string(operation), resource.String())}},
			Method:  http.MethodGet, URL: resource,
		})
		if err != nil || result.Authenticated || result.Response.Body.Code != aep.ErrorNotRecognized {
			t.Fatalf("command operation %q authenticated a protected resource: %#v, %v", operation, result, err)
		}
		_ = index
	}

	authenticateAtCommand, err := service.Status(context.Background(), CommandOptions{ClientAssertion: assertion(aep.AssertionAuthenticate, "authenticate-at-status", resource.String())})
	if err != nil || authenticateAtCommand.Problem == nil || authenticateAtCommand.Problem.Code != aep.ErrorNotRecognized {
		t.Fatalf("an authenticate assertion reached a command endpoint: %#v, %v", authenticateAtCommand, err)
	}
	wrongCommand, err := service.Status(context.Background(), CommandOptions{ClientAssertion: assertion(aep.AssertionEnroll, "enroll-at-status", "")})
	if err != nil || wrongCommand.Problem == nil || wrongCommand.Problem.Code != aep.ErrorNotRecognized {
		t.Fatalf("a mismatched command operation was accepted: %#v, %v", wrongCommand, err)
	}
}

// CORE-CA-002, CORE-CA-005, CORE-CA-006, CORE-CA-008, CORE-CA-010, CORE-CA-011, CORE-CA-019 and
// CORE-CA-024: every assertion defect collapses to not_recognized.
func TestAssertionValidationRejectsEveryDefect(t *testing.T) {
	service := newTestService(t, Options{})
	seedEnrollment(t, service.enrollmentStore)
	for _, test := range []struct {
		claims func(map[string]any)
		header func(map[string]any)
		name   string
	}{
		{name: "unadvertised algorithm", header: func(header map[string]any) { header["alg"] = "HS256" }},
		{name: "prohibited none algorithm", header: func(header map[string]any) { header["alg"] = "none" }},
		{name: "missing algorithm", header: func(header map[string]any) { delete(header, "alg") }},
		{name: "non-string algorithm", header: func(header map[string]any) { header["alg"] = 7 }},
		{name: "wrong typ", header: func(header map[string]any) { header["typ"] = "at+jwt" }},
		{name: "missing typ", header: func(header map[string]any) { delete(header, "typ") }},
		{name: "missing kid", header: func(header map[string]any) { delete(header, "kid") }},
		{name: "kid for another DID", header: func(header map[string]any) { header["kid"] = "did:web:attacker.example#key-1" }},
		{name: "issuer and subject differ", claims: func(claims map[string]any) { claims["iss"] = "did:web:other.example" }},
		{name: "audience is another Service", claims: func(claims map[string]any) { claims["aud"] = "did:web:other.example" }},
		{name: "lifetime beyond 300 seconds", claims: func(claims map[string]any) { claims["exp"] = testNow.Add(301 * time.Second).Unix() }},
		{name: "non-positive lifetime", claims: func(claims map[string]any) { claims["exp"] = claims["iat"] }},
		{name: "issued in the future", claims: func(claims map[string]any) {
			claims["iat"] = testNow.Add(time.Minute).Unix()
			claims["exp"] = testNow.Add(2 * time.Minute).Unix()
		}},
		{name: "already expired", claims: func(claims map[string]any) {
			claims["iat"] = testNow.Add(-2 * time.Minute).Unix()
			claims["exp"] = testNow.Add(-time.Minute).Unix()
		}},
		{name: "unexpected resource on a command", claims: func(claims map[string]any) { claims["resource"] = "https://service.example/private" }},
		{name: "unsupported identity method", claims: func(claims map[string]any) {
			claims["iss"] = "did:key:z6Mk"
			claims["sub"] = "did:key:z6Mk"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			header, claims := defaultHeader(), defaultClaims(aep.AssertionStatus, "defect-"+test.name)
			if test.header != nil {
				test.header(header)
			}
			if test.claims != nil {
				test.claims(claims)
			}
			result, err := service.Status(context.Background(), CommandOptions{ClientAssertion: customAssertion(header, claims)})
			if err != nil || result.Problem == nil || result.Problem.Code != aep.ErrorNotRecognized || result.Status != http.StatusUnauthorized {
				t.Fatalf("defective assertion was accepted: %#v, %v", result, err)
			}
		})
	}
}

// CORE-CA-021 and CORE-CA-022: a jti is consumed once, for the assertion lifetime plus the skew.
func TestReplayCacheConsumesEachAssertionOnce(t *testing.T) {
	service := newTestService(t, Options{})
	seedEnrollment(t, service.enrollmentStore)
	first, err := service.Status(context.Background(), CommandOptions{ClientAssertion: assertion(aep.AssertionStatus, "replay-once", "")})
	if err != nil || first.Problem != nil {
		t.Fatalf("the first assertion was rejected: %#v, %v", first, err)
	}
	second, err := service.Status(context.Background(), CommandOptions{ClientAssertion: assertion(aep.AssertionStatus, "replay-once", "")})
	if err != nil || second.Problem == nil || second.Problem.Code != aep.ErrorNotRecognized {
		t.Fatalf("a replayed jti was accepted: %#v, %v", second, err)
	}
	store := NewMemoryReplayStore()
	record := ReplayRecord{ExpiresAt: testNow.Add(time.Minute).Unix(), JWTID: "window", Subject: "did:web:agent.example"}
	if consumed, err := store.ConsumeReplay(context.Background(), record, testNow.Unix()); err != nil || !consumed {
		t.Fatalf("the replay record was not consumed: %v, %v", consumed, err)
	}
	if consumed, err := store.ConsumeReplay(context.Background(), record, testNow.Unix()); err != nil || consumed {
		t.Fatalf("the replay record was consumed twice: %v, %v", consumed, err)
	}
	later := ReplayRecord{ExpiresAt: testNow.Add(2 * time.Minute).Unix(), JWTID: "window", Subject: "did:web:agent.example"}
	if consumed, err := store.ConsumeReplay(context.Background(), later, testNow.Add(time.Minute).Unix()); err != nil || !consumed {
		t.Fatalf("an expired record was not evicted: %v, %v", consumed, err)
	}
}

// CORE-RVK-002, CORE-RVK-007, CORE-RVK-008, CORE-RVK-009, CORE-RVK-010, CORE-INS-012 and
// CORE-SEC-012 together describe which Revoke shapes a Service accepts and what it answers.
func TestRevokeTargetingFollowsTheAdvertisedConfiguration(t *testing.T) {
	var revoked []string
	record := func(name string) *testGrantHandler {
		return &testGrantHandler{revoke: func(request aep.RevokeRequest, _ RevokeContext) error {
			revoked = append(revoked, name+":"+request.CredentialID)
			return nil
		}}
	}
	service := newTestService(t, Options{GrantTypes: []GrantTypeDefinition{
		{Config: aep.GrantTypeConfig{SupportsPerCredentialRevoke: "true"}, GrantType: "targeted-session", Handler: record("targeted-session")},
		{GrantType: "bulk-session", Handler: record("bulk-session")},
	}})
	seedEnrollment(t, service.enrollmentStore)

	targeted, err := service.Revoke(context.Background(), []byte(`{"grant_type":"targeted-session","credential_id":"credential-1"}`), commandOptions(aep.AssertionRevoke, "revoke-targeted", "revoke-targeted"))
	if err != nil || targeted.Problem != nil || targeted.Status != http.StatusOK {
		t.Fatalf("CORE-INS-012 targeted Revoke was refused: %#v, %v", targeted, err)
	}

	unsupportedTarget, err := service.Revoke(context.Background(), []byte(`{"grant_type":"bulk-session","credential_id":"credential-1"}`), commandOptions(aep.AssertionRevoke, "revoke-unsupported-target", "revoke-unsupported-target"))
	if err != nil || unsupportedTarget.Problem == nil || unsupportedTarget.Problem.Code != aep.ErrorInvalidRequest {
		t.Fatalf("unadvertised per-credential Revoke was accepted: %#v, %v", unsupportedTarget, err)
	}

	unknownType, err := service.Revoke(context.Background(), []byte(`{"grant_type":"absent-session"}`), commandOptions(aep.AssertionRevoke, "revoke-unknown", "revoke-unknown"))
	if err != nil || unknownType.Problem == nil || unknownType.Problem.Code != aep.ErrorUnsupportedGrantType {
		t.Fatalf("an unadvertised grant type was accepted: %#v, %v", unknownType, err)
	}

	revoked = nil
	all, err := service.Revoke(context.Background(), []byte(`{"all_grant_types":"true"}`), commandOptions(aep.AssertionRevoke, "revoke-all", "revoke-all"))
	if err != nil || all.Problem != nil || len(revoked) != 2 || revoked[0] != "bulk-session:" || revoked[1] != "targeted-session:" {
		t.Fatalf("CORE-RVK-007 all_grant_types did not reach every handler: %v, %#v, %v", revoked, all, err)
	}
	if encoded, marshalErr := json.Marshal(all.Body); marshalErr != nil || string(encoded) != "{}" {
		t.Fatalf("CORE-RVK-010 response was %s, %v", encoded, marshalErr)
	}

	for _, body := range []string{`{"credential_id":"credential-1"}`, `{"all_grant_types":"true","grant_type":"bulk-session"}`, `{"all_grant_types":"false"}`, `{}`} {
		malformed, malformedErr := service.Revoke(context.Background(), []byte(body), commandOptions(aep.AssertionRevoke, "revoke-malformed-"+body, "revoke-malformed-"+body))
		if malformedErr != nil || malformed.Problem == nil || malformed.Problem.Code != aep.ErrorInvalidRequest {
			t.Fatalf("CORE-RVK-008 accepted %s: %#v, %v", body, malformed, malformedErr)
		}
	}
}

// CORE-INS-009 and CORE-INS-022: the advertised command set follows the configured capabilities.
func TestInspectAdvertisementMatchesConfiguredCapabilities(t *testing.T) {
	withoutGrants := newTestService(t, Options{})
	document, err := withoutGrants.InspectDocument()
	if err != nil {
		t.Fatal(err)
	}
	if containsCommand(document.Commands.Supported, aep.CommandGrant) || containsCommand(document.Commands.Supported, aep.CommandRevoke) {
		t.Fatalf("CORE-INS-009 advertised Grant or Revoke without grant types: %#v", document.Commands)
	}
	if len(document.Identity.Methods) == 0 {
		t.Fatalf("CORE-INS-022 advertised no identity method: %#v", document.Identity)
	}
	if err := aep.ValidateInspectDocument(document); err != nil {
		t.Fatalf("the advertised document is not valid: %v", err)
	}

	withGrants := newTestService(t, Options{GrantTypes: []GrantTypeDefinition{{GrantType: "custom-session", Handler: &testGrantHandler{}}}})
	granted, err := withGrants.InspectDocument()
	if err != nil {
		t.Fatal(err)
	}
	if !containsCommand(granted.Commands.Supported, aep.CommandGrant) || !containsCommand(granted.Commands.Supported, aep.CommandRevoke) {
		t.Fatalf("a Service with grant types did not advertise them: %#v", granted.Commands)
	}
}

// CORE-GRT-003 and CORE-GRT-004: Grant never implicitly enrolls.
func TestGrantRequiresAnExistingEnrollment(t *testing.T) {
	service := newTestService(t, Options{GrantTypes: []GrantTypeDefinition{{GrantType: "custom-session", Handler: &testGrantHandler{
		grant: func(aep.GrantRequest, GrantContext) (json.RawMessage, error) {
			t.Fatal("Grant reached the handler for an unenrolled Agent")
			return nil, nil
		},
	}}}})
	result, err := service.Grant(context.Background(), []byte(`{"grant_type":"custom-session"}`), commandOptions(aep.AssertionGrant, "grant-unenrolled", "grant-unenrolled"))
	if err != nil || result.Problem == nil || result.Problem.Code != aep.ErrorNotRecognized {
		t.Fatalf("Grant before Enroll was accepted: %#v, %v", result, err)
	}
	if _, err := service.enrollmentStore.FindEnrollment(context.Background(), "did:web:agent.example"); err != nil {
		t.Fatal(err)
	}
	record, err := service.enrollmentStore.FindEnrollment(context.Background(), "did:web:agent.example")
	if err != nil || record != nil {
		t.Fatalf("Grant implicitly enrolled the Agent: %#v, %v", record, err)
	}
}

// CORE-ERR-009: each error code carries its fixed default status.
func TestErrorCodesCarryTheirDefaultStatus(t *testing.T) {
	service := newTestService(t, Options{GrantTypes: []GrantTypeDefinition{{GrantType: "custom-session", Handler: &testGrantHandler{}}}})
	handler, err := NewHTTPHandler(service, HTTPHandlerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	unauthorized := serveRequest(handler, http.MethodGet, "/aep/status", "", http.Header{})
	assertAEPProblem(t, unauthorized, http.StatusUnauthorized, aep.ErrorNotRecognized)
	if !strings.Contains(unauthorized.Header().Get("WWW-Authenticate"), `reason="not_recognized"`) {
		t.Fatalf("a 401 command response carried no AEP challenge: %q", unauthorized.Header().Get("WWW-Authenticate"))
	}

	seedEnrollment(t, service.enrollmentStore)
	unsupported := serveRequest(handler, http.MethodPost, "/aep/grant", `{"grant_type":"absent-session"}`, commandHeaders(assertion(aep.AssertionGrant, "grant-unsupported", ""), "grant-unsupported"))
	assertAEPProblem(t, unsupported, http.StatusBadRequest, aep.ErrorUnsupportedGrantType)

	invalid := serveRequest(handler, http.MethodPost, "/aep/enroll", `{`, commandHeaders(assertion(aep.AssertionEnroll, "enroll-invalid", ""), "enroll-invalid"))
	assertAEPProblem(t, invalid, http.StatusBadRequest, aep.ErrorInvalidRequest)

	first := serveRequest(handler, http.MethodPost, "/aep/enroll", `{"agent_did":"did:web:agent.example"}`, commandHeaders(assertion(aep.AssertionEnroll, "conflict-1", ""), "conflict-key"))
	if first.Code != http.StatusOK {
		t.Fatalf("the first Enroll returned %d: %s", first.Code, first.Body.String())
	}
	conflict := serveRequest(handler, http.MethodPost, "/aep/grant", `{"grant_type":"custom-session"}`, commandHeaders(assertion(aep.AssertionGrant, "conflict-2", ""), "conflict-key"))
	assertAEPProblem(t, conflict, http.StatusConflict, aep.ErrorIdempotencyConflict)
}

// CORE-ENR-010 and CORE-ERR-004..006: a blocked lifecycle state answers with names, never values.
func TestLifecycleProblemsCarryNamesWithoutClaimValues(t *testing.T) {
	store := NewMemoryEnrollmentStore()
	if _, err := store.SaveEnrollment(context.Background(), EnrollmentRecord{
		AgentDID: "did:web:agent.example", CreatedAt: testNow, EnrollmentID: "enrollment-1", OwnerActionRequired: true,
		RequirementsPending: []string{"contact.email"}, Since: testNow, Status: aep.AgentPending, UpdatedAt: testNow,
		VerificationPending: []string{"domain-control"},
	}); err != nil {
		t.Fatal(err)
	}
	service := newTestService(t, Options{
		EnrollmentStore: store,
		GrantTypes:      []GrantTypeDefinition{{GrantType: "custom-session", Handler: &testGrantHandler{}}},
	})
	result, err := service.Grant(context.Background(), []byte(`{"grant_type":"custom-session"}`), commandOptions(aep.AssertionGrant, "grant-pending", "grant-pending"))
	if err != nil || result.Problem == nil || result.Problem.Code != aep.ErrorVerificationPending || result.Status != http.StatusForbidden {
		t.Fatalf("a pending identity was not blocked: %#v, %v", result, err)
	}
	problem := result.Problem
	if problem.OwnerActionRequired == nil || *problem.OwnerActionRequired != "true" {
		t.Fatalf("CORE-ERR-005 owner_action_required was %#v", problem.OwnerActionRequired)
	}
	if len(problem.VerificationPending) != 1 || problem.VerificationPending[0] != "domain-control" {
		t.Fatalf("CORE-ERR-004 verification_pending was %#v", problem.VerificationPending)
	}
	if len(problem.RequirementsPending) != 1 || problem.RequirementsPending[0] != "contact.email" {
		t.Fatalf("CORE-ERR-006 requirements_pending was %#v", problem.RequirementsPending)
	}
}

// APK-RSP-006, APK-SEC-005 and APK-PRS-002 bind an API key to exactly the issued header.
func TestAPIKeyCredentialsAreBoundToTheIssuedHeader(t *testing.T) {
	store := NewMemoryServiceCredentialStore()
	expiry := testNow.Add(time.Hour).UTC().Format(time.RFC3339)
	definition, err := StoredAPIKeyGrantType(StoredCredentialGrantTypeOptions[aep.APIKeyGrantResponse]{
		Config: aep.GrantTypeConfig{Additional: aep.AdditionalMembers{"header_names": json.RawMessage(`["x-api-key"]`)}},
		Issue: func(context.Context, aep.GrantRequest, GrantContext) (aep.APIKeyGrantResponse, error) {
			return aep.APIKeyGrantResponse{APIKey: "key-value", CredentialID: "credential-1", ExpiresAt: expiry, Header: "x-api-key"}, nil
		},
		Store: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	service := newTestService(t, Options{
		AuthenticationMethods: []aep.AuthenticationMethod{aep.AuthenticationMethod(aep.GrantTypeAPIKey)},
		GrantTypes:            []GrantTypeDefinition{definition},
	})
	seedEnrollment(t, service.enrollmentStore)
	if granted, grantErr := service.Grant(context.Background(), []byte(`{"grant_type":"api-key"}`), commandOptions(aep.AssertionGrant, "grant-api-key", "grant-api-key")); grantErr != nil || granted.Problem != nil {
		t.Fatalf("the API key was not issued: %#v, %v", granted, grantErr)
	}
	resource := mustURL(t, "https://service.example/private")

	issued, err := service.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{
		Headers: http.Header{"X-Api-Key": {"key-value"}}, Method: http.MethodGet, URL: resource,
	})
	if err != nil || !issued.Authenticated || issued.Principal == nil || issued.Principal.CredentialID != "credential-1" {
		t.Fatalf("the issued header did not authenticate: %#v, %v", issued, err)
	}

	wrongHeader, err := service.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{
		Headers: http.Header{"Authorization": {"Bearer key-value"}}, Method: http.MethodGet, URL: resource,
	})
	if err != nil || wrongHeader.Authenticated || wrongHeader.Response.Body.Code != aep.ErrorUnsupportedAuthenticationMethod {
		t.Fatalf("APK-PRS-002 answered %#v, %v", wrongHeader.Response, err)
	}

	unknownValue, err := service.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{
		Headers: http.Header{"X-Api-Key": {"another-value"}}, Method: http.MethodGet, URL: resource,
	})
	if err != nil || unknownValue.Authenticated || unknownValue.Response.Body.Code != aep.ErrorNotRecognized {
		t.Fatalf("APK-PRS-003 answered %#v, %v", unknownValue.Response, err)
	}

	ambiguous, err := service.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{
		Headers: http.Header{"X-Api-Key": {"key-value", "key-value"}}, Method: http.MethodGet, URL: resource,
	})
	if err != nil || ambiguous.Authenticated || ambiguous.Response.Body.Code != aep.ErrorNotRecognized {
		t.Fatalf("APK-SEC-006 accepted repeated API-key headers: %#v, %v", ambiguous.Response, err)
	}

	revoked, err := service.Revoke(context.Background(), []byte(`{"grant_type":"api-key","credential_id":"credential-1"}`), commandOptions(aep.AssertionRevoke, "revoke-api-key", "revoke-api-key"))
	if err != nil || revoked.Problem != nil {
		t.Fatalf("the API key was not revoked: %#v, %v", revoked, err)
	}
	afterRevoke, err := service.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{
		Headers: http.Header{"X-Api-Key": {"key-value"}}, Method: http.MethodGet, URL: resource,
	})
	if err != nil || afterRevoke.Authenticated || afterRevoke.Response.Body.Code != aep.ErrorNotRecognized {
		t.Fatalf("a revoked API key still authenticated: %#v, %v", afterRevoke.Response, err)
	}
}

// CORE-SEC and OAB/BSC presentation rules: a session credential expires and is then unknown.
func TestSessionCredentialsStopAuthenticatingAtExpiry(t *testing.T) {
	store := NewMemoryServiceCredentialStore()
	expiry := testNow.Add(time.Minute)
	definition, err := StoredOAuthBearerGrantType(StoredCredentialGrantTypeOptions[aep.OAuthBearerGrantResponse]{
		Issue: func(context.Context, aep.GrantRequest, GrantContext) (aep.OAuthBearerGrantResponse, error) {
			return aep.OAuthBearerGrantResponse{
				AccessToken: "token-value", CredentialID: "credential-1", ExpiresAt: expiry.UTC().Format(time.RFC3339),
				Scopes: []string{"read"}, TokenType: "Bearer",
			}, nil
		},
		Store: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := testNow
	service := newClockedTestService(t, func() time.Time { return now }, Options{
		AuthenticationMethods: []aep.AuthenticationMethod{aep.AuthenticationMethod(aep.GrantTypeOAuthBearer)},
		GrantTypes:            []GrantTypeDefinition{definition},
	})
	seedEnrollment(t, service.enrollmentStore)
	if granted, grantErr := service.Grant(context.Background(), []byte(`{"grant_type":"oauth-bearer"}`), commandOptions(aep.AssertionGrant, "grant-bearer", "grant-bearer")); grantErr != nil || granted.Problem != nil {
		t.Fatalf("the bearer credential was not issued: %#v, %v", granted, grantErr)
	}
	resource := mustURL(t, "https://service.example/private")
	headers := http.Header{"Authorization": {"Bearer token-value"}}

	valid, err := service.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{Headers: headers, Method: http.MethodGet, URL: resource})
	if err != nil || !valid.Authenticated || valid.Principal == nil || len(valid.Principal.Scopes) != 1 || valid.Principal.Scopes[0] != "read" {
		t.Fatalf("the bearer credential did not authenticate: %#v, %v", valid, err)
	}
	now = expiry
	expired, err := service.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{Headers: headers, Method: http.MethodGet, URL: resource})
	if err != nil || expired.Authenticated || expired.Response.Body.Code != aep.ErrorNotRecognized {
		t.Fatalf("an expired credential still authenticated: %#v, %v", expired.Response, err)
	}
}

// CORE-CA-015 and CORE-CA-016: the resource claim must identify the request target exactly.
func TestProtectedResourceBindsTheAssertionToItsTarget(t *testing.T) {
	service := newTestService(t, Options{AuthenticationMethods: []aep.AuthenticationMethod{aep.AuthenticationMethodJWT}})
	seedEnrollment(t, service.enrollmentStore)
	target := mustURL(t, "https://service.example/private")
	for _, claimed := range []string{"https://service.example/other", "https://elsewhere.example/private", ""} {
		result, err := service.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{
			Headers: http.Header{"Authorization": {"AEP " + assertion(aep.AssertionAuthenticate, "resource-"+claimed, claimed)}},
			Method:  http.MethodGet, URL: target,
		})
		if err != nil || result.Authenticated || result.Response.Body.Code != aep.ErrorNotRecognized {
			t.Fatalf("resource %q authenticated against %s: %#v, %v", claimed, target, result, err)
		}
	}
	matching, err := service.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{
		Headers: http.Header{"Authorization": {"AEP " + assertion(aep.AssertionAuthenticate, "resource-match", target.String())}},
		Method:  http.MethodGet, URL: target,
	})
	if err != nil || !matching.Authenticated {
		t.Fatalf("a matching resource claim was rejected: %#v, %v", matching, err)
	}
}

// CORE-PR-024 and the AEP resource rules: a protected resource target must be an absolute HTTPS URI
// without credentials or a fragment, and loopback HTTP only when it is explicitly permitted.
func TestProtectedResourceTargetsMustBeSafeAbsoluteURLs(t *testing.T) {
	service := newTestService(t, Options{})
	for _, value := range []string{
		"https://user:secret@service.example/private",
		"https://service.example/private#fragment",
		"/private",
		"http://service.example/private",
		"http://127.0.0.1/private",
		"mailto:agent@example.com",
	} {
		if _, err := service.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{
			Headers: http.Header{}, Method: http.MethodGet, URL: mustURL(t, value),
		}); err == nil {
			t.Fatalf("an unsafe protected resource target was accepted: %s", value)
		}
	}
	if _, err := service.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{
		Headers: http.Header{}, Method: http.MethodGet, URL: nil,
	}); err == nil {
		t.Fatal("a nil protected resource target was accepted")
	}

	loopback := newTestService(t, Options{ClientAssertion: ClientAssertionOptions{AllowInsecureLoopback: true}})
	for _, value := range []string{"http://127.0.0.1:8080/private", "http://localhost/private", "http://[::1]/private"} {
		result, err := loopback.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{
			Headers: http.Header{}, Method: http.MethodGet, URL: mustURL(t, value),
		})
		if err != nil || result.Response == nil || result.Response.Body.Code != aep.ErrorAuthenticationRequired {
			t.Fatalf("a permitted loopback target was refused: %s, %#v, %v", value, result, err)
		}
	}
	if _, err := loopback.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{
		Headers: http.Header{}, Method: http.MethodGet, URL: mustURL(t, "http://service.example/private"),
	}); err == nil {
		t.Fatal("plaintext HTTP outside loopback was accepted")
	}
}

// CORE-ENR-002: the Enroll body must name the Agent the assertion authenticated.
func TestEnrollBindsTheRequestBodyToTheAssertionSubject(t *testing.T) {
	service := newTestService(t, Options{})
	result, err := service.Enroll(context.Background(), []byte(`{"agent_did":"did:web:attacker.example"}`), commandOptions(aep.AssertionEnroll, "enroll-substituted", "enroll-substituted"))
	if err != nil || result.Problem == nil || result.Problem.Code != aep.ErrorInvalidRequest {
		t.Fatalf("Enroll accepted another Agent's DID: %#v, %v", result, err)
	}
}

// CORE-ERR-001: the WWW-Authenticate challenge is a well-formed auth-param list even when the
// Service DID and Inspect URL are attacker-visible configuration.
func TestChallengeParametersAreQuotedStrings(t *testing.T) {
	service := newTestService(t, Options{InspectURL: mustURL(t, "https://service.example/.well-known/aep")})
	resource := mustURL(t, "https://service.example/private")
	result, err := service.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{
		Headers: http.Header{}, Method: http.MethodGet, URL: resource,
	})
	if err != nil || result.Response == nil {
		t.Fatalf("unexpected result: %#v, %v", result, err)
	}
	challenge := result.Response.Headers.Get("WWW-Authenticate")
	expected := `AEP service_did="did:web:service.example",inspect="https://service.example/.well-known/aep",reason="authentication_required"`
	if challenge != expected {
		t.Fatalf("challenge was %q, expected %q", challenge, expected)
	}
	if strings.ContainsAny(challenge, "\r\n") {
		t.Fatalf("challenge carried a line break: %q", challenge)
	}
}

// The Inspect URL is published in every challenge, so it must be validated at construction.
func TestInspectURLIsValidatedAtConstruction(t *testing.T) {
	for _, value := range []string{
		"http://service.example/.well-known/aep",
		"https://user:secret@service.example/.well-known/aep",
		"https://service.example/.well-known/aep#fragment",
		"/.well-known/aep",
		"mailto:agent@example.com",
	} {
		if _, err := New(Options{
			IdentityMethods: []aep.IdentityMethod{aep.IdentityMethodDIDWeb},
			InspectURL:      mustURL(t, value),
			ServiceDID:      "did:web:service.example",
			Verifier: func(context.Context, string, AssertionVerificationContext) (aep.ClientAssertionClaims, error) {
				return aep.ClientAssertionClaims{}, nil
			},
		}); err == nil {
			t.Fatalf("an unsafe Inspect URL was accepted: %s", value)
		}
	}
	loopback, err := New(Options{
		ClientAssertion: ClientAssertionOptions{AllowInsecureLoopback: true},
		IdentityMethods: []aep.IdentityMethod{aep.IdentityMethodDIDWeb},
		InspectURL:      mustURL(t, "http://localhost:8080/.well-known/aep"),
		ServiceDID:      "did:web:service.example",
		Verifier: func(context.Context, string, AssertionVerificationContext) (aep.ClientAssertionClaims, error) {
			return aep.ClientAssertionClaims{}, nil
		},
	})
	if err != nil || loopback.inspectURL == nil || loopback.inspectURL.String() != "http://localhost:8080/.well-known/aep" {
		t.Fatalf("a permitted loopback Inspect URL was refused: %#v, %v", loopback, err)
	}
}

// CORE-CA-019 and CORE-CA-020: the configured lifetime and skew bounds are the spec's bounds.
func TestClientAssertionBoundsFollowTheSpecLimits(t *testing.T) {
	for _, test := range []struct {
		lifetime time.Duration
		skew     *time.Duration
		valid    bool
	}{
		{lifetime: aep.MaxAssertionLifetime, valid: true},
		{lifetime: time.Second, valid: true},
		{lifetime: aep.MaxAssertionLifetime + time.Second},
		{lifetime: 500 * time.Millisecond},
		{lifetime: 1500 * time.Millisecond},
		{skew: durationPointer(-time.Second)},
		{skew: durationPointer(aep.RecommendedClockSkew + time.Second)},
		{skew: durationPointer(1500 * time.Millisecond)},
		{skew: durationPointer(aep.RecommendedClockSkew), valid: true},
	} {
		options := ClientAssertionOptions{MaximumLifetime: test.lifetime, ClockSkew: test.skew}
		resolved, err := resolveClientAssertionOptions(options)
		if test.valid != (err == nil) {
			t.Fatalf("options %#v resolved to %#v, %v", options, resolved, err)
		}
		if test.valid && resolved.MaximumLifetime > aep.MaxAssertionLifetime {
			t.Fatalf("resolved lifetime exceeded the protocol maximum: %s", resolved.MaximumLifetime)
		}
	}
}

func durationPointer(value time.Duration) *time.Duration {
	return &value
}

// CORE-HTTP-006: the baseline Authorization carrier reaches every advertised command, and only it.
func TestCommandsAcceptOnlyTheBaselineAuthorizationCarrier(t *testing.T) {
	service := newTestService(t, Options{})
	seedEnrollment(t, service.enrollmentStore)
	handler, err := NewHTTPHandler(service, HTTPHandlerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	baseline := serveRequest(handler, http.MethodGet, "/aep/status", "", http.Header{
		"Authorization": {"AEP " + assertion(aep.AssertionStatus, "status-baseline", "")},
	})
	if baseline.Code != http.StatusOK {
		t.Fatalf("the baseline carrier was refused: %d %s", baseline.Code, baseline.Body.String())
	}
	dedicated := serveRequest(handler, http.MethodGet, "/aep/status", "", http.Header{
		"Aep-Authorization": {"AEP " + assertion(aep.AssertionStatus, "status-dedicated", "")},
	})
	assertAEPProblem(t, dedicated, http.StatusUnauthorized, aep.ErrorNotRecognized)
	repeated := serveRequest(handler, http.MethodGet, "/aep/status", "", http.Header{
		"Authorization": {"AEP " + assertion(aep.AssertionStatus, "status-repeat-1", ""), "AEP " + assertion(aep.AssertionStatus, "status-repeat-2", "")},
	})
	assertAEPProblem(t, repeated, http.StatusUnauthorized, aep.ErrorNotRecognized)
}

// CORE-ENR-001: the command binding requires the AEP media type on every state-mutating command.
func TestCommandsRequireTheAEPMediaType(t *testing.T) {
	service := newTestService(t, Options{})
	handler, err := NewHTTPHandler(service, HTTPHandlerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, contentType := range []string{"application/json", "", "not a media type"} {
		headers := http.Header{"Idempotency-Key": {"media-type"}}
		if contentType != "" {
			headers.Set("Content-Type", contentType)
		}
		recorder := serveRequest(handler, http.MethodPost, "/aep/enroll", `{}`, headers)
		if recorder.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("Content-Type %q returned %d", contentType, recorder.Code)
		}
	}
	repeated := serveRequest(handler, http.MethodPost, "/aep/enroll", `{}`, http.Header{
		"Content-Type": {aep.MediaType, aep.MediaType}, "Idempotency-Key": {"media-type"},
	})
	if repeated.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("repeated Content-Type returned %d", repeated.Code)
	}
}

// The protected-resource middleware rebuilds the target from a fixed origin so a forwarded Host
// header cannot move the resource an assertion is checked against.
func TestProtectedResourceMiddlewarePinsTheConfiguredOrigin(t *testing.T) {
	service := newTestService(t, Options{AuthenticationMethods: []aep.AuthenticationMethod{aep.AuthenticationMethodJWT}})
	seedEnrollment(t, service.enrollmentStore)
	middleware, err := NewProtectedResourceMiddleware(service, "https://service.example")
	if err != nil {
		t.Fatal(err)
	}
	guarded := middleware(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "/private", nil)
	request.Host = "attacker.example"
	request.Header.Set("Authorization", "AEP "+assertion(aep.AssertionAuthenticate, "origin-pin", "https://service.example/private"))
	recorder := httptest.NewRecorder()
	guarded.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("the configured origin was not used: %d %s", recorder.Code, recorder.Body.String())
	}

	for _, origin := range []string{"https://service.example/base", "http://service.example", "https://user:secret@service.example", "https://service.example?query", "https://service.example#fragment", "service.example", "://"} {
		if _, originErr := NewProtectedResourceMiddleware(service, origin); originErr == nil {
			t.Fatalf("an unsafe middleware origin was accepted: %s", origin)
		}
	}
}

var _ = url.Parse

// newClockedTestService builds a Service the way newTestService does but keeps the caller's clock,
// so a test can move time forward across a credential's expiry.
func newClockedTestService(t *testing.T, clock func() time.Time, options Options) *Service {
	t.Helper()
	service := newTestService(t, options)
	service.clock = clock
	return service
}
