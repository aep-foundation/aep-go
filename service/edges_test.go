package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	aep "github.com/aep-foundation/aep-go"
)

// invalidClaimValues carries a member whose raw JSON cannot be encoded, which is how a caller-
// supplied claim set reaches the cloning failures the command paths guard against.
func invalidClaimValues() *aep.ClaimValues {
	return &aep.ClaimValues{Additional: aep.AdditionalMembers{"vendor.example": json.RawMessage("not json")}}
}

func recordWithInvalidClaims(agentDID string) EnrollmentRecord {
	record := activeEnrollment(agentDID)
	record.Claims = invalidClaimValues()
	return record
}

func TestCommandsSurfaceReplayStoreFailures(t *testing.T) {
	failing := Options{ReplayStore: stubReplayStore{consume: func(ReplayRecord, int64) (bool, error) { return false, errStore }}}
	service := newTestService(t, failing)
	seedEnrollment(t, service.enrollmentStore)
	if _, err := service.Status(context.Background(), commandOptions(aep.AssertionStatus, "replay-status", "")); !errors.Is(err, errStore) {
		t.Fatalf("Status swallowed a replay store failure: %v", err)
	}

	withGrants := newTestService(t, Options{
		AuthenticationMethods: []aep.AuthenticationMethod{aep.AuthenticationMethodJWT},
		GrantTypes:            []GrantTypeDefinition{{GrantType: "custom-session", Handler: &testGrantHandler{}}},
		ReplayStore:           stubReplayStore{consume: func(ReplayRecord, int64) (bool, error) { return false, errStore }},
	})
	seedEnrollment(t, withGrants.enrollmentStore)
	if _, err := withGrants.Grant(context.Background(), []byte(`{"grant_type":"custom-session"}`), commandOptions(aep.AssertionGrant, "replay-grant", "replay-grant")); !errors.Is(err, errStore) {
		t.Fatalf("Grant swallowed a replay store failure: %v", err)
	}
	if _, err := withGrants.Revoke(context.Background(), []byte(`{"grant_type":"custom-session"}`), commandOptions(aep.AssertionRevoke, "replay-revoke", "replay-revoke")); !errors.Is(err, errStore) {
		t.Fatalf("Revoke swallowed a replay store failure: %v", err)
	}
	resource := mustURL(t, "https://service.example/private")
	if _, err := withGrants.AuthenticateProtectedResource(context.Background(), ProtectedResourceRequest{
		Headers: http.Header{"Authorization": {"AEP " + assertion(aep.AssertionAuthenticate, "replay-resource", resource.String())}},
		Method:  http.MethodGet, URL: resource,
	}); !errors.Is(err, errStore) {
		t.Fatalf("the protected resource swallowed a replay store failure: %v", err)
	}
}

func TestCommandsRefuseUnrepresentableStoredRecords(t *testing.T) {
	enrollBody := []byte(`{"agent_did":"did:web:agent.example"}`)

	// An EnrollResponse assembled from a record with an empty pending name is not a valid response.
	invalidPending := newTestService(t, Options{EnrollmentStore: stubEnrollmentStore{
		find: func(agentDID string) (*EnrollmentRecord, error) {
			record := activeEnrollment(agentDID)
			record.VerificationPending = []string{""}
			return &record, nil
		},
		findOrCreate: func(agentDID string, _ func() (EnrollmentRecord, error)) (EnrollmentRecord, bool, error) {
			record := activeEnrollment(agentDID)
			record.VerificationPending = []string{""}
			return record, false, nil
		},
	}})
	if _, err := invalidPending.Enroll(context.Background(), enrollBody, commandOptions(aep.AssertionEnroll, "enroll-invalid-pending", "enroll-invalid-pending")); err == nil {
		t.Fatal("Enroll returned an invalid response body")
	}
	if _, err := invalidPending.Status(context.Background(), commandOptions(aep.AssertionStatus, "status-invalid-pending", "")); err == nil {
		t.Fatal("Status returned an invalid response body")
	}

	// A policy decision that cannot become a valid response fails before anything is stored.
	badDecision := newTestService(t, Options{EnrollmentPolicy: testEnrollmentPolicy(func(aep.EnrollRequest, EnrollmentPolicyContext) (EnrollmentDecision, error) {
		return EnrollmentDecision{Status: aep.EnrollmentActive, VerificationPending: []string{""}}, nil
	})})
	if _, err := badDecision.Enroll(context.Background(), enrollBody, commandOptions(aep.AssertionEnroll, "enroll-bad-decision", "enroll-bad-decision")); err == nil {
		t.Fatal("an unrepresentable enrollment decision was stored")
	}

	// An absent decision status defaults to active rather than failing validation.
	defaulted := newTestService(t, Options{EnrollmentPolicy: testEnrollmentPolicy(func(aep.EnrollRequest, EnrollmentPolicyContext) (EnrollmentDecision, error) {
		return EnrollmentDecision{}, nil
	})})
	result, err := defaulted.Enroll(context.Background(), enrollBody, commandOptions(aep.AssertionEnroll, "enroll-defaulted", "enroll-defaulted"))
	if err != nil || result.Problem != nil || result.Body.Status != aep.AgentActive {
		t.Fatalf("an absent decision status did not default to active: %#v, %v", result, err)
	}

	// A stored record whose claim values cannot be re-encoded stops Grant and Revoke.
	corrupt := newTestService(t, Options{
		EnrollmentStore: stubEnrollmentStore{find: func(agentDID string) (*EnrollmentRecord, error) {
			record := recordWithInvalidClaims(agentDID)
			return &record, nil
		}},
		GrantTypes: []GrantTypeDefinition{{GrantType: "custom-session", Handler: &testGrantHandler{}}},
	})
	if _, err := corrupt.Grant(context.Background(), []byte(`{"grant_type":"custom-session"}`), commandOptions(aep.AssertionGrant, "grant-corrupt", "grant-corrupt")); err == nil {
		t.Fatal("Grant proceeded from an unreadable enrollment record")
	}
	if _, err := corrupt.Revoke(context.Background(), []byte(`{"grant_type":"custom-session"}`), commandOptions(aep.AssertionRevoke, "revoke-corrupt", "revoke-corrupt")); err == nil {
		t.Fatal("Revoke proceeded from an unreadable enrollment record")
	}
	if _, err := cloneClaimValues(invalidClaimValues()); err == nil {
		t.Fatal("unencodable claim values cloned successfully")
	}
	if _, err := cloneEnrollment(recordWithInvalidClaims("did:web:agent.example")); err == nil {
		t.Fatal("an unreadable enrollment record cloned successfully")
	}
}

// validAssertion re-checks the lifetime and clock bounds that the shared claim validator already
// enforces, so these vectors reach the defence directly rather than through a command.
func TestValidAssertionEnforcesItsOwnLifetimeAndClockBounds(t *testing.T) {
	service := newTestService(t, Options{})
	base := func() aep.ClientAssertionClaims {
		return aep.ClientAssertionClaims{
			Audience: "did:web:service.example", ExpiresAt: testNow.Add(time.Minute).Unix(), IssuedAt: testNow.Unix(),
			Issuer: "did:web:agent.example", JWTID: "bounds", Operation: aep.AssertionStatus, Subject: "did:web:agent.example",
		}
	}
	token := assertion(aep.AssertionStatus, "bounds", "")
	if !service.validAssertion(token, base(), aep.AssertionStatus, "", testNow) {
		t.Fatal("a well-formed assertion was rejected")
	}
	for _, test := range []struct {
		mutate func(*aep.ClientAssertionClaims)
		name   string
	}{
		{name: "expiry at issuance", mutate: func(claims *aep.ClientAssertionClaims) { claims.ExpiresAt = claims.IssuedAt }},
		{name: "expiry before issuance", mutate: func(claims *aep.ClientAssertionClaims) { claims.ExpiresAt = claims.IssuedAt - 1 }},
		{name: "lifetime beyond the maximum", mutate: func(claims *aep.ClientAssertionClaims) {
			claims.ExpiresAt = claims.IssuedAt + int64(aep.MaxAssertionLifetime/time.Second) + 1
		}},
		{name: "issuance that overflows the lifetime window", mutate: func(claims *aep.ClientAssertionClaims) {
			claims.IssuedAt = math.MaxInt64 - 1
			claims.ExpiresAt = math.MaxInt64
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			claims := base()
			test.mutate(&claims)
			if service.validAssertion(token, claims, aep.AssertionStatus, "", testNow) {
				t.Fatalf("an out-of-bounds assertion was accepted: %#v", claims)
			}
		})
	}

	// Saturating arithmetic keeps the comparison meaningful at the extremes of the clock.
	late := time.Unix(math.MaxInt64-10, 0)
	lateClaims := base()
	lateClaims.ExpiresAt = math.MaxInt64 - 1
	lateClaims.IssuedAt = lateClaims.ExpiresAt - int64(aep.MaxAssertionLifetime/time.Second)
	if !service.validAssertion(token, lateClaims, aep.AssertionStatus, "", late) {
		t.Fatal("a valid assertion was rejected at the upper end of the clock")
	}
	early := time.Unix(math.MinInt64+10, 0)
	earlyClaims := base()
	earlyClaims.IssuedAt = early.Unix()
	earlyClaims.ExpiresAt = early.Unix() + int64(aep.MaxAssertionLifetime/time.Second)
	if !service.validAssertion(token, earlyClaims, aep.AssertionStatus, "", early) {
		t.Fatal("a valid assertion was rejected at the lower end of the clock")
	}

	// An expiry that would overflow the replay window is refused rather than wrapped.
	overflow := newTestService(t, Options{})
	overflow.verifier = func(context.Context, string, AssertionVerificationContext) (aep.ClientAssertionClaims, error) {
		claims := base()
		claims.IssuedAt = math.MaxInt64 - 60
		claims.ExpiresAt = math.MaxInt64 - 1
		return claims, nil
	}
	result, err := overflow.Status(context.Background(), CommandOptions{ClientAssertion: token})
	if err != nil || result.Problem == nil || result.Problem.Code != aep.ErrorNotRecognized {
		t.Fatalf("an overflowing replay window was accepted: %#v, %v", result, err)
	}
}

func TestStoredCredentialGrantTypeWithoutAdvertisedHeaders(t *testing.T) {
	store := NewMemoryServiceCredentialStore()
	expiry := testNow.Add(time.Hour).UTC().Format(time.RFC3339)
	definition, err := StoredAPIKeyGrantType(StoredCredentialGrantTypeOptions[aep.APIKeyGrantResponse]{
		Issue: func(context.Context, aep.GrantRequest, GrantContext) (aep.APIKeyGrantResponse, error) {
			return aep.APIKeyGrantResponse{APIKey: "key-value", CredentialID: "credential-1", ExpiresAt: expiry, Header: "x-vendor-key"}, nil
		},
		Store: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	service := newTestService(t, Options{GrantTypes: []GrantTypeDefinition{definition}})
	seedEnrollment(t, service.enrollmentStore)
	granted, err := service.Grant(context.Background(), []byte(`{"grant_type":"api-key"}`), commandOptions(aep.AssertionGrant, "grant-unadvertised-header", "grant-unadvertised-header"))
	if err != nil || granted.Problem != nil {
		t.Fatalf("APK-CFG-004 leaves the header free when none is advertised: %#v, %v", granted, err)
	}
}

func TestServiceCredentialRecordRequiresABuiltInCredential(t *testing.T) {
	if _, err := serviceCredentialRecord("did:web:agent.example", nil, testNow); err == nil {
		t.Fatal("a record was built from an unknown credential shape")
	}
}

func TestCredentialPresentationsSkipUnparseableValues(t *testing.T) {
	headers := http.Header{"Authorization": {"Payment orthogonal", "Bearer token", "AEP"}}
	presentations := credentialPresentations(aep.GrantTypeOAuthBearer, headers)
	if len(presentations) != 1 || presentations[0].value != "token" {
		t.Fatalf("unexpected presentations: %#v", presentations)
	}
	if presentations := credentialPresentations(aep.GrantTypeAPIKey, headers); presentations != nil {
		t.Fatalf("an API-key grant type read the Authorization field: %#v", presentations)
	}
}

func TestHTTPHandlerRefusesAServiceItCannotRoute(t *testing.T) {
	service := newTestService(t, Options{})
	unroutable := *service
	unroutable.document.HTTP.EndpointBase = "relative"
	if _, err := NewHTTPHandler(&unroutable, HTTPHandlerOptions{}); err == nil {
		t.Fatal("a Service with an unroutable endpoint base was wrapped")
	}

	unserializable := *service
	unserializable.document.AEPVersion = ""
	if _, err := NewHTTPHandler(&unserializable, HTTPHandlerOptions{}); err == nil {
		t.Fatal("a Service whose document cannot be republished was wrapped")
	}
	if _, err := unserializable.InspectDocument(); err == nil {
		t.Fatal("an unrepublishable document was returned")
	}
}

func TestServeCommandHandlesBodyFailuresAndUnroutableCommands(t *testing.T) {
	service := newTestService(t, Options{GrantTypes: []GrantTypeDefinition{{GrantType: "custom-session", Handler: &testGrantHandler{}}}})
	handler, err := NewHTTPHandler(service, HTTPHandlerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	seedEnrollment(t, service.enrollmentStore)

	revoke := serveRequest(handler, http.MethodPost, "/aep/revoke", `{"grant_type":"custom-session"}`, commandHeaders(assertion(aep.AssertionRevoke, "http-revoke", ""), "http-revoke"))
	if revoke.Code != http.StatusOK {
		t.Fatalf("Revoke over HTTP returned %d: %s", revoke.Code, revoke.Body.String())
	}

	request := httptest.NewRequest(http.MethodPost, "/aep/enroll", errorReader{})
	request.Header = commandHeaders(assertion(aep.AssertionEnroll, "http-body", ""), "http-body")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("an unreadable request body returned %d", recorder.Code)
	}

	// Inspect is answered from its own route, so routing it as a command has no handler.
	handler.commandPaths["/aep/inspect"] = aep.CommandInspect
	unroutable := serveRequest(handler, http.MethodPost, "/aep/inspect", `{}`, commandHeaders("", "unroutable"))
	if unroutable.Code != http.StatusNotFound {
		t.Fatalf("an unroutable command returned %d", unroutable.Code)
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, errors.New("read failed")
}

func TestWriteProblemResponseRejectsAnUnencodableProblem(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeProblemResponse(recorder, &ProblemResponse{
		Body:        aep.ProblemDetails{Additional: aep.AdditionalMembers{"vendor.example": json.RawMessage("not json")}},
		ContentType: aep.ProblemMediaType, Status: http.StatusBadRequest,
	})
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("an unencodable Problem returned %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "Internal Server Error") {
		t.Fatalf("unexpected fallback body: %s", recorder.Body.String())
	}
}

func TestMemoryStoresHonourCancellationWhileAnotherCallerHoldsTheKey(t *testing.T) {
	enrollments := NewMemoryEnrollmentStore()
	release := make(chan struct{})
	entered := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(1)
	go func() {
		defer wait.Done()
		_, _, _ = enrollments.FindOrCreateEnrollment(context.Background(), "did:web:agent.example", func() (EnrollmentRecord, error) {
			close(entered)
			<-release
			return EnrollmentRecord{}, errStore
		})
	}()
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := enrollments.FindOrCreateEnrollment(ctx, "did:web:agent.example", func() (EnrollmentRecord, error) {
		return activeEnrollment("did:web:agent.example"), nil
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled waiter did not give up: %v", err)
	}
	if _, err := enrollments.SaveEnrollment(ctx, activeEnrollment("did:web:agent.example")); !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled save did not give up: %v", err)
	}
	close(release)
	wait.Wait()

	// A waiter that is not cancelled resumes once the in-flight create finishes.
	second := NewMemoryEnrollmentStore()
	gate := make(chan struct{})
	started := make(chan struct{})
	wait.Add(1)
	go func() {
		defer wait.Done()
		_, _, _ = second.FindOrCreateEnrollment(context.Background(), "did:web:agent.example", func() (EnrollmentRecord, error) {
			close(started)
			<-gate
			return activeEnrollment("did:web:agent.example"), nil
		})
	}()
	<-started
	saved := make(chan error, 1)
	go func() {
		_, err := second.SaveEnrollment(context.Background(), activeEnrollment("did:web:agent.example"))
		saved <- err
	}()
	time.Sleep(10 * time.Millisecond)
	close(gate)
	if err := <-saved; err != nil {
		t.Fatalf("a queued save failed: %v", err)
	}
	wait.Wait()

	// The same contract holds for the idempotency store.
	idempotency := NewMemoryIdempotencyStore()
	input := IdempotencyInput{AgentDID: "did:web:agent.example", Command: IdempotentEnroll, IdempotencyKey: "key", RequestHash: "sha256:abc"}
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
	if _, err := idempotency.ExecuteIdempotent(ctx, input, func() (StoredResponse, error) {
		return StoredResponse{}, nil
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled idempotency waiter did not give up: %v", err)
	}
	queued := make(chan IdempotencyResult, 1)
	go func() {
		result, _ := idempotency.ExecuteIdempotent(context.Background(), input, func() (StoredResponse, error) {
			return StoredResponse{}, errors.New("the queued caller executed twice")
		})
		queued <- result
	}()
	time.Sleep(10 * time.Millisecond)
	close(finish)
	if result := <-queued; result.State != IdempotencyReplayed {
		t.Fatalf("a queued caller did not replay the stored response: %#v", result)
	}
	wait.Wait()
}

func TestSaveEnrollmentRefusesRecordsItCannotCopy(t *testing.T) {
	store := NewMemoryEnrollmentStore()
	if _, err := store.SaveEnrollment(context.Background(), recordWithInvalidClaims("did:web:agent.example")); err == nil {
		t.Fatal("a record with unencodable claim values was saved")
	}
	if record, err := store.FindEnrollment(context.Background(), "did:web:agent.example"); err != nil || record != nil {
		t.Fatalf("a refused record was stored anyway: %#v, %v", record, err)
	}
}

var _ io.Reader = errorReader{}

func TestMemoryEnrollmentStoreGivesUpWhenAWaiterIsCancelled(t *testing.T) {
	store := NewMemoryEnrollmentStore()
	entered := make(chan struct{})
	release := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(1)
	go func() {
		defer wait.Done()
		_, _, _ = store.FindOrCreateEnrollment(context.Background(), "did:web:agent.example", func() (EnrollmentRecord, error) {
			close(entered)
			<-release
			return EnrollmentRecord{}, errStore
		})
	}()
	<-entered

	findCtx, cancelFind := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelFind()
	if _, _, err := store.FindOrCreateEnrollment(findCtx, "did:web:agent.example", func() (EnrollmentRecord, error) {
		return activeEnrollment("did:web:agent.example"), nil
	}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a waiting creator did not give up when its deadline passed: %v", err)
	}
	saveCtx, cancelSave := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelSave()
	if _, err := store.SaveEnrollment(saveCtx, activeEnrollment("did:web:agent.example")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a waiting save did not give up when its deadline passed: %v", err)
	}
	close(release)
	wait.Wait()
}

// A record that reached the store before its claim values became unreadable still fails closed.
func TestMemoryEnrollmentStoreFailsClosedOnAnUnreadableStoredRecord(t *testing.T) {
	store := &memoryEnrollmentStore{
		pending: make(map[string]chan struct{}),
		records: map[string]EnrollmentRecord{"did:web:agent.example": recordWithInvalidClaims("did:web:agent.example")},
	}
	if _, err := store.FindEnrollment(context.Background(), "did:web:agent.example"); err == nil {
		t.Fatal("an unreadable stored record was returned")
	}
	if _, _, err := store.FindOrCreateEnrollment(context.Background(), "did:web:agent.example", func() (EnrollmentRecord, error) {
		return activeEnrollment("did:web:agent.example"), nil
	}); err == nil {
		t.Fatal("an unreadable stored record was returned to a creator")
	}
}

func TestInspectDocumentFailsClosedWhenItCannotBeEncoded(t *testing.T) {
	service := newTestService(t, Options{GrantTypes: []GrantTypeDefinition{{GrantType: "custom-session", Handler: &testGrantHandler{}}}})
	unencodable := *service
	unencodable.document.Commands.GrantTypesConfig = map[string]aep.GrantTypeConfig{
		"custom-session": {Additional: aep.AdditionalMembers{"vendor.example": json.RawMessage("not json")}},
	}
	if _, err := unencodable.InspectDocument(); err == nil {
		t.Fatal("an unencodable document was published")
	}
	if _, err := NewHTTPHandler(&unencodable, HTTPHandlerOptions{}); err == nil {
		t.Fatal("a Service with an unencodable document was wrapped")
	}
}
