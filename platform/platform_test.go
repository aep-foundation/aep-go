package platform

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	aep "github.com/aep-foundation/aep-go"
)

const (
	testAgentIdentityID = "pai_01J0AEPPLATFORM000000000001"
	testAgentDIDID      = "4Yf7p2xQd9"
	testPrincipal       = "owner-1"
	testServiceDID      = "did:web:api.service.example"
)

var testClock = time.Now().UTC().Truncate(time.Second)

type testAuthorizer struct {
	allowed    bool
	mu         sync.Mutex
	operations []AuthorizationOperation
}

func (authorizer *testAuthorizer) Authorize(_ context.Context, request AuthorizationRequest, _ RequestContext) (bool, error) {
	authorizer.mu.Lock()
	authorizer.operations = append(authorizer.operations, request.Operation)
	authorizer.mu.Unlock()
	return authorizer.allowed, nil
}

func (authorizer *testAuthorizer) recordedOperations() []AuthorizationOperation {
	authorizer.mu.Lock()
	defer authorizer.mu.Unlock()
	return slices.Clone(authorizer.operations)
}

type testDIDResolver struct {
	resolved bool
}

func (resolver testDIDResolver) ResolveServiceDID(context.Context, string) (bool, error) {
	return resolver.resolved, nil
}

type testLifecyclePolicy struct {
	sign       bool
	transition bool
	verify     bool
}

func (policy testLifecyclePolicy) CanSign(context.Context, IdentityRecord, RequestContext) (bool, error) {
	return policy.sign, nil
}

func (policy testLifecyclePolicy) CanTransition(context.Context, IdentityRecord, ManagedAgentStatus, RequestContext) (bool, error) {
	return policy.transition, nil
}

func (policy testLifecyclePolicy) CanVerify(context.Context, IdentityRecord, RequestContext) (bool, error) {
	return policy.verify, nil
}

type failingKeyStore struct {
	KeyStore
}

func (store failingKeyStore) CreateKey(context.Context, IdentityRecord) error {
	return errors.New("key creation failed")
}

type testKeyStore struct {
	privateKey *ecdsa.PrivateKey
	mu         sync.Mutex
	created    []string
}

func newTestKeyStore(t *testing.T) *testKeyStore {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &testKeyStore{privateKey: privateKey}
}

func (store *testKeyStore) CreateKey(_ context.Context, identity IdentityRecord) error {
	store.mu.Lock()
	store.created = append(store.created, identity.AgentIdentityID)
	store.mu.Unlock()
	return nil
}

func (store *testKeyStore) DIDVerificationMethod(_ context.Context, identity IdentityRecord) (DIDVerificationMethod, error) {
	jwk, err := json.Marshal(jose.JSONWebKey{Key: &store.privateKey.PublicKey})
	if err != nil {
		return DIDVerificationMethod{}, err
	}
	return DIDVerificationMethod{Controller: identity.AgentDID, ID: identity.KeyID, PublicKeyJWK: jwk, Type: "JsonWebKey2020"}, nil
}

func (store *testKeyStore) Sign(_ context.Context, identity IdentityRecord, claims aep.ClientAssertionClaims) (string, error) {
	return aep.SignClientAssertion(claims, aep.SignClientAssertionOptions{
		Algorithm: aep.SigningAlgorithmES256,
		Key:       store.privateKey,
		KeyID:     identity.KeyID,
	})
}

func (store *testKeyStore) VerificationKey(context.Context, IdentityRecord) (any, error) {
	return &store.privateKey.PublicKey, nil
}

func (store *testKeyStore) createdCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.created)
}

func TestPlatformLifecycle(t *testing.T) {
	platform, authorizer, keys := newTestPlatform(t, true)
	ctx := context.Background()
	discovery := platform.Discovery()
	if discovery.Status != 200 || discovery.Body.AEPVersion != "1.0" || !discovery.Body.Platform.HostedVerification || discovery.Body.Endpoints.HostedVerification != "/v1/aep/verifications" {
		t.Fatalf("unexpected discovery response: %#v", discovery)
	}
	if discovery.Body.Signing.DefaultLifetimeSeconds != "300" || discovery.Headers.Get("Cache-Control") != "max-age=300" {
		t.Fatalf("unexpected discovery defaults: %#v", discovery)
	}

	requestContext := RequestContext{IdempotencyKey: "provision-1", Principal: testPrincipal}
	provisioned, err := platform.Provision(ctx, ProvisionRequest{ServiceDID: testServiceDID}, requestContext)
	if err != nil {
		t.Fatal(err)
	}
	if provisioned.Status != 200 || provisioned.Body.AgentIdentityID != testAgentIdentityID || provisioned.Body.AgentDID != "did:web:platform.example.com:agents:"+testAgentDIDID || provisioned.Body.KeyID != provisioned.Body.AgentDID {
		t.Fatalf("unexpected provision response: %#v", provisioned)
	}
	if provisioned.Body.DIDDocumentURL != "https://platform.example.com/agents/4Yf7p2xQd9/did.json" || keys.createdCount() != 1 {
		t.Fatalf("unexpected identity publication data: %#v", provisioned.Body)
	}

	replayed, err := platform.Provision(ctx, ProvisionRequest{ServiceDID: testServiceDID}, requestContext)
	if err != nil || !equalJSON(provisioned, replayed) {
		t.Fatalf("exact replay changed response: %#v, %v", replayed, err)
	}
	conflict, err := platform.Provision(ctx, ProvisionRequest{ServiceDID: "did:web:other.service.example"}, requestContext)
	if err != nil || conflict.Status != 409 || conflict.Problem == nil || conflict.Problem.Code != aep.ErrorIdempotencyConflict {
		t.Fatalf("expected idempotency conflict: %#v, %v", conflict, err)
	}

	didDocument, err := platform.GetDIDDocument(ctx, testAgentDIDID)
	if err != nil || didDocument.Status != 200 || didDocument.ContentType != DIDMediaType || didDocument.Body.ID != provisioned.Body.AgentDID || didDocument.Body.VerificationMethod[0].ID != provisioned.Body.AgentDID {
		t.Fatalf("unexpected DID document: %#v, %v", didDocument, err)
	}

	identity, err := platform.GetIdentity(ctx, testAgentIdentityID, RequestContext{Principal: testPrincipal})
	if err != nil || identity.Status != 200 || identity.Body.AgentIdentityID != testAgentIdentityID {
		t.Fatalf("unexpected identity: %#v, %v", identity, err)
	}
	listed, err := platform.List(ctx, IdentityListQuery{ServiceDID: testServiceDID, Status: ManagedAgentActive}, RequestContext{Principal: testPrincipal})
	if err != nil || listed.Status != 200 || listed.Body.Count != "1" || listed.Body.Total != "1" || len(listed.Body.Data) != 1 {
		t.Fatalf("unexpected list response: %#v, %v", listed, err)
	}

	signed, err := platform.Sign(ctx, testAgentIdentityID, SignRequest{
		JWTID:           "01J0AEPASSERTION0000000001",
		LifetimeSeconds: "300",
		Operation:       aep.AssertionEnroll,
		PlatformContext: map[string]json.RawMessage{"authorization_handle": json.RawMessage(`"opaque"`)},
		ServiceDID:      testServiceDID,
	}, RequestContext{IdempotencyKey: "sign-1", Now: testClock, Principal: testPrincipal})
	if err != nil || signed.Status != 200 || signed.Body.Status != "completed" || signed.Body.ClientAssertion == "" || signed.Body.AgentDID != provisioned.Body.AgentDID || signed.Body.PlatformContext == nil {
		t.Fatalf("unexpected sign response: %#v, %v", signed, err)
	}
	verificationRequest := VerificationRequest{
		ClientAssertion: signed.Body.ClientAssertion,
		Operation:       aep.AssertionEnroll,
		ServiceDID:      testServiceDID,
	}
	authorizer.allowed = false
	deniedVerification, err := platform.Verify(ctx, verificationRequest, RequestContext{IdempotencyKey: "verify-denied", Now: testClock, Principal: testPrincipal})
	if err != nil || deniedVerification.Body.Verified || deniedVerification.Body.Reason != "not_recognized" {
		t.Fatalf("denied verification leaked identity state: %#v, %v", deniedVerification, err)
	}
	authorizer.allowed = true
	wrongPrincipalVerification, err := platform.Verify(ctx, verificationRequest, RequestContext{IdempotencyKey: "verify-wrong-principal", Now: testClock, Principal: "owner-2"})
	if err != nil || wrongPrincipalVerification.Body.Verified {
		t.Fatalf("cross-principal verification succeeded: %#v, %v", wrongPrincipalVerification, err)
	}
	wrongOperation := verificationRequest
	wrongOperation.Operation = aep.AssertionStatus
	wrongOperationVerification, err := platform.Verify(ctx, wrongOperation, RequestContext{IdempotencyKey: "verify-wrong-operation", Now: testClock, Principal: testPrincipal})
	if err != nil || wrongOperationVerification.Body.Verified {
		t.Fatalf("wrong-operation verification succeeded: %#v, %v", wrongOperationVerification, err)
	}
	invalidSignature := verificationRequest
	invalidSignature.ClientAssertion += "invalid"
	invalidSignatureVerification, err := platform.Verify(ctx, invalidSignature, RequestContext{IdempotencyKey: "verify-invalid-signature", Now: testClock, Principal: testPrincipal})
	if err != nil || invalidSignatureVerification.Body.Verified {
		t.Fatalf("invalid signature was recognized: %#v, %v", invalidSignatureVerification, err)
	}

	verified, err := platform.Verify(ctx, verificationRequest, RequestContext{IdempotencyKey: "verify-1", Now: testClock, Principal: testPrincipal})
	if err != nil || verified.Status != 200 || !verified.Body.Verified || verified.Body.AgentIdentityID != testAgentIdentityID || verified.Body.Reason != "verified" {
		t.Fatalf("unexpected verification response: %#v, %v", verified, err)
	}
	verificationReplay, err := platform.Verify(ctx, verificationRequest, RequestContext{IdempotencyKey: "verify-1", Now: testClock, Principal: testPrincipal})
	if err != nil || !equalJSON(verified, verificationReplay) {
		t.Fatalf("exact verification replay changed response: %#v, %v", verificationReplay, err)
	}
	replayedAssertion, err := platform.Verify(ctx, verificationRequest, RequestContext{IdempotencyKey: "verify-2", Now: testClock, Principal: testPrincipal})
	if err != nil || replayedAssertion.Body.Verified || replayedAssertion.Body.Reason != "not_recognized" {
		t.Fatalf("replayed assertion was recognized: %#v, %v", replayedAssertion, err)
	}

	suspended, err := platform.UpdateIdentity(ctx, testAgentIdentityID, LifecycleRequest{Status: ManagedAgentSuspended}, RequestContext{Principal: testPrincipal})
	if err != nil || suspended.Status != 200 || suspended.Body.Status != ManagedAgentSuspended {
		t.Fatalf("unexpected lifecycle response: %#v, %v", suspended, err)
	}
	suspendedVerification, err := platform.Verify(ctx, verificationRequest, RequestContext{IdempotencyKey: "verify-suspended", Now: testClock, Principal: testPrincipal})
	if err != nil || suspendedVerification.Body.Verified {
		t.Fatalf("suspended identity was verified: %#v, %v", suspendedVerification, err)
	}
	blocked, err := platform.Sign(ctx, testAgentIdentityID, SignRequest{JWTID: "blocked", Operation: aep.AssertionStatus, ServiceDID: testServiceDID}, RequestContext{IdempotencyKey: "sign-blocked", Principal: testPrincipal})
	if err != nil || blocked.Status != 403 || blocked.Problem == nil || blocked.Problem.Code != aep.ErrorIdentitySuspended {
		t.Fatalf("suspended identity signed: %#v, %v", blocked, err)
	}

	operations := authorizer.recordedOperations()
	for _, expected := range []AuthorizationOperation{AuthorizeProvision, AuthorizeGetIdentity, AuthorizeListIdentities, AuthorizeSign, AuthorizeVerify, AuthorizeUpdateIdentity} {
		if !slices.Contains(operations, expected) {
			t.Fatalf("authorization operation %q was not checked: %v", expected, operations)
		}
	}
}

func TestPlatformAuthorizationFailsClosed(t *testing.T) {
	platform, authorizer, _ := newTestPlatform(t, true)
	ctx := context.Background()
	provisioned, err := platform.Provision(ctx, ProvisionRequest{ServiceDID: testServiceDID}, RequestContext{IdempotencyKey: "provision", Principal: testPrincipal})
	if err != nil || provisioned.Status != 200 {
		t.Fatalf("setup provision failed: %#v, %v", provisioned, err)
	}
	authorizer.allowed = false

	identity, err := platform.GetIdentity(ctx, testAgentIdentityID, RequestContext{Principal: testPrincipal})
	if err != nil || identity.Status != 404 || identity.Problem == nil || identity.Problem.Code != aep.ErrorNotRecognized {
		t.Fatalf("identity authorization leaked: %#v, %v", identity, err)
	}
	listed, err := platform.List(ctx, IdentityListQuery{}, RequestContext{Principal: testPrincipal})
	if err != nil || listed.Status != 404 || listed.Problem == nil || listed.Problem.Code != aep.ErrorNotRecognized {
		t.Fatalf("list authorization leaked: %#v, %v", listed, err)
	}
	signed, err := platform.Sign(ctx, testAgentIdentityID, SignRequest{JWTID: "denied", Operation: aep.AssertionEnroll, ServiceDID: testServiceDID}, RequestContext{IdempotencyKey: "sign", Principal: testPrincipal})
	if err != nil || signed.Status != 404 || signed.Problem == nil || signed.Problem.Code != aep.ErrorNotRecognized {
		t.Fatalf("sign authorization leaked: %#v, %v", signed, err)
	}

	didDocument, err := platform.GetDIDDocument(ctx, testAgentDIDID)
	if err != nil || didDocument.Status != 200 {
		t.Fatalf("public DID document was authorization-gated: %#v, %v", didDocument, err)
	}
}

func TestPlatformProtocolFailures(t *testing.T) {
	platform, authorizer, _ := newTestPlatform(t, true)
	ctx := context.Background()
	invalidProvision, err := platform.Provision(ctx, ProvisionRequest{ServiceDID: "not-a-did"}, RequestContext{IdempotencyKey: "invalid", Principal: testPrincipal})
	if err != nil || invalidProvision.Status != 400 {
		t.Fatalf("invalid Service DID was accepted: %#v, %v", invalidProvision, err)
	}

	authorizer.allowed = false
	deniedProvision, err := platform.Provision(ctx, ProvisionRequest{ServiceDID: testServiceDID}, RequestContext{IdempotencyKey: "denied", Principal: testPrincipal})
	if err != nil || deniedProvision.Status != 404 {
		t.Fatalf("denied provisioning leaked: %#v, %v", deniedProvision, err)
	}
	authorizer.allowed = true
	platform.serviceDIDResolver = testDIDResolver{resolved: false}
	unresolved, err := platform.Provision(ctx, ProvisionRequest{ServiceDID: testServiceDID}, RequestContext{IdempotencyKey: "unresolved", Principal: testPrincipal})
	if err != nil || unresolved.Status != 400 {
		t.Fatalf("unresolved Service DID was accepted: %#v, %v", unresolved, err)
	}
	platform.serviceDIDResolver = testDIDResolver{resolved: true}
	provisioned, err := platform.Provision(ctx, ProvisionRequest{ServiceDID: testServiceDID}, RequestContext{IdempotencyKey: "provision", Principal: testPrincipal})
	if err != nil || provisioned.Status != 200 {
		t.Fatalf("setup provisioning failed: %#v, %v", provisioned, err)
	}

	missingDID, err := platform.GetDIDDocument(ctx, "missing")
	if err != nil || missingDID.Status != 404 {
		t.Fatalf("missing DID document response is invalid: %#v, %v", missingDID, err)
	}
	missingIdentity, err := platform.GetIdentity(ctx, "missing", RequestContext{Principal: testPrincipal})
	if err != nil || missingIdentity.Status != 404 {
		t.Fatalf("missing identity response is invalid: %#v, %v", missingIdentity, err)
	}
	wrongPrincipal, err := platform.GetIdentity(ctx, testAgentIdentityID, RequestContext{Principal: "owner-2"})
	if err != nil || wrongPrincipal.Status != 404 {
		t.Fatalf("cross-principal identity leaked: %#v, %v", wrongPrincipal, err)
	}
	missingSign, err := platform.Sign(ctx, "missing", SignRequest{JWTID: "missing", Operation: aep.AssertionEnroll, ServiceDID: testServiceDID}, RequestContext{IdempotencyKey: "missing-sign", Principal: testPrincipal})
	if err != nil || missingSign.Status != 404 {
		t.Fatalf("missing signing identity response is invalid: %#v, %v", missingSign, err)
	}
	wrongService, err := platform.Sign(ctx, testAgentIdentityID, SignRequest{JWTID: "wrong-service", Operation: aep.AssertionEnroll, ServiceDID: "did:web:other.service"}, RequestContext{IdempotencyKey: "wrong-service", Principal: testPrincipal})
	if err != nil || wrongService.Status != 404 {
		t.Fatalf("cross-Service signing leaked: %#v, %v", wrongService, err)
	}
	invalidLifecycle, err := platform.UpdateIdentity(ctx, testAgentIdentityID, LifecycleRequest{Status: "future"}, RequestContext{Principal: testPrincipal})
	if err != nil || invalidLifecycle.Status != 400 {
		t.Fatalf("invalid lifecycle state was accepted: %#v, %v", invalidLifecycle, err)
	}
	missingLifecycle, err := platform.UpdateIdentity(ctx, "missing", LifecycleRequest{Status: ManagedAgentActive}, RequestContext{Principal: testPrincipal})
	if err != nil || missingLifecycle.Status != 404 {
		t.Fatalf("missing lifecycle identity response is invalid: %#v, %v", missingLifecycle, err)
	}
	invalidVerification, err := platform.Verify(ctx, VerificationRequest{}, RequestContext{IdempotencyKey: "invalid-verify", Principal: testPrincipal})
	if err != nil || invalidVerification.Status != 400 {
		t.Fatalf("invalid verification request was accepted: %#v, %v", invalidVerification, err)
	}
	malformedVerification, err := platform.Verify(ctx, VerificationRequest{ClientAssertion: "not-a-jwt", Operation: aep.AssertionEnroll, ServiceDID: testServiceDID}, RequestContext{IdempotencyKey: "malformed-verify", Principal: testPrincipal})
	if err != nil || malformedVerification.Status != 200 || malformedVerification.Body.Verified {
		t.Fatalf("malformed assertion was recognized: %#v, %v", malformedVerification, err)
	}

	withoutVerification, _, _ := newTestPlatform(t, false)
	notAvailable, err := withoutVerification.Verify(ctx, VerificationRequest{ClientAssertion: "jwt", Operation: aep.AssertionEnroll, ServiceDID: testServiceDID}, RequestContext{IdempotencyKey: "verify", Principal: testPrincipal})
	if err != nil || notAvailable.Status != 404 {
		t.Fatalf("unadvertised hosted verification was available: %#v, %v", notAvailable, err)
	}
}

func TestPlatformOperationalFailureBoundaries(t *testing.T) {
	ctx := context.Background()
	options, _, _ := testOptions(t, false)
	options.Identifier = func() (string, error) { return "", errors.New("identifier failed") }
	identifierFailure, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identifierFailure.Provision(ctx, ProvisionRequest{ServiceDID: testServiceDID}, RequestContext{IdempotencyKey: "identifier", Principal: testPrincipal}); err == nil {
		t.Fatal("identity generator error was discarded")
	}

	options, _, keys := testOptions(t, false)
	options.KeyStore = failingKeyStore{KeyStore: keys}
	keyFailure, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keyFailure.Provision(ctx, ProvisionRequest{ServiceDID: testServiceDID}, RequestContext{IdempotencyKey: "key", Principal: testPrincipal}); err == nil {
		t.Fatal("key creation error was discarded")
	}

	platform, _, _ := newTestPlatform(t, false)
	provisioned, err := platform.Provision(ctx, ProvisionRequest{ServiceDID: testServiceDID}, RequestContext{IdempotencyKey: "provision", Principal: testPrincipal})
	if err != nil || provisioned.Status != 200 {
		t.Fatalf("setup provisioning failed: %#v, %v", provisioned, err)
	}
	missingIdempotency, err := platform.Sign(ctx, testAgentIdentityID, SignRequest{JWTID: "missing-key", Operation: aep.AssertionEnroll, ServiceDID: testServiceDID}, RequestContext{Principal: testPrincipal})
	if err != nil || missingIdempotency.Status != 400 {
		t.Fatalf("missing idempotency key was accepted: %#v, %v", missingIdempotency, err)
	}
	invalidContext := map[string]json.RawMessage{"invalid": json.RawMessage(`{`)}
	if _, err := platform.Sign(ctx, testAgentIdentityID, SignRequest{JWTID: "invalid-context", Operation: aep.AssertionEnroll, PlatformContext: invalidContext, ServiceDID: testServiceDID}, RequestContext{IdempotencyKey: "invalid-context", Principal: testPrincipal}); err == nil {
		t.Fatal("invalid Platform context was accepted")
	}

	platform.signHandler = func(context.Context, SignHandlerInput, RequestContext) (*Result[SignResponse], error) {
		return nil, errors.New("sign handler failed")
	}
	if _, err := platform.Sign(ctx, testAgentIdentityID, SignRequest{JWTID: "handler-error", Operation: aep.AssertionEnroll, ServiceDID: testServiceDID}, RequestContext{IdempotencyKey: "handler-error", Principal: testPrincipal}); err == nil {
		t.Fatal("sign handler error was discarded")
	}
	platform.signHandler = func(context.Context, SignHandlerInput, RequestContext) (*Result[SignResponse], error) {
		return &Result[SignResponse]{Body: SignResponse{Status: SignPending}, Status: 202}, nil
	}
	if _, err := platform.Sign(ctx, testAgentIdentityID, SignRequest{JWTID: "handler-invalid", Operation: aep.AssertionEnroll, ServiceDID: testServiceDID}, RequestContext{IdempotencyKey: "handler-invalid", Principal: testPrincipal}); err == nil {
		t.Fatal("invalid sign handler result was accepted")
	}
	platform.signHandler = func(context.Context, SignHandlerInput, RequestContext) (*Result[SignResponse], error) {
		problem := problemResult[SignResponse](400, aep.ErrorInvalidRequest, "Rejected.")
		return &problem, nil
	}
	handledProblem, err := platform.Sign(ctx, testAgentIdentityID, SignRequest{JWTID: "handler-problem", Operation: aep.AssertionEnroll, ServiceDID: testServiceDID}, RequestContext{IdempotencyKey: "handler-problem", Principal: testPrincipal})
	if err != nil || handledProblem.Status != 400 || handledProblem.Problem == nil {
		t.Fatalf("sign handler problem was not preserved: %#v, %v", handledProblem, err)
	}

	platform.signHandler = nil
	platform.lifecyclePolicy = testLifecyclePolicy{sign: false, transition: false, verify: false}
	rejectedTransition, err := platform.UpdateIdentity(ctx, testAgentIdentityID, LifecycleRequest{Status: ManagedAgentSuspended}, RequestContext{Principal: testPrincipal})
	if err != nil || rejectedTransition.Status != 403 {
		t.Fatalf("rejected transition was applied: %#v, %v", rejectedTransition, err)
	}
}

func TestPlatformProvisioningIsAtomicAndPrincipalScoped(t *testing.T) {
	platform, _, keys := newTestPlatform(t, false)
	const callers = 16
	results := make(chan AgentIdentity, callers)
	errorsChannel := make(chan error, callers)
	var group sync.WaitGroup
	for index := 0; index < callers; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			result, err := platform.Provision(context.Background(), ProvisionRequest{ServiceDID: testServiceDID}, RequestContext{IdempotencyKey: fmt.Sprintf("provision-%d", index), Principal: testPrincipal})
			if err != nil {
				errorsChannel <- err
				return
			}
			results <- result.Body
		}(index)
	}
	group.Wait()
	close(results)
	close(errorsChannel)
	for err := range errorsChannel {
		t.Fatal(err)
	}
	for identity := range results {
		if identity.AgentIdentityID != testAgentIdentityID {
			t.Fatalf("concurrent provisioning returned different identity: %#v", identity)
		}
	}
	if keys.createdCount() != 1 {
		t.Fatalf("concurrent provisioning created %d keys", keys.createdCount())
	}

	other, err := platform.Provision(context.Background(), ProvisionRequest{ServiceDID: testServiceDID}, RequestContext{IdempotencyKey: "other-principal", Principal: "owner-2"})
	if err != nil || other.Status != 200 || other.Body.AgentIdentityID == testAgentIdentityID || other.Body.AgentDID == "did:web:platform.example.com:agents:"+testAgentDIDID {
		t.Fatalf("unrelated principals shared identity material: %#v, %v", other, err)
	}
}

func TestPlatformSigningRequestSemanticsAndPendingResponses(t *testing.T) {
	platform, _, _ := newTestPlatform(t, false)
	ctx := context.Background()
	_, err := platform.Provision(ctx, ProvisionRequest{ServiceDID: testServiceDID}, RequestContext{IdempotencyKey: "provision", Principal: testPrincipal})
	if err != nil {
		t.Fatal(err)
	}

	invalidCases := []SignRequest{
		{JWTID: "missing-resource", Operation: aep.AssertionAuthenticate, ServiceDID: testServiceDID},
		{JWTID: "unexpected-resource", Operation: aep.AssertionEnroll, Resource: "https://service.example/resource", ServiceDID: testServiceDID},
		{JWTID: "unknown-operation", Operation: "future", ServiceDID: testServiceDID},
		{JWTID: "bad-lifetime", LifetimeSeconds: "301", Operation: aep.AssertionEnroll, ServiceDID: testServiceDID},
		{JWTID: "overflow-lifetime", LifetimeSeconds: "9223372036854775807", Operation: aep.AssertionEnroll, ServiceDID: testServiceDID},
	}
	for index, request := range invalidCases {
		result, err := platform.Sign(ctx, testAgentIdentityID, request, RequestContext{IdempotencyKey: fmt.Sprintf("invalid-%d", index), Principal: testPrincipal})
		if err != nil || result.Status != 400 || result.Problem == nil || result.Problem.Code != aep.ErrorInvalidRequest {
			t.Fatalf("invalid signing request accepted: %#v, %v", result, err)
		}
	}

	pendingPlatform, _, _ := newTestPlatformWithHandler(t, SignHandler(func(_ context.Context, input SignHandlerInput, _ RequestContext) (*Result[SignResponse], error) {
		return &Result[SignResponse]{
			Body: SignResponse{
				PlatformContext:   cloneRawMap(input.Request.PlatformContext),
				RetryAfterSeconds: "5",
				Status:            SignPending,
			},
			ContentType: aep.MediaType,
			Status:      202,
		}, nil
	}))
	_, err = pendingPlatform.Provision(ctx, ProvisionRequest{ServiceDID: testServiceDID}, RequestContext{IdempotencyKey: "provision-pending", Principal: testPrincipal})
	if err != nil {
		t.Fatal(err)
	}
	pending, err := pendingPlatform.Sign(ctx, testAgentIdentityID, SignRequest{JWTID: "pending", Operation: aep.AssertionEnroll, ServiceDID: testServiceDID}, RequestContext{IdempotencyKey: "pending", Principal: testPrincipal})
	if err != nil || pending.Status != 202 || pending.Body.Status != "pending" || pending.Body.RetryAfterSeconds != "5" || pending.Headers.Get("Retry-After") != "" {
		t.Fatalf("unexpected pending response: %#v, %v", pending, err)
	}
}

func TestPlatformWireShapesMatchSharedVectors(t *testing.T) {
	platform, _, _ := newTestPlatform(t, true)
	discoveryJSON, err := json.Marshal(platform.Discovery().Body)
	if err != nil {
		t.Fatal(err)
	}
	var discovery map[string]any
	if err := json.Unmarshal(discoveryJSON, &discovery); err != nil {
		t.Fatal(err)
	}
	if discovery["aep_version"] != "1.0" || discovery["endpoints"] == nil || discovery["signing"] == nil {
		t.Fatalf("discovery vector fields are missing: %s", discoveryJSON)
	}

	pending := SignResponse{RetryAfterSeconds: "5", Status: SignPending}
	pendingJSON, err := json.Marshal(pending)
	if err != nil {
		t.Fatal(err)
	}
	if string(pendingJSON) != `{"retry_after_seconds":"5","status":"pending"}` {
		t.Fatalf("pending response differs from the shared vector shape: %s", pendingJSON)
	}
	unrecognized := VerificationResponse{Reason: "not_recognized", ServiceDID: testServiceDID, Verified: false}
	unrecognizedJSON, err := json.Marshal(unrecognized)
	if err != nil {
		t.Fatal(err)
	}
	if string(unrecognizedJSON) != `{"reason":"not_recognized","service_did":"did:web:api.service.example","verified":false}` {
		t.Fatalf("unrecognized response differs from the shared vector shape: %s", unrecognizedJSON)
	}
}

func TestPlatformConfigurationValidation(t *testing.T) {
	valid, _, _ := testOptions(t, false)
	cases := []Options{
		func() Options { copy := valid; copy.Authorizer = nil; return copy }(),
		func() Options { copy := valid; copy.KeyStore = nil; return copy }(),
		func() Options { copy := valid; copy.ServiceDIDResolver = nil; return copy }(),
		func() Options {
			copy := valid
			copy.DIDURLTemplate = "https://platform.example.com/did.json"
			return copy
		}(),
		func() Options { copy := valid; copy.SigningAlgorithms = []aep.SigningAlgorithm{"future"}; return copy }(),
		func() Options {
			copy := valid
			copy.SigningAlgorithms = []aep.SigningAlgorithm{aep.SigningAlgorithmES256, aep.SigningAlgorithmES256}
			return copy
		}(),
		func() Options { copy := valid; copy.MaximumLifetime = 301 * time.Second; return copy }(),
		func() Options {
			copy := valid
			copy.HostedVerification = true
			copy.Discovery.HostedVerificationEndpoint = "/v1/aep/verifications"
			copy.ReplayStore = nil
			return copy
		}(),
	}
	for index, options := range cases {
		if _, err := New(options); err == nil {
			t.Fatalf("invalid Platform configuration %d was accepted", index)
		}
	}
	defaults := valid
	defaults.AgentDIDIDGenerator = nil
	defaults.Clock = nil
	defaults.Identifier = nil
	defaults.IdempotencyStore = nil
	defaults.IdentityStore = nil
	defaults.LifecyclePolicy = nil
	if _, err := New(defaults); err != nil {
		t.Fatalf("valid default Platform dependencies were rejected: %v", err)
	}

	if _, err := CreateServiceScopedAgentDID("platform.example.com", "agents", "opaque"); err != nil {
		t.Fatal(err)
	}
	didWithPort, err := CreateServiceScopedAgentDID("localhost:9900", "agents", "opaque")
	if err != nil || didWithPort != "did:web:localhost%3A9900:agents:opaque" {
		t.Fatalf("DID host port was not percent-encoded: %q, %v", didWithPort, err)
	}
	if _, err := CreateServiceScopedAgentDID("bad/path", "agents", "opaque"); err == nil {
		t.Fatal("invalid DID host was accepted")
	}
}

func newTestPlatform(t *testing.T, hostedVerification bool) (*Platform, *testAuthorizer, *testKeyStore) {
	return newTestPlatformWithHandler(t, nil, hostedVerification)
}

func newTestPlatformWithHandler(t *testing.T, handler SignHandler, hosted ...bool) (*Platform, *testAuthorizer, *testKeyStore) {
	t.Helper()
	hostedVerification := false
	if len(hosted) != 0 {
		hostedVerification = hosted[0]
	}
	options, authorizer, keys := testOptions(t, hostedVerification)
	options.SignHandler = handler
	platform, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	return platform, authorizer, keys
}

func testOptions(t *testing.T, hostedVerification bool) (Options, *testAuthorizer, *testKeyStore) {
	t.Helper()
	authorizer := &testAuthorizer{allowed: true}
	keys := newTestKeyStore(t)
	identifiers := []string{"01J0AEPPLATFORM000000000001", "01J0AEPPLATFORM000000000002"}
	didIdentifiers := []string{testAgentDIDID, "9Qm2t6RaL4"}
	var identifierMutex sync.Mutex
	next := func(values *[]string) func() (string, error) {
		return func() (string, error) {
			identifierMutex.Lock()
			defer identifierMutex.Unlock()
			if len(*values) == 0 {
				return "", errors.New("test identifiers exhausted")
			}
			value := (*values)[0]
			*values = (*values)[1:]
			return value, nil
		}
	}
	options := Options{
		AgentDIDIDGenerator: next(&didIdentifiers),
		Authorizer:          authorizer,
		Clock:               func() time.Time { return testClock },
		DIDHost:             "platform.example.com",
		DIDURLTemplate:      "https://platform.example.com/agents/{agent_did_id}/did.json",
		Discovery: DiscoveryOptions{
			EndpointBase:               "/v1/aep",
			HostedVerificationEndpoint: map[bool]string{true: "/v1/aep/verifications"}[hostedVerification],
			LifecycleEndpoint:          "/v1/aep/agent-identities/{agent_identity_id}",
			ListEndpoint:               "/v1/aep/agent-identities",
			PlatformDID:                "did:web:platform.example.com",
			PlatformName:               "Example Platform",
			ProvisionEndpoint:          "/v1/aep/agent-identities",
			SignEndpoint:               "/v1/aep/agent-identities/{agent_identity_id}/sign",
		},
		HostedVerification: hostedVerification,
		Identifier:         next(&identifiers),
		KeyStore:           keys,
		ReplayStore:        map[bool]ReplayStore{true: NewMemoryReplayStore()}[hostedVerification],
		ServiceDIDResolver: testDIDResolver{resolved: true},
		SigningAlgorithms:  []aep.SigningAlgorithm{aep.SigningAlgorithmES256},
	}
	return options, authorizer, keys
}

func equalJSON(first any, second any) bool {
	firstJSON, firstErr := json.Marshal(first)
	secondJSON, secondErr := json.Marshal(second)
	return firstErr == nil && secondErr == nil && string(firstJSON) == string(secondJSON)
}
