package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"

	aep "github.com/aep-foundation/aep-go"
	"github.com/aep-foundation/aep-go/platform"
)

const (
	platformPrincipal  = "stable-principal-123"
	platformServiceDID = "did:web:api.service.example"
)

type platformAuthorizer struct {
	allowed bool
	calls   int
}

func (authorizer *platformAuthorizer) Authorize(context.Context, platform.AuthorizationRequest, platform.RequestContext) (bool, error) {
	authorizer.calls++
	return authorizer.allowed, nil
}

type platformDIDResolver struct{ calls int }

func (resolver *platformDIDResolver) ResolveServiceDID(context.Context, string) (bool, error) {
	resolver.calls++
	return true, nil
}

type platformKeyStore struct {
	privateKey *ecdsa.PrivateKey
	created    int
	signed     int
}

type platformReplayStore struct {
	keys map[string]struct{}
	mu   sync.Mutex
}

func (store *platformReplayStore) ConsumeReplay(_ context.Context, key string, _ time.Time) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, found := store.keys[key]; found {
		return false, nil
	}
	store.keys[key] = struct{}{}
	return true, nil
}

func (store *platformKeyStore) CreateKey(context.Context, platform.IdentityRecord) error {
	store.created++
	return nil
}

func (store *platformKeyStore) DIDVerificationMethod(_ context.Context, identity platform.IdentityRecord) (platform.DIDVerificationMethod, error) {
	value, err := json.Marshal(jose.JSONWebKey{Key: &store.privateKey.PublicKey})
	if err != nil {
		return platform.DIDVerificationMethod{}, err
	}
	return platform.DIDVerificationMethod{Controller: identity.AgentDID, ID: identity.KeyID, PublicKeyJWK: value, Type: "JsonWebKey2020"}, nil
}

func (store *platformKeyStore) Sign(_ context.Context, identity platform.IdentityRecord, claims aep.ClientAssertionClaims) (string, error) {
	store.signed++
	return aep.SignClientAssertion(claims, aep.SignClientAssertionOptions{Algorithm: aep.SigningAlgorithmES256, Key: store.privateKey, KeyID: identity.KeyID})
}

func (store *platformKeyStore) VerificationKey(context.Context, platform.IdentityRecord) (any, error) {
	return &store.privateKey.PublicKey, nil
}

type platformFixture struct {
	platform   *platform.Platform
	context    platform.RequestContext
	now        *time.Time
	authorizer *platformAuthorizer
	keyStore   *platformKeyStore
	resolver   *platformDIDResolver
	options    platform.Options
}

func newPlatformFixture(authorized bool, signHandler platform.SignHandler) (platformFixture, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return platformFixture{}, err
	}
	identityIDs := []string{"01J0AEPPLATFORM000000000001", "01J0AEPPLATFORM000000000002"}
	agentDIDIDs := []string{"4Yf7p2xQd9", "9Lm2r8VnQ4"}
	identityIndex := 0
	agentDIDIndex := 0
	now := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	keyStore := &platformKeyStore{privateKey: privateKey}
	authorizer := &platformAuthorizer{allowed: authorized}
	resolver := &platformDIDResolver{}
	options := platform.Options{
		AgentDIDIDGenerator: func() (string, error) {
			value := agentDIDIDs[agentDIDIndex]
			agentDIDIndex++
			return value, nil
		},
		Authorizer:         authorizer,
		Clock:              clock,
		DIDHost:            "p.example",
		DIDPathPrefix:      "a",
		DIDURLTemplate:     "https://p.example/a/{agent_did_id}/did.json",
		HostedVerification: true,
		Identifier: func() (string, error) {
			value := identityIDs[identityIndex]
			identityIndex++
			return value, nil
		},
		KeyStore:           keyStore,
		ReplayStore:        &platformReplayStore{keys: make(map[string]struct{})},
		ServiceDIDResolver: resolver,
		SignHandler:        signHandler,
		SigningAlgorithms:  []aep.SigningAlgorithm{aep.SigningAlgorithmES256},
		Discovery: platform.DiscoveryOptions{
			EndpointBase:               "/v1/aep",
			HostedVerificationEndpoint: "/v1/aep/verifications",
			LifecycleEndpoint:          "/v1/aep/agent-identities/{agent_identity_id}",
			ListEndpoint:               "/v1/aep/agent-identities",
			PlatformDID:                "did:web:p.example",
			PlatformName:               "Example Platform",
			ProvisionEndpoint:          "/v1/aep/agent-identities",
			SignEndpoint:               "/v1/aep/agent-identities/{agent_identity_id}/sign",
		},
	}
	instance, err := platform.New(options)
	return platformFixture{platform: instance, context: platform.RequestContext{Authorization: "Bearer platform", IdempotencyKey: "01J0AEPPLATFORM000000000001", Now: clock(), Principal: platformPrincipal}, now: &now, authorizer: authorizer, keyStore: keyStore, resolver: resolver, options: options}, err
}

func evaluatePlatform(request adapterRequest) (bool, error) {
	switch request.Vector.ID {
	case "authorization-required":
		return evaluatePlatformAuthorization(request)
	case "discovery":
		return evaluatePlatformDiscovery(request)
	case "idempotency-replay-conflict":
		return evaluatePlatformIdempotency(request)
	case "lifecycle-request", "lifecycle-response":
		return evaluatePlatformLifecycle(request)
	case "list-response":
		return evaluatePlatformList(request)
	case "provision-request", "provision-response":
		return evaluatePlatformProvision(request)
	case "provision-response-distinct-services":
		return evaluatePlatformDistinctServices(request)
	case "sign-request", "sign-response":
		return evaluatePlatformSign(request)
	case "sign-response-pending":
		return evaluatePlatformPendingSign(request)
	case "verification-authenticate-missing-resource":
		return evaluatePlatformMissingResource(request)
	case "verification-request":
		return evaluatePlatformVerificationRequest(request)
	case "verification-response-recognized":
		return evaluatePlatformRecognizedVerification(request)
	case "verification-response-unrecognized":
		return evaluatePlatformUnrecognizedVerification(request)
	default:
		return false, fmt.Errorf("no Platform operation maps vector %s/%s", request.Vector.Category, request.Vector.ID)
	}
}

func evaluatePlatformAuthorization(request adapterRequest) (bool, error) {
	operations, err := requiredField[[]string](request.Case.Input, "private_operations")
	if err != nil {
		return false, err
	}
	status, err := requiredField[int](request.Case.Expected, "management_denied_status")
	if err != nil {
		return false, err
	}
	code, err := requiredField[aep.ErrorCode](request.Case.Expected, "management_denied_code")
	if err != nil {
		return false, err
	}
	missing, err := requiredField[string](request.Case.Expected, "missing_authorizer")
	if err != nil || missing != "construction-error" {
		return false, err
	}
	public, err := requiredField[bool](request.Case.Expected, "did_document_public")
	if err != nil || !public {
		return false, err
	}
	effects, err := requiredField[bool](request.Case.Expected, "side_effects")
	if err != nil || effects {
		return false, err
	}
	denied, err := requiredField[struct {
		Reason   string `json:"reason"`
		Verified bool   `json:"verified"`
	}](request.Case.Expected, "verification_denied")
	if err != nil {
		return false, err
	}
	fixture, err := newPlatformFixture(true, nil)
	if err != nil {
		return false, err
	}
	options := fixture.options
	options.Authorizer = nil
	if _, err := platform.New(options); err == nil {
		return false, fmt.Errorf("accepted missing authorizer")
	}
	ctx := context.Background()
	provisioned, err := fixture.platform.Provision(ctx, platform.ProvisionRequest{ServiceDID: platformServiceDID}, fixture.context)
	if err != nil || provisioned.Status != http.StatusOK {
		return false, fmt.Errorf("authorization fixture provisioning failed: %v", err)
	}
	fixture.context.IdempotencyKey = "authorization-sign"
	signRequest := platform.SignRequest{JWTID: "authorization", Operation: aep.AssertionEnroll, ServiceDID: platformServiceDID}
	signed, err := fixture.platform.Sign(ctx, provisioned.Body.AgentIdentityID, signRequest, fixture.context)
	if err != nil || signed.Status != http.StatusOK {
		return false, fmt.Errorf("authorization fixture signing failed: %v", err)
	}
	created, signatures := fixture.keyStore.created, fixture.keyStore.signed
	fixture.authorizer.allowed = false
	for _, operation := range operations {
		fixture.context.IdempotencyKey = "denied-" + operation
		calls := fixture.authorizer.calls
		var actualStatus int
		var problem *aep.ProblemDetails
		switch operation {
		case "get-identity":
			result, callErr := fixture.platform.GetIdentity(ctx, provisioned.Body.AgentIdentityID, fixture.context)
			actualStatus, problem, err = result.Status, result.Problem, callErr
		case "list-identities":
			result, callErr := fixture.platform.List(ctx, platform.IdentityListQuery{}, fixture.context)
			actualStatus, problem, err = result.Status, result.Problem, callErr
		case "provision-identity":
			result, callErr := fixture.platform.Provision(ctx, platform.ProvisionRequest{ServiceDID: "did:web:other.example"}, fixture.context)
			actualStatus, problem, err = result.Status, result.Problem, callErr
		case "sign":
			result, callErr := fixture.platform.Sign(ctx, provisioned.Body.AgentIdentityID, signRequest, fixture.context)
			actualStatus, problem, err = result.Status, result.Problem, callErr
		case "update-identity":
			result, callErr := fixture.platform.UpdateIdentity(ctx, provisioned.Body.AgentIdentityID, platform.LifecycleRequest{Status: platform.ManagedAgentSuspended}, fixture.context)
			actualStatus, problem, err = result.Status, result.Problem, callErr
		case "verify":
			result, callErr := fixture.platform.Verify(ctx, platform.VerificationRequest{ClientAssertion: signed.Body.ClientAssertion, Operation: aep.AssertionEnroll, ServiceDID: platformServiceDID}, fixture.context)
			expected := platform.VerificationResponse{Reason: denied.Reason, Verified: denied.Verified, ServiceDID: platformServiceDID}
			if callErr != nil || result.Status != http.StatusOK || !jsonEqual(result.Body, expected) || fixture.authorizer.calls != calls+1 {
				return false, fmt.Errorf("denied verification mismatch: %v", callErr)
			}
			continue
		default:
			return false, fmt.Errorf("unknown private operation %q", operation)
		}
		if err != nil || actualStatus != status || problem == nil || problem.Code != code || fixture.authorizer.calls != calls+1 {
			return false, fmt.Errorf("%s did not enforce authorization: %v", operation, err)
		}
	}
	calls := fixture.authorizer.calls
	document, err := fixture.platform.GetDIDDocument(ctx, "4Yf7p2xQd9")
	if err != nil || document.Status != http.StatusOK || document.Body.ID != provisioned.Body.AgentDID || fixture.authorizer.calls != calls || fixture.keyStore.created != created || fixture.keyStore.signed != signatures {
		return false, fmt.Errorf("public DID access or denied side effects mismatch: %v", err)
	}
	fixture.authorizer.allowed = true
	identity, err := fixture.platform.GetIdentity(ctx, provisioned.Body.AgentIdentityID, fixture.context)
	if err != nil || !jsonEqual(identity.Body, provisioned.Body) {
		return false, fmt.Errorf("denied lifecycle call changed identity: %v", err)
	}
	fixture.context.IdempotencyKey = "allowed-verification"
	verification, err := fixture.platform.Verify(ctx, platform.VerificationRequest{ClientAssertion: signed.Body.ClientAssertion, Operation: aep.AssertionEnroll, ServiceDID: platformServiceDID}, fixture.context)
	return err == nil && verification.Status == http.StatusOK && verification.Body.Verified && len(operations) > 0, err
}

func evaluatePlatformDiscovery(request adapterRequest) (bool, error) {
	fixture, err := newPlatformFixture(true, nil)
	if err != nil {
		return false, err
	}
	result := fixture.platform.Discovery()
	if result.Status != http.StatusOK || !jsonEqual(result.Body, request.Case.Expected) {
		actual, _ := json.Marshal(result.Body)
		expected, _ := json.Marshal(request.Case.Expected)
		return false, fmt.Errorf("discovery mismatch: actual=%s expected=%s", actual, expected)
	}
	return true, nil
}

func evaluatePlatformProvision(request adapterRequest) (bool, error) {
	fixture, err := newPlatformFixture(true, nil)
	if err != nil {
		return false, err
	}
	serviceDID := platformServiceDID
	if raw, found := request.Case.Input["service_did"]; found {
		if err := json.Unmarshal(raw, &serviceDID); err != nil {
			return false, err
		}
	}
	result, err := fixture.platform.Provision(context.Background(), platform.ProvisionRequest{ServiceDID: serviceDID}, fixture.context)
	if err != nil || result.Status != http.StatusOK {
		return false, err
	}
	if request.Vector.ID == "provision-response" {
		return jsonEqual(result.Body, request.Case.Expected), nil
	}
	return result.Body.ServiceDID == serviceDID, nil
}

func evaluatePlatformDistinctServices(request adapterRequest) (bool, error) {
	fixture, err := newPlatformFixture(true, nil)
	if err != nil {
		return false, err
	}
	type provisionInput struct {
		ServiceDID string `json:"service_did"`
	}
	firstInput, err := requiredField[provisionInput](request.Case.Input, "first_request")
	if err != nil {
		return false, err
	}
	secondInput, err := requiredField[provisionInput](request.Case.Input, "second_request")
	if err != nil {
		return false, err
	}
	first, err := fixture.platform.Provision(context.Background(), platform.ProvisionRequest{ServiceDID: firstInput.ServiceDID}, fixture.context)
	if err != nil {
		return false, err
	}
	fixture.context.IdempotencyKey = "01J0AEPPLATFORM000000000002"
	second, err := fixture.platform.Provision(context.Background(), platform.ProvisionRequest{ServiceDID: secondInput.ServiceDID}, fixture.context)
	return err == nil && first.Body.AgentDID != second.Body.AgentDID && first.Body.ServiceDID != second.Body.ServiceDID, err
}

func evaluatePlatformList(request adapterRequest) (bool, error) {
	fixture, err := newPlatformFixture(true, nil)
	if err != nil {
		return false, err
	}
	if _, err := fixture.platform.Provision(context.Background(), platform.ProvisionRequest{ServiceDID: platformServiceDID}, fixture.context); err != nil {
		return false, err
	}
	query, err := requiredField[platform.IdentityListQuery](request.Case.Input, "query")
	if err != nil {
		return false, err
	}
	result, err := fixture.platform.List(context.Background(), query, fixture.context)
	return err == nil && jsonEqual(result.Body, request.Case.Expected), err
}

func evaluatePlatformLifecycle(request adapterRequest) (bool, error) {
	fixture, err := newPlatformFixture(true, nil)
	if err != nil {
		return false, err
	}
	provisioned, err := fixture.platform.Provision(context.Background(), platform.ProvisionRequest{ServiceDID: platformServiceDID}, fixture.context)
	if err != nil {
		return false, err
	}
	status := platform.ManagedAgentSuspended
	if raw, found := request.Case.Input["status"]; found {
		if err := json.Unmarshal(raw, &status); err != nil {
			return false, err
		}
	}
	*fixture.now = time.Date(2026, 7, 6, 12, 10, 0, 0, time.UTC)
	fixture.context.Now = *fixture.now
	result, err := fixture.platform.UpdateIdentity(context.Background(), provisioned.Body.AgentIdentityID, platform.LifecycleRequest{Status: status}, fixture.context)
	if err != nil || result.Status != http.StatusOK || result.Body.Status != status {
		return false, err
	}
	if request.Vector.ID == "lifecycle-response" {
		if !jsonEqual(result.Body, request.Case.Expected) {
			actual, _ := json.Marshal(result.Body)
			expected, _ := json.Marshal(request.Case.Expected)
			return false, fmt.Errorf("lifecycle mismatch: actual=%s expected=%s", actual, expected)
		}
	}
	return true, nil
}

func evaluatePlatformSign(request adapterRequest) (bool, error) {
	fixture, err := newPlatformFixture(true, nil)
	if err != nil {
		return false, err
	}
	provisioned, err := fixture.platform.Provision(context.Background(), platform.ProvisionRequest{ServiceDID: platformServiceDID}, fixture.context)
	if err != nil {
		return false, err
	}
	signRequest := platform.SignRequest{JWTID: "01J0AEPASSERTION0000000001", LifetimeSeconds: "300", Operation: aep.AssertionEnroll, ServiceDID: platformServiceDID, PlatformContext: map[string]json.RawMessage{"authorization_handle": json.RawMessage(`"opaque-value"`)}}
	if request.Vector.ID == "sign-request" {
		encoded, marshalErr := json.Marshal(request.Case.Input)
		if marshalErr != nil {
			return false, marshalErr
		}
		if err := json.Unmarshal(encoded, &signRequest); err != nil {
			return false, err
		}
	}
	fixture.context.IdempotencyKey = "01J0AEPSIGNINITIAL0000000001"
	if request.Vector.ID == "sign-request" {
		key, err := requiredField[string](request.Case.Expected, "idempotency_key_header")
		if err != nil || key == "" {
			return false, err
		}
		fixture.context.IdempotencyKey = key
	}
	result, err := fixture.platform.Sign(context.Background(), provisioned.Body.AgentIdentityID, signRequest, fixture.context)
	if err != nil || result.Status != http.StatusOK {
		return false, err
	}
	document, err := fixture.platform.GetDIDDocument(context.Background(), "4Yf7p2xQd9")
	if err != nil || document.Status != http.StatusOK || len(document.Body.VerificationMethod) != 1 {
		return false, fmt.Errorf("public verification material unavailable: %v", err)
	}
	var key jose.JSONWebKey
	if err := json.Unmarshal(document.Body.VerificationMethod[0].PublicKeyJWK, &key); err != nil {
		return false, err
	}
	claims, err := aep.VerifyClientAssertion(context.Background(), result.Body.ClientAssertion, aep.VerifyClientAssertionOptions{
		Key: key.Key, Algorithms: []aep.SigningAlgorithm{aep.SigningAlgorithmES256}, Audience: signRequest.ServiceDID,
		Issuer: provisioned.Body.AgentDID, Subject: provisioned.Body.AgentDID, Operation: signRequest.Operation,
		Resource: signRequest.Resource, CurrentTime: *fixture.now,
	})
	if err != nil {
		return false, err
	}
	issued, issuedErr := time.Parse(time.RFC3339, result.Body.IssuedAt)
	expires, expiresErr := time.Parse(time.RFC3339, result.Body.ExpiresAt)
	lifetime, lifetimeErr := time.ParseDuration(signRequest.LifetimeSeconds + "s")
	if issuedErr != nil || expiresErr != nil || lifetimeErr != nil || !issued.Equal(*fixture.now) || expires.Sub(issued) != lifetime || claims.IssuedAt != issued.Unix() || claims.ExpiresAt != expires.Unix() || claims.JWTID != signRequest.JWTID || result.Body.JWTID != signRequest.JWTID || result.Body.AgentDID != provisioned.Body.AgentDID || result.Body.ServiceDID != signRequest.ServiceDID || result.Body.Status != platform.SignCompleted || !jsonEqual(result.Body.PlatformContext, signRequest.PlatformContext) {
		return false, fmt.Errorf("signed assertion and response metadata disagree")
	}
	decoded, err := aep.DecodeJWTUnverified(result.Body.ClientAssertion)
	if err != nil {
		return false, err
	}
	expectedClaims := map[string]any{"iss": provisioned.Body.AgentDID, "sub": provisioned.Body.AgentDID, "aud": signRequest.ServiceDID, "op": signRequest.Operation, "jti": signRequest.JWTID, "iat": issued.Unix(), "exp": expires.Unix()}
	if signRequest.Resource != "" {
		expectedClaims["resource"] = signRequest.Resource
	}
	if !jsonEqual(decoded.Payload, expectedClaims) || decoded.Header["kid"] != document.Body.VerificationMethod[0].ID {
		return false, fmt.Errorf("assertion includes unexpected claims")
	}
	if request.Vector.ID == "sign-response" {
		encoded, err := json.Marshal(request.Case.Expected)
		if err != nil {
			return false, err
		}
		var expected platform.SignResponse
		if err := json.Unmarshal(encoded, &expected); err != nil {
			return false, err
		}
		// The vector token is illustrative; verify the generated signature above instead.
		expected.ClientAssertion = result.Body.ClientAssertion
		return jsonEqual(result.Body, expected), nil
	}
	return true, nil
}

func evaluatePlatformPendingSign(request adapterRequest) (bool, error) {
	handler := func(context.Context, platform.SignHandlerInput, platform.RequestContext) (*platform.Result[platform.SignResponse], error) {
		return &platform.Result[platform.SignResponse]{Status: http.StatusAccepted, ContentType: aep.MediaType, Body: platform.SignResponse{Status: platform.SignPending, PlatformContext: map[string]json.RawMessage{"authorization_handle": json.RawMessage(`"opaque-value"`)}, RetryAfterSeconds: "5"}}, nil
	}
	fixture, err := newPlatformFixture(true, handler)
	if err != nil {
		return false, err
	}
	provisioned, err := fixture.platform.Provision(context.Background(), platform.ProvisionRequest{ServiceDID: platformServiceDID}, fixture.context)
	if err != nil {
		return false, err
	}
	fixture.context.IdempotencyKey = "01J0AEPSIGNINITIAL0000000001"
	result, err := fixture.platform.Sign(context.Background(), provisioned.Body.AgentIdentityID, platform.SignRequest{JWTID: "pending", Operation: aep.AssertionEnroll, ServiceDID: platformServiceDID}, fixture.context)
	return err == nil && result.Status == http.StatusAccepted && jsonEqual(result.Body, request.Case.Expected), err
}

func evaluatePlatformIdempotency(request adapterRequest) (bool, error) {
	operations, err := requiredField[[]string](request.Case.Input, "operations")
	if err != nil || len(operations) == 0 {
		return false, err
	}
	principal, err := requiredField[string](request.Case.Input, "principal")
	if err != nil || principal == "" {
		return false, err
	}
	retention, err := requiredField[string](request.Case.Expected, "retention_seconds_minimum")
	if err != nil {
		return false, err
	}
	duration, err := time.ParseDuration(retention + "s")
	if err != nil || duration < time.Second {
		return false, fmt.Errorf("invalid retention %q", retention)
	}
	replay, err := requiredField[string](request.Case.Expected, "exact_replay")
	if err != nil || replay != "stored_http_result" {
		return false, err
	}
	status, err := requiredField[int](request.Case.Expected, "changed_input_or_operation_status")
	if err != nil {
		return false, err
	}
	code, err := requiredField[aep.ErrorCode](request.Case.Expected, "changed_input_or_operation_code")
	if err != nil {
		return false, err
	}
	for _, operation := range operations {
		if passed, err := checkPlatformIdempotentOperation(operation, principal, duration, status, code); err != nil || !passed {
			return false, fmt.Errorf("%s replay check: %v", operation, err)
		}
	}
	return evaluatePlatformPendingReplay(request, principal, duration, status, code)
}

func checkPlatformIdempotentOperation(operation, principal string, retention time.Duration, status int, code aep.ErrorCode) (bool, error) {
	fixture, err := newPlatformFixture(true, nil)
	if err != nil {
		return false, err
	}
	ctx := context.Background()
	fixture.context.Principal = principal
	provision := platform.ProvisionRequest{ServiceDID: platformServiceDID}
	identity, err := fixture.platform.Provision(ctx, provision, fixture.context)
	if err != nil || identity.Status != http.StatusOK {
		return false, err
	}
	fixture.context.IdempotencyKey = "sign-setup"
	sign := platform.SignRequest{JWTID: "idempotency", Operation: aep.AssertionEnroll, ServiceDID: platformServiceDID}
	signed, err := fixture.platform.Sign(ctx, identity.Body.AgentIdentityID, sign, fixture.context)
	if err != nil || signed.Status != http.StatusOK {
		return false, err
	}
	fixture.context.IdempotencyKey = "operation-key"
	var passed bool
	switch operation {
	case "provision":
		passed, err = checkPlatformResultReplay(fixture, retention, status, code, func(caller platform.RequestContext, changed bool) (platform.Result[platform.AgentIdentity], error) {
			input := provision
			if changed {
				input.ServiceDID = "did:web:other.example"
			}
			return fixture.platform.Provision(ctx, input, caller)
		})
	case "sign":
		passed, err = checkPlatformResultReplay(fixture, retention, status, code, func(caller platform.RequestContext, changed bool) (platform.Result[platform.SignResponse], error) {
			input := sign
			if changed {
				input.JWTID = "changed"
			}
			return fixture.platform.Sign(ctx, identity.Body.AgentIdentityID, input, caller)
		})
	case "hosted_verification":
		passed, err = checkPlatformResultReplay(fixture, retention, status, code, func(caller platform.RequestContext, changed bool) (platform.Result[platform.VerificationResponse], error) {
			input := platform.VerificationRequest{ClientAssertion: signed.Body.ClientAssertion, Operation: aep.AssertionEnroll, ServiceDID: platformServiceDID}
			if changed {
				input.Operation = aep.AssertionStatus
			}
			result, err := fixture.platform.Verify(ctx, input, caller)
			if err == nil && result.Status == http.StatusOK && !result.Body.Verified {
				return result, fmt.Errorf("verification did not return the recognized result")
			}
			return result, err
		})
	default:
		return false, fmt.Errorf("unknown operation %q", operation)
	}
	if err != nil || !passed {
		return false, err
	}
	fixture.context.Now = *fixture.now
	var conflictStatus int
	var problem *aep.ProblemDetails
	if operation == "provision" {
		result, callErr := fixture.platform.Sign(ctx, identity.Body.AgentIdentityID, sign, fixture.context)
		conflictStatus, problem, err = result.Status, result.Problem, callErr
	} else {
		result, callErr := fixture.platform.Provision(ctx, provision, fixture.context)
		conflictStatus, problem, err = result.Status, result.Problem, callErr
	}
	if err != nil || conflictStatus != status || problem == nil || problem.Code != code {
		return false, fmt.Errorf("cross-operation conflict mismatch: %v", err)
	}
	other := fixture.context
	other.Principal += "-other"
	independent, err := fixture.platform.Provision(ctx, provision, other)
	if err != nil || independent.Status != http.StatusOK || independent.Body.AgentDID == identity.Body.AgentDID || fixture.keyStore.created != 2 {
		return false, fmt.Errorf("principal isolation failed: %v", err)
	}
	// Expiring the replay record must not create another identity for this owner and Service.
	*fixture.now = fixture.now.Add(time.Second)
	fixture.context.Now = *fixture.now
	fixture.context.IdempotencyKey = "01J0AEPPLATFORM000000000001"
	afterExpiry, err := fixture.platform.Provision(ctx, provision, fixture.context)
	return err == nil && jsonEqual(identity, afterExpiry) && fixture.keyStore.created == 2, err
}

func checkPlatformResultReplay[T any](fixture platformFixture, retention time.Duration, status int, code aep.ErrorCode, execute func(platform.RequestContext, bool) (platform.Result[T], error)) (bool, error) {
	first, err := execute(fixture.context, false)
	if err != nil || first.Status != http.StatusOK || first.Problem != nil {
		return false, err
	}
	created, signed, resolved := fixture.keyStore.created, fixture.keyStore.signed, fixture.resolver.calls
	*fixture.now = fixture.now.Add(retention - time.Second)
	caller := fixture.context
	caller.Now = *fixture.now
	caller.Authorization = "Bearer refreshed"
	caller.RequestID = "retry-request"
	replay, err := execute(caller, false)
	if err != nil || !jsonEqual(first, replay) || fixture.keyStore.created != created || fixture.keyStore.signed != signed || fixture.resolver.calls != resolved {
		return false, fmt.Errorf("complete stored result was not replayed: %v", err)
	}
	conflict, err := execute(caller, true)
	return err == nil && conflict.Status == status && conflict.Problem != nil && conflict.Problem.Code == code && fixture.keyStore.created == created && fixture.keyStore.signed == signed && fixture.resolver.calls == resolved, err
}

func evaluatePlatformPendingReplay(request adapterRequest, principal string, retention time.Duration, status int, code aep.ErrorCode) (bool, error) {
	initialKey, err := requiredField[string](request.Case.Input, "initial_sign_key")
	if err != nil {
		return false, err
	}
	finalKey, err := requiredField[string](request.Case.Input, "final_sign_key")
	if err != nil {
		return false, err
	}
	calls := 0
	handler := func(_ context.Context, input platform.SignHandlerInput, _ platform.RequestContext) (*platform.Result[platform.SignResponse], error) {
		calls++
		if input.Request.PlatformContext != nil {
			return nil, nil
		}
		return &platform.Result[platform.SignResponse]{Status: http.StatusAccepted, ContentType: aep.MediaType, Headers: http.Header{"X-Request-Id": {"initial-sign"}}, Body: platform.SignResponse{Status: platform.SignPending, RetryAfterSeconds: "5", PlatformContext: map[string]json.RawMessage{"authorization_handle": json.RawMessage(`"opaque-value"`)}}}, nil
	}
	fixture, err := newPlatformFixture(true, handler)
	if err != nil {
		return false, err
	}
	ctx := context.Background()
	fixture.context.Principal = principal
	identity, err := fixture.platform.Provision(ctx, platform.ProvisionRequest{ServiceDID: platformServiceDID}, fixture.context)
	if err != nil || identity.Status != http.StatusOK {
		return false, err
	}
	fixture.context.IdempotencyKey = initialKey
	input := platform.SignRequest{JWTID: "pending-replay", Operation: aep.AssertionEnroll, ServiceDID: platformServiceDID}
	pending, err := fixture.platform.Sign(ctx, identity.Body.AgentIdentityID, input, fixture.context)
	if err != nil || pending.Status != http.StatusAccepted || calls != 1 {
		return false, err
	}
	*fixture.now = fixture.now.Add(retention - time.Second)
	fixture.context.Now = *fixture.now
	replay, err := fixture.platform.Sign(ctx, identity.Body.AgentIdentityID, input, fixture.context)
	if err != nil || !jsonEqual(pending, replay) || calls != 1 {
		return false, err
	}
	input.PlatformContext = pending.Body.PlatformContext
	conflict, err := fixture.platform.Sign(ctx, identity.Body.AgentIdentityID, input, fixture.context)
	if err != nil || conflict.Status != status || conflict.Problem == nil || conflict.Problem.Code != code || calls != 1 {
		return false, err
	}
	fixture.context.IdempotencyKey = finalKey
	completed, err := fixture.platform.Sign(ctx, identity.Body.AgentIdentityID, input, fixture.context)
	if err != nil || completed.Status != http.StatusOK || completed.Body.ClientAssertion == "" || calls != 2 || fixture.keyStore.signed != 1 {
		return false, err
	}
	replay, err = fixture.platform.Sign(ctx, identity.Body.AgentIdentityID, input, fixture.context)
	return err == nil && jsonEqual(completed, replay) && calls == 2 && fixture.keyStore.signed == 1, err
}

func evaluatePlatformMissingResource(request adapterRequest) (bool, error) {
	valid, err := requiredField[bool](request.Case.Expected, "valid")
	if err != nil || valid {
		return false, err
	}
	fixture, err := newPlatformFixture(true, nil)
	if err != nil {
		return false, err
	}
	input, err := requiredField[platform.VerificationRequest](request.Case.Input, "request")
	if err != nil {
		return false, err
	}
	result, err := fixture.platform.Verify(context.Background(), input, fixture.context)
	return err == nil && result.Status == http.StatusBadRequest && result.Problem != nil && result.Problem.Code == aep.ErrorInvalidRequest, err
}

func evaluatePlatformVerificationRequest(request adapterRequest) (bool, error) {
	encoded, err := json.Marshal(request.Case.Input)
	if err != nil {
		return false, err
	}
	var input platform.VerificationRequest
	if err := json.Unmarshal(encoded, &input); err != nil {
		return false, err
	}
	fixture, err := newPlatformFixture(true, nil)
	if err != nil {
		return false, err
	}
	fixture.context.IdempotencyKey = "01J0AEPVERIFY0000000000001"
	result, err := fixture.platform.Verify(context.Background(), input, fixture.context)
	return err == nil && result.Status == http.StatusOK && !result.Body.Verified && result.Body.Reason == "not_recognized", err
}

func evaluatePlatformRecognizedVerification(request adapterRequest) (bool, error) {
	fixture, err := newPlatformFixture(true, nil)
	if err != nil {
		return false, err
	}
	provisioned, err := fixture.platform.Provision(context.Background(), platform.ProvisionRequest{ServiceDID: platformServiceDID}, fixture.context)
	if err != nil {
		return false, err
	}
	fixture.context.IdempotencyKey = "sign-for-verification"
	signed, err := fixture.platform.Sign(context.Background(), provisioned.Body.AgentIdentityID, platform.SignRequest{JWTID: "verification", Operation: aep.AssertionEnroll, ServiceDID: platformServiceDID}, fixture.context)
	if err != nil {
		return false, err
	}
	fixture.context.IdempotencyKey = "verify-recognized"
	verified, err := fixture.platform.Verify(context.Background(), platform.VerificationRequest{ClientAssertion: signed.Body.ClientAssertion, Operation: aep.AssertionEnroll, ServiceDID: platformServiceDID}, fixture.context)
	if err != nil || verified.Status != http.StatusOK || !jsonEqual(verified.Body, request.Case.Expected) {
		return false, fmt.Errorf("recognized verification mismatch: result=%#v error=%v", verified, err)
	}
	fixture.context.IdempotencyKey = "verify-replayed-assertion"
	replayed, err := fixture.platform.Verify(context.Background(), platform.VerificationRequest{ClientAssertion: signed.Body.ClientAssertion, Operation: aep.AssertionEnroll, ServiceDID: platformServiceDID}, fixture.context)
	expected := platform.VerificationResponse{Reason: "not_recognized", ServiceDID: platformServiceDID, Verified: false}
	return err == nil && replayed.Status == http.StatusOK && jsonEqual(replayed.Body, expected), err
}

func evaluatePlatformUnrecognizedVerification(request adapterRequest) (bool, error) {
	fixture, err := newPlatformFixture(true, nil)
	if err != nil {
		return false, err
	}
	result, err := fixture.platform.Verify(context.Background(), platform.VerificationRequest{ClientAssertion: "invalid", Operation: aep.AssertionEnroll, ServiceDID: platformServiceDID}, fixture.context)
	return err == nil && result.Status == http.StatusOK && jsonEqual(result.Body, request.Case.Expected), err
}
