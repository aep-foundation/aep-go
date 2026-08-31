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

type platformAuthorizer bool

func (authorizer platformAuthorizer) Authorize(context.Context, platform.AuthorizationRequest, platform.RequestContext) (bool, error) {
	return bool(authorizer), nil
}

type platformDIDResolver struct{}

func (platformDIDResolver) ResolveServiceDID(context.Context, string) (bool, error) { return true, nil }

type platformKeyStore struct{ privateKey *ecdsa.PrivateKey }

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

func (platformKeyStore) CreateKey(context.Context, platform.IdentityRecord) error { return nil }

func (store platformKeyStore) DIDVerificationMethod(_ context.Context, identity platform.IdentityRecord) (platform.DIDVerificationMethod, error) {
	value, err := json.Marshal(jose.JSONWebKey{Key: &store.privateKey.PublicKey})
	if err != nil {
		return platform.DIDVerificationMethod{}, err
	}
	return platform.DIDVerificationMethod{Controller: identity.AgentDID, ID: identity.KeyID, PublicKeyJWK: value, Type: "JsonWebKey2020"}, nil
}

func (store platformKeyStore) Sign(_ context.Context, identity platform.IdentityRecord, claims aep.ClientAssertionClaims) (string, error) {
	return aep.SignClientAssertion(claims, aep.SignClientAssertionOptions{Algorithm: aep.SigningAlgorithmES256, Key: store.privateKey, KeyID: identity.KeyID})
}

func (store platformKeyStore) VerificationKey(context.Context, platform.IdentityRecord) (any, error) {
	return &store.privateKey.PublicKey, nil
}

type platformFixture struct {
	platform *platform.Platform
	context  platform.RequestContext
	now      *time.Time
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
	keyStore := platformKeyStore{privateKey: privateKey}
	instance, err := platform.New(platform.Options{
		AgentDIDIDGenerator: func() (string, error) {
			value := agentDIDIDs[agentDIDIndex]
			agentDIDIndex++
			return value, nil
		},
		Authorizer:         platformAuthorizer(authorized),
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
		ServiceDIDResolver: platformDIDResolver{},
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
	})
	return platformFixture{platform: instance, context: platform.RequestContext{Authorization: "Bearer platform", IdempotencyKey: "01J0AEPPLATFORM000000000001", Now: clock(), Principal: platformPrincipal}, now: &now}, err
}

func evaluatePlatform(request adapterRequest) (bool, error) {
	switch request.Vector.ID {
	case "authorization-required":
		return evaluatePlatformAuthorization()
	case "discovery":
		return evaluatePlatformDiscovery(request)
	case "idempotency-replay-conflict":
		return evaluatePlatformIdempotency()
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
		return evaluatePlatformUnrecognizedVerification()
	default:
		return false, fmt.Errorf("no Platform operation maps vector %s/%s", request.Vector.Category, request.Vector.ID)
	}
}

func evaluatePlatformAuthorization() (bool, error) {
	if _, err := platform.New(platform.Options{}); err == nil {
		return false, nil
	}
	fixture, err := newPlatformFixture(false, nil)
	if err != nil {
		return false, err
	}
	result, err := fixture.platform.Provision(context.Background(), platform.ProvisionRequest{ServiceDID: platformServiceDID}, fixture.context)
	return err == nil && result.Status == http.StatusNotFound && result.Problem != nil && result.Problem.Code == aep.ErrorNotRecognized, err
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
	signRequest := platform.SignRequest{JWTID: "01J0AEPASSERTION0000000001", LifetimeSeconds: "300", Operation: aep.AssertionEnroll, ServiceDID: platformServiceDID}
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
	result, err := fixture.platform.Sign(context.Background(), provisioned.Body.AgentIdentityID, signRequest, fixture.context)
	if err != nil || result.Status != http.StatusOK {
		return false, err
	}
	return result.Body.Status == platform.SignCompleted && result.Body.ClientAssertion != "" && result.Body.JWTID == signRequest.JWTID, nil
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

func evaluatePlatformIdempotency() (bool, error) {
	fixture, err := newPlatformFixture(true, nil)
	if err != nil {
		return false, err
	}
	first, err := fixture.platform.Provision(context.Background(), platform.ProvisionRequest{ServiceDID: platformServiceDID}, fixture.context)
	if err != nil {
		return false, err
	}
	replay, err := fixture.platform.Provision(context.Background(), platform.ProvisionRequest{ServiceDID: platformServiceDID}, fixture.context)
	if err != nil {
		return false, err
	}
	conflict, err := fixture.platform.Provision(context.Background(), platform.ProvisionRequest{ServiceDID: "did:web:other.example"}, fixture.context)
	return err == nil && jsonEqual(first.Body, replay.Body) && conflict.Status == http.StatusConflict && conflict.Problem != nil && conflict.Problem.Code == aep.ErrorIdempotencyConflict, err
}

func evaluatePlatformMissingResource(request adapterRequest) (bool, error) {
	fixture, err := newPlatformFixture(true, nil)
	if err != nil {
		return false, err
	}
	input, err := requiredField[platform.VerificationRequest](request.Case.Input, "request")
	if err != nil {
		return false, err
	}
	result, err := fixture.platform.Verify(context.Background(), input, fixture.context)
	return err == nil && result.Status == http.StatusBadRequest, err
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
	if err != nil || verified.Status != http.StatusOK || !verified.Body.Verified || verified.Body.Reason != "verified" || verified.Body.AgentIdentityID != provisioned.Body.AgentIdentityID {
		return false, fmt.Errorf("recognized verification mismatch: result=%#v error=%v", verified, err)
	}
	return true, nil
}

func evaluatePlatformUnrecognizedVerification() (bool, error) {
	fixture, err := newPlatformFixture(true, nil)
	if err != nil {
		return false, err
	}
	result, err := fixture.platform.Verify(context.Background(), platform.VerificationRequest{ClientAssertion: "invalid", Operation: aep.AssertionEnroll, ServiceDID: platformServiceDID}, fixture.context)
	return err == nil && !result.Body.Verified && result.Body.Reason == "not_recognized", err
}
