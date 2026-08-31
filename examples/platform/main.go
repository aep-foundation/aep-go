package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/go-jose/go-jose/v4"

	aep "github.com/aep-foundation/aep-go"
	"github.com/aep-foundation/aep-go/platform"
)

const serviceDID = "did:web:service.example"

func main() {
	if err := run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	keys := newKeyStore()
	hosted, err := platform.New(platform.Options{
		Authorizer:     allowAuthorizer{},
		DIDHost:        "platform.example",
		DIDPathPrefix:  "agents",
		DIDURLTemplate: "https://platform.example/agents/{agent_did_id}/did.json",
		Discovery: platform.DiscoveryOptions{
			EndpointBase:      "/aep/",
			LifecycleEndpoint: "/aep/identities/{agent_identity_id}",
			ListEndpoint:      "/aep/identities",
			PlatformDID:       "did:web:platform.example",
			PlatformName:      "Example Platform",
			ProvisionEndpoint: "/aep/identities",
			SignEndpoint:      "/aep/identities/{agent_identity_id}/sign",
		},
		KeyStore:           keys,
		ServiceDIDResolver: resolvedService{},
		SigningAlgorithms:  []aep.SigningAlgorithm{aep.SigningAlgorithmES256},
	})
	if err != nil {
		return err
	}

	discovery := hosted.Discovery()
	fmt.Printf("Platform: %s\n", discovery.Body.Platform.Name)

	requestContext := platform.RequestContext{IdempotencyKey: "provision-1", Principal: "agent-runtime"}
	provisioned, err := hosted.Provision(ctx, platform.ProvisionRequest{ServiceDID: serviceDID}, requestContext)
	if err != nil {
		return err
	}
	if provisioned.Problem != nil {
		return fmt.Errorf("provision identity: %s", provisioned.Problem.Title)
	}
	fmt.Printf("Identity: %s\n", provisioned.Body.AgentDID)

	signed, err := hosted.Sign(ctx, provisioned.Body.AgentIdentityID, platform.SignRequest{
		JWTID:      "assertion-1",
		Operation:  aep.AssertionEnroll,
		ServiceDID: serviceDID,
	}, platform.RequestContext{IdempotencyKey: "sign-1", Principal: "agent-runtime"})
	if err != nil {
		return err
	}
	if signed.Problem != nil {
		return fmt.Errorf("sign assertion: %s", signed.Problem.Title)
	}
	fmt.Printf("Assertion: %s\n", signed.Body.Status)

	listed, err := hosted.List(ctx, platform.IdentityListQuery{ServiceDID: serviceDID}, platform.RequestContext{Principal: "agent-runtime"})
	if err != nil {
		return err
	}
	fmt.Printf("Managed identities: %s\n", listed.Body.Total)
	return nil
}

type allowAuthorizer struct{}

func (allowAuthorizer) Authorize(context.Context, platform.AuthorizationRequest, platform.RequestContext) (bool, error) {
	return true, nil
}

type resolvedService struct{}

func (resolvedService) ResolveServiceDID(context.Context, string) (bool, error) {
	return true, nil
}

type keyStore struct {
	mu   sync.RWMutex
	keys map[string]*ecdsa.PrivateKey
}

func newKeyStore() *keyStore {
	return &keyStore{keys: make(map[string]*ecdsa.PrivateKey)}
}

func (store *keyStore) CreateKey(_ context.Context, identity platform.IdentityRecord) error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, found := store.keys[identity.AgentIdentityID]; found {
		return errors.New("identity key already exists")
	}
	store.keys[identity.AgentIdentityID] = privateKey
	return nil
}

func (store *keyStore) DIDVerificationMethod(_ context.Context, identity platform.IdentityRecord) (platform.DIDVerificationMethod, error) {
	privateKey, err := store.key(identity.AgentIdentityID)
	if err != nil {
		return platform.DIDVerificationMethod{}, err
	}
	publicKey, err := json.Marshal(jose.JSONWebKey{Key: &privateKey.PublicKey})
	if err != nil {
		return platform.DIDVerificationMethod{}, err
	}
	return platform.DIDVerificationMethod{
		Controller:   identity.AgentDID,
		ID:           identity.KeyID,
		PublicKeyJWK: publicKey,
		Type:         "JsonWebKey2020",
	}, nil
}

func (store *keyStore) Sign(_ context.Context, identity platform.IdentityRecord, claims aep.ClientAssertionClaims) (string, error) {
	privateKey, err := store.key(identity.AgentIdentityID)
	if err != nil {
		return "", err
	}
	return aep.SignClientAssertion(claims, aep.SignClientAssertionOptions{
		Algorithm: aep.SigningAlgorithmES256,
		Key:       privateKey,
		KeyID:     identity.KeyID,
	})
}

func (store *keyStore) VerificationKey(_ context.Context, identity platform.IdentityRecord) (any, error) {
	privateKey, err := store.key(identity.AgentIdentityID)
	if err != nil {
		return nil, err
	}
	return &privateKey.PublicKey, nil
}

func (store *keyStore) key(identityID string) (*ecdsa.PrivateKey, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	privateKey := store.keys[identityID]
	if privateKey == nil {
		return nil, errors.New("identity key not found")
	}
	return privateKey, nil
}
