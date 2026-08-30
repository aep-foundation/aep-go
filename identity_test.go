package aep

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func TestDIDWebDocumentURL(t *testing.T) {
	root, err := DIDWebDocumentURL("did:web:api.example.com")
	if err != nil || root.String() != "https://api.example.com/.well-known/did.json" {
		t.Fatalf("unexpected root URL: %v, %v", root, err)
	}
	path, err := DIDWebDocumentURL("did:web:127.0.0.1%3A4100:agents:example-agent")
	if err != nil || path.String() != "http://127.0.0.1:4100/agents/example-agent/did.json" {
		t.Fatalf("unexpected path URL: %v, %v", path, err)
	}
}

func TestResolveDIDWebPublicKey(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := jose.JSONWebKey{Key: publicKey, KeyID: "key-1", Algorithm: string(jose.EdDSA), Use: "sig"}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/agents/123/did.json" {
			t.Errorf("unexpected DID path: %s", request.URL.Path)
		}
		response.Header().Set("Content-Type", "application/did+json")
		_ = json.NewEncoder(response).Encode(map[string]any{
			"verificationMethod": []any{map[string]any{
				"id": "did:web:agent#key-1", "publicKeyJwk": jwk,
			}},
		})
	}))
	defer server.Close()
	didHost := strings.TrimPrefix(server.URL, "http://")
	did := "did:web:" + strings.ReplaceAll(didHost, ":", "%3A") + ":agents:123"
	resolved, err := ResolveDIDWebPublicKey(context.Background(), ResolveDIDWebPublicKeyOptions{
		Client: server.Client(), DID: did, KeyID: "did:web:agent#key-1",
	})
	if err != nil || !resolved.Valid() {
		t.Fatalf("unexpected resolved key: %#v, %v", resolved, err)
	}
}

func TestClientAssertionJWT(t *testing.T) {
	now := time.Unix(1_748_428_800, 0)
	claims := ClientAssertionClaims{
		Audience:   "did:web:api.example.com",
		ExpiresAt:  now.Add(time.Minute).Unix(),
		IssuedAt:   now.Unix(),
		Issuer:     "did:web:agent.example.com:agents:123",
		JWTID:      "jti-1",
		Operation:  AssertionStatus,
		Subject:    "did:web:agent.example.com:agents:123",
		Additional: AdditionalMembers{"future": json.RawMessage("true")},
	}
	tests := []struct {
		algorithm  SigningAlgorithm
		privateKey any
		publicKey  any
	}{
		func() struct {
			algorithm  SigningAlgorithm
			privateKey any
			publicKey  any
		} {
			publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			return struct {
				algorithm  SigningAlgorithm
				privateKey any
				publicKey  any
			}{SigningAlgorithmEdDSA, privateKey, publicKey}
		}(),
		func() struct {
			algorithm  SigningAlgorithm
			privateKey any
			publicKey  any
		} {
			privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			return struct {
				algorithm  SigningAlgorithm
				privateKey any
				publicKey  any
			}{SigningAlgorithmES256, privateKey, &privateKey.PublicKey}
		}(),
	}
	for _, test := range tests {
		t.Run(string(test.algorithm), func(t *testing.T) {
			keyID := claims.Issuer + "#key-1"
			assertion, err := SignClientAssertion(claims, SignClientAssertionOptions{
				Algorithm: test.algorithm, Key: test.privateKey, KeyID: keyID,
			})
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeJWTUnverified(assertion)
			if err != nil || decoded.Header["kid"] != keyID {
				t.Fatalf("unexpected decoded JWT: %#v, %v", decoded, err)
			}
			options := VerifyClientAssertionOptions{
				Algorithms: []SigningAlgorithm{test.algorithm}, Audience: claims.Audience,
				CurrentTime: now.Add(30 * time.Second), Key: test.publicKey,
				Operation: claims.Operation, Subject: claims.Subject,
			}
			if test.algorithm == SigningAlgorithmEdDSA {
				options.Key = nil
				options.KeyResolver = func(_ context.Context, header jose.Header) (any, error) {
					if header.KeyID != keyID {
						t.Fatalf("unexpected key ID: %s", header.KeyID)
					}
					return test.publicKey, nil
				}
			}
			verified, err := VerifyClientAssertion(context.Background(), assertion, options)
			if err != nil || verified.JWTID != claims.JWTID || verified.Additional["future"] == nil {
				t.Fatalf("unexpected verification: %#v, %v", verified, err)
			}
			options.Audience = "did:web:other.example.com"
			if _, err := VerifyClientAssertion(context.Background(), assertion, options); err == nil {
				t.Fatal("wrong audience was accepted")
			}
		})
	}
}

func TestInvalidIdentityInputs(t *testing.T) {
	if _, err := DIDWebDocumentURL("did:key:example"); err == nil {
		t.Fatal("unsupported DID method was accepted")
	}
	if _, err := DecodeJWTUnverified("not-a-jwt"); err == nil {
		t.Fatal("invalid JWT was accepted")
	}
	if _, err := SignClientAssertion(ClientAssertionClaims{}, SignClientAssertionOptions{Algorithm: SigningAlgorithmEdDSA}); err == nil {
		t.Fatal("invalid assertion claims were accepted")
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claims := ClientAssertionClaims{
		Audience: "did:web:service.example", ExpiresAt: 60, IssuedAt: 1,
		Issuer: "did:web:agent.example", JWTID: "jti", Operation: AssertionStatus,
		Subject: "did:web:agent.example",
	}
	if _, err := SignClientAssertion(claims, SignClientAssertionOptions{Algorithm: SigningAlgorithmEdDSA, Key: privateKey}); err == nil {
		t.Fatal("missing kid was accepted")
	}
}
