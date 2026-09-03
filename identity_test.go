package aep

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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
	if err != nil || path.String() != "https://127.0.0.1:4100/agents/example-agent/did.json" {
		t.Fatalf("unexpected path URL: %v, %v", path, err)
	}
	loopback, err := DIDWebDocumentURLWithOptions(
		"did:web:127.0.0.1%3A4100:agents:example-agent",
		DIDWebDocumentURLOptions{AllowInsecureLoopback: true},
	)
	if err != nil || loopback.String() != "http://127.0.0.1:4100/agents/example-agent/did.json" {
		t.Fatalf("unexpected loopback URL: %v, %v", loopback, err)
	}
}

func TestResolveDIDWebPublicKey(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := jose.JSONWebKey{Key: publicKey, KeyID: "key-1", Algorithm: string(jose.EdDSA), Use: "sig"}
	var did string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/agents/123/did.json" {
			t.Errorf("unexpected DID path: %s", request.URL.Path)
		}
		response.Header().Set("Content-Type", "application/did+json")
		_ = json.NewEncoder(response).Encode(map[string]any{
			"verificationMethod": []any{map[string]any{
				"id": did + "#key-1", "publicKeyJwk": jwk,
			}},
		})
	}))
	defer server.Close()
	didHost := strings.TrimPrefix(server.URL, "http://")
	did = "did:web:" + strings.ReplaceAll(didHost, ":", "%3A") + ":agents:123"
	resolved, err := ResolveDIDWebPublicKey(context.Background(), ResolveDIDWebPublicKeyOptions{
		AllowInsecureLoopback: true,
		Client:                server.Client(),
		DID:                   did,
		KeyID:                 did + "#key-1",
	})
	if err != nil || !resolved.Valid() {
		t.Fatalf("unexpected resolved key: %#v, %v", resolved, err)
	}
	if _, err := ResolveDIDWebPublicKey(context.Background(), ResolveDIDWebPublicKeyOptions{DID: did}); err == nil {
		t.Fatal("missing did:web key ID was accepted")
	}
	if _, err := ResolveDIDWebPublicKey(context.Background(), ResolveDIDWebPublicKeyOptions{
		DID: did, KeyID: "did:web:different.example.com#key-1",
	}); err == nil {
		t.Fatal("mismatched did:web key ID was accepted")
	}
}

func TestResolveDIDWebPublicKeyRejectsRedirect(t *testing.T) {
	var targetCalled atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetCalled.Store(true)
	}))
	defer target.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, target.URL, http.StatusFound)
	}))
	defer redirect.Close()
	host := strings.TrimPrefix(redirect.URL, "https://")
	did := "did:web:" + strings.ReplaceAll(host, ":", "%3A")
	if _, err := ResolveDIDWebPublicKey(context.Background(), ResolveDIDWebPublicKeyOptions{
		Client: redirect.Client(), DID: did, KeyID: did + "#key-1",
	}); err == nil {
		t.Fatal("did:web redirect was accepted")
	}
	if targetCalled.Load() {
		t.Fatal("did:web redirect target was requested")
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

func TestVerifyClientAssertionRejectsExpirationBoundary(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_748_428_800, 0)
	claims := ClientAssertionClaims{
		Audience: "did:web:service.example", ExpiresAt: now.Unix(), IssuedAt: now.Add(-time.Minute).Unix(),
		Issuer: "did:web:agent.example", JWTID: "expiration-boundary", Operation: AssertionStatus,
		Subject: "did:web:agent.example",
	}
	assertion, err := SignClientAssertion(claims, SignClientAssertionOptions{
		Algorithm: SigningAlgorithmEdDSA, Key: privateKey, KeyID: claims.Issuer + "#key-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyClientAssertion(context.Background(), assertion, VerifyClientAssertionOptions{
		ClockTolerance: 30 * time.Second, CurrentTime: now.Add(30 * time.Second), Key: publicKey,
	})
	if err == nil {
		t.Fatal("assertion was accepted at the expiration boundary")
	}
}

func TestVerifyClientAssertionClockToleranceDoesNotOverflow(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		now     int64
		issued  int64
		expires int64
	}{
		{name: "minimum", now: math.MinInt64 + 10, issued: math.MinInt64 + 1, expires: math.MinInt64 + 61},
		{name: "maximum", now: math.MaxInt64 - 10, issued: math.MaxInt64 - 20, expires: math.MaxInt64},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claims := ClientAssertionClaims{
				Audience: "did:web:service.example", ExpiresAt: test.expires, IssuedAt: test.issued,
				Issuer: "did:web:agent.example", JWTID: test.name, Operation: AssertionStatus,
				Subject: "did:web:agent.example",
			}
			assertion, signErr := SignClientAssertion(claims, SignClientAssertionOptions{
				Algorithm: SigningAlgorithmEdDSA, Key: privateKey, KeyID: claims.Issuer + "#key-1",
			})
			if signErr != nil {
				t.Fatal(signErr)
			}
			_, verifyErr := VerifyClientAssertion(context.Background(), assertion, VerifyClientAssertionOptions{
				ClockTolerance: 30 * time.Second, CurrentTime: time.Unix(test.now, 0), Key: publicKey,
			})
			if verifyErr != nil {
				t.Fatalf("valid assertion was rejected near the timestamp boundary: %v", verifyErr)
			}
		})
	}
}

func TestClientAssertionLoopbackResource(t *testing.T) {
	claims := ClientAssertionClaims{
		Audience: "did:web:127.0.0.1%3A4100", ExpiresAt: 61, IssuedAt: 1,
		Issuer: "did:web:agent.example", JWTID: "jti", Operation: AssertionAuthenticate,
		Resource: "http://127.0.0.1:4100/private", Subject: "did:web:agent.example",
	}
	if err := ValidateClientAssertionClaims(claims); err == nil {
		t.Fatal("plaintext loopback resource was accepted by default")
	}
	if err := ValidateClientAssertionClaimsWithOptions(claims, ClientAssertionValidationOptions{AllowInsecureLoopback: true}); err != nil {
		t.Fatalf("explicit plaintext loopback resource was rejected: %v", err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := SignClientAssertion(claims, SignClientAssertionOptions{
		Algorithm:             SigningAlgorithmEdDSA,
		AllowInsecureLoopback: true,
		Key:                   privateKey,
		KeyID:                 claims.Issuer,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyClientAssertion(context.Background(), assertion, VerifyClientAssertionOptions{
		Algorithms:            []SigningAlgorithm{SigningAlgorithmEdDSA},
		AllowInsecureLoopback: true,
		Audience:              claims.Audience,
		CurrentTime:           time.Unix(30, 0),
		Key:                   publicKey,
		Operation:             claims.Operation,
		Resource:              claims.Resource,
	}); err != nil {
		t.Fatalf("explicit plaintext loopback assertion was rejected: %v", err)
	}
	claims.Resource = "http://api.example.com/private"
	if err := ValidateClientAssertionClaimsWithOptions(claims, ClientAssertionValidationOptions{AllowInsecureLoopback: true}); err == nil {
		t.Fatal("non-loopback plaintext resource was accepted")
	}
}

func TestClientAssertionLifetimeDoesNotOverflow(t *testing.T) {
	claims := ClientAssertionClaims{
		Audience: "did:web:service.example", ExpiresAt: math.MaxInt64, IssuedAt: math.MinInt64,
		Issuer: "did:web:agent.example", JWTID: "jti", Operation: AssertionEnroll,
		Subject: "did:web:agent.example",
	}
	if err := ValidateClientAssertionClaims(claims); err == nil {
		t.Fatal("overflowing client assertion lifetime was accepted")
	}
	claims.IssuedAt = math.MaxInt64 - 300
	if err := ValidateClientAssertionClaims(claims); err != nil {
		t.Fatalf("valid upper-bound client assertion lifetime was rejected: %v", err)
	}
}
