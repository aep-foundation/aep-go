package aep

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func TestEnrollValidatesClaimWireValuesConsistently(t *testing.T) {
	for _, name := range RegisteredClaims() {
		claims, err := json.Marshal(map[string]any{string(name): nil})
		if err != nil {
			t.Fatal(err)
		}
		body := []byte(`{"agent_did":"did:web:agent.example","claims":` + string(claims) + `}`)
		if _, err := ParseClaimValues(claims); err == nil {
			t.Fatalf("standalone %s null accepted", name)
		}
		if _, err := ParseEnrollRequest(body); err == nil {
			t.Fatalf("Enroll %s null accepted", name)
		}
	}
	for _, claims := range []string{`{}`, `{"contact.email":"person@example.com"}`, `{"custom.example":null}`} {
		if _, err := ParseEnrollRequest([]byte(`{"agent_did":"did:web:agent.example","claims":` + claims + `}`)); err != nil {
			t.Fatalf("valid or additive claims rejected: %s: %v", claims, err)
		}
	}
}

// ---------------------------------------------------------------- helpers

type stubDoer struct {
	body     string
	err      error
	noReq    bool
	status   int
	rawBody  io.ReadCloser
	redirect string
}

func (doer stubDoer) Do(request *http.Request) (*http.Response, error) {
	if doer.err != nil {
		return nil, doer.err
	}
	status := doer.status
	if status == 0 {
		status = http.StatusOK
	}
	body := doer.rawBody
	if body == nil {
		body = io.NopCloser(strings.NewReader(doer.body))
	}
	response := &http.Response{Body: body, StatusCode: status}
	if !doer.noReq {
		response.Request = request
		if doer.redirect != "" {
			redirected := request.Clone(request.Context())
			parsed, err := request.URL.Parse(doer.redirect)
			if err == nil {
				redirected.URL = parsed
			}
			response.Request = redirected
		}
	}
	return response, nil
}

func testDIDDocument(t *testing.T, did string, methodID string) string {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(map[string]any{
		"id": did,
		"verificationMethod": []any{map[string]any{
			"controller":   did,
			"id":           methodID,
			"publicKeyJwk": jose.JSONWebKey{Key: publicKey, Algorithm: string(jose.EdDSA), Use: "sig"},
			"type":         "JsonWebKey2020",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func assertionClaims() ClientAssertionClaims {
	return ClientAssertionClaims{
		Audience:  "did:web:api.example.com",
		ExpiresAt: 1_800_000_300,
		IssuedAt:  1_800_000_000,
		Issuer:    "did:web:agent.example.com:agents:123",
		JWTID:     "jti-1",
		Operation: AssertionEnroll,
		Subject:   "did:web:agent.example.com:agents:123",
	}
}

// ---------------------------------------------------------------- CORE-CA-025: resource claims

func TestProtectedResourceURIRejectsFragmentAndUserInfo(t *testing.T) {
	rejected := []string{
		"https://api.example.com/orders#",
		"https://api.example.com/orders#section",
		"https://user@api.example.com/orders",
		"https://user:pass@api.example.com/orders",
		"https://api.example.com/or\x01ders",
		"http://api.example.com/orders",
		"mailto:someone@example.com",
		"https:///orders",
		"://nonsense",
	}
	for _, resource := range rejected {
		claims := assertionClaims()
		claims.Operation = AssertionAuthenticate
		claims.Resource = resource
		if err := ValidateClientAssertionClaims(claims); err == nil {
			t.Fatalf("resource %q was accepted", resource)
		}
	}

	accepted := []string{
		"https://api.example.com/orders",
		"https://api.example.com/orders?page=2",
		"https://api.example.com:8443/orders",
	}
	for _, resource := range accepted {
		claims := assertionClaims()
		claims.Operation = AssertionAuthenticate
		claims.Resource = resource
		if err := ValidateClientAssertionClaims(claims); err != nil {
			t.Fatalf("resource %q was rejected: %v", resource, err)
		}
	}
}

func TestProtectedResourceURIAllowsConfiguredLoopback(t *testing.T) {
	claims := assertionClaims()
	claims.Operation = AssertionAuthenticate
	claims.Resource = "http://127.0.0.1:8080/orders"
	if err := ValidateClientAssertionClaims(claims); err == nil {
		t.Fatal("plaintext loopback was accepted without opting in")
	}
	if err := ValidateClientAssertionClaimsWithOptions(claims, ClientAssertionValidationOptions{AllowInsecureLoopback: true}); err != nil {
		t.Fatalf("loopback resource was rejected: %v", err)
	}
	claims.Resource = "http://198.51.100.7/orders"
	if err := ValidateClientAssertionClaimsWithOptions(claims, ClientAssertionValidationOptions{AllowInsecureLoopback: true}); err == nil {
		t.Fatal("plaintext non-loopback resource was accepted")
	}
}

// ---------------------------------------------------------------- CORE-AUTH-001: credentials

func TestParseProtectedResourceAuthorizationGrammar(t *testing.T) {
	accepted := map[string]string{
		"AEP abc.def.ghi":    "abc.def.ghi",
		"AEP  abc.def.ghi":   "abc.def.ghi",
		"AEP\tabc.def.ghi":   "abc.def.ghi",
		"AEP abc.def.ghi   ": "abc.def.ghi",
		"aep abc.def.ghi":    "abc.def.ghi",
		"Bearer token-value": "token-value",
		"basic dXNlcjpwYXNz": "dXNlcjpwYXNz",
	}
	for field, credentials := range accepted {
		parsed, err := ParseProtectedResourceAuthorization(field, ProtectedResourceStandard)
		if err != nil {
			t.Fatalf("field %q was rejected: %v", field, err)
		}
		if parsed.Credentials != credentials {
			t.Fatalf("field %q produced credentials %q, want %q", field, parsed.Credentials, credentials)
		}
	}

	rejected := []string{
		"",
		"AEP",
		"AEP ",
		"AEP   ",
		" AEP abc",
		"AEP abc def",
		"AEP abc\r\nX-Injected: 1",
		"AEP abc\x00def",
		"AEP abc\x7f",
		"Negotiate abc",
		"abc.def.ghi",
	}
	for _, field := range rejected {
		if _, err := ParseProtectedResourceAuthorization(field, ProtectedResourceStandard); err == nil {
			t.Fatalf("field %q was accepted", field)
		}
	}
}

func TestParseProtectedResourceAuthorizationCarriers(t *testing.T) {
	if _, err := ParseProtectedResourceAuthorization("AEP abc", "Made-Up"); err == nil {
		t.Fatal("unsupported carrier was accepted")
	}
	parsed, err := ParseProtectedResourceAuthorization("AEP abc", "")
	if err != nil || parsed.Carrier != ProtectedResourceStandard {
		t.Fatalf("empty carrier did not default to the standard field: %v, %v", parsed, err)
	}
	// A comma in the dedicated field may be a joined repeat of the header.
	if _, err := ParseProtectedResourceAuthorization("AEP abc,AEP def", ProtectedResourceDedicated); err == nil {
		t.Fatal("joined dedicated field was accepted")
	}
	if _, err := ParseProtectedResourceAuthorization("AEP abc,AEP def", ProtectedResourceStandard); err == nil {
		t.Fatal("comma-bearing credentials were accepted")
	}
}

func TestRenderAndValidateProtectedResourceAuthorization(t *testing.T) {
	header, value, err := RenderProtectedResourceAuthorization(ProtectedResourceAuthorization{
		Carrier:     ProtectedResourceDedicated,
		Credentials: "abc.def.ghi",
		Scheme:      CredentialSchemeAEP,
	})
	if err != nil || header != AuthorizationHeader || value != "AEP abc.def.ghi" {
		t.Fatalf("unexpected rendering: %q, %q, %v", header, value, err)
	}

	if _, _, err := RenderProtectedResourceAuthorization(ProtectedResourceAuthorization{
		Credentials: "abc", Scheme: "Negotiate",
	}); err == nil {
		t.Fatal("unsupported scheme was rendered")
	}
	if _, _, err := RenderProtectedResourceAuthorization(ProtectedResourceAuthorization{
		Carrier: "Made-Up", Credentials: "abc", Scheme: CredentialSchemeAEP,
	}); err == nil {
		t.Fatal("unsupported carrier was rendered")
	}

	// A credential assembled in code, not parsed, must still be renderable as a field value.
	if err := ValidateProtectedResourceAuthorization(ProtectedResourceAuthorization{
		Credentials: "abc\r\nX-Injected: 1", Scheme: CredentialSchemeAEP,
	}); err == nil {
		t.Fatal("credentials carrying CRLF were accepted")
	}
	if err := ValidateProtectedResourceAuthorization(ProtectedResourceAuthorization{
		Credentials: "", Scheme: CredentialSchemeAEP,
	}); err == nil {
		t.Fatal("empty credentials were accepted")
	}

	if _, err := ProtectedResourceAuthorizationHeader("Made-Up"); err == nil {
		t.Fatal("unsupported carrier produced a header name")
	}
	name, err := ProtectedResourceAuthorizationHeader("")
	if err != nil || name != "Authorization" {
		t.Fatalf("unexpected default carrier header: %q, %v", name, err)
	}
}

// ---------------------------------------------------------------- DWB-RES: did:web resolution

func TestDIDWebDocumentURLRejectsUnsafeComponents(t *testing.T) {
	rejected := []string{
		"did:key:z6Mk",
		"did:web:",
		"did:web:agent.example.com:..%2F..%2Fetc",
		"did:web:agent.example.com:a%2Fb",
		"did:web:agent.example.com:%2E%2E",
		"did:web:agent.example.com:.",
		"did:web:agent.example.com::agents",
		"did:web:agent.example.com:a%5Cb",
		"did:web:agent.example.com:a%3Fb",
		"did:web:agent.example.com:a%23b",
		"did:web:agent.example.com:a%20b",
		"did:web:agent.example.com:a%00b",
		"did:web:user%40agent.example.com",
		"did:web:agent.example.com%2Fpath",
		"did:web:%ZZ",
		"did:web:agent.example.com:%ZZ",
	}
	for _, did := range rejected {
		if resolved, err := DIDWebDocumentURL(did); err == nil {
			t.Fatalf("DID %q resolved to %s", did, resolved)
		}
	}

	resolved, err := DIDWebDocumentURL("did:web:agent.example.com")
	if err != nil || resolved.String() != "https://agent.example.com/.well-known/did.json" {
		t.Fatalf("unexpected bare-host resolution: %v, %v", resolved, err)
	}
}

func TestResolveDIDWebPublicKeyBindsDocumentIdentity(t *testing.T) {
	const did = "did:web:agent.example.com:agents:123"
	const keyID = did + "#key-1"

	// A document served under the Agent's path but claiming another DID is not the Agent's.
	foreign := strings.Replace(
		testDIDDocument(t, "did:web:attacker.example", keyID),
		`"id":"did:web:attacker.example"`, `"id":"did:web:attacker.example"`, 1,
	)
	if _, err := ResolveDIDWebPublicKey(context.Background(), ResolveDIDWebPublicKeyOptions{
		Client: stubDoer{body: foreign}, DID: did, KeyID: keyID,
	}); err == nil {
		t.Fatal("a document naming another DID was accepted")
	}

	key, err := ResolveDIDWebPublicKey(context.Background(), ResolveDIDWebPublicKeyOptions{
		Client: stubDoer{body: testDIDDocument(t, did, keyID)}, DID: did, KeyID: keyID,
	})
	if err != nil || !key.Valid() {
		t.Fatalf("absolute verification method id did not resolve: %v", err)
	}
}

func TestResolveDIDWebPublicKeyAcceptsRelativeFragment(t *testing.T) {
	const did = "did:web:agent.example.com:agents:123"
	key, err := ResolveDIDWebPublicKey(context.Background(), ResolveDIDWebPublicKeyOptions{
		Client: stubDoer{body: testDIDDocument(t, did, "#key-1")},
		DID:    did,
		KeyID:  did + "#key-1",
	})
	if err != nil || !key.Valid() {
		t.Fatalf("relative verification method id did not resolve: %v", err)
	}

	// Without a fragment in kid there is no relative form to match.
	if _, err := ResolveDIDWebPublicKey(context.Background(), ResolveDIDWebPublicKeyOptions{
		Client: stubDoer{body: testDIDDocument(t, did, "#key-1")}, DID: did, KeyID: did,
	}); err == nil {
		t.Fatal("a fragment-less kid matched a relative verification method")
	}
}

func TestResolveDIDWebPublicKeyFailureModes(t *testing.T) {
	const did = "did:web:agent.example.com:agents:123"
	const keyID = did + "#key-1"
	document := testDIDDocument(t, did, keyID)

	cases := []struct {
		name    string
		options ResolveDIDWebPublicKeyOptions
	}{
		{"missing key id", ResolveDIDWebPublicKeyOptions{Client: stubDoer{body: document}, DID: did}},
		{"foreign key id", ResolveDIDWebPublicKeyOptions{Client: stubDoer{body: document}, DID: did, KeyID: "did:web:other.example#key-1"}},
		{"unresolvable did", ResolveDIDWebPublicKeyOptions{Client: stubDoer{body: document}, DID: "did:key:z6Mk", KeyID: "did:key:z6Mk#key-1"}},
		{"transport failure", ResolveDIDWebPublicKeyOptions{Client: stubDoer{err: errors.New("dial")}, DID: did, KeyID: keyID}},
		{"redirected request", ResolveDIDWebPublicKeyOptions{Client: stubDoer{body: document, redirect: "https://elsewhere.example/did.json"}, DID: did, KeyID: keyID}},
		{"no request recorded", ResolveDIDWebPublicKeyOptions{Client: stubDoer{body: document, noReq: true}, DID: did, KeyID: keyID}},
		{"error status", ResolveDIDWebPublicKeyOptions{Client: stubDoer{body: document, status: http.StatusNotFound}, DID: did, KeyID: keyID}},
		{"malformed json", ResolveDIDWebPublicKeyOptions{Client: stubDoer{body: "{"}, DID: did, KeyID: keyID}},
		{"two json documents", ResolveDIDWebPublicKeyOptions{Client: stubDoer{body: document + document}, DID: did, KeyID: keyID}},
		{"unknown method", ResolveDIDWebPublicKeyOptions{Client: stubDoer{body: testDIDDocument(t, did, did+"#key-2")}, DID: did, KeyID: keyID}},
		{"method without jwk", ResolveDIDWebPublicKeyOptions{
			Client: stubDoer{body: `{"id":"` + did + `","verificationMethod":[{"id":"` + keyID + `"}]}`},
			DID:    did, KeyID: keyID,
		}},
		{"unusable jwk", ResolveDIDWebPublicKeyOptions{
			Client: stubDoer{body: `{"id":"` + did + `","verificationMethod":[{"id":"` + keyID + `","publicKeyJwk":{"kty":"OKP"}}]}`},
			DID:    did, KeyID: keyID,
		}},
		{"undecodable jwk", ResolveDIDWebPublicKeyOptions{
			Client: stubDoer{body: `{"id":"` + did + `","verificationMethod":[{"id":"` + keyID + `","publicKeyJwk":"nope"}]}`},
			DID:    did, KeyID: keyID,
		}},
	}
	for _, testCase := range cases {
		if _, err := ResolveDIDWebPublicKey(context.Background(), testCase.options); err == nil {
			t.Fatalf("%s was accepted", testCase.name)
		}
	}
}

func TestResolveDIDWebPublicKeyRejectsOversizedDocument(t *testing.T) {
	const did = "did:web:agent.example.com:agents:123"
	oversized := `{"id":"` + did + `","padding":"` + strings.Repeat("a", (1<<20)+16) + `"}`
	if _, err := ResolveDIDWebPublicKey(context.Background(), ResolveDIDWebPublicKeyOptions{
		Client: stubDoer{body: oversized}, DID: did, KeyID: did + "#key-1",
	}); err == nil || !strings.Contains(err.Error(), "1 MiB") {
		t.Fatalf("oversized document was not refused by size: %v", err)
	}
}

// ---------------------------------------------------------------- JWT

func TestSignClientAssertionRejectsUnusableInputs(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claims := assertionClaims()

	if _, err := SignClientAssertion(ClientAssertionClaims{}, SignClientAssertionOptions{
		Algorithm: SigningAlgorithmEdDSA, Key: privateKey, KeyID: claims.Issuer,
	}); err == nil {
		t.Fatal("invalid claims were signed")
	}
	if _, err := SignClientAssertion(claims, SignClientAssertionOptions{
		Algorithm: "RS256", Key: privateKey, KeyID: claims.Issuer,
	}); err == nil {
		t.Fatal("an unregistered algorithm was signed")
	}
	if _, err := SignClientAssertion(claims, SignClientAssertionOptions{
		Algorithm: SigningAlgorithmEdDSA, KeyID: claims.Issuer,
	}); err == nil {
		t.Fatal("a missing key was signed")
	}
	if _, err := SignClientAssertion(claims, SignClientAssertionOptions{
		Algorithm: SigningAlgorithmEdDSA, Key: privateKey,
	}); err == nil {
		t.Fatal("a missing kid was signed")
	}
	if _, err := SignClientAssertion(claims, SignClientAssertionOptions{
		Algorithm: SigningAlgorithmEdDSA, Key: privateKey, KeyID: "did:web:other.example",
	}); err == nil {
		t.Fatal("a kid naming another DID was signed")
	}
	if _, err := SignClientAssertion(claims, SignClientAssertionOptions{
		Algorithm: SigningAlgorithmES256, Key: privateKey, KeyID: claims.Issuer,
	}); err == nil {
		t.Fatal("a key that does not match the algorithm was signed")
	}
}

func TestVerifyClientAssertionRejectsUnusableInputs(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claims := assertionClaims()
	now := time.Unix(claims.IssuedAt+10, 0)
	assertion, err := SignClientAssertion(claims, SignClientAssertionOptions{
		Algorithm: SigningAlgorithmEdDSA, Key: privateKey, KeyID: claims.Issuer,
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := VerifyClientAssertion(context.Background(), assertion, VerifyClientAssertionOptions{
		CurrentTime: now, Key: publicKey,
	}); err != nil {
		t.Fatalf("a well-formed assertion was rejected: %v", err)
	}

	cases := []struct {
		name    string
		options VerifyClientAssertionOptions
	}{
		{"unregistered algorithm", VerifyClientAssertionOptions{Algorithms: []SigningAlgorithm{"RS256"}, CurrentTime: now, Key: publicKey}},
		{"missing key", VerifyClientAssertionOptions{CurrentTime: now}},
		{"wrong key", func() VerifyClientAssertionOptions {
			other, _, _ := ed25519.GenerateKey(rand.Reader)
			return VerifyClientAssertionOptions{CurrentTime: now, Key: other}
		}()},
		{"audience mismatch", VerifyClientAssertionOptions{Audience: "did:web:other.example", CurrentTime: now, Key: publicKey}},
		{"issuer mismatch", VerifyClientAssertionOptions{CurrentTime: now, Issuer: "did:web:other.example", Key: publicKey}},
		{"subject mismatch", VerifyClientAssertionOptions{CurrentTime: now, Key: publicKey, Subject: "did:web:other.example"}},
		{"operation mismatch", VerifyClientAssertionOptions{CurrentTime: now, Key: publicKey, Operation: AssertionStatus}},
		{"resource mismatch", VerifyClientAssertionOptions{CurrentTime: now, Key: publicKey, Resource: "https://api.example.com/orders"}},
		{"negative tolerance", VerifyClientAssertionOptions{ClockTolerance: -time.Second, CurrentTime: now, Key: publicKey}},
		{"issued in the future", VerifyClientAssertionOptions{CurrentTime: time.Unix(claims.IssuedAt-60, 0), Key: publicKey}},
		{"already expired", VerifyClientAssertionOptions{CurrentTime: time.Unix(claims.ExpiresAt+60, 0), Key: publicKey}},
		{"resolver failure", VerifyClientAssertionOptions{
			CurrentTime: now,
			KeyResolver: func(context.Context, jose.Header) (any, error) { return nil, errors.New("no key") },
		}},
	}
	for _, testCase := range cases {
		if _, err := VerifyClientAssertion(context.Background(), assertion, testCase.options); err == nil {
			t.Fatalf("%s was accepted", testCase.name)
		}
	}

	if _, err := VerifyClientAssertion(context.Background(), "not-a-jwt", VerifyClientAssertionOptions{
		CurrentTime: now, Key: publicKey,
	}); err == nil {
		t.Fatal("a malformed assertion was accepted")
	}

	resolved, err := VerifyClientAssertion(context.Background(), assertion, VerifyClientAssertionOptions{
		CurrentTime: now,
		KeyResolver: func(_ context.Context, header jose.Header) (any, error) {
			if header.KeyID != claims.Issuer {
				t.Fatalf("resolver received kid %q", header.KeyID)
			}
			return publicKey, nil
		},
	})
	if err != nil || resolved.JWTID != claims.JWTID {
		t.Fatalf("key resolver path failed: %v, %v", resolved, err)
	}
}

func TestVerifyClientAssertionRequiresTypeAndKeyID(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claims := assertionClaims()
	now := time.Unix(claims.IssuedAt+10, 0)

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.EdDSA, Key: privateKey},
		(&jose.SignerOptions{}).WithHeader("kid", claims.Issuer),
	)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	object, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	untyped, err := object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyClientAssertion(context.Background(), untyped, VerifyClientAssertionOptions{
		CurrentTime: now, Key: publicKey,
	}); err == nil {
		t.Fatal("an assertion without typ=JWT was accepted")
	}

	anonymous, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.EdDSA, Key: privateKey},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatal(err)
	}
	object, err = anonymous.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	keyless, err := object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyClientAssertion(context.Background(), keyless, VerifyClientAssertionOptions{
		CurrentTime: now, Key: publicKey,
	}); err == nil {
		t.Fatal("an assertion without kid was accepted")
	}
}

func TestDecodeJWTUnverified(t *testing.T) {
	encode := func(value any) string {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(data)
	}
	assertion := encode(map[string]any{"alg": "EdDSA", "typ": "JWT"}) + "." +
		encode(map[string]any{"iss": "did:web:agent.example.com"}) + ".signature"

	decoded, err := DecodeJWTUnverified(assertion)
	if err != nil || decoded.Header["alg"] != "EdDSA" || decoded.Payload["iss"] != "did:web:agent.example.com" {
		t.Fatalf("unexpected decode: %#v, %v", decoded, err)
	}

	rejected := []string{
		"",
		"only.two",
		"a.b.c.d",
		"!!!." + encode(map[string]any{}) + ".sig",
		encode(map[string]any{}) + ".!!!.sig",
		base64.RawURLEncoding.EncodeToString([]byte("null")) + "." + encode(map[string]any{}) + ".sig",
		base64.RawURLEncoding.EncodeToString([]byte("[]")) + "." + encode(map[string]any{}) + ".sig",
	}
	for _, value := range rejected {
		if _, err := DecodeJWTUnverified(value); err == nil {
			t.Fatalf("assertion %q was decoded", value)
		}
	}
}

// ---------------------------------------------------------------- protocol surface

func TestParseClientAssertionClaimsFromJSON(t *testing.T) {
	claims := assertionClaims()
	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseClientAssertionClaims(data)
	if err != nil || parsed.JWTID != claims.JWTID {
		t.Fatalf("unexpected parse: %#v, %v", parsed, err)
	}
	if _, err := ParseClientAssertionClaims([]byte("{")); err == nil {
		t.Fatal("malformed claims were parsed")
	}
	if _, err := ParseClientAssertionClaims([]byte(`{"iss":""}`)); err == nil {
		t.Fatal("empty claims were parsed")
	}

	loopback := assertionClaims()
	loopback.Operation = AssertionAuthenticate
	loopback.Resource = "http://localhost:8080/orders"
	data, err = json.Marshal(loopback)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseClientAssertionClaimsWithOptions(data, ClientAssertionValidationOptions{AllowInsecureLoopback: true}); err != nil {
		t.Fatalf("loopback claims were rejected: %v", err)
	}
}

func TestBuiltInGrantResponseDispatch(t *testing.T) {
	oauth := OAuthBearerGrantResponse{
		AccessToken:  "token",
		CredentialID: "cred-1",
		ExpiresAt:    "2999-01-01T00:00:00Z",
		Scopes:       []string{},
		TokenType:    "Bearer",
	}
	apiKey := APIKeyGrantResponse{
		APIKey:       "key-value",
		CredentialID: "cred-2",
		ExpiresAt:    "2999-01-01T00:00:00Z",
		Header:       "x-api-key",
		Scopes:       []string{},
	}
	basic := BasicGrantResponse{
		CredentialID: "cred-3",
		ExpiresAt:    "2999-01-01T00:00:00Z",
		Password:     "pass",
		Scopes:       []string{},
		Username:     "user",
	}

	if oauth.GrantType() != GrantTypeOAuthBearer || apiKey.GrantType() != GrantTypeAPIKey || basic.GrantType() != GrantTypeBasic {
		t.Fatal("grant-type discriminators do not match their responses")
	}

	for grantType, value := range map[GrantType]BuiltInGrantResponse{
		GrantTypeOAuthBearer: oauth,
		GrantTypeAPIKey:      apiKey,
		GrantTypeBasic:       basic,
	} {
		if err := ValidateBuiltInGrantResponse(grantType, value); err != nil {
			t.Fatalf("%s response was rejected: %v", grantType, err)
		}
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseBuiltInGrantResponse(grantType, data); err != nil {
			t.Fatalf("%s response did not parse: %v", grantType, err)
		}
	}

	for grantType, value := range map[GrantType]BuiltInGrantResponse{
		GrantTypeOAuthBearer: &oauth,
		GrantTypeAPIKey:      &apiKey,
		GrantTypeBasic:       &basic,
	} {
		if err := ValidateBuiltInGrantResponse(grantType, value); err != nil {
			t.Fatalf("%s pointer response was rejected: %v", grantType, err)
		}
	}

	// A response validated against the wrong grant type is a mismatch, not a pass.
	mismatches := []struct {
		grantType GrantType
		value     BuiltInGrantResponse
	}{
		{GrantTypeAPIKey, oauth},
		{GrantTypeBasic, apiKey},
		{GrantTypeOAuthBearer, basic},
		{GrantTypeAPIKey, &oauth},
		{GrantTypeBasic, &apiKey},
		{GrantTypeOAuthBearer, &basic},
		{GrantTypeOAuthBearer, nil},
		{GrantTypeOAuthBearer, (*OAuthBearerGrantResponse)(nil)},
		{GrantTypeAPIKey, (*APIKeyGrantResponse)(nil)},
		{GrantTypeBasic, (*BasicGrantResponse)(nil)},
		{"made-up", oauth},
	}
	for _, mismatch := range mismatches {
		if err := ValidateBuiltInGrantResponse(mismatch.grantType, mismatch.value); err == nil {
			t.Fatalf("%s accepted a mismatched response", mismatch.grantType)
		}
	}

	if _, err := ParseBuiltInGrantResponse("made-up", []byte("{}")); err == nil {
		t.Fatal("an unregistered grant type was parsed")
	}
	if _, err := ParseBuiltInGrantResponse(GrantTypeAPIKey, []byte("{")); err == nil {
		t.Fatal("a malformed API-key response was parsed")
	}
	if _, err := ParseBuiltInGrantResponse(GrantTypeBasic, []byte(`{"realm":null}`)); err == nil {
		t.Fatal("a null realm was parsed")
	}
}

func TestRevokeResponseAndMetadata(t *testing.T) {
	if _, err := ParseRevokeResponse([]byte("{}")); err != nil {
		t.Fatalf("an empty Revoke response was rejected: %v", err)
	}
	for _, body := range []string{`{"extra":1}`, "null", "[]", "{", "{} {}"} {
		if _, err := ParseRevokeResponse([]byte(body)); err == nil {
			t.Fatalf("Revoke response %q was accepted", body)
		}
	}
	if err := ValidateRevokeResponse(RevokeResponse{}); err != nil {
		t.Fatalf("a Revoke response was rejected: %v", err)
	}

	agentDID := "did:web:agent.example.com"
	empty := ""
	badHash := "sha256:NOPE"
	if err := ValidateIdempotencyMetadata(IdempotencyMetadata{
		AgentDID: &agentDID, IdempotencyKey: "key-1",
	}); err != nil {
		t.Fatalf("valid metadata was rejected: %v", err)
	}
	if err := ValidateIdempotencyMetadata(IdempotencyMetadata{AgentDID: &empty, IdempotencyKey: "key-1"}); err == nil {
		t.Fatal("an empty agent_did was accepted")
	}
	if err := ValidateIdempotencyMetadata(IdempotencyMetadata{
		FirstBodyHash: &badHash, IdempotencyKey: "key-1",
	}); err == nil {
		t.Fatal("a malformed body hash was accepted")
	}
	if err := ValidateIdempotencyMetadata(IdempotencyMetadata{}); err == nil {
		t.Fatal("metadata without an idempotency key was accepted")
	}
}

func TestValidationErrorReporting(t *testing.T) {
	err := ValidateEnrollRequest(EnrollRequest{})
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("expected a validation error, got %v", err)
	}
	if validation.Error() != "invalid AEP Enroll request" {
		t.Fatalf("unexpected error text: %q", validation.Error())
	}
	if len(validation.Issues) == 0 || validation.Issues[0].Path != "$.agent_did" {
		t.Fatalf("unexpected issues: %#v", validation.Issues)
	}

	carrier := &AuthorizationCarrierError{Code: ErrorNotRecognized, Text: "nope"}
	if carrier.Error() != "nope" {
		t.Fatalf("unexpected carrier error text: %q", carrier.Error())
	}
}

func TestStatusAndEnrollResponseValidation(t *testing.T) {
	if err := ValidateStatusResponse(StatusResponse{Since: "not-a-date", Status: AgentActive}); err == nil {
		t.Fatal("a malformed since was accepted")
	}
	if err := ValidateStatusResponse(StatusResponse{Since: "2026-02-30T00:00:00Z", Status: AgentActive}); err == nil {
		t.Fatal("a date that does not exist was accepted")
	}
	if err := ValidateStatusResponse(StatusResponse{Status: "made-up"}); err == nil {
		t.Fatal("an unregistered status was accepted")
	}

	ownerAction := "maybe"
	if err := ValidateEnrollResponse(EnrollResponse{OwnerActionRequired: &ownerAction, Status: AgentActive}); err == nil {
		t.Fatal("a non-boolean owner_action_required was accepted")
	}
	if err := ValidateEnrollResponse(EnrollResponse{
		RequirementsPending: []string{"contact.email", "contact.email"},
		Status:              AgentPending,
	}); err == nil {
		t.Fatal("duplicate requirements_pending entries were accepted")
	}
	if err := ValidateEnrollResponse(EnrollResponse{
		Status:              AgentPending,
		VerificationPending: []string{},
	}); err == nil {
		t.Fatal("an empty verification_pending array was accepted")
	}
	if err := ValidateEnrollResponse(EnrollResponse{
		Status:              AgentPending,
		VerificationPending: []string{""},
	}); err == nil {
		t.Fatal("an empty verification_pending entry was accepted")
	}
}

func TestRevokeRequestCombinations(t *testing.T) {
	accepted := []RevokeRequest{
		{GrantType: GrantTypeOAuthBearer},
		{CredentialID: "cred-1", GrantType: GrantTypeOAuthBearer},
		{AllGrantTypes: "true"},
	}
	for _, request := range accepted {
		if err := ValidateRevokeRequest(request); err != nil {
			t.Fatalf("%#v was rejected: %v", request, err)
		}
	}
	rejected := []RevokeRequest{
		{},
		{AllGrantTypes: "false"},
		{AllGrantTypes: "true", GrantType: GrantTypeOAuthBearer},
		{AllGrantTypes: "true", CredentialID: "cred-1"},
		{CredentialID: "cred-1"},
	}
	for _, request := range rejected {
		if err := ValidateRevokeRequest(request); err == nil {
			t.Fatalf("%#v was accepted", request)
		}
	}
}

func TestGrantResponseFieldValidation(t *testing.T) {
	if err := ValidateOAuthBearerGrantResponse(OAuthBearerGrantResponse{
		AccessToken: "token", CredentialID: "c", ExpiresAt: "2999-01-01T00:00:00Z", TokenType: "bearer",
	}); err == nil {
		t.Fatal("a lowercase token_type was accepted")
	}
	if err := ValidateOAuthBearerGrantResponse(OAuthBearerGrantResponse{
		AccessToken: "token", CredentialID: "c", ExpiresAt: "not-a-date", TokenType: "Bearer",
	}); err == nil {
		t.Fatal("a malformed expires_at was accepted")
	}
	if err := ValidateOAuthBearerGrantResponse(OAuthBearerGrantResponse{
		AccessToken: "token", CredentialID: "c", ExpiresAt: "2999-01-01T00:00:00Z", Scopes: []string{""}, TokenType: "Bearer",
	}); err == nil {
		t.Fatal("an empty scope was accepted")
	}

	realm := ""
	if err := ValidateBasicGrantResponse(BasicGrantResponse{
		CredentialID: "c", ExpiresAt: "2999-01-01T00:00:00Z", Password: "p", Realm: &realm, Username: "u",
	}); err == nil {
		t.Fatal("an empty realm was accepted")
	}
	if err := ValidateBasicGrantResponse(BasicGrantResponse{
		CredentialID: "c", ExpiresAt: "2999-01-01T00:00:00Z", Password: "p\x01", Username: "u",
	}); err == nil {
		t.Fatal("a password carrying a control character was accepted")
	}
	if err := ValidateBasicGrantResponse(BasicGrantResponse{
		CredentialID: "c", ExpiresAt: "2999-01-01T00:00:00Z", Password: "p", Username: "u:v",
	}); err == nil {
		t.Fatal("a username carrying a colon was accepted")
	}

	if err := ValidateAPIKeyGrantResponse(APIKeyGrantResponse{
		APIKey: "key,value", CredentialID: "c", ExpiresAt: "2999-01-01T00:00:00Z", Header: "x-api-key",
	}); err == nil {
		t.Fatal("an API key carrying a comma was accepted")
	}
	if err := ValidateAPIKeyGrantResponse(APIKeyGrantResponse{
		APIKey: "key", CredentialID: "c", ExpiresAt: "2999-01-01T00:00:00Z", Header: "x api key",
	}); err == nil {
		t.Fatal("a header name carrying a space was accepted")
	}
	if !IsHTTPFieldName("X-API-Key") || IsHTTPFieldName("") || IsHTTPFieldName("bad header") {
		t.Fatal("HTTP field-name validation is wrong")
	}
}

func TestProblemDetailsValidation(t *testing.T) {
	if err := ValidateProblemDetails(NewProblemDetails(ErrorInvalidRequest, "Invalid request", 400)); err != nil {
		t.Fatalf("a well-formed problem was rejected: %v", err)
	}
	if err := ValidateProblemDetails(ProblemDetails{
		Code: ErrorInvalidRequest, Status: 400, Title: "Invalid request", Type: "urn:aep:error:other",
	}); err == nil {
		t.Fatal("a type that disagrees with code was accepted")
	}
	if err := ValidateProblemDetails(ProblemDetails{
		Code: ErrorInvalidRequest, Title: "Invalid request", Type: "urn:aep:error:invalid_request",
	}); err == nil {
		t.Fatal("a problem without a status was accepted")
	}
	pending := []string{"contact.email"}
	if err := ValidateProblemDetails(ProblemDetails{
		Code: ErrorNotRecognized, RequirementsPending: pending, Status: 401,
		Title: "Not recognized", Type: "urn:aep:error:not_recognized",
	}); err == nil {
		t.Fatal("not_recognized exposed pending metadata")
	}
}

// ---------------------------------------------------------------- Inspect

func TestInspectValidationDetails(t *testing.T) {
	base := func() InspectDocument {
		return InspectDocument{
			AEPVersion: Version,
			Bindings:   Bindings{Supported: []Binding{BindingHTTP}},
			Commands:   Commands{Supported: []Command{CommandInspect}},
			Core:       Core{SigningAlgorithms: []SigningAlgorithm{SigningAlgorithmEdDSA, SigningAlgorithmES256}},
			Service:    ServiceIdentity{DID: "did:web:api.example.com"},
		}
	}
	if err := ValidateInspectDocument(base()); err != nil {
		t.Fatalf("a minimal document was rejected: %v", err)
	}

	document := base()
	document.Extensions = &Extensions{Supported: []string{"not a uri"}}
	if err := ValidateInspectDocument(document); err == nil {
		t.Fatal("a relative extension identifier was accepted")
	}
	document.Extensions = &Extensions{Supported: []string{"urn:aep:ext:aep:demo#v=1.0.0"}}
	if err := ValidateInspectDocument(document); err != nil {
		t.Fatalf("an absolute extension identifier was rejected: %v", err)
	}

	document = base()
	document.HTTP = HTTPConfiguration{EndpointBase: "//evil.example/aep"}
	if err := ValidateInspectDocument(document); err == nil {
		t.Fatal("an off-origin endpoint base was accepted")
	}
	document.HTTP = HTTPConfiguration{EndpointBase: "aep"}
	if err := ValidateInspectDocument(document); err == nil {
		t.Fatal("a relative endpoint base was accepted")
	}

	document = base()
	document.HTTP = HTTPConfiguration{OpenAPI: &OpenAPIReference{
		PathMatching: OpenAPIPathMatching{TrailingSlash: "strict"},
	}}
	if err := ValidateInspectDocument(document); err == nil {
		t.Fatal("an OpenAPI configuration without a URL was accepted")
	}
	document.HTTP.OpenAPI.URL = "https://api.example.com/open api.json"
	if err := ValidateInspectDocument(document); err == nil {
		t.Fatal("an OpenAPI URL carrying whitespace was accepted")
	}
	document.HTTP.OpenAPI.URL = "https://api.example.com/openapi.json"
	document.HTTP.OpenAPI.PathMatching.TrailingSlash = "loose"
	if err := ValidateInspectDocument(document); err == nil {
		t.Fatal("an unregistered trailing-slash policy was accepted")
	}
	document.HTTP.OpenAPI.PathMatching.TrailingSlash = "equivalent"
	if err := ValidateInspectDocument(document); err != nil {
		t.Fatalf("a valid OpenAPI configuration was rejected: %v", err)
	}
	document.HTTP.OpenAPI.Additional = AdditionalMembers{"extra": json.RawMessage(`1`)}
	if err := ValidateInspectDocument(document); err == nil {
		t.Fatal("an unknown OpenAPI member was accepted")
	}
	document.HTTP.OpenAPI.Additional = nil
	document.HTTP.OpenAPI.PathMatching.Additional = AdditionalMembers{"extra": json.RawMessage(`1`)}
	if err := ValidateInspectDocument(document); err == nil {
		t.Fatal("an unknown path-matching member was accepted")
	}

	document = base()
	document.Authentication = &Authentication{}
	if err := ValidateInspectDocument(document); err == nil {
		t.Fatal("an empty authentication method list was accepted")
	}
	document.Authentication = &Authentication{Methods: []AuthenticationMethod{"aep-jwt", "aep-jwt"}}
	if err := ValidateInspectDocument(document); err == nil {
		t.Fatal("duplicate authentication methods were accepted")
	}
	document.Authentication = &Authentication{Methods: []AuthenticationMethod{"AEP-JWT"}}
	if err := ValidateInspectDocument(document); err == nil {
		t.Fatal("an uppercase authentication method was accepted")
	}
	document.Authentication = &Authentication{
		Additional: AdditionalMembers{"extra": json.RawMessage(`1`)},
		Methods:    []AuthenticationMethod{"aep-jwt"},
	}
	if err := ValidateInspectDocument(document); err == nil {
		t.Fatal("an unknown authentication member was accepted")
	}

	tooMany := make([]AuthenticationMethod, 0, MaxAuthenticationMethods+1)
	for index := 0; index <= MaxAuthenticationMethods; index++ {
		tooMany = append(tooMany, AuthenticationMethod("method-"+string(rune('a'+index%26))+string(rune('a'+index/26))))
	}
	document.Authentication = &Authentication{Methods: tooMany}
	if err := ValidateInspectDocument(document); err == nil {
		t.Fatal("more than the maximum number of authentication methods was accepted")
	}

	document = base()
	document.Claims = &InspectClaims{Required: []ClaimName{"Contact.Email"}}
	if err := ValidateInspectDocument(document); err == nil {
		t.Fatal("a malformed claim name was accepted")
	}
	document.Claims = &InspectClaims{Optional: []ClaimName{"contact.email"}, Preferred: []ClaimName{"person.username"}}
	if err := ValidateInspectDocument(document); err != nil {
		t.Fatalf("registered claim names were rejected: %v", err)
	}

	document = base()
	document.Identity = Identity{Methods: []IdentityMethod{"DID:WEB"}}
	if err := ValidateInspectDocument(document); err == nil {
		t.Fatal("an uppercase identity method was accepted")
	}
	document.Commands.Supported = []Command{CommandInspect, CommandEnroll}
	document.Identity = Identity{}
	if err := ValidateInspectDocument(document); err == nil {
		t.Fatal("an authenticated command without an identity method was accepted")
	}

	document = base()
	document.Commands.GrantTypesConfig = map[string]GrantTypeConfig{
		"oauth-bearer": {SupportsPerCredentialRevoke: "maybe"},
	}
	if err := ValidateInspectDocument(document); err == nil {
		t.Fatal("a non-boolean supports_per_credential_revoke was accepted")
	}
	document.Commands.GrantTypesConfig = map[string]GrantTypeConfig{"OAuth-Bearer": {}}
	if err := ValidateInspectDocument(document); err == nil {
		t.Fatal("an uppercase grant-type configuration key was accepted")
	}
}

func TestVersionCompatibility(t *testing.T) {
	if !IsVersionCompatible("1.9", "1.0") {
		t.Fatal("a later minor version was treated as incompatible")
	}
	if IsVersionCompatible("2.0", "1.0") || IsVersionCompatible("nope", "1.0") || IsVersionCompatible("1.0", "nope") {
		t.Fatal("incompatible versions were accepted")
	}
}

// ---------------------------------------------------------------- OpenAPI

func TestMatchOpenAPIPathEdges(t *testing.T) {
	templates := []string{"/orders/{id}", "/orders/mine", "/orders/{id}/items/{item}"}

	match, err := MatchOpenAPIPath(templates, OpenAPIPathMatchOptions{
		Method: "get", Path: "/orders/mine", TrailingSlash: "strict",
	})
	if err != nil || match.Template != "/orders/mine" || match.Method != "GET" {
		t.Fatalf("literal precedence failed: %#v, %v", match, err)
	}

	if _, err := MatchOpenAPIPath(templates, OpenAPIPathMatchOptions{
		Method: "GET", Path: "/orders/7/", TrailingSlash: "equivalent",
	}); err != nil {
		t.Fatalf("equivalent trailing slash failed: %v", err)
	}
	if _, err := MatchOpenAPIPath(templates, OpenAPIPathMatchOptions{
		Method: "GET", Path: "/orders/7/", TrailingSlash: "strict",
	}); err == nil {
		t.Fatal("a strict trailing slash matched")
	}

	invalid := []OpenAPIPathMatchOptions{
		{Method: "", Path: "/orders", TrailingSlash: "strict"},
		{Method: "GET", Path: "", TrailingSlash: "strict"},
		{Method: "GET", Path: "/orders?page=2", TrailingSlash: "strict"},
		{Method: "GET", Path: "/orders", TrailingSlash: "loose"},
		{Method: "GET", Path: "/unknown", TrailingSlash: "strict"},
	}
	for _, options := range invalid {
		if _, err := MatchOpenAPIPath(templates, options); err == nil {
			t.Fatalf("%#v was accepted", options)
		}
	}

	if _, err := MatchOpenAPIPath([]string{"/orders/{a}", "/orders/{b}"}, OpenAPIPathMatchOptions{
		Method: "GET", Path: "/orders/7", TrailingSlash: "strict",
	}); err == nil {
		t.Fatal("ambiguous templates were resolved")
	}

	// An empty placeholder is a literal segment, not a template.
	if _, err := MatchOpenAPIPath([]string{"/orders/{}"}, OpenAPIPathMatchOptions{
		Method: "GET", Path: "/orders/7", TrailingSlash: "strict",
	}); err == nil {
		t.Fatal("an empty placeholder matched an arbitrary segment")
	}
}

func TestResolveOpenAPIURLRejectsUnsafeTargets(t *testing.T) {
	if _, err := ResolveOpenAPIURL("https://api.example.com/.well-known/aep", "openapi.json", false); err != nil {
		t.Fatalf("a relative reference was rejected: %v", err)
	}
	rejected := []struct{ base, reference string }{
		{"http://api.example.com/.well-known/aep", "openapi.json"},
		{"https://user@api.example.com/.well-known/aep", "openapi.json"},
		{"not a url", "openapi.json"},
		{"https://api.example.com/.well-known/aep", "http://api.example.com/openapi.json"},
		{"https://api.example.com/.well-known/aep", "https://user@api.example.com/openapi.json"},
		{"https://api.example.com/.well-known/aep", "openapi.json#section"},
		{"https://api.example.com/.well-known/aep", "mailto:someone@example.com"},
		{"https://api.example.com/.well-known/aep", "://nonsense"},
	}
	for _, testCase := range rejected {
		if resolved, err := ResolveOpenAPIURL(testCase.base, testCase.reference, false); err == nil {
			t.Fatalf("base %q reference %q resolved to %s", testCase.base, testCase.reference, resolved)
		}
	}
}

// ---------------------------------------------------------------- claims

func TestClaimPresenceAndNegotiation(t *testing.T) {
	address := ContactAddressPrimary{Country: "US"}
	email := "agent@example.com"
	mobile := "+15555550123"
	birthdate := "1990-01-01"
	first := "Ada"
	last := "Lovelace"
	username := "ada"
	values := ClaimValues{
		Additional:            AdditionalMembers{"vendor.custom": json.RawMessage(`"x"`)},
		ContactAddressPrimary: &address,
		ContactEmail:          &email,
		ContactMobile:         &mobile,
		PersonBirthdate:       &birthdate,
		PersonFirstName:       &first,
		PersonLastName:        &last,
		PersonUsername:        &username,
	}

	present := []ClaimName{
		ClaimContactAddressPrimary, ClaimContactEmail, ClaimContactMobile,
		ClaimPersonBirthdate, ClaimPersonFirstName, ClaimPersonLastName,
		ClaimPersonUsername, "vendor.custom",
	}
	if missing := MissingRequiredClaimNames(present, &values); len(missing) != 0 {
		t.Fatalf("expected no missing claims, got %v", missing)
	}
	if missing := MissingRequiredClaimNames([]ClaimName{"vendor.absent"}, &values); len(missing) != 1 {
		t.Fatalf("expected one missing claim, got %v", missing)
	}
	if missing := MissingRequiredClaimNames(present, nil); len(missing) != len(present) {
		t.Fatalf("expected every claim missing, got %v", missing)
	}
}

func TestEmailMailboxValidation(t *testing.T) {
	accepted := []string{
		"agent@example.com",
		"first.last@example.com",
		"a@[192.0.2.1]",
		"a@[IPv6:2001:db8::1]",
		"a@[custom:literal]",
		`"quoted local"@example.com`,
		`"escaped\"quote"@example.com`,
	}
	rejected := []string{
		"",
		"no-at-sign",
		"@example.com",
		"agent@",
		"two@at@example.com",
		"agent@exa mple.com",
		"agent@-example.com",
		`"unterminated@example.com`,
		`"bad"x@example.com`,
		`"tab	"@example.com`,
		`"trailing\`,
		"a@[]",
		"a@[IPv6:not-an-address]",
		"a@[:literal]",
		"a@[bad-:literal]",
		"a@[custom:lit eral]",
		strings.Repeat("a", 65) + "@example.com",
		"a@" + strings.Repeat("b", 256),
		"a@" + strings.Repeat("c", 64) + ".example.com",
	}
	for _, mailbox := range accepted {
		if err := ValidateClaimValues(ClaimValues{ContactEmail: &mailbox}); err != nil {
			t.Fatalf("mailbox %q was rejected: %v", mailbox, err)
		}
	}
	for _, mailbox := range rejected {
		value := mailbox
		if err := ValidateClaimValues(ClaimValues{ContactEmail: &value}); err == nil {
			t.Fatalf("mailbox %q was accepted", mailbox)
		}
	}
}

func TestClaimValueFieldValidation(t *testing.T) {
	empty := ""
	if err := ValidateClaimValues(ClaimValues{PersonFirstName: &empty}); err == nil {
		t.Fatal("an empty first name was accepted")
	}
	if err := ValidateClaimValues(ClaimValues{PersonLastName: &empty}); err == nil {
		t.Fatal("an empty last name was accepted")
	}
	if err := ValidateClaimValues(ClaimValues{PersonUsername: &empty}); err == nil {
		t.Fatal("an empty username was accepted")
	}
	if err := ValidateClaimValues(ClaimValues{ContactMobile: &empty}); err == nil {
		t.Fatal("an empty mobile number was accepted")
	}

	for _, birthdate := range []string{"1990-1-1", "1990-02-30", "not-a-date", "1990-01-01T00:00:00Z", ""} {
		value := birthdate
		if err := ValidateClaimValues(ClaimValues{PersonBirthdate: &value}); err == nil {
			t.Fatalf("birthdate %q was accepted", birthdate)
		}
	}
	valid := "2000-02-29"
	if err := ValidateClaimValues(ClaimValues{PersonBirthdate: &valid}); err != nil {
		t.Fatalf("a leap-day birthdate was rejected: %v", err)
	}
}

// ---------------------------------------------------------------- additional members

func TestAdditionalMemberRoundTrip(t *testing.T) {
	round := func(t *testing.T, name string, target json.Unmarshaler, encoded string) {
		t.Helper()
		if err := target.UnmarshalJSON([]byte(encoded)); err != nil {
			t.Fatalf("%s did not decode: %v", name, err)
		}
		marshaler, ok := target.(json.Marshaler)
		if !ok {
			t.Fatalf("%s is not a marshaler", name)
		}
		data, err := marshaler.MarshalJSON()
		if err != nil {
			t.Fatalf("%s did not encode: %v", name, err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("%s produced invalid JSON: %v", name, err)
		}
		if _, ok := decoded["vendor.custom"]; !ok {
			t.Fatalf("%s dropped its additional member: %s", name, data)
		}
	}

	round(t, "Authentication", &Authentication{}, `{"methods":["aep-jwt"],"vendor.custom":1}`)
	round(t, "OpenAPIPathMatching", &OpenAPIPathMatching{}, `{"trailing_slash":"strict","vendor.custom":1}`)
	round(t, "GrantTypeConfig", &GrantTypeConfig{}, `{"supports_per_credential_revoke":"true","vendor.custom":1}`)
	round(t, "ContactAddressPrimary", &ContactAddressPrimary{}, `{"country":"US","vendor.custom":1}`)
	round(t, "EnrollRequest", &EnrollRequest{}, `{"agent_did":"did:web:a.example","vendor.custom":1}`)
	round(t, "EnrollResponse", &EnrollResponse{}, `{"status":"active","vendor.custom":1}`)
	round(t, "StatusResponse", &StatusResponse{}, `{"since":"2026-01-01T00:00:00Z","status":"active","vendor.custom":1}`)
	round(t, "GrantRequest", &GrantRequest{}, `{"grant_type":"oauth-bearer","vendor.custom":1}`)
	round(t, "RevokeRequest", &RevokeRequest{}, `{"grant_type":"oauth-bearer","vendor.custom":1}`)
	round(t, "ProblemDetails", &ProblemDetails{}, `{"code":"invalid_request","status":400,"title":"t","type":"urn:aep:error:invalid_request","vendor.custom":1}`)
}

func TestAdditionalMemberDecodeFailures(t *testing.T) {
	if err := (&Authentication{}).UnmarshalJSON([]byte("[]")); err == nil {
		t.Fatal("a non-object Authentication was decoded")
	}
	if err := (&GrantTypeConfig{}).UnmarshalJSON([]byte("null")); err == nil {
		t.Fatal("a null GrantTypeConfig was decoded")
	}
	if err := (&GrantTypeConfig{}).UnmarshalJSON([]byte(`{"supports_per_credential_revoke":null}`)); err == nil {
		t.Fatal("a null supports_per_credential_revoke was decoded")
	}
	if err := (&GrantTypeConfig{}).UnmarshalJSON([]byte(`{"supports_per_credential_revoke":""}`)); err == nil {
		t.Fatal("an empty supports_per_credential_revoke was decoded")
	}
	if err := (&GrantTypeConfig{}).UnmarshalJSON([]byte(`{"supports_per_credential_revoke":5}`)); err == nil {
		t.Fatal("a numeric supports_per_credential_revoke was decoded")
	}
	if err := (&ClaimValues{}).UnmarshalJSON([]byte("null")); err == nil {
		t.Fatal("a null ClaimValues was decoded")
	}
	if err := (&ClaimValues{}).UnmarshalJSON([]byte("[]")); err == nil {
		t.Fatal("a non-object ClaimValues was decoded")
	}
	for _, encoded := range []string{
		`{"contact.address.primary":5}`,
		`{"contact.email":5}`,
		`{"contact.mobile":5}`,
		`{"person.birthdate":5}`,
		`{"person.first_name":5}`,
		`{"person.last_name":5}`,
		`{"person.username":5}`,
	} {
		if err := (&ClaimValues{}).UnmarshalJSON([]byte(encoded)); err == nil {
			t.Fatalf("%s was decoded", encoded)
		}
	}
}

func TestClaimValuesMarshalOmitsAbsentMembers(t *testing.T) {
	var values ClaimValues
	data, err := values.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "{}" {
		t.Fatalf("expected an empty object, got %s", data)
	}
}

// ---------------------------------------------------------------- misc helpers

func TestCommandPathHelpers(t *testing.T) {
	path, err := CommandPath(CommandEnroll, "")
	if err != nil || path != DefaultHTTPEndpointBase+"enroll" {
		t.Fatalf("unexpected default command path: %q, %v", path, err)
	}
	if _, err := CommandPath(CommandInspect, ""); err == nil {
		t.Fatal("Inspect produced a command path")
	}
	if _, err := CommandPath(CommandEnroll, "aep"); err == nil {
		t.Fatal("a relative endpoint base was accepted")
	}
	if _, err := CommandPath(CommandEnroll, "//evil.example"); err == nil {
		t.Fatal("an off-origin endpoint base was accepted")
	}
	path, err = CommandPathFromInspect(InspectDocument{HTTP: HTTPConfiguration{EndpointBase: "/aep/"}}, CommandStatus)
	if err != nil || path != "/aep/status" {
		t.Fatalf("unexpected Inspect-derived path: %q, %v", path, err)
	}
	if base, err := NormalizeEndpointBase("/aep"); err != nil || base != "/aep/" {
		t.Fatalf("unexpected normalized base: %q, %v", base, err)
	}
}

func TestOpenAPISecuritySchemeValidation(t *testing.T) {
	scheme, err := ParseOpenAPIAEPSecurityScheme([]byte(`{"x-aep-authentication-method":"aep-jwt"}`))
	if err != nil || scheme.AuthenticationMethod != "aep-jwt" {
		t.Fatalf("unexpected scheme: %#v, %v", scheme, err)
	}
	if _, err := ParseOpenAPIAEPSecurityScheme([]byte(`{"x-aep-authentication-method":"AEP-JWT"}`)); err == nil {
		t.Fatal("an uppercase authentication method was accepted")
	}
	if _, err := ParseOpenAPIAEPSecurityScheme([]byte("{")); err == nil {
		t.Fatal("a malformed scheme was parsed")
	}
}
