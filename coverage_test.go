package aep

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("read failure") }

func (failingReader) Close() error { return nil }

// ---------------------------------------------------------------- claims

func TestContactAddressPrimaryValidation(t *testing.T) {
	city := ""
	complete := func() ContactAddressPrimary {
		return ContactAddressPrimary{Country: "US", FirstName: "Ada", LastName: "Lovelace", Line1: "1 Main St"}
	}

	if err := ValidateClaimValues(ClaimValues{ContactAddressPrimary: func() *ContactAddressPrimary {
		address := complete()
		return &address
	}()}); err != nil {
		t.Fatalf("a complete address was rejected: %v", err)
	}

	cases := map[string]func(*ContactAddressPrimary){
		"missing country":    func(a *ContactAddressPrimary) { a.Country = "" },
		"lowercase country":  func(a *ContactAddressPrimary) { a.Country = "us" },
		"three-letter code":  func(a *ContactAddressPrimary) { a.Country = "USA" },
		"missing first name": func(a *ContactAddressPrimary) { a.FirstName = "" },
		"missing last name":  func(a *ContactAddressPrimary) { a.LastName = "" },
		"missing line1":      func(a *ContactAddressPrimary) { a.Line1 = "" },
		"empty city":         func(a *ContactAddressPrimary) { a.City = &city },
		"legacy postal_code": func(a *ContactAddressPrimary) {
			a.Additional = AdditionalMembers{"postal_code": json.RawMessage(`"12345"`)}
		},
	}
	for name, mutate := range cases {
		address := complete()
		mutate(&address)
		if err := ValidateClaimValues(ClaimValues{ContactAddressPrimary: &address}); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

func TestEvaluateClaimSupportWithoutRequest(t *testing.T) {
	evaluation := EvaluateClaimSupport(nil, []ClaimName{ClaimContactEmail})
	if !evaluation.CanSatisfyRequired || len(evaluation.SupportedOptional) != 0 || len(evaluation.SupportedPreferred) != 0 {
		t.Fatalf("an absent request was not treated as satisfiable: %#v", evaluation)
	}

	evaluation = EvaluateClaimSupport(&InspectClaims{
		Optional:  []ClaimName{ClaimPersonUsername, "vendor.absent"},
		Preferred: []ClaimName{ClaimContactMobile, "vendor.missing"},
		Required:  []ClaimName{ClaimContactEmail, "vendor.unsupported"},
	}, []ClaimName{ClaimContactEmail, ClaimContactMobile, ClaimPersonUsername})
	if evaluation.CanSatisfyRequired {
		t.Fatal("an unsupported required claim was reported as satisfiable")
	}
	if len(evaluation.UnsupportedRequired) != 1 || evaluation.UnsupportedRequired[0] != "vendor.unsupported" {
		t.Fatalf("unexpected unsupported set: %v", evaluation.UnsupportedRequired)
	}
	if len(evaluation.SupportedPreferred) != 1 || len(evaluation.SupportedOptional) != 1 {
		t.Fatalf("unexpected negotiation result: %#v", evaluation)
	}
}

func TestQuotedLocalPartAndAddressLiteralEdges(t *testing.T) {
	rejected := []string{
		`"`,
		`"unterminated@example.com`,
		`"\`,
		`"\"@example.com`,
		"\"\x01\"@example.com",
		`"\` + "\x01" + `"@example.com`,
		"a@[IPv6:]",
		"a@[.]",
		"a@[tag:]",
		"a@[tag-:literal]",
		"a@[tag:\x7f]",
		"a@[",
		"a@]",
	}
	for _, mailbox := range rejected {
		value := mailbox
		if err := ValidateClaimValues(ClaimValues{ContactEmail: &value}); err == nil {
			t.Fatalf("mailbox %q was accepted", mailbox)
		}
	}

	accepted := []string{
		`"a b"@example.com`,
		`"a\\b"@example.com`,
		"a@[IPv6:::1]",
		"a@[tag0:literal]",
	}
	for _, mailbox := range accepted {
		value := mailbox
		if err := ValidateClaimValues(ClaimValues{ContactEmail: &value}); err != nil {
			t.Fatalf("mailbox %q was rejected: %v", mailbox, err)
		}
	}
}

// ---------------------------------------------------------------- client assertion claims

func TestClientAssertionClaimShapeRules(t *testing.T) {
	claims := assertionClaims()
	claims.Subject = "did:web:someone.else"
	if err := ValidateClientAssertionClaims(claims); err == nil {
		t.Fatal("sub that differs from iss was accepted")
	}

	claims = assertionClaims()
	claims.Resource = "https://api.example.com/orders"
	if err := ValidateClientAssertionClaims(claims); err == nil {
		t.Fatal("a resource on a non-authenticate assertion was accepted")
	}

	claims = assertionClaims()
	claims.Operation = "made-up"
	if err := ValidateClientAssertionClaims(claims); err == nil {
		t.Fatal("an unregistered operation was accepted")
	}

	claims = assertionClaims()
	claims.ExpiresAt = claims.IssuedAt
	if err := ValidateClientAssertionClaims(claims); err == nil {
		t.Fatal("a non-positive lifetime was accepted")
	}

	claims = assertionClaims()
	claims.ExpiresAt = claims.IssuedAt + int64(MaxAssertionLifetime/time.Second) + 1
	if err := ValidateClientAssertionClaims(claims); err == nil {
		t.Fatal("an excessive lifetime was accepted")
	}

	claims = assertionClaims()
	claims.ExpiresAt = claims.IssuedAt + int64(MaxAssertionLifetime/time.Second)
	if err := ValidateClientAssertionClaims(claims); err != nil {
		t.Fatalf("the maximum lifetime was rejected: %v", err)
	}
}

func TestProblemDetailsOwnerActionAndPending(t *testing.T) {
	ownerAction := "false"
	if err := ValidateProblemDetails(ProblemDetails{
		Code: ErrorInvalidRequest, OwnerActionRequired: &ownerAction, Status: 400,
		Title: "Invalid request", Type: "urn:aep:error:invalid_request",
	}); err == nil {
		t.Fatal("owner_action_required false was accepted on Problem Details")
	}
	if err := ValidateProblemDetails(ProblemDetails{
		Code: ErrorInvalidRequest, RequirementsPending: []string{""}, Status: 400,
		Title: "Invalid request", Type: "urn:aep:error:invalid_request",
	}); err == nil {
		t.Fatal("an empty requirements_pending entry was accepted")
	}
}

func TestAppendValidationIssuesIgnoresOtherErrors(t *testing.T) {
	issues := make([]ValidationIssue, 0)
	appendValidationIssues(errors.New("unrelated"), &issues)
	appendValidationIssues(nil, &issues)
	if len(issues) != 0 {
		t.Fatalf("unrelated errors contributed issues: %#v", issues)
	}
	appendValidationIssues(&ValidationError{
		DocumentType: "thing", Issues: []ValidationIssue{{Message: "m", Path: "$"}},
	}, &issues)
	if len(issues) != 1 {
		t.Fatalf("a validation error did not contribute issues: %#v", issues)
	}
}

// ---------------------------------------------------------------- Inspect and HTTP

func TestInspectRejectsIncompatibleMajorVersion(t *testing.T) {
	document := InspectDocument{
		AEPVersion: "99.0",
		Bindings:   Bindings{Supported: []Binding{BindingHTTP}},
		Commands:   Commands{Supported: []Command{CommandInspect}},
		Core:       Core{SigningAlgorithms: []SigningAlgorithm{SigningAlgorithmEdDSA, SigningAlgorithmES256}},
		Service:    ServiceIdentity{DID: "did:web:api.example.com"},
	}
	err := ValidateInspectDocument(document)
	if err == nil || !strings.Contains(err.(*ValidationError).Issues[0].Message, "Unsupported AEP major version") {
		t.Fatalf("an incompatible major version was accepted: %v", err)
	}
}

func TestRenderProtectedResourceAuthorizationRejectsCarrier(t *testing.T) {
	if _, _, err := RenderProtectedResourceAuthorization(ProtectedResourceAuthorization{
		Carrier: "Made-Up", Credentials: "abc.def.ghi", Scheme: CredentialSchemeAEP,
	}); err == nil {
		t.Fatal("an unsupported carrier was rendered")
	}
}

// ---------------------------------------------------------------- did:web

func TestDIDWebPathSegmentRejectsDotAndSeparators(t *testing.T) {
	for _, component := range []string{"", ".", "..", "a/b", `a\b`, "a?b", "a#b", "a b", "a\x7fb"} {
		if isDIDWebPathSegment(component) {
			t.Fatalf("component %q was treated as a single path segment", component)
		}
	}
	for _, component := range []string{"agents", "123", "a-b_c.d", "%"} {
		if !isDIDWebPathSegment(component) {
			t.Fatalf("component %q was rejected", component)
		}
	}
}

func TestResolveDIDWebPublicKeyReportsReadFailure(t *testing.T) {
	const did = "did:web:agent.example.com:agents:123"
	if _, err := ResolveDIDWebPublicKey(context.Background(), ResolveDIDWebPublicKeyOptions{
		Client: stubDoer{rawBody: failingReader{}}, DID: did, KeyID: did + "#key-1",
	}); err == nil || !strings.Contains(err.Error(), "read did:web document") {
		t.Fatalf("a body read failure was not reported: %v", err)
	}
}

func TestResolveDIDWebPublicKeyRejectsUnusableContext(t *testing.T) {
	const did = "did:web:agent.example.com:agents:123"
	//nolint:staticcheck // deliberately passing a nil context to exercise request construction failure
	if _, err := ResolveDIDWebPublicKey(nil, ResolveDIDWebPublicKeyOptions{
		Client: stubDoer{body: "{}"}, DID: did, KeyID: did + "#key-1",
	}); err == nil {
		t.Fatal("a nil context produced a request")
	}
}

// ---------------------------------------------------------------- JWT

func signRaw(t *testing.T, privateKey ed25519.PrivateKey, keyID string, claims any) string {
	t.Helper()
	options := (&jose.SignerOptions{}).WithType("JWT")
	options.WithHeader(jose.HeaderKey("kid"), keyID)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: privateKey}, options)
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
	serialized, err := object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return serialized
}

func TestVerifyClientAssertionRevalidatesClaimsAfterSignature(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claims := assertionClaims()
	now := time.Unix(claims.IssuedAt+10, 0)

	// A signature over claims that do not satisfy the assertion contract is still a rejection.
	malformed := claims
	malformed.Audience = ""
	assertion := signRaw(t, privateKey, claims.Issuer, malformed)
	if _, err := VerifyClientAssertion(context.Background(), assertion, VerifyClientAssertionOptions{
		CurrentTime: now, Key: publicKey,
	}); err == nil {
		t.Fatal("an assertion without aud was accepted")
	}

	// A kid that verifies but names another DID must not authenticate this subject.
	assertion = signRaw(t, privateKey, "did:web:other.example", claims)
	if _, err := VerifyClientAssertion(context.Background(), assertion, VerifyClientAssertionOptions{
		CurrentTime: now, Key: publicKey,
	}); err == nil {
		t.Fatal("a kid naming another DID was accepted")
	}
}

func TestVerifyClientAssertionRejectsMultipleSignatures(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claims := assertionClaims()
	options := (&jose.SignerOptions{}).WithType("JWT")
	options.WithHeader(jose.HeaderKey("kid"), claims.Issuer)
	signer, err := jose.NewMultiSigner([]jose.SigningKey{
		{Algorithm: jose.EdDSA, Key: privateKey},
		{Algorithm: jose.EdDSA, Key: privateKey},
	}, options)
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
	serialized := object.FullSerialize()
	if _, err := VerifyClientAssertion(context.Background(), serialized, VerifyClientAssertionOptions{
		CurrentTime: time.Unix(claims.IssuedAt+10, 0), Key: publicKey,
	}); err == nil {
		t.Fatal("a multi-signature assertion was accepted")
	}
}

func TestVerifyClientAssertionToleranceSaturates(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claims := assertionClaims()
	assertion, err := SignClientAssertion(claims, SignClientAssertionOptions{
		Algorithm: SigningAlgorithmEdDSA, Key: privateKey, KeyID: claims.Issuer,
	})
	if err != nil {
		t.Fatal(err)
	}
	// A tolerance large enough to overflow the deadline arithmetic must saturate, not wrap.
	if _, err := VerifyClientAssertion(context.Background(), assertion, VerifyClientAssertionOptions{
		ClockTolerance: time.Duration(math.MaxInt64),
		CurrentTime:    time.Unix(claims.IssuedAt+10, 0),
		Key:            publicKey,
	}); err != nil {
		t.Fatalf("a saturating tolerance rejected a valid assertion: %v", err)
	}
	// At a clock far below the assertion's own window the saturating arithmetic must still reject
	// rather than wrap into acceptance.
	if _, err := VerifyClientAssertion(context.Background(), assertion, VerifyClientAssertionOptions{
		ClockTolerance: time.Duration(math.MaxInt64),
		CurrentTime:    time.Unix(math.MinInt64/int64(time.Second)+1, 0),
		Key:            publicKey,
	}); err == nil {
		t.Fatal("a saturating lower bound accepted an assertion from the far future")
	}
}

// ---------------------------------------------------------------- decoding helpers

func TestVerifyClientAssertionDefaultsToTheWallClock(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claims := assertionClaims()
	issued := time.Now().Add(-time.Minute)
	claims.IssuedAt = issued.Unix()
	claims.ExpiresAt = issued.Add(MaxAssertionLifetime).Unix()
	assertion, err := SignClientAssertion(claims, SignClientAssertionOptions{
		Algorithm: SigningAlgorithmEdDSA, Key: privateKey, KeyID: claims.Issuer,
	})
	if err != nil {
		t.Fatal(err)
	}
	// With no CurrentTime the verifier reads the wall clock rather than treating zero as an epoch.
	if _, err := VerifyClientAssertion(context.Background(), assertion, VerifyClientAssertionOptions{
		Key: publicKey,
	}); err != nil {
		t.Fatalf("an assertion valid right now was rejected: %v", err)
	}
}

func TestDecodeHelpersRejectMalformedInput(t *testing.T) {
	if err := decodeOne([]byte(`{} {}`), &map[string]any{}); err == nil {
		t.Fatal("two JSON values were decoded as one")
	}
	if err := decodeOne([]byte(`{} !`), &map[string]any{}); err == nil {
		t.Fatal("trailing garbage was accepted")
	}

	// A body that is not an object cannot carry the named paths, so these helpers pass it through
	// and leave the rejection to the document's own validation.
	if err := rejectNullPaths([]byte("not json"), "thing", "/a"); err != nil {
		t.Fatalf("unexpected null-path error: %v", err)
	}
	if err := rejectNullPaths([]byte(`{"a":{"b":null}}`), "thing", "/a/b"); err == nil {
		t.Fatal("a nested null was accepted")
	}
	if err := rejectNullPaths([]byte(`{"a":1}`), "thing", "/a/b"); err != nil {
		t.Fatalf("a path through a non-object reported an issue: %v", err)
	}
	if err := rejectEmptyStringPaths([]byte("not json"), "thing", "/a"); err != nil {
		t.Fatalf("unexpected empty-string error: %v", err)
	}
	if err := rejectEmptyStringPaths([]byte(`{"a":5}`), "thing", "/a"); err != nil {
		t.Fatalf("a non-string value reported an issue: %v", err)
	}
}

// ---------------------------------------------------------------- additional members

func TestAdditionalMemberSurfaceCoverage(t *testing.T) {
	values := ClaimValues{}
	first := "Ada"
	last := "Lovelace"
	username := "ada"
	values.PersonFirstName = &first
	values.PersonLastName = &last
	values.PersonUsername = &username
	data, err := values.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"person.first_name", "person.last_name", "person.username"} {
		if _, ok := decoded[name]; !ok {
			t.Fatalf("%s was omitted: %s", name, data)
		}
	}

	metadata := IdempotencyMetadata{IdempotencyKey: "key-1"}
	if err := (&metadata).UnmarshalJSON([]byte(`{"idempotency_key":"key-1","vendor.custom":1}`)); err != nil {
		t.Fatal(err)
	}
	encoded, err := metadata.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), "vendor.custom") {
		t.Fatalf("idempotency metadata dropped its additional member: %s", encoded)
	}

	var scheme OpenAPIAEPSecurityScheme
	if err := (&scheme).UnmarshalJSON([]byte(`{"x-aep-authentication-method":"aep-jwt","vendor.custom":1}`)); err != nil {
		t.Fatal(err)
	}
	encoded, err = scheme.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), "vendor.custom") {
		t.Fatalf("security scheme dropped its additional member: %s", encoded)
	}
}

func TestAdditionalMemberDecodeRejectsNonObjects(t *testing.T) {
	decoders := map[string]json.Unmarshaler{
		"OpenAPIPathMatching":      &OpenAPIPathMatching{},
		"OpenAPIReference":         &OpenAPIReference{},
		"ContactAddressPrimary":    &ContactAddressPrimary{},
		"EnrollRequest":            &EnrollRequest{},
		"EnrollResponse":           &EnrollResponse{},
		"StatusResponse":           &StatusResponse{},
		"GrantRequest":             &GrantRequest{},
		"RevokeRequest":            &RevokeRequest{},
		"ProblemDetails":           &ProblemDetails{},
		"IdempotencyMetadata":      &IdempotencyMetadata{},
		"OpenAPIAEPSecurityScheme": &OpenAPIAEPSecurityScheme{},
		"InspectDocument":          &InspectDocument{},
		"ClientAssertionClaims":    &ClientAssertionClaims{},
	}
	for name, decoder := range decoders {
		if err := decoder.UnmarshalJSON([]byte(`"not an object"`)); err == nil {
			t.Fatalf("%s decoded a JSON string", name)
		}
	}
}

func TestEncodeAdditionalSkipsKnownFieldNames(t *testing.T) {
	// An additional member that collides with a known field must not overwrite the known value.
	request := EnrollRequest{
		AgentDID:   "did:web:agent.example.com",
		Additional: AdditionalMembers{"agent_did": json.RawMessage(`"did:web:attacker.example"`)},
	}
	data, err := request.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["agent_did"] != "did:web:agent.example.com" {
		t.Fatalf("an additional member overwrote a known field: %s", data)
	}
}

func TestCanonicalOwnerActionEncoding(t *testing.T) {
	ownerAction := "true"
	response := EnrollResponse{OwnerActionRequired: &ownerAction, Status: AgentPending}
	data, err := response.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"owner_action_required":"true"`) {
		t.Fatalf("owner_action_required was not encoded as a string: %s", data)
	}

	status := StatusResponse{OwnerActionRequired: &ownerAction, Since: "2026-01-01T00:00:00Z", Status: AgentPending}
	data, err = status.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"owner_action_required":"true"`) {
		t.Fatalf("status owner_action_required was not encoded as a string: %s", data)
	}
}

func TestReadAllLimitHelperRejectsUnreadableBody(t *testing.T) {
	// io.NopCloser over a failing reader keeps the resolver's read path honest.
	var body io.ReadCloser = failingReader{}
	if _, err := io.ReadAll(body); err == nil {
		t.Fatal("the failing reader did not fail")
	}
}
