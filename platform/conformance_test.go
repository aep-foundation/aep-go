package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	aep "github.com/aep-foundation/aep-go"
)

// newCountingPlatform builds a Platform whose identifier generators do not run out, for suites that
// provision more identities than the shared two-identifier harness supplies.
func newCountingPlatform(t *testing.T, hostedVerification bool) *Platform {
	t.Helper()
	options, _, _ := testOptions(t, hostedVerification)
	var mutex sync.Mutex
	counter := 0
	next := func(prefix string) func() (string, error) {
		return func() (string, error) {
			mutex.Lock()
			defer mutex.Unlock()
			counter++
			return fmt.Sprintf("%s%06d", prefix, counter), nil
		}
	}
	options.AgentDIDIDGenerator = next("DIDTEST")
	options.Identifier = next("01J0AEPPLATFORMTEST")
	platform, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	return platform
}

func TestCachedManagementResultsRequireCurrentAuthorization(t *testing.T) {
	instance, authorizer, keys := newTestPlatform(t, true)
	ctx := context.Background()
	provisionRequest := ProvisionRequest{ServiceDID: testServiceDID}
	provisioned, err := instance.Provision(ctx, provisionRequest, testRequestContext("provision"))
	if err != nil || provisioned.Problem != nil {
		t.Fatalf("Provision: %#v, %v", provisioned, err)
	}
	signRequest := SignRequest{JWTID: "retry", Operation: aep.AssertionEnroll, ServiceDID: testServiceDID}
	signed, err := instance.Sign(ctx, provisioned.Body.AgentIdentityID, signRequest, testRequestContext("sign"))
	if err != nil || signed.Problem != nil {
		t.Fatalf("Sign: %#v, %v", signed, err)
	}
	verifyRequest := VerificationRequest{ClientAssertion: signed.Body.ClientAssertion, Operation: aep.AssertionEnroll, ServiceDID: testServiceDID}
	verified, err := instance.Verify(ctx, verifyRequest, testRequestContext("verify"))
	if err != nil || !verified.Body.Verified {
		t.Fatalf("Verify: %#v, %v", verified, err)
	}
	created := keys.createdCount()
	authorizer.allowed = false
	deniedProvision, err := instance.Provision(ctx, provisionRequest, testRequestContext("provision"))
	if err != nil || deniedProvision.Status != http.StatusNotFound || deniedProvision.Body.AgentIdentityID != "" {
		t.Fatalf("cached Provision disclosed identity: %#v, %v", deniedProvision, err)
	}
	deniedSign, err := instance.Sign(ctx, provisioned.Body.AgentIdentityID, signRequest, testRequestContext("sign"))
	if err != nil || deniedSign.Status != http.StatusNotFound || deniedSign.Body.ClientAssertion != "" {
		t.Fatalf("cached Sign disclosed assertion: %#v, %v", deniedSign, err)
	}
	deniedVerify, err := instance.Verify(ctx, verifyRequest, testRequestContext("verify"))
	if err != nil || deniedVerify.Body.Verified || deniedVerify.Body.AgentDID != "" {
		t.Fatalf("cached Verify disclosed identity: %#v, %v", deniedVerify, err)
	}
	authorizer.allowed = true
	retriedProvision, err := instance.Provision(ctx, provisionRequest, testRequestContext("provision"))
	if err != nil || !equalJSON(retriedProvision, provisioned) || keys.createdCount() != created {
		t.Fatalf("authorized Provision retry changed result: %#v, %v", retriedProvision, err)
	}
	retriedSign, err := instance.Sign(ctx, provisioned.Body.AgentIdentityID, signRequest, testRequestContext("sign"))
	if err != nil || !equalJSON(retriedSign, signed) {
		t.Fatalf("authorized Sign retry changed result: %#v, %v", retriedSign, err)
	}
	retriedVerify, err := instance.Verify(ctx, verifyRequest, testRequestContext("verify"))
	if err != nil || !equalJSON(retriedVerify, verified) {
		t.Fatalf("authorized Verify retry consumed replay twice: %#v, %v", retriedVerify, err)
	}
	freshVerify, err := instance.Verify(ctx, verifyRequest, testRequestContext("fresh-verify"))
	if err != nil || freshVerify.Body.Verified {
		t.Fatalf("fresh verification accepted a consumed assertion: %#v, %v", freshVerify, err)
	}
}

func testRequestContext(key string) RequestContext {
	return RequestContext{IdempotencyKey: key, Now: testClock, Principal: testPrincipal}
}

func TestHostedVerificationAuthorizesServiceCaller(t *testing.T) {
	instance, authorizer, _ := newTestPlatform(t, true)
	authorizer.verifyPrincipal = "trusted-service"
	ctx := context.Background()
	identity := provisionedIdentity(t, instance, testServiceDID, "provision")
	signed, err := instance.Sign(ctx, identity.AgentIdentityID, SignRequest{
		JWTID: "service-verification", Operation: aep.AssertionEnroll, ServiceDID: testServiceDID,
	}, testRequestContext("sign"))
	if err != nil || signed.Problem != nil {
		t.Fatalf("sign: %#v, %v", signed, err)
	}
	request := VerificationRequest{ClientAssertion: signed.Body.ClientAssertion, Operation: aep.AssertionEnroll, ServiceDID: testServiceDID}
	caller := RequestContext{IdempotencyKey: "verify", Now: testClock, Principal: "trusted-service"}
	assertDenied := func(caller RequestContext) {
		t.Helper()
		result, err := instance.Verify(ctx, request, caller)
		if err != nil || result.Status != 200 || result.Problem != nil || result.Body.Verified || result.Body.Reason != "not_recognized" || result.Body.AgentDID != "" || result.Body.AgentIdentityID != "" || result.Body.Status != "" {
			t.Fatalf("verification disclosed identity: %#v, %v", result, err)
		}
	}
	unauthorized := caller
	unauthorized.Principal = "untrusted-service"
	assertDenied(unauthorized)
	verified, err := instance.Verify(ctx, request, caller)
	if err != nil || verified.Status != 200 || !verified.Body.Verified || verified.Body.AgentDID != identity.AgentDID {
		t.Fatalf("authorized Service could not verify: %#v, %v", verified, err)
	}
	assertDenied(unauthorized)
	authorizer.allowed = false
	assertDenied(caller)
	authorizer.allowed = true
	retried, err := instance.Verify(ctx, request, caller)
	if err != nil || !equalJSON(retried, verified) {
		t.Fatalf("authorized retry changed result: %#v, %v", retried, err)
	}
	// A different authorized caller cannot reuse another caller's cached acceptance.
	authorizer.verifyPrincipal = "second-trusted-service"
	otherCaller := caller
	otherCaller.Principal = authorizer.verifyPrincipal
	assertDenied(otherCaller)
	authorizer.verifyPrincipal = caller.Principal
	fresh := caller
	fresh.IdempotencyKey = "fresh-verification"
	assertDenied(fresh)

	identityResult, err := instance.GetIdentity(ctx, identity.AgentIdentityID, caller)
	if err != nil || identityResult.Status != 404 {
		t.Fatalf("verification caller accessed identity management: %#v, %v", identityResult, err)
	}
	signResult, err := instance.Sign(ctx, identity.AgentIdentityID, SignRequest{
		JWTID: "unauthorized-sign", Operation: aep.AssertionEnroll, ServiceDID: testServiceDID,
	}, caller)
	if err != nil || signResult.Status != 404 || signResult.Body.ClientAssertion != "" {
		t.Fatalf("verification caller could sign: %#v, %v", signResult, err)
	}
}

func provisionedIdentity(t *testing.T, platform *Platform, serviceDID string, key string) AgentIdentity {
	t.Helper()
	result, err := platform.Provision(context.Background(), ProvisionRequest{ServiceDID: serviceDID}, testRequestContext(key))
	if err != nil || result.Problem != nil {
		t.Fatalf("provisioning failed: %#v, %v", result, err)
	}
	return result.Body
}

// PLT-DISC-012 and PLT-DISC-013: a freshness lifetime is only half the caching contract. Without
// validators a client has nothing to revalidate with, so it cannot make the conditional request
// PLT-DISC-013 requires it to honour.
func TestDiscoveryCarriesFreshnessAndValidators(t *testing.T) {
	platform, _, _ := newTestPlatform(t, true)
	result := platform.Discovery()
	if result.Status != http.StatusOK || result.ContentType != aep.MediaType {
		t.Fatalf("unexpected Discovery result: %d %q", result.Status, result.ContentType)
	}
	if result.Headers.Get("Cache-Control") == "" {
		t.Fatal("PLT-DISC-012 requires Cache-Control on Discovery")
	}
	etag := result.Headers.Get("ETag")
	if !strings.HasPrefix(etag, `"sha256:`) || !strings.HasSuffix(etag, `"`) {
		t.Fatalf("PLT-DISC-012 requires an ETag on Discovery, got %q", etag)
	}
	modified := result.Headers.Get("Last-Modified")
	if _, err := time.Parse(http.TimeFormat, modified); err != nil {
		t.Fatalf("PLT-DISC-012 requires a usable Last-Modified on Discovery, got %q: %v", modified, err)
	}

	// The validator must describe the bytes a caller actually serializes, and must not drift
	// between calls for a document that never changes.
	encoded, err := json.Marshal(result.Body)
	if err != nil {
		t.Fatal(err)
	}
	if entityTag(encoded) != etag {
		t.Fatalf("the ETag does not identify the served document: %q", etag)
	}
	again := platform.Discovery()
	if again.Headers.Get("ETag") != etag || again.Headers.Get("Last-Modified") != modified {
		t.Fatalf("the Discovery validators are unstable: %v", again.Headers)
	}

	// Mutating the returned document must not reach the Platform's copy.
	result.Body.Platform.Name = "Impostor"
	result.Body.Signing.Algorithms[0] = aep.SigningAlgorithmEdDSA
	fresh := platform.Discovery()
	if fresh.Body.Platform.Name != "Example Platform" || fresh.Body.Signing.Algorithms[0] != aep.SigningAlgorithmES256 {
		t.Fatalf("the Discovery document is aliased: %#v", fresh.Body)
	}
}

// PLT-DISC-003, PLT-DISC-005..008 and PLT-DISC-011 fix the shape of the discovery document.
func TestDiscoveryDocumentShape(t *testing.T) {
	platform, _, _ := newTestPlatform(t, true)
	document := platform.Discovery().Body
	if document.AEPVersion != aep.Version {
		t.Fatalf("aep_version was %q", document.AEPVersion)
	}
	for name, path := range map[string]string{
		"endpoint_base":       document.HTTP.EndpointBase,
		"lifecycle":           document.Endpoints.Lifecycle,
		"list":                document.Endpoints.List,
		"provision":           document.Endpoints.Provision,
		"sign":                document.Endpoints.Sign,
		"hosted_verification": document.Endpoints.HostedVerification,
	} {
		if !strings.HasPrefix(path, "/") {
			t.Fatalf("PLT-DISC-011 requires %s to be an absolute path, got %q", name, path)
		}
	}
	if !document.Platform.HostedVerification {
		t.Fatal("PLT-VER-001 requires platform.hosted_verification to be true when the endpoint is advertised")
	}
	if !strings.HasPrefix(document.Platform.DID, "did:") {
		t.Fatalf("PLT-DISC-005 requires platform.did to be a DID, got %q", document.Platform.DID)
	}
	if !strings.HasPrefix(document.Identity.DIDURLTemplate, "https://") || !strings.Contains(document.Identity.DIDURLTemplate, "{agent_did_id}") {
		t.Fatalf("PLT-DISC-006 requires an HTTPS URL template, got %q", document.Identity.DIDURLTemplate)
	}
	lifetime, err := strconv.Atoi(document.Signing.DefaultLifetimeSeconds)
	if err != nil || lifetime < 1 || lifetime > 300 {
		t.Fatalf("PLT-DISC-008 constrains default_lifetime_seconds to a 1-300 JSON string, got %q", document.Signing.DefaultLifetimeSeconds)
	}
	for _, algorithm := range document.Signing.Algorithms {
		if algorithm != aep.SigningAlgorithmES256 && algorithm != aep.SigningAlgorithmEdDSA {
			t.Fatalf("PLT-DISC-007 requires core signing algorithms, got %q", algorithm)
		}
	}

	// PLT-VER-001 keeps the endpoint and the flag together in both directions.
	without, _, _ := newTestPlatform(t, false)
	plain := without.Discovery().Body
	if plain.Platform.HostedVerification || plain.Endpoints.HostedVerification != "" {
		t.Fatalf("hosted verification was advertised without support: %#v", plain.Platform)
	}
}

// PLT-DID-005 and PLT-DISC-006: a Service resolves the minted Agent DID as an ordinary did:web DID,
// so the advertised did_document_url has to name the place that resolution actually reaches.
func TestPublishedDIDURLMatchesDIDWebResolution(t *testing.T) {
	platform, _, _ := newTestPlatform(t, false)
	identity := provisionedIdentity(t, platform, testServiceDID, "provision-did-url")
	resolved, err := aep.DIDWebDocumentURL(identity.AgentDID)
	if err != nil {
		t.Fatalf("PLT-DID-005 requires the Agent DID to resolve as did:web: %v", err)
	}
	if identity.DIDDocumentURL != resolved.String() {
		t.Fatalf("did_document_url is %q where did:web resolution reaches %q", identity.DIDDocumentURL, resolved)
	}

	// A template that names anywhere else is a silent break for every Service, so it is refused at
	// construction rather than at the first handshake.
	for _, template := range []string{
		"https://platform.example.com/{agent_did_id}/did.json",
		"https://platform.example.com/agents/{agent_did_id}/document.json",
		"https://elsewhere.example/agents/{agent_did_id}/did.json",
		"https://platform.example.com/agents/{agent_did_id}",
	} {
		options, _, _ := testOptions(t, false)
		options.DIDURLTemplate = template
		if _, err := New(options); err == nil {
			t.Fatalf("a DID URL template that disagrees with did:web resolution was accepted: %s", template)
		}
	}

	// Moving the DID path prefix moves both sides together.
	options, _, _ := testOptions(t, false)
	options.DIDPathPrefix = "identities"
	options.DIDURLTemplate = "https://platform.example.com/identities/{agent_did_id}/did.json"
	moved, err := New(options)
	if err != nil {
		t.Fatalf("a consistent DID path prefix was refused: %v", err)
	}
	relocated := provisionedIdentity(t, moved, testServiceDID, "provision-relocated")
	relocatedURL, err := aep.DIDWebDocumentURL(relocated.AgentDID)
	if err != nil || relocated.DIDDocumentURL != relocatedURL.String() {
		t.Fatalf("relocated identity resolves to %q, published %q: %v", relocatedURL, relocated.DIDDocumentURL, err)
	}
}

// PLT-SIGN-021, PLT-SIGN-022 and PLT-SIGN-004 constrain the assertion the Platform produces.
func TestDelegatedSigningProducesAConformantAssertion(t *testing.T) {
	platform, _, _ := newTestPlatform(t, false)
	identity := provisionedIdentity(t, platform, testServiceDID, "provision-sign")
	if identity.KeyID != identity.AgentDID {
		t.Fatalf("PLT-SIGN-022 requires key_id to be the Service-scoped Agent DID, got %q", identity.KeyID)
	}
	request := SignRequest{
		JWTID: "jti-sign-1", Operation: aep.AssertionEnroll,
		PlatformContext: map[string]json.RawMessage{"tenant": json.RawMessage(`"acme"`)},
		ServiceDID:      testServiceDID,
	}
	result, err := platform.Sign(context.Background(), identity.AgentIdentityID, request, testRequestContext("sign-1"))
	if err != nil || result.Problem != nil || result.Body.Status != SignCompleted || result.Status != http.StatusOK {
		t.Fatalf("signing failed: %#v, %v", result, err)
	}
	decoded, err := aep.DecodeJWTUnverified(result.Body.ClientAssertion)
	if err != nil {
		t.Fatal(err)
	}
	keyID, _ := decoded.Header["kid"].(string)
	if keyID != identity.AgentDID || strings.Contains(keyID, "#") {
		t.Fatalf("PLT-SIGN-022 requires a bare Agent DID kid without a verification-method fragment, got %q", keyID)
	}
	if decoded.Payload["iss"] != identity.AgentDID || decoded.Payload["sub"] != identity.AgentDID {
		t.Fatalf("PLT-SIGN-021 requires iss and sub to be the Agent DID: %#v", decoded.Payload)
	}
	if decoded.Payload["aud"] != testServiceDID || decoded.Payload["op"] != string(aep.AssertionEnroll) {
		t.Fatalf("PLT-SIGN-021 requires aud to be the Service DID and op the requested operation: %#v", decoded.Payload)
	}
	for _, member := range []string{"platform_context", "tenant", "resource"} {
		if _, found := decoded.Payload[member]; found {
			t.Fatalf("PLT-SIGN-004 keeps %q out of the assertion claims: %#v", member, decoded.Payload)
		}
		if _, found := decoded.Header[member]; found {
			t.Fatalf("PLT-SIGN-004 keeps %q out of the assertion header: %#v", member, decoded.Header)
		}
	}
	// PLT-SIGN-018: the context returns to the caller unchanged even though it never signed anything.
	if string(result.Body.PlatformContext["tenant"]) != `"acme"` {
		t.Fatalf("PLT-SIGN-018 returns platform_context unchanged, got %#v", result.Body.PlatformContext)
	}
	// PLT-SIGN-019: nothing to return means the member is absent.
	plain, err := platform.Sign(context.Background(), identity.AgentIdentityID, SignRequest{
		JWTID: "jti-sign-2", Operation: aep.AssertionStatus, ServiceDID: testServiceDID,
	}, testRequestContext("sign-2"))
	if err != nil || plain.Problem != nil || plain.Body.PlatformContext != nil {
		t.Fatalf("PLT-SIGN-019 omits an empty platform_context: %#v, %v", plain, err)
	}
	encoded, err := json.Marshal(plain.Body)
	if err != nil || strings.Contains(string(encoded), "platform_context") || strings.Contains(string(encoded), "retry_after_seconds") {
		t.Fatalf("a completed response carried pending-only members: %s, %v", encoded, err)
	}
}

// PLT-SIGN-008, PLT-SIGN-009, PLT-SIGN-010 and PLT-DISC-009 bound the effective assertion lifetime.
func TestSigningLifetimeIsCanonicalAndBounded(t *testing.T) {
	platform, _, _ := newTestPlatform(t, false)
	identity := provisionedIdentity(t, platform, testServiceDID, "provision-lifetime")

	// The schema spells lifetime_seconds as plain decimal digits, so a signed or zero-padded
	// spelling of the same number is a second encoding of one value and is refused.
	for _, lifetime := range []string{"+60", "060", "0", "-60", " 60", "60 ", "60.0", "abc", "301", "1e2", ""} {
		if lifetime == "" {
			continue
		}
		result, err := platform.Sign(context.Background(), identity.AgentIdentityID, SignRequest{
			JWTID: "jti-" + lifetime, LifetimeSeconds: lifetime, Operation: aep.AssertionStatus, ServiceDID: testServiceDID,
		}, testRequestContext("lifetime-"+lifetime))
		if err != nil || result.Problem == nil || result.Problem.Code != aep.ErrorInvalidRequest || result.Status != http.StatusBadRequest {
			t.Fatalf("lifetime_seconds %q was accepted: %#v, %v", lifetime, result, err)
		}
	}

	for _, lifetime := range []string{"1", "60", "300"} {
		result, err := platform.Sign(context.Background(), identity.AgentIdentityID, SignRequest{
			JWTID: "jti-ok-" + lifetime, LifetimeSeconds: lifetime, Operation: aep.AssertionStatus, ServiceDID: testServiceDID,
		}, testRequestContext("lifetime-ok-"+lifetime))
		if err != nil || result.Problem != nil {
			t.Fatalf("lifetime_seconds %q was refused: %#v, %v", lifetime, result, err)
		}
		issuedAt, issuedErr := time.Parse(time.RFC3339, result.Body.IssuedAt)
		expiresAt, expiresErr := time.Parse(time.RFC3339, result.Body.ExpiresAt)
		seconds, _ := strconv.Atoi(lifetime)
		if issuedErr != nil || expiresErr != nil || expiresAt.Sub(issuedAt) != time.Duration(seconds)*time.Second {
			t.Fatalf("lifetime_seconds %q produced %s..%s: %v, %v", lifetime, result.Body.IssuedAt, result.Body.ExpiresAt, issuedErr, expiresErr)
		}
		if expiresAt.Sub(issuedAt) > aep.MaxAssertionLifetime {
			t.Fatalf("PLT-SIGN-010 caps the effective lifetime at 300 seconds, got %s", expiresAt.Sub(issuedAt))
		}
	}

	// PLT-SIGN-009: an omitted lifetime uses the advertised default.
	advertised, err := strconv.Atoi(platform.Discovery().Body.Signing.DefaultLifetimeSeconds)
	if err != nil {
		t.Fatal(err)
	}
	defaulted, err := platform.Sign(context.Background(), identity.AgentIdentityID, SignRequest{
		JWTID: "jti-default", Operation: aep.AssertionStatus, ServiceDID: testServiceDID,
	}, testRequestContext("lifetime-default"))
	if err != nil || defaulted.Problem != nil {
		t.Fatalf("a default lifetime was refused: %#v, %v", defaulted, err)
	}
	issuedAt, _ := time.Parse(time.RFC3339, defaulted.Body.IssuedAt)
	expiresAt, _ := time.Parse(time.RFC3339, defaulted.Body.ExpiresAt)
	if expiresAt.Sub(issuedAt) != time.Duration(advertised)*time.Second {
		t.Fatalf("PLT-SIGN-009 uses the advertised default, got %s for %d", expiresAt.Sub(issuedAt), advertised)
	}

	// PLT-SIGN-011: a shorter local maximum is enforced against the request.
	options, _, _ := testOptions(t, false)
	options.MaximumLifetime = 30 * time.Second
	options.DefaultLifetime = 30 * time.Second
	shorter, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	local := provisionedIdentity(t, shorter, testServiceDID, "provision-short")
	refused, err := shorter.Sign(context.Background(), local.AgentIdentityID, SignRequest{
		JWTID: "jti-short", LifetimeSeconds: "60", Operation: aep.AssertionStatus, ServiceDID: testServiceDID,
	}, testRequestContext("lifetime-short"))
	if err != nil || refused.Problem == nil || refused.Problem.Code != aep.ErrorInvalidRequest {
		t.Fatalf("a shorter local maximum was not enforced: %#v, %v", refused, err)
	}
}

// PLT-SIGN-012, PLT-SIGN-013 and PLT-SIGN-024: the request shape is checked before anything signs.
func TestSigningRequestShapeFailsClosed(t *testing.T) {
	platform, _, _ := newTestPlatform(t, false)
	identity := provisionedIdentity(t, platform, testServiceDID, "provision-shape")
	for _, test := range []struct {
		name    string
		request SignRequest
	}{
		{name: "authenticate without a resource", request: SignRequest{JWTID: "j", Operation: aep.AssertionAuthenticate, ServiceDID: testServiceDID}},
		{name: "authenticate with a plaintext resource", request: SignRequest{JWTID: "j", Operation: aep.AssertionAuthenticate, Resource: "http://api.service.example/x", ServiceDID: testServiceDID}},
		{name: "authenticate with a fragmented resource", request: SignRequest{JWTID: "j", Operation: aep.AssertionAuthenticate, Resource: "https://api.service.example/x#y", ServiceDID: testServiceDID}},
		{name: "authenticate with a credentialed resource", request: SignRequest{JWTID: "j", Operation: aep.AssertionAuthenticate, Resource: "https://user:pass@api.service.example/x", ServiceDID: testServiceDID}},
		{name: "enroll with a resource", request: SignRequest{JWTID: "j", Operation: aep.AssertionEnroll, Resource: "https://api.service.example/x", ServiceDID: testServiceDID}},
		{name: "unregistered operation", request: SignRequest{JWTID: "j", Operation: "inspect", ServiceDID: testServiceDID}},
		{name: "absent operation", request: SignRequest{JWTID: "j", ServiceDID: testServiceDID}},
		{name: "absent jti", request: SignRequest{Operation: aep.AssertionStatus, ServiceDID: testServiceDID}},
		{name: "service_did that is not a DID", request: SignRequest{JWTID: "j", Operation: aep.AssertionStatus, ServiceDID: "api.service.example"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := platform.Sign(context.Background(), identity.AgentIdentityID, test.request, testRequestContext("shape-"+test.name))
			if err != nil || result.Problem == nil || result.Problem.Code != aep.ErrorInvalidRequest || result.Status != http.StatusBadRequest {
				t.Fatalf("an invalid signing request was accepted: %#v, %v", result, err)
			}
		})
	}

	// PLT-SIGN-012: an accepted authenticate carries the resource into the assertion.
	resource := "https://api.service.example/private"
	result, err := platform.Sign(context.Background(), identity.AgentIdentityID, SignRequest{
		JWTID: "jti-authenticate", Operation: aep.AssertionAuthenticate, Resource: resource, ServiceDID: testServiceDID,
	}, testRequestContext("shape-authenticate"))
	if err != nil || result.Problem != nil {
		t.Fatalf("a well-formed authenticate request was refused: %#v, %v", result, err)
	}
	decoded, err := aep.DecodeJWTUnverified(result.Body.ClientAssertion)
	if err != nil || decoded.Payload["resource"] != resource {
		t.Fatalf("PLT-SIGN-012 carries resource into the assertion: %#v, %v", decoded.Payload, err)
	}
}

// PLT-LIFE-002 and PLT-SIGN-007: a Platform must not sign for a revoked, suspended, or terminated
// identity. A configured lifecycle policy narrows that rule; it cannot widen it.
func TestSigningRefusesNonActiveIdentitiesWhateverThePolicySays(t *testing.T) {
	for _, status := range []ManagedAgentStatus{ManagedAgentRevoked, ManagedAgentSuspended, ManagedAgentTerminated} {
		t.Run(string(status), func(t *testing.T) {
			options, _, _ := testOptions(t, true)
			options.LifecyclePolicy = testLifecyclePolicy{sign: true, transition: true, verify: true}
			platform, err := New(options)
			if err != nil {
				t.Fatal(err)
			}
			identity := provisionedIdentity(t, platform, testServiceDID, "provision-"+string(status))
			updated, err := platform.UpdateIdentity(context.Background(), identity.AgentIdentityID, LifecycleRequest{Status: status}, testRequestContext("update-"+string(status)))
			if err != nil || updated.Problem != nil || updated.Body.Status != status {
				t.Fatalf("the lifecycle transition failed: %#v, %v", updated, err)
			}
			result, err := platform.Sign(context.Background(), identity.AgentIdentityID, SignRequest{
				JWTID: "jti-" + string(status), Operation: aep.AssertionStatus, ServiceDID: testServiceDID,
			}, testRequestContext("sign-"+string(status)))
			if err != nil || result.Problem == nil || result.Status != http.StatusForbidden {
				t.Fatalf("a permissive policy signed for a %s identity: %#v, %v", status, result, err)
			}
			if result.Body.ClientAssertion != "" {
				t.Fatalf("PLT-SIGN-024 forbids producing an assertion here: %#v", result.Body)
			}
		})
	}
}

// PLT-SIGN-017: retry cadence is carried in the body, never in an HTTP Retry-After header, on any
// response this contract produces.
func TestSignHandlerResponsesAreValidated(t *testing.T) {
	identityID := ""
	for _, test := range []struct {
		name   string
		result Result[SignResponse]
	}{
		{name: "Retry-After on a pending response", result: Result[SignResponse]{
			Body: SignResponse{RetryAfterSeconds: "5", Status: SignPending}, ContentType: aep.MediaType,
			Headers: http.Header{"Retry-After": []string{"5"}}, Status: http.StatusAccepted,
		}},
		{name: "Retry-After on a completed response", result: Result[SignResponse]{
			Body: SignResponse{Status: SignCompleted}, ContentType: aep.MediaType,
			Headers: http.Header{"Retry-After": []string{"5"}}, Status: http.StatusOK,
		}},
		{name: "Retry-After on a Problem response", result: Result[SignResponse]{
			ContentType: aep.ProblemMediaType, Headers: http.Header{"Retry-After": []string{"5"}},
			Problem: problemPointer(aep.NewProblemDetails(aep.ErrorRateLimited, "Rate limited", http.StatusTooManyRequests)),
			Status:  http.StatusTooManyRequests,
		}},
		{name: "pending without a retry cadence", result: Result[SignResponse]{
			Body: SignResponse{Status: SignPending}, ContentType: aep.MediaType, Status: http.StatusAccepted,
		}},
		{name: "pending with a non-canonical cadence", result: Result[SignResponse]{
			Body: SignResponse{RetryAfterSeconds: "+5", Status: SignPending}, ContentType: aep.MediaType, Status: http.StatusAccepted,
		}},
		{name: "pending with a zero cadence", result: Result[SignResponse]{
			Body: SignResponse{RetryAfterSeconds: "0", Status: SignPending}, ContentType: aep.MediaType, Status: http.StatusAccepted,
		}},
		{name: "pending beyond the cadence ceiling", result: Result[SignResponse]{
			Body: SignResponse{RetryAfterSeconds: "301", Status: SignPending}, ContentType: aep.MediaType, Status: http.StatusAccepted,
		}},
		{name: "pending with the wrong status code", result: Result[SignResponse]{
			Body: SignResponse{RetryAfterSeconds: "5", Status: SignPending}, ContentType: aep.MediaType, Status: http.StatusOK,
		}},
		{name: "Problem whose status disagrees with its body", result: Result[SignResponse]{
			ContentType: aep.ProblemMediaType,
			Problem:     problemPointer(aep.NewProblemDetails(aep.ErrorRateLimited, "Rate limited", http.StatusTooManyRequests)),
			Status:      http.StatusOK,
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := test.result
			platform, _, _ := newTestPlatformWithHandler(t, func(_ context.Context, input SignHandlerInput, _ RequestContext) (*Result[SignResponse], error) {
				copy := response
				copy.Body.AgentDID = input.Identity.AgentDID
				copy.Body.JWTID = input.Request.JWTID
				copy.Body.ServiceDID = input.Request.ServiceDID
				return &copy, nil
			})
			identity := provisionedIdentity(t, platform, testServiceDID, "provision-handler")
			identityID = identity.AgentIdentityID
			if _, err := platform.Sign(context.Background(), identityID, SignRequest{
				JWTID: "jti-handler", Operation: aep.AssertionStatus, ServiceDID: testServiceDID,
			}, testRequestContext("handler-"+test.name)); err == nil {
				t.Fatalf("an invalid handler response was accepted: %#v", response)
			}
		})
	}

	// A well-formed pending response is returned as the handler wrote it.
	platform, _, _ := newTestPlatformWithHandler(t, func(_ context.Context, input SignHandlerInput, _ RequestContext) (*Result[SignResponse], error) {
		return &Result[SignResponse]{
			Body: SignResponse{
				PlatformContext:   map[string]json.RawMessage{"ticket": json.RawMessage(`"t-1"`)},
				RetryAfterSeconds: "5", ServiceDID: input.Request.ServiceDID, Status: SignPending,
			},
			ContentType: aep.MediaType, Status: http.StatusAccepted,
		}, nil
	})
	identity := provisionedIdentity(t, platform, testServiceDID, "provision-pending")
	pending, err := platform.Sign(context.Background(), identity.AgentIdentityID, SignRequest{
		JWTID: "jti-pending", Operation: aep.AssertionStatus, ServiceDID: testServiceDID,
	}, testRequestContext("handler-pending"))
	if err != nil || pending.Status != http.StatusAccepted || pending.Body.Status != SignPending || pending.Body.RetryAfterSeconds != "5" {
		t.Fatalf("PLT-SIGN-015 pending response was not preserved: %#v, %v", pending, err)
	}
	if pending.Headers.Get("Retry-After") != "" {
		t.Fatalf("PLT-SIGN-017 forbids a Retry-After header: %v", pending.Headers)
	}
	if string(pending.Body.PlatformContext["ticket"]) != `"t-1"` {
		t.Fatalf("PLT-SIGN-018 returns platform_context on a pending response: %#v", pending.Body.PlatformContext)
	}
}

func problemPointer(problem aep.ProblemDetails) *aep.ProblemDetails {
	return &problem
}

// PLT-PROV-008, PLT-PROV-011, PLT-PROV-012 and PLT-PRV-001: one Agent at two Services gets two
// unrelated DIDs sharing nothing but the Platform-controlled prefix.
func TestServiceScopedDIDsShareNoStructureBeyondThePlatformPrefix(t *testing.T) {
	platform, _, _ := newTestPlatform(t, false)
	first := provisionedIdentity(t, platform, testServiceDID, "provision-first")
	second := provisionedIdentity(t, platform, "did:web:other.service.example", "provision-second")
	if first.AgentDID == second.AgentDID || first.AgentIdentityID == second.AgentIdentityID {
		t.Fatalf("PLT-PROV-011 forbids reusing one Agent DID across Services: %q", first.AgentDID)
	}
	prefix := "did:web:platform.example.com:agents:"
	if !strings.HasPrefix(first.AgentDID, prefix) || !strings.HasPrefix(second.AgentDID, prefix) {
		t.Fatalf("unexpected DID shape: %q, %q", first.AgentDID, second.AgentDID)
	}
	firstSuffix := strings.TrimPrefix(first.AgentDID, prefix)
	secondSuffix := strings.TrimPrefix(second.AgentDID, prefix)
	if firstSuffix == secondSuffix {
		t.Fatal("PLT-PROV-012 requires the opaque components to differ")
	}
	for _, leak := range []string{testPrincipal, "service", "api", "other", "owner"} {
		if strings.Contains(strings.ToLower(firstSuffix), leak) || strings.Contains(strings.ToLower(secondSuffix), leak) {
			t.Fatalf("PLT-PROV-010 forbids revealing %q in the DID path component: %q, %q", leak, firstSuffix, secondSuffix)
		}
	}

	// PLT-PROV-008: the same Service DID resolves back to the same identity rather than minting one.
	repeated := provisionedIdentity(t, platform, testServiceDID, "provision-repeat")
	if repeated.AgentIdentityID != first.AgentIdentityID || repeated.AgentDID != first.AgentDID {
		t.Fatalf("a repeated provision minted a second identity: %#v", repeated)
	}
}

// PLT-IDP-003, PLT-IDP-005, PLT-IDP-007, PLT-IDP-008 and PLT-IDP-009 govern the idempotency record.
func TestPlatformIdempotencyScopingAndFingerprint(t *testing.T) {
	platform, _, keys := newTestPlatform(t, false)
	first := provisionedIdentity(t, platform, testServiceDID, "shared-key")
	minted := keys.createdCount()

	// PLT-IDP-005: an exact retry returns the stored result without minting anything.
	replayed, err := platform.Provision(context.Background(), ProvisionRequest{ServiceDID: testServiceDID}, testRequestContext("shared-key"))
	if err != nil || replayed.Problem != nil || !equalJSON(replayed.Body, first) || keys.createdCount() != minted {
		t.Fatalf("an exact retry was not replayed: %#v, %v", replayed, err)
	}

	// PLT-IDP-009: the same key with different material input conflicts.
	conflict, err := platform.Provision(context.Background(), ProvisionRequest{ServiceDID: "did:web:other.service.example"}, testRequestContext("shared-key"))
	if err != nil || conflict.Problem == nil || conflict.Problem.Code != aep.ErrorIdempotencyConflict || conflict.Status != http.StatusConflict {
		t.Fatalf("a changed body under one key did not conflict: %#v, %v", conflict, err)
	}

	// PLT-IDP-009: reuse for another operation conflicts too.
	signConflict, err := platform.Sign(context.Background(), first.AgentIdentityID, SignRequest{
		JWTID: "jti-conflict", Operation: aep.AssertionStatus, ServiceDID: testServiceDID,
	}, testRequestContext("shared-key"))
	if err != nil || signConflict.Problem == nil || signConflict.Problem.Code != aep.ErrorIdempotencyConflict {
		t.Fatalf("cross-operation key reuse did not conflict: %#v, %v", signConflict, err)
	}

	// PLT-IDP-003: another principal's use of the same key is independent.
	other := RequestContext{IdempotencyKey: "shared-key", Now: testClock, Principal: "owner-2"}
	independent, err := platform.Provision(context.Background(), ProvisionRequest{ServiceDID: "did:web:other.service.example"}, other)
	if err != nil || independent.Problem != nil || independent.Body.AgentIdentityID == first.AgentIdentityID {
		t.Fatalf("idempotency was not scoped by principal: %#v, %v", independent, err)
	}

	// PLT-IDP-008: the key itself and transport-only values stay out of the fingerprint, so a
	// different key over the same body is a fresh request rather than a conflict.
	fresh := RequestContext{Authorization: "Bearer other", IdempotencyKey: "another-key", Now: testClock, Principal: testPrincipal}
	again, err := platform.Provision(context.Background(), ProvisionRequest{ServiceDID: testServiceDID}, fresh)
	if err != nil || again.Problem != nil || again.Body.AgentIdentityID != first.AgentIdentityID {
		t.Fatalf("a second key over the same body did not resolve to the same identity: %#v, %v", again, err)
	}

	// PLT-SIGN-002, PLT-VER-002 and PLT-IDP-001: the header is required on every idempotent call.
	anonymous := RequestContext{Now: testClock, Principal: testPrincipal}
	for name, call := range map[string]func() (*aep.ProblemDetails, error){
		"provision": func() (*aep.ProblemDetails, error) {
			result, callErr := platform.Provision(context.Background(), ProvisionRequest{ServiceDID: testServiceDID}, anonymous)
			return result.Problem, callErr
		},
		"sign": func() (*aep.ProblemDetails, error) {
			result, callErr := platform.Sign(context.Background(), first.AgentIdentityID, SignRequest{
				JWTID: "jti-anonymous", Operation: aep.AssertionStatus, ServiceDID: testServiceDID,
			}, anonymous)
			return result.Problem, callErr
		},
	} {
		problem, callErr := call()
		if callErr != nil || problem == nil || problem.Code != aep.ErrorInvalidRequest {
			t.Fatalf("%s accepted a request without an Idempotency-Key: %#v, %v", name, problem, callErr)
		}
	}
}

// PLT-IDP-004: the replayable result survives at least an hour.
func TestPlatformIdempotencyRetainsResultsForAnHour(t *testing.T) {
	now := testClock
	store := newMemoryIdempotencyStore(func() time.Time { return now })
	input := IdempotencyInput{IdempotencyKey: "key", Operation: IdempotentProvision, Principal: testPrincipal, RequestHash: "abc"}
	execute := func() (StoredResponse, error) {
		return StoredResponse{Body: json.RawMessage(`{}`), ContentType: aep.MediaType, Status: http.StatusOK}, nil
	}
	if _, err := store.ExecuteIdempotent(context.Background(), input, execute); err != nil {
		t.Fatal(err)
	}
	now = testClock.Add(time.Hour - time.Second)
	replayed, err := store.ExecuteIdempotent(context.Background(), input, func() (StoredResponse, error) {
		t.Fatal("the record was discarded inside the retention window")
		return StoredResponse{}, nil
	})
	if err != nil || replayed.State != IdempotencyReplayed {
		t.Fatalf("unexpected replay state: %#v, %v", replayed, err)
	}
	now = testClock.Add(2 * time.Hour)
	expired, err := store.ExecuteIdempotent(context.Background(), input, execute)
	if err != nil || expired.State != IdempotencyCreated {
		t.Fatalf("an expired record was still replayed: %#v, %v", expired, err)
	}
}

// PLT-VER-004, PLT-VER-005, PLT-VER-006, PLT-VER-008, PLT-VER-009 and PLT-VER-010: hosted
// verification answers with one of two reasons and never discloses what it could not match.
func TestHostedVerificationRecognizesOnlyItsOwnLiveAssertions(t *testing.T) {
	platform, _, _ := newTestPlatform(t, true)
	identity := provisionedIdentity(t, platform, testServiceDID, "provision-verify")
	signed, err := platform.Sign(context.Background(), identity.AgentIdentityID, SignRequest{
		JWTID: "jti-verify", Operation: aep.AssertionStatus, ServiceDID: testServiceDID,
	}, testRequestContext("sign-verify"))
	if err != nil || signed.Problem != nil {
		t.Fatalf("signing failed: %#v, %v", signed, err)
	}
	assertion := signed.Body.ClientAssertion

	verified, err := platform.Verify(context.Background(), VerificationRequest{
		ClientAssertion: assertion, Operation: aep.AssertionStatus, ServiceDID: testServiceDID,
	}, testRequestContext("verify-1"))
	if err != nil || verified.Problem != nil || !verified.Body.Verified || verified.Body.Reason != "verified" {
		t.Fatalf("a live assertion was not recognized: %#v, %v", verified, err)
	}
	if verified.Body.AgentDID != identity.AgentDID || verified.Body.AgentIdentityID != identity.AgentIdentityID || verified.Body.Status != ManagedAgentActive {
		t.Fatalf("PLT-VER-008 identity metadata was incomplete: %#v", verified.Body)
	}

	// PLT-VER-005: the same assertion under a fresh idempotency key is a replay.
	replayed, err := platform.Verify(context.Background(), VerificationRequest{
		ClientAssertion: assertion, Operation: aep.AssertionStatus, ServiceDID: testServiceDID,
	}, testRequestContext("verify-2"))
	if err != nil || replayed.Body.Verified || replayed.Body.Reason != "not_recognized" {
		t.Fatalf("a replayed assertion was recognized: %#v, %v", replayed, err)
	}

	// PLT-VER-009 and PLT-VER-010: every other failure collapses to the same answer, and the
	// response never names the identity it declined to match.
	for _, test := range []struct {
		name    string
		request VerificationRequest
		context RequestContext
	}{
		{name: "another Service", request: VerificationRequest{ClientAssertion: assertion, Operation: aep.AssertionStatus, ServiceDID: "did:web:other.service.example"}},
		{name: "another operation", request: VerificationRequest{ClientAssertion: assertion, Operation: aep.AssertionGrant, ServiceDID: testServiceDID}},
		{name: "not a JWT", request: VerificationRequest{ClientAssertion: "opaque", Operation: aep.AssertionStatus, ServiceDID: testServiceDID}},
		{
			name:    "another principal",
			request: VerificationRequest{ClientAssertion: assertion, Operation: aep.AssertionStatus, ServiceDID: testServiceDID},
			context: RequestContext{IdempotencyKey: "verify-other", Now: testClock, Principal: "owner-2"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			requestContext := test.context
			if requestContext.Principal == "" {
				requestContext = testRequestContext("verify-" + test.name)
			}
			result, verifyErr := platform.Verify(context.Background(), test.request, requestContext)
			if verifyErr != nil || result.Problem != nil || result.Body.Verified || result.Body.Reason != "not_recognized" {
				t.Fatalf("an unverifiable assertion was recognized: %#v, %v", result, verifyErr)
			}
			if result.Body.AgentDID != "" || result.Body.AgentIdentityID != "" || result.Body.Status != "" {
				t.Fatalf("PLT-VER-009 leaked identity metadata: %#v", result.Body)
			}
		})
	}

	// PLT-VER-006 and PLT-VER-007: the resource rules mirror delegated signing.
	for _, request := range []VerificationRequest{
		{ClientAssertion: assertion, Operation: aep.AssertionAuthenticate, ServiceDID: testServiceDID},
		{ClientAssertion: assertion, Operation: aep.AssertionStatus, Resource: "https://api.service.example/x", ServiceDID: testServiceDID},
		{ClientAssertion: assertion, Operation: aep.AssertionAuthenticate, Resource: "http://api.service.example/x", ServiceDID: testServiceDID},
		{Operation: aep.AssertionStatus, ServiceDID: testServiceDID},
		{ClientAssertion: assertion, Operation: "inspect", ServiceDID: testServiceDID},
		{ClientAssertion: assertion, Operation: aep.AssertionStatus, ServiceDID: "api.service.example"},
	} {
		result, verifyErr := platform.Verify(context.Background(), request, testRequestContext("verify-shape"))
		if verifyErr != nil || result.Problem == nil || result.Problem.Code != aep.ErrorInvalidRequest {
			t.Fatalf("an invalid verification request was accepted: %#v, %v", result, verifyErr)
		}
	}
}

// PLT-LIFE-002 and PLT-VER-004: verification also checks the current lifecycle state, and the
// configured policy may only narrow that floor.
func TestHostedVerificationRefusesNonActiveIdentities(t *testing.T) {
	options, _, _ := testOptions(t, true)
	options.LifecyclePolicy = testLifecyclePolicy{sign: true, transition: true, verify: true}
	platform, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	identity := provisionedIdentity(t, platform, testServiceDID, "provision-suspend")
	signed, err := platform.Sign(context.Background(), identity.AgentIdentityID, SignRequest{
		JWTID: "jti-suspend", Operation: aep.AssertionStatus, ServiceDID: testServiceDID,
	}, testRequestContext("sign-suspend"))
	if err != nil || signed.Problem != nil {
		t.Fatalf("signing failed: %#v, %v", signed, err)
	}
	if _, err := platform.UpdateIdentity(context.Background(), identity.AgentIdentityID, LifecycleRequest{Status: ManagedAgentSuspended}, testRequestContext("update-suspend")); err != nil {
		t.Fatal(err)
	}
	result, err := platform.Verify(context.Background(), VerificationRequest{
		ClientAssertion: signed.Body.ClientAssertion, Operation: aep.AssertionStatus, ServiceDID: testServiceDID,
	}, testRequestContext("verify-suspend"))
	if err != nil || result.Body.Verified {
		t.Fatalf("a suspended identity verified under a permissive policy: %#v, %v", result, err)
	}
}

// PLT-VER-001: a Platform that does not offer hosted verification says so the same way it says
// anything else it will not answer.
func TestHostedVerificationIsRefusedWhenUnsupported(t *testing.T) {
	platform, _, _ := newTestPlatform(t, false)
	result, err := platform.Verify(context.Background(), VerificationRequest{
		ClientAssertion: "assertion", Operation: aep.AssertionStatus, ServiceDID: testServiceDID,
	}, testRequestContext("verify-unsupported"))
	if err != nil || result.Problem == nil || result.Problem.Code != aep.ErrorNotRecognized || result.Status != http.StatusNotFound {
		t.Fatalf("hosted verification answered without support: %#v, %v", result, err)
	}
}

// PLT-LIST-002, PLT-LIST-003, PLT-LIST-004, PLT-LIST-005 and PLT-LIST-006 describe the listing.
func TestListingIsDeterministicBoundedAndPrincipalScoped(t *testing.T) {
	platform := newCountingPlatform(t, false)
	first := provisionedIdentity(t, platform, testServiceDID, "list-1")
	second := provisionedIdentity(t, platform, "did:web:other.service.example", "list-2")
	stranger := RequestContext{IdempotencyKey: "list-3", Now: testClock, Principal: "owner-2"}
	if _, err := platform.Provision(context.Background(), ProvisionRequest{ServiceDID: testServiceDID}, stranger); err != nil {
		t.Fatal(err)
	}

	all, err := platform.List(context.Background(), IdentityListQuery{}, testRequestContext(""))
	if err != nil || all.Problem != nil {
		t.Fatalf("listing failed: %#v, %v", all, err)
	}
	if all.Body.Count != strconv.Itoa(len(all.Body.Data)) || all.Body.Total != "2" {
		t.Fatalf("PLT-LIST-006 count and total must be JSON strings over the caller's own records: %#v", all.Body)
	}
	for _, identity := range all.Body.Data {
		if identity.AgentIdentityID != first.AgentIdentityID && identity.AgentIdentityID != second.AgentIdentityID {
			t.Fatalf("PLT-LIST-005 returned another principal's identity: %#v", identity)
		}
	}

	// PLT-LIST-003: ordering is applied before offset and limit, and is stable across calls.
	ordered := []string{all.Body.Data[0].AgentIdentityID, all.Body.Data[1].AgentIdentityID}
	repeat, err := platform.List(context.Background(), IdentityListQuery{}, testRequestContext(""))
	if err != nil || repeat.Body.Data[0].AgentIdentityID != ordered[0] || repeat.Body.Data[1].AgentIdentityID != ordered[1] {
		t.Fatalf("listing order is unstable: %#v, %v", repeat.Body.Data, err)
	}
	page, err := platform.List(context.Background(), IdentityListQuery{Limit: 1, Offset: 1}, testRequestContext(""))
	if err != nil || len(page.Body.Data) != 1 || page.Body.Data[0].AgentIdentityID != ordered[1] || page.Body.Total != "2" {
		t.Fatalf("offset and limit were applied before ordering: %#v, %v", page.Body, err)
	}
	descending, err := platform.List(context.Background(), IdentityListQuery{Descending: true, Limit: 1}, testRequestContext(""))
	if err != nil || len(descending.Body.Data) != 1 || descending.Body.Data[0].AgentIdentityID != ordered[1] {
		t.Fatalf("descending order was not applied: %#v, %v", descending.Body, err)
	}
	beyond, err := platform.List(context.Background(), IdentityListQuery{Offset: 10}, testRequestContext(""))
	if err != nil || len(beyond.Body.Data) != 0 || beyond.Body.Count != "0" || beyond.Body.Total != "2" {
		t.Fatalf("an offset beyond the end returned %#v, %v", beyond.Body, err)
	}

	// PLT-LIST-002: the documented filters narrow the result.
	filtered, err := platform.List(context.Background(), IdentityListQuery{ServiceDID: testServiceDID}, testRequestContext(""))
	if err != nil || len(filtered.Body.Data) != 1 || filtered.Body.Data[0].AgentIdentityID != first.AgentIdentityID {
		t.Fatalf("service_did did not filter: %#v, %v", filtered.Body, err)
	}
	active, err := platform.List(context.Background(), IdentityListQuery{Status: ManagedAgentActive}, testRequestContext(""))
	if err != nil || len(active.Body.Data) != 2 {
		t.Fatalf("status did not filter: %#v, %v", active.Body, err)
	}
	revoked, err := platform.List(context.Background(), IdentityListQuery{Status: ManagedAgentRevoked}, testRequestContext(""))
	if err != nil || len(revoked.Body.Data) != 0 || revoked.Body.Total != "0" {
		t.Fatalf("status did not filter: %#v, %v", revoked.Body, err)
	}

	// PLT-LIST-004: the limit is bounded to protect availability.
	for _, query := range []IdentityListQuery{
		{Limit: maximumListLimit + 1}, {Limit: -1}, {Offset: -1},
		{ServiceDID: "not-a-did"}, {Status: "archived"},
	} {
		result, listErr := platform.List(context.Background(), query, testRequestContext(""))
		if listErr != nil || result.Problem == nil || result.Problem.Code != aep.ErrorInvalidRequest {
			t.Fatalf("an invalid list query was accepted: %#v, %#v", query, result)
		}
	}
}

// PLT-ERR-002, PLT-ERR-003, PLT-ERR-004 and PLT-ERR-005: a denied management operation is
// indistinguishable from one against an identity that does not exist, and leaves nothing behind.
func TestDeniedManagementOperationsAreIndistinguishableAndInert(t *testing.T) {
	platform, authorizer, keys := newTestPlatform(t, true)
	identity := provisionedIdentity(t, platform, testServiceDID, "provision-denied")
	minted := keys.createdCount()
	authorizer.allowed = false

	for name, call := range map[string]func(string) (int, *aep.ProblemDetails, error){
		"get": func(key string) (int, *aep.ProblemDetails, error) {
			result, err := platform.GetIdentity(context.Background(), identity.AgentIdentityID, testRequestContext(key))
			return result.Status, result.Problem, err
		},
		"list": func(key string) (int, *aep.ProblemDetails, error) {
			result, err := platform.List(context.Background(), IdentityListQuery{}, testRequestContext(key))
			return result.Status, result.Problem, err
		},
		"provision": func(key string) (int, *aep.ProblemDetails, error) {
			result, err := platform.Provision(context.Background(), ProvisionRequest{ServiceDID: "did:web:new.service.example"}, testRequestContext(key))
			return result.Status, result.Problem, err
		},
		"sign": func(key string) (int, *aep.ProblemDetails, error) {
			result, err := platform.Sign(context.Background(), identity.AgentIdentityID, SignRequest{
				JWTID: "jti-denied", Operation: aep.AssertionStatus, ServiceDID: testServiceDID,
			}, testRequestContext(key))
			return result.Status, result.Problem, err
		},
		"update": func(key string) (int, *aep.ProblemDetails, error) {
			result, err := platform.UpdateIdentity(context.Background(), identity.AgentIdentityID, LifecycleRequest{Status: ManagedAgentRevoked}, testRequestContext(key))
			return result.Status, result.Problem, err
		},
	} {
		status, problem, err := call("denied-" + name)
		if err != nil || problem == nil || status != http.StatusNotFound || problem.Code != aep.ErrorNotRecognized {
			t.Fatalf("%s did not fail closed: %d %#v, %v", name, status, problem, err)
		}
		if problem.Type != "urn:aep:error:not_recognized" || problem.Title == "" || problem.Status != http.StatusNotFound {
			t.Fatalf("PLT-ERR-002 and PLT-ERR-003 shape the Problem: %#v", problem)
		}
		if validateErr := aep.ValidateProblemDetails(*problem); validateErr != nil {
			t.Fatalf("%s returned an invalid Problem: %v", name, validateErr)
		}
	}
	if keys.createdCount() != minted {
		t.Fatal("PLT-ERR-005 requires a denied operation to produce no side effects")
	}

	// PLT-ERR-005: a missing authorizer is a construction error, never an implicit allow.
	options, _, _ := testOptions(t, false)
	options.Authorizer = nil
	if _, err := New(options); err == nil {
		t.Fatal("a Platform without an authorizer was constructed")
	}

	// An unknown identity answers exactly as a denied one does.
	authorizer.allowed = true
	unknown, err := platform.GetIdentity(context.Background(), "pai_absent", testRequestContext("unknown"))
	if err != nil || unknown.Problem == nil || unknown.Status != http.StatusNotFound || unknown.Problem.Code != aep.ErrorNotRecognized {
		t.Fatalf("an unknown identity answered differently: %#v, %v", unknown, err)
	}
	stranger := RequestContext{IdempotencyKey: "stranger", Now: testClock, Principal: "owner-2"}
	foreign, err := platform.GetIdentity(context.Background(), identity.AgentIdentityID, stranger)
	if err != nil || foreign.Problem == nil || foreign.Status != http.StatusNotFound {
		t.Fatalf("another principal read an identity: %#v, %v", foreign, err)
	}
}

// PLT-LIFE-001, PLT-LIFE-006, PLT-LIFE-007 and PLT-LIFE-008 describe the lifecycle surface.
func TestLifecycleSurfaceExposesAndUpdatesTheDefinedStates(t *testing.T) {
	platform, _, _ := newTestPlatform(t, false)
	identity := provisionedIdentity(t, platform, testServiceDID, "provision-lifecycle")
	fetched, err := platform.GetIdentity(context.Background(), identity.AgentIdentityID, testRequestContext("get"))
	if err != nil || fetched.Problem != nil || !equalJSON(fetched.Body, identity) {
		t.Fatalf("PLT-LIFE-006 must return the Agent identity object: %#v, %v", fetched, err)
	}
	for _, status := range []ManagedAgentStatus{ManagedAgentSuspended, ManagedAgentActive, ManagedAgentRevoked, ManagedAgentTerminated} {
		updated, updateErr := platform.UpdateIdentity(context.Background(), identity.AgentIdentityID, LifecycleRequest{Status: status}, testRequestContext("update"))
		if updateErr != nil || updated.Problem != nil || updated.Body.Status != status {
			t.Fatalf("PLT-LIFE-007 must accept %q: %#v, %v", status, updated, updateErr)
		}
		if updated.Body.AgentIdentityID != identity.AgentIdentityID || updated.Body.AgentDID != identity.AgentDID {
			t.Fatalf("PLT-LIFE-008 must return the updated identity object: %#v", updated.Body)
		}
	}
	for _, status := range []ManagedAgentStatus{"", "archived", "Active", "ACTIVE", "pending"} {
		result, updateErr := platform.UpdateIdentity(context.Background(), identity.AgentIdentityID, LifecycleRequest{Status: status}, testRequestContext("update"))
		if updateErr != nil || result.Problem == nil || result.Problem.Code != aep.ErrorInvalidRequest {
			t.Fatalf("PLT-LIFE-001 fixes the wire states; %q was accepted: %#v", status, result)
		}
	}
}

// PLT-DID-001, PLT-DID-002 and PLT-DID-006: the DID document is public, complete, and carries only
// public verification material. PLT-SEC-005 and PLT-SEC-007 keep private material off every surface.
func TestDIDDocumentIsPublicAndCarriesOnlyPublicMaterial(t *testing.T) {
	platform, authorizer, _ := newTestPlatform(t, false)
	identity := provisionedIdentity(t, platform, testServiceDID, "provision-did-document")
	record, err := platform.identityStore.FindIdentityByAgentDID(context.Background(), identity.AgentDID)
	if err != nil || record == nil {
		t.Fatalf("the provisioned identity is not indexed: %#v, %v", record, err)
	}

	// PLT-DID-006: resolution stays public even though every management call is authorized.
	authorizer.allowed = false
	result, err := platform.GetDIDDocument(context.Background(), record.AgentDIDID)
	if err != nil || result.Problem != nil || result.Status != http.StatusOK {
		t.Fatalf("DID document resolution required authorization: %#v, %v", result, err)
	}
	if result.ContentType != DIDMediaType {
		t.Fatalf("the DID document media type was %q", result.ContentType)
	}
	if result.Headers.Get("Cache-Control") == "" || result.Headers.Get("ETag") == "" {
		t.Fatalf("the DID document carried no caching metadata: %v", result.Headers)
	}
	document := result.Body
	if document.ID != identity.AgentDID || len(document.VerificationMethod) != 1 {
		t.Fatalf("PLT-DID-002 requires verification material for the Agent DID: %#v", document)
	}
	method := document.VerificationMethod[0]
	if method.ID != identity.KeyID || method.Controller != identity.AgentDID {
		t.Fatalf("PLT-SIGN-022 binds the verification method to the Agent DID: %#v", method)
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{`"d"`, `"p"`, `"q"`, "privateKey", "private_key"} {
		if strings.Contains(string(encoded), private) {
			t.Fatalf("PLT-SEC-005 forbids private material in a published document: %s", encoded)
		}
	}

	unknown, err := platform.GetDIDDocument(context.Background(), "absent")
	if err != nil || unknown.Problem == nil || unknown.Status != http.StatusNotFound || unknown.Problem.Code != aep.ErrorNotRecognized {
		t.Fatalf("an unknown DID answered %#v, %v", unknown, err)
	}
}

// PLT-PROV-006 and PLT-PROV-007: the Service DID is checked syntactically and then resolved.
func TestProvisioningValidatesAndResolvesTheServiceDID(t *testing.T) {
	platform, _, keys := newTestPlatform(t, false)
	for _, serviceDID := range []string{"", "api.service.example", "did:", "did:web", "did:web:", "did::x", "did:WEB:x", "https://api.service.example"} {
		result, err := platform.Provision(context.Background(), ProvisionRequest{ServiceDID: serviceDID}, testRequestContext("provision-invalid"))
		if err != nil || result.Problem == nil || result.Problem.Code != aep.ErrorInvalidRequest || result.Status != http.StatusBadRequest {
			t.Fatalf("service_did %q was accepted: %#v, %v", serviceDID, result, err)
		}
	}
	if keys.createdCount() != 0 {
		t.Fatal("a rejected provisioning request still minted a key")
	}

	options, _, unresolved := testOptions(t, false)
	options.ServiceDIDResolver = testDIDResolver{resolved: false}
	deferring, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	result, err := deferring.Provision(context.Background(), ProvisionRequest{ServiceDID: testServiceDID}, testRequestContext("provision-unresolved"))
	if err != nil || result.Problem == nil || result.Problem.Code != aep.ErrorInvalidRequest {
		t.Fatalf("PLT-PROV-007 requires resolution before first signing: %#v, %v", result, err)
	}
	if unresolved.createdCount() != 0 {
		t.Fatal("an unresolvable Service DID still minted a key")
	}
}

// PLT-PROV-015: the provisioning response is the Agent identity object, complete.
func TestProvisioningResponseCarriesEveryRequiredMember(t *testing.T) {
	platform, _, _ := newTestPlatform(t, false)
	identity := provisionedIdentity(t, platform, testServiceDID, "provision-shape")
	encoded, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &members); err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"agent_identity_id", "agent_did", "created_at", "did_document_url", "key_id", "service_did",
		"signing_algorithms", "status", "updated_at",
	} {
		if _, found := members[required]; !found {
			t.Fatalf("PLT-PROV-015 requires %q: %s", required, encoded)
		}
	}
	if _, err := time.Parse(time.RFC3339, identity.CreatedAt); err != nil {
		t.Fatalf("created_at is not RFC 3339: %q", identity.CreatedAt)
	}
	if _, err := time.Parse(time.RFC3339, identity.UpdatedAt); err != nil {
		t.Fatalf("updated_at is not RFC 3339: %q", identity.UpdatedAt)
	}
	if !strings.HasPrefix(identity.AgentIdentityID, "pai_") || identity.Status != ManagedAgentActive {
		t.Fatalf("unexpected identity: %#v", identity)
	}
}
