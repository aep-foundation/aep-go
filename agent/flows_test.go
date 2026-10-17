package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	aep "github.com/aep-foundation/aep-go"
)

type lifecycleFailingStore struct {
	CredentialStore
	failure               error
	operation             string
	saves, lists, deletes int
}

type failingIdentityStore struct {
	IdentityStore
	failure   error
	operation string
	saves     int
}

type failingInspectCache struct {
	InspectCache
	failure   error
	operation string
	entry     *InspectCacheEntry
}

type uncheckedCredentialStore struct {
	CredentialStore
	record CredentialRecord
	reads  *int
}

type interruptedResponseBody struct {
	failure error
	closed  bool
}

func (body *interruptedResponseBody) Read([]byte) (int, error) { return 0, body.failure }
func (body *interruptedResponseBody) Close() error             { body.closed = true; return nil }

func TestCommandTransportFailuresPreserveErrorsAndCloseBody(t *testing.T) {
	for _, mode := range []string{"transport", "read"} {
		t.Run(mode, func(t *testing.T) {
			stub := newServiceStub(t, nil)
			if _, err := stub.session.Identity(context.Background()); err != nil {
				t.Fatal(err)
			}
			failure := errors.New("connection interrupted")
			body := &interruptedResponseBody{failure: failure}
			calls := 0
			stub.client.commandHTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				if mode == "transport" {
					return nil, failure
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {aep.MediaType}}, Body: body}, nil
			})}
			result, err := stub.session.Status(context.Background())
			if !errors.Is(err, failure) || calls != 1 || result.Body.Status != "" || (mode == "read" && !body.closed) {
				t.Fatalf("failure lost: %#v %v calls=%d closed=%v", result, err, calls, body.closed)
			}
		})
	}
}

func TestInvalidEnrollmentClaimsStopBeforeCommand(t *testing.T) {
	stub := newServiceStub(t, nil)
	email := "not an email"
	_, err := stub.session.Enroll(context.Background(), EnrollOptions{Claims: &aep.ClaimValues{ContactEmail: &email}})
	if err == nil || len(stub.requests) != 0 {
		t.Fatalf("invalid claims reached Service: %v", err)
	}
}

func TestGrantSelectionAndIdentityFailuresDoNotIssueCredentials(t *testing.T) {
	for _, mode := range []string{"unsupported grant", "store error", "invalid identity", "inspect error"} {
		t.Run(mode, func(t *testing.T) {
			stub := newServiceStub(t, nil)
			identity, err := stub.session.Identity(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			options := GrantOptions{GrantType: aep.GrantTypeOAuthBearer}
			switch mode {
			case "unsupported grant":
				options.GrantType = "unknown"
			case "store error":
				stub.client.identityStore = &failingIdentityStore{IdentityStore: stub.client.identityStore, operation: "find", failure: errors.New("store unavailable")}
			case "invalid identity":
				identity.SigningAlgorithms = nil
				if err := stub.client.identityStore.SaveIdentity(context.Background(), identity); err != nil {
					t.Fatal(err)
				}
			case "inspect error":
				stub.client.inspectCache = &failingInspectCache{operation: "find", failure: errors.New("cache unavailable")}
			}
			_, err = stub.session.Grant(context.Background(), options)
			if err == nil || len(stub.requests) != 0 {
				t.Fatalf("invalid Grant prerequisite reached Service: %v", err)
			}
		})
	}
}

func TestInspectReadFailureAndNoStoreEvictionFailure(t *testing.T) {
	for _, mode := range []string{"read", "no-store eviction", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			stub := newServiceStub(t, nil)
			failure := errors.New("cache or transport failure")
			body := &interruptedResponseBody{failure: failure}
			stub.client.inspectHTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				if mode == "cancelled" {
					return nil, context.Canceled
				}
				var reader io.ReadCloser = body
				if mode != "read" {
					encoded, err := json.Marshal(stub.document)
					if err != nil {
						return nil, err
					}
					reader = io.NopCloser(strings.NewReader(string(encoded)))
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {aep.MediaType}, "Cache-Control": {"no-store"}}, Body: reader}, nil
			})}
			if mode == "no-store eviction" {
				stub.client.inspectCache = &failingInspectCache{InspectCache: stub.client.inspectCache, operation: "delete", failure: failure}
			}
			_, err := stub.session.Inspect(context.Background())
			if mode == "cancelled" {
				var inspectErr *InspectError
				if !errors.As(err, &inspectErr) || inspectErr.Code != InspectAborted {
					t.Fatalf("wrong cancellation: %v", err)
				}
				return
			}
			if !errors.Is(err, failure) || (mode == "read" && !body.closed) {
				t.Fatalf("lost error or body: %v closed=%v", err, body.closed)
			}
		})
	}
}

func TestInvalidCachedIdentityStopsIdentityAndAuthentication(t *testing.T) {
	for _, location := range []string{"session", "store"} {
		t.Run(location, func(t *testing.T) {
			stub := newServiceStub(t, nil)
			identity, err := stub.session.Identity(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			identity.SigningAlgorithms = nil
			if location == "session" {
				stub.session.identity = &identity
			} else {
				stub.session.identity = nil
				if err := stub.client.identityStore.SaveIdentity(context.Background(), identity); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := stub.session.Identity(context.Background()); err == nil {
				t.Fatal("accepted invalid cached identity")
			}
			if headers, err := stub.session.AuthenticationHeaders(context.Background(), AuthenticationOptions{ClientAssertionOnly: true, Resource: mustURL(t, stub.server.URL+"/resource")}); err == nil || len(headers) != 0 {
				t.Fatalf("signed with invalid identity: %v %v", headers, err)
			}
			if len(stub.requests) != 0 {
				t.Fatal("sent a command")
			}
		})
	}
}

func TestEmptyAssertionIdentifierStopsAuthentication(t *testing.T) {
	stub := newServiceStub(t, nil)
	stub.client.jti = func() (string, error) { return "", nil }
	headers, err := stub.session.AuthenticationHeaders(context.Background(), AuthenticationOptions{ClientAssertionOnly: true, Resource: mustURL(t, stub.server.URL+"/resource")})
	var validation *aep.ValidationError
	if !errors.As(err, &validation) || len(headers) != 0 {
		t.Fatalf("empty identifier reached signer: %v %v", headers, err)
	}
}

func TestInspectCacheRejectsMalformedAdditionalJSON(t *testing.T) {
	cache := NewMemoryInspectCache()
	entry := InspectCacheEntry{Document: testInspectDocument("did:web:service.example")}
	entry.Document.Additional = aep.AdditionalMembers{"extension": json.RawMessage(`{`)}
	if err := cache.SaveInspect(context.Background(), "key", entry); err == nil {
		t.Fatal("saved malformed JSON")
	}
	if found, err := cache.FindInspect(context.Background(), "key"); err != nil || found != nil {
		t.Fatalf("partial cache write: %#v %v", found, err)
	}
}

func TestInvalidFreshnessDoesNotKeepDocumentsFresh(t *testing.T) {
	now := time.Now()
	for _, cacheControl := range []string{"max-age=-1", "max-age=invalid", "max-age=9223372036854775807"} {
		if inspectCacheFresh(InspectCacheEntry{CacheControl: cacheControl, CachedAt: now}, now) {
			t.Fatalf("Inspect accepted %q", cacheControl)
		}
		if platformDiscoveryFresh(platformDiscoveryEntry{cacheControl: cacheControl, cachedAt: now}, now) {
			t.Fatalf("Platform accepted %q", cacheControl)
		}
	}
}

func TestPublicWorkflowErrorsExplainFailure(t *testing.T) {
	for _, test := range []struct {
		err  error
		want string
	}{
		{&CommandError{Status: 401, Text: "Authentication failed"}, "Authentication failed"},
		{&EnrollmentStateError{Status: aep.AgentSuspended}, "AEP Agent identity did not become active: suspended"},
		{&ClaimRequirementsError{MissingRequiredClaimNames: []aep.ClaimName{"contact.email", "person.name.given"}}, "AEP Agent cannot satisfy the Service's required Claim Names: contact.email, person.name.given"},
	} {
		if got := test.err.Error(); got != test.want {
			t.Fatalf("got %q, want %q", got, test.want)
		}
	}
}

func (store uncheckedCredentialStore) FindCredential(context.Context, string, string) (*CredentialRecord, error) {
	*store.reads++
	return &store.record, nil
}

func (store uncheckedCredentialStore) ListCredentials(context.Context, string) ([]CredentialRecord, error) {
	*store.reads++
	return []CredentialRecord{store.record}, nil
}

func TestCustomCredentialStoreCannotBypassSelectionValidation(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		for _, fault := range []string{"wrong service", "expired", "payload identifier", "excluded method"} {
			if !explicit && fault == "excluded method" {
				continue
			}
			t.Run(fmt.Sprintf("explicit=%v/%s", explicit, fault), func(t *testing.T) {
				stub := newServiceStub(t, nil)
				expiry := time.Date(2999, 1, 1, 0, 0, 0, 0, time.UTC)
				record := CredentialRecord{CredentialID: "credential", ServiceDID: stub.serviceDID, GrantType: aep.GrantTypeOAuthBearer, ExpiresAt: expiry, Payload: json.RawMessage(`{"credential_id":"credential","access_token":"secret","token_type":"Bearer","expires_at":"2999-01-01T00:00:00Z"}`)}
				options := AuthenticationOptions{Resource: mustURL(t, stub.server.URL+"/resource")}
				if explicit {
					options.CredentialID = "credential"
				}
				switch fault {
				case "wrong service":
					record.ServiceDID = "did:web:other.example"
				case "expired":
					record.ExpiresAt = time.Now().Add(-time.Hour)
				case "payload identifier":
					record.CredentialID = "different"
				case "excluded method":
					options.AllowedMethods = []aep.AuthenticationMethod{aep.AuthenticationMethodJWT}
				}
				reads := 0
				stub.client.credentialStore = uncheckedCredentialStore{CredentialStore: stub.client.credentialStore, record: record, reads: &reads}
				headers, err := stub.session.AuthenticationHeaders(context.Background(), options)
				if err == nil || reads != 1 || len(headers) != 0 || len(stub.requests) != 0 {
					t.Fatalf("invalid record escaped: headers=%v error=%v", headers, err)
				}
			})
		}
	}
}

func TestCredentialListPrunesExpiredAndOrdersStableIdentifiers(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	store := newMemoryCredentialStore(func() time.Time { return now })
	for _, id := range []string{"b", "a", "expired"} {
		expiry := now.Add(time.Hour)
		if id == "expired" {
			expiry = now.Add(time.Second)
		}
		payload, err := json.Marshal(aep.OAuthBearerGrantResponse{CredentialID: id, AccessToken: "secret", TokenType: "Bearer", ExpiresAt: expiry.Format(time.RFC3339)})
		if err != nil {
			t.Fatal(err)
		}
		if err := store.SaveCredential(context.Background(), CredentialRecord{CredentialID: id, GrantType: aep.GrantTypeOAuthBearer, Payload: payload, ExpiresAt: expiry, IssuedAt: now, ServiceDID: "did:web:service.example"}); err != nil {
			t.Fatal(err)
		}
	}
	now = now.Add(time.Second)
	listed, err := store.ListCredentials(context.Background(), "did:web:service.example")
	if err != nil || len(listed) != 2 || listed[0].CredentialID != "a" || listed[1].CredentialID != "b" {
		t.Fatalf("unexpected list: %#v %v", listed, err)
	}
	listed[0].Payload[0] = '!'
	found, err := store.FindCredential(context.Background(), "did:web:service.example", "a")
	if err != nil || found == nil || !json.Valid(found.Payload) {
		t.Fatal("caller mutation reached store")
	}
}

func TestAuthenticationPreparationFailuresDoNotReturnHeaders(t *testing.T) {
	for _, mode := range []string{"inspect", "signer lookup", "signing", "assertion identifier"} {
		t.Run(mode, func(t *testing.T) {
			stub := newServiceStub(t, nil)
			failure := errors.New("authentication dependency unavailable")
			switch mode {
			case "inspect":
				stub.client.inspectCache = &failingInspectCache{operation: "find", failure: failure}
			case "signer lookup":
				stub.client.identityProvider = failingIdentityProvider{signerErr: failure}
			case "signing":
				provider := newTestIdentityProvider(t)
				provider.signer = func(context.Context, aep.ClientAssertionClaims, []aep.SigningAlgorithm) (string, error) {
					return "", failure
				}
				stub.client.identityProvider = provider
			case "assertion identifier":
				stub.client.jti = func() (string, error) { return "", failure }
			}
			headers, err := stub.session.AuthenticationHeaders(context.Background(), AuthenticationOptions{ClientAssertionOnly: true, Resource: mustURL(t, stub.server.URL+"/private")})
			if !errors.Is(err, failure) || len(headers) != 0 || len(stub.requests) != 0 {
				t.Fatalf("failure was not contained: headers=%v requests=%d error=%v", headers, len(stub.requests), err)
			}
		})
	}
}

func TestDiscoveryFailureStopsIdentityAndCredentialDeletion(t *testing.T) {
	for _, operation := range []string{"identity", "forget"} {
		t.Run(operation, func(t *testing.T) {
			stub := newServiceStub(t, nil)
			failure := errors.New("discovery unavailable")
			stub.client.inspectCache = &failingInspectCache{operation: "find", failure: failure}
			store := &lifecycleFailingStore{CredentialStore: stub.client.credentialStore}
			stub.client.credentialStore = store
			var err error
			if operation == "identity" {
				_, err = stub.session.Identity(context.Background())
			} else {
				err = stub.session.ForgetCredential(context.Background(), "credential-1")
			}
			if !errors.Is(err, failure) || store.deletes != 0 || len(stub.requests) != 0 {
				t.Fatalf("discovery failure did not stop operation: deletes=%d requests=%d error=%v", store.deletes, len(stub.requests), err)
			}
		})
	}
}

func TestWaitForActiveDeadlineStopsPendingPolling(t *testing.T) {
	var calls atomic.Int32
	stub := newServiceStub(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/aep/status" {
			return false
		}
		calls.Add(1)
		w.Header().Set("Content-Type", aep.MediaType)
		_, _ = w.Write([]byte(`{"status":"pending"}`))
		return true
	})
	if _, err := stub.session.Identity(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, err := stub.session.WaitForActive(context.Background(), WaitOptions{Interval: time.Hour, Timeout: 100 * time.Millisecond})
	if !errors.Is(err, context.DeadlineExceeded) || calls.Load() != 1 {
		t.Fatalf("pending poll did not stop: calls=%d error=%v", calls.Load(), err)
	}
}

func (cache *failingInspectCache) FindInspect(ctx context.Context, key string) (*InspectCacheEntry, error) {
	if cache.operation == "find" {
		return nil, cache.failure
	}
	if cache.entry != nil {
		return cache.entry, nil
	}
	return cache.InspectCache.FindInspect(ctx, key)
}

func (cache *failingInspectCache) SaveInspect(ctx context.Context, key string, entry InspectCacheEntry) error {
	if cache.operation == "save" {
		return cache.failure
	}
	return cache.InspectCache.SaveInspect(ctx, key, entry)
}

func (cache *failingInspectCache) DeleteInspect(ctx context.Context, key string) error {
	if cache.operation == "delete" {
		return cache.failure
	}
	return cache.InspectCache.DeleteInspect(ctx, key)
}

func TestInspectCacheFailuresStopEnrollment(t *testing.T) {
	for _, mode := range []string{"find", "save", "invalid document", "fresh foreign URL", "stale foreign URL"} {
		t.Run(mode, func(t *testing.T) {
			stub := newServiceStub(t, nil)
			failure := errors.New("Inspect cache unavailable")
			cache := &failingInspectCache{InspectCache: NewMemoryInspectCache(), failure: failure, operation: mode}
			if mode != "find" && mode != "save" {
				cache.operation = "delete"
				cache.entry = &InspectCacheEntry{Document: stub.document, FinalURL: "https://other.example/.well-known/aep", CachedAt: time.Now(), CacheControl: "max-age=300"}
				if mode == "invalid document" {
					cache.entry.Document = aep.InspectDocument{}
				}
				if mode == "stale foreign URL" {
					cache.entry.CacheControl = "no-cache"
				}
			}
			stub.client.inspectCache = cache
			if _, err := stub.session.Enroll(context.Background(), EnrollOptions{}); !errors.Is(err, failure) {
				t.Fatalf("cache failure lost: %v", err)
			}
			if len(stub.requests) != 0 {
				t.Fatal("enrollment sent despite Inspect cache failure")
			}
			cache.operation = ""
			cache.entry = nil
			if _, err := stub.session.Enroll(context.Background(), EnrollOptions{}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func (store *failingIdentityStore) FindIdentity(ctx context.Context, did string) (*ServiceIdentity, error) {
	if store.operation == "find" {
		return nil, store.failure
	}
	return store.IdentityStore.FindIdentity(ctx, did)
}

func (store *failingIdentityStore) SaveIdentity(ctx context.Context, identity ServiceIdentity) error {
	store.saves++
	if store.operation == "save" {
		return store.failure
	}
	return store.IdentityStore.SaveIdentity(ctx, identity)
}

func TestIdentityStoreFailuresStopCommandsAndCanBeRetried(t *testing.T) {
	for _, operation := range []string{"identity", "enroll", "status", "authenticate", "revoke"} {
		for _, failurePoint := range []string{"find", "save"} {
			t.Run(operation+"/"+failurePoint, func(t *testing.T) {
				stub := newServiceStub(t, nil)
				failure := errors.New("identity storage unavailable")
				store := &failingIdentityStore{IdentityStore: NewMemoryIdentityStore(), failure: failure, operation: failurePoint}
				stub.client.identityStore = store
				provider := newTestIdentityProvider(t)
				stub.client.identityProvider = provider
				resource, err := url.Parse(stub.server.URL + "/resource")
				if err != nil {
					t.Fatal(err)
				}
				invoke := func() error {
					switch operation {
					case "identity":
						_, err := stub.session.Identity(context.Background())
						return err
					case "enroll":
						_, err := stub.session.Enroll(context.Background(), EnrollOptions{})
						return err
					case "status":
						_, err := stub.session.Status(context.Background())
						return err
					case "authenticate":
						_, err := stub.session.AuthenticationHeaders(context.Background(), AuthenticationOptions{ClientAssertionOnly: true, Resource: resource})
						return err
					default:
						_, err := stub.session.Revoke(context.Background(), RevokeOptions{AllGrantTypes: true})
						return err
					}
				}
				if err := invoke(); !errors.Is(err, failure) {
					t.Fatalf("storage error lost: %v", err)
				}
				if len(stub.requests) != 0 {
					t.Fatal("command sent despite identity storage failure")
				}
				wantCreated := int32(0)
				if failurePoint == "save" {
					wantCreated = 1
				}
				if provider.created.Load() != wantCreated {
					t.Fatalf("provider calls=%d want=%d", provider.created.Load(), wantCreated)
				}
				store.operation = ""
				if err := invoke(); err != nil {
					t.Fatalf("retry failed: %v", err)
				}
				stored, err := store.IdentityStore.FindIdentity(context.Background(), stub.serviceDID)
				if err != nil || stored == nil {
					t.Fatalf("retry did not persist identity: %v", err)
				}
			})
		}
	}
}

func (store *lifecycleFailingStore) SaveCredential(ctx context.Context, record CredentialRecord) error {
	store.saves++
	if store.operation == "save" {
		return store.failure
	}
	return store.CredentialStore.SaveCredential(ctx, record)
}

func (store *lifecycleFailingStore) ListCredentials(ctx context.Context, did string) ([]CredentialRecord, error) {
	store.lists++
	if store.operation == "list" {
		return nil, store.failure
	}
	return store.CredentialStore.ListCredentials(ctx, did)
}

func (store *lifecycleFailingStore) DeleteCredential(ctx context.Context, did, id string) error {
	store.deletes++
	if store.operation == "delete" {
		return store.failure
	}
	return store.CredentialStore.DeleteCredential(ctx, did, id)
}

func TestGrantStorageFailureIsReportedAfterOneRemoteGrant(t *testing.T) {
	var grants atomic.Int32
	stub := newServiceStub(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/aep/grant" {
			grants.Add(1)
		}
		return false
	})
	if _, err := stub.session.Enroll(context.Background(), EnrollOptions{}); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("credential database unavailable")
	store := &lifecycleFailingStore{CredentialStore: NewMemoryCredentialStore(), operation: "save", failure: failure}
	stub.client.credentialStore = store
	if _, err := stub.session.Grant(context.Background(), GrantOptions{GrantType: aep.GrantTypeOAuthBearer}); !errors.Is(err, failure) {
		t.Fatalf("%v", err)
	}
	if grants.Load() != 1 || store.saves != 1 {
		t.Fatalf("grants=%d saves=%d", grants.Load(), store.saves)
	}
	records, err := store.CredentialStore.ListCredentials(context.Background(), stub.serviceDID)
	if err != nil || len(records) != 0 {
		t.Fatalf("%v %v", records, err)
	}
}

func TestGrantRejectsInvalidResponsesWithoutSaving(t *testing.T) {
	for _, body := range []string{`{`, `null`, `[]`, `{"credential_id":"missing-token"}`, `{"access_token":"token","credential_id":"expired","expires_at":"2000-01-01T00:00:00Z","scopes":[],"token_type":"Bearer"}`} {
		t.Run(body, func(t *testing.T) {
			stub := newServiceStub(t, func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != "/aep/grant" {
					return false
				}
				w.Header().Set("Content-Type", aep.MediaType)
				w.Write([]byte(body))
				return true
			})
			if _, err := stub.session.Enroll(context.Background(), EnrollOptions{}); err != nil {
				t.Fatal(err)
			}
			store := &lifecycleFailingStore{CredentialStore: NewMemoryCredentialStore()}
			stub.client.credentialStore = store
			if _, err := stub.session.Grant(context.Background(), GrantOptions{GrantType: aep.GrantTypeOAuthBearer}); err == nil {
				t.Fatal("invalid Grant accepted")
			}
			if store.saves != 0 {
				t.Fatal("invalid credential reached store")
			}
		})
	}
}

func TestRevokeFailuresPreserveLocalCredentials(t *testing.T) {
	for _, mode := range []string{"remote", "list", "delete"} {
		t.Run(mode, func(t *testing.T) {
			var revokes atomic.Int32
			stub := newServiceStub(t, func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != "/aep/revoke" {
					return false
				}
				revokes.Add(1)
				if mode != "remote" {
					return false
				}
				w.WriteHeader(http.StatusServiceUnavailable)
				return true
			})
			if _, err := stub.session.Enroll(context.Background(), EnrollOptions{}); err != nil {
				t.Fatal(err)
			}
			if _, err := stub.session.Grant(context.Background(), GrantOptions{GrantType: aep.GrantTypeOAuthBearer}); err != nil {
				t.Fatal(err)
			}
			failure := errors.New("credential database unavailable")
			store := &lifecycleFailingStore{CredentialStore: stub.client.credentialStore, operation: mode, failure: failure}
			stub.client.credentialStore = store
			_, err := stub.session.Revoke(context.Background(), RevokeOptions{AllGrantTypes: true})
			if err == nil || mode != "remote" && !errors.Is(err, failure) {
				t.Fatalf("%v", err)
			}
			if revokes.Load() != 1 {
				t.Fatalf("remote revoke calls=%d", revokes.Load())
			}
			if mode == "remote" && (store.lists != 0 || store.deletes != 0) {
				t.Fatal("remote failure modified local state")
			}
			if mode == "list" && store.deletes != 0 {
				t.Fatal("listing failure attempted deletion")
			}
			if mode == "delete" && store.deletes != 1 {
				t.Fatal("delete failure was not exercised")
			}
			record, err := store.CredentialStore.FindCredential(context.Background(), stub.serviceDID, "cred-1")
			if err != nil || record == nil {
				t.Fatalf("credential lost: %v %v", record, err)
			}
		})
	}
}

func TestGrantAndRevokeStopBeforeSendingOnLocalFailure(t *testing.T) {
	for _, operation := range []string{"grant", "revoke"} {
		for _, failurePoint := range []string{"idempotency", "signer"} {
			t.Run(operation+"/"+failurePoint, func(t *testing.T) {
				stub := newServiceStub(t, nil)
				if _, err := stub.session.Enroll(context.Background(), EnrollOptions{}); err != nil {
					t.Fatal(err)
				}
				before := len(stub.requests)
				failure := errors.New("local dependency failed")
				if failurePoint == "idempotency" {
					stub.client.idempotencyKeys = stubIdempotencyKeys{err: failure}
				} else {
					provider := newTestIdentityProvider(t)
					provider.signer = func(context.Context, aep.ClientAssertionClaims, []aep.SigningAlgorithm) (string, error) {
						return "", failure
					}
					stub.client.identityProvider = provider
				}
				var err error
				if operation == "grant" {
					_, err = stub.session.Grant(context.Background(), GrantOptions{GrantType: aep.GrantTypeOAuthBearer})
				} else {
					_, err = stub.session.Revoke(context.Background(), RevokeOptions{AllGrantTypes: true})
				}
				if !errors.Is(err, failure) || len(stub.requests) != before {
					t.Fatalf("requests=%d before=%d err=%v", len(stub.requests), before, err)
				}
			})
		}
	}
}

func TestCustomGrantRequiresObjectAndPreservesPayload(t *testing.T) {
	for _, body := range []string{`null`, `[]`, `"token"`, `{`, `{"credential_id":"custom-id","opaque":{"value":"token"}}`} {
		t.Run(body, func(t *testing.T) {
			stub := newServiceStub(t, func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != "/aep/grant" {
					return false
				}
				w.Header().Set("Content-Type", aep.MediaType)
				w.Write([]byte(body))
				return true
			})
			stub.document.Commands.GrantTypes = []aep.GrantType{"custom-session"}
			stub.document.Commands.GrantTypesConfig = nil
			if _, err := stub.session.Enroll(context.Background(), EnrollOptions{}); err != nil {
				t.Fatal(err)
			}
			store := &lifecycleFailingStore{CredentialStore: NewMemoryCredentialStore()}
			stub.client.credentialStore = store
			result, err := stub.session.Grant(context.Background(), GrantOptions{GrantType: "custom-session"})
			valid := strings.HasPrefix(body, `{"credential_id"`)
			if valid && (err != nil || string(result.Body.Raw) != body || result.Body.Credential != nil) {
				t.Fatalf("%#v %v", result, err)
			}
			if !valid && err == nil {
				t.Fatal("non-object custom Grant accepted")
			}
			if store.saves != 0 {
				t.Fatal("custom payload treated as a built-in credential")
			}
		})
	}
}

// ---------------------------------------------------------------- credential lifecycle

func TestGrantStoresPresentsAndRevokesACredential(t *testing.T) {
	stub := newServiceStub(t, nil)
	if _, err := stub.session.Enroll(context.Background(), EnrollOptions{}); err != nil {
		t.Fatal(err)
	}

	granted, err := stub.session.Grant(context.Background(), GrantOptions{
		GrantType: aep.GrantTypeOAuthBearer, RequestedScopes: []string{"orders:read"},
	})
	if err != nil {
		t.Fatalf("Grant failed: %v", err)
	}
	if granted.Body.GrantType != aep.GrantTypeOAuthBearer || granted.Body.Credential == nil {
		t.Fatalf("unexpected Grant result: %#v", granted.Body)
	}

	// The stored credential is presented on a protected-resource request.
	headers, err := stub.session.AuthenticationHeaders(context.Background(), AuthenticationOptions{
		Resource: mustURL(t, stub.server.URL+"/orders"),
	})
	if err != nil || headers.Get("Authorization") != "Bearer t" {
		t.Fatalf("unexpected credential headers: %#v, %v", headers, err)
	}

	// Selecting it explicitly by identifier resolves the same credential.
	headers, err = stub.session.AuthenticationHeaders(context.Background(), AuthenticationOptions{
		CredentialID: "cred-1", Resource: mustURL(t, stub.server.URL+"/orders"),
	})
	if err != nil || headers.Get("Authorization") != "Bearer t" {
		t.Fatalf("unexpected selected credential headers: %#v, %v", headers, err)
	}

	// A grant type that does not match the stored credential is refused.
	if _, err := stub.session.AuthenticationHeaders(context.Background(), AuthenticationOptions{
		CredentialID: "cred-1", GrantType: aep.GrantTypeBasic,
		Resource: mustURL(t, stub.server.URL+"/orders"),
	}); err == nil {
		t.Fatal("a mismatched grant type selected the credential")
	}

	if _, err := stub.session.Revoke(context.Background(), RevokeOptions{
		GrantType: aep.GrantTypeOAuthBearer,
	}); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}

	// After Revoke the credential is gone and the Agent falls back to a client assertion.
	headers, err = stub.session.AuthenticationHeaders(context.Background(), AuthenticationOptions{
		Resource: mustURL(t, stub.server.URL+"/orders"),
	})
	if err != nil || !strings.HasPrefix(headers.Get("Authorization"), "AEP ") {
		t.Fatalf("expected a client assertion after Revoke: %#v, %v", headers, err)
	}
}

func TestRevokeAllGrantTypesClearsEveryCredential(t *testing.T) {
	stub := newServiceStub(t, nil)
	if _, err := stub.session.Enroll(context.Background(), EnrollOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := stub.session.Grant(context.Background(), GrantOptions{
		GrantType: aep.GrantTypeOAuthBearer,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := stub.session.Revoke(context.Background(), RevokeOptions{AllGrantTypes: true}); err != nil {
		t.Fatal(err)
	}
	records, err := stub.client.credentialStore.ListCredentials(context.Background(), stub.serviceDID)
	if err != nil || len(records) != 0 {
		t.Fatalf("credentials survived an all-grant-types Revoke: %#v, %v", records, err)
	}
}

func TestForgetCredentialRemovesAStoredRecord(t *testing.T) {
	stub := newServiceStub(t, nil)
	if _, err := stub.session.Enroll(context.Background(), EnrollOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := stub.session.Grant(context.Background(), GrantOptions{
		GrantType: aep.GrantTypeOAuthBearer,
	}); err != nil {
		t.Fatal(err)
	}
	if err := stub.session.ForgetCredential(context.Background(), "cred-1"); err != nil {
		t.Fatal(err)
	}
	found, err := stub.client.credentialStore.FindCredential(context.Background(), stub.serviceDID, "cred-1")
	if err != nil || found != nil {
		t.Fatalf("the credential survived ForgetCredential: %#v, %v", found, err)
	}
}

func TestGrantRejectsACredentialItCannotStore(t *testing.T) {
	stub := newServiceStub(t, func(response http.ResponseWriter, request *http.Request) bool {
		if request.URL.Path != "/aep/grant" {
			return false
		}
		response.Header().Set("Content-Type", aep.MediaType)
		// The payload's expiry disagrees with nothing, but the credential is already expired.
		_, _ = response.Write([]byte(`{"access_token":"t","credential_id":"cred-old","expires_at":"2000-01-01T00:00:00Z","scopes":[],"token_type":"Bearer"}`))
		return true
	})
	if _, err := stub.session.Enroll(context.Background(), EnrollOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := stub.session.Grant(context.Background(), GrantOptions{
		GrantType: aep.GrantTypeOAuthBearer,
	}); err == nil {
		t.Fatal("an already-expired credential was stored")
	}
}

func TestCustomGrantTypeIsReturnedRaw(t *testing.T) {
	stub := newServiceStub(t, func(response http.ResponseWriter, request *http.Request) bool {
		if request.URL.Path != "/aep/grant" {
			return false
		}
		response.Header().Set("Content-Type", aep.MediaType)
		_, _ = response.Write([]byte(`{"vendor_token":"v"}`))
		return true
	})
	stub.document.Commands.GrantTypes = []aep.GrantType{"vendor-token"}
	stub.document.Commands.GrantTypesConfig = nil
	if _, err := stub.session.Enroll(context.Background(), EnrollOptions{}); err != nil {
		t.Fatal(err)
	}
	result, err := stub.session.Grant(context.Background(), GrantOptions{GrantType: "vendor-token"})
	if err != nil {
		t.Fatalf("a custom grant type failed: %v", err)
	}
	if result.Body.Credential != nil || !strings.Contains(string(result.Body.Raw), "vendor_token") {
		t.Fatalf("unexpected custom grant result: %#v", result.Body)
	}

	// A custom grant type still has to answer with a JSON object.
	stub.requests = nil
	stub.server.Close()
}

func TestGrantSelectionPrefersTheCallerOrder(t *testing.T) {
	document := testInspectDocument("did:web:api.example.com")
	document.Commands.GrantTypes = []aep.GrantType{aep.GrantTypeOAuthBearer, aep.GrantTypeAPIKey}

	selected, err := selectGrantType(document, "", []aep.GrantType{aep.GrantTypeAPIKey})
	if err != nil || selected != aep.GrantTypeAPIKey {
		t.Fatalf("preference order ignored: %q, %v", selected, err)
	}
	selected, err = selectGrantType(document, "", nil)
	if err != nil || selected != aep.GrantTypeOAuthBearer {
		t.Fatalf("advertised order ignored: %q, %v", selected, err)
	}
	if _, err := selectGrantType(document, aep.GrantTypeBasic, nil); !errors.Is(err, ErrNoCompatibleGrantType) {
		t.Fatalf("an unadvertised selection was honoured: %v", err)
	}
	if _, err := selectGrantType(document, "", []aep.GrantType{aep.GrantTypeBasic}); !errors.Is(err, ErrNoCompatibleGrantType) {
		t.Fatalf("an unadvertised preference was honoured: %v", err)
	}
}

// ---------------------------------------------------------------- identity flow

func TestGrantRequiresAnExistingIdentity(t *testing.T) {
	stub := newServiceStub(t, nil)
	_, err := stub.session.Grant(context.Background(), GrantOptions{GrantType: aep.GrantTypeOAuthBearer})
	var commandErr *CommandError
	if !errors.As(err, &commandErr) || commandErr.Status != http.StatusUnauthorized {
		t.Fatalf("Grant created an identity: %v", err)
	}
}

func TestIdentityIsReusedAcrossCallsAndSessions(t *testing.T) {
	stub := newServiceStub(t, nil)
	first, err := stub.session.Identity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := stub.session.Identity(context.Background())
	if err != nil || second.AgentDID != first.AgentDID {
		t.Fatalf("identity changed between calls: %#v, %#v, %v", first, second, err)
	}

	other, err := stub.client.Service(stub.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	third, err := other.Identity(context.Background())
	if err != nil || third.AgentDID != first.AgentDID {
		t.Fatalf("a second session minted a new identity: %#v, %v", third, err)
	}
}

func TestIdentityProviderFailurePropagates(t *testing.T) {
	var document aep.InspectDocument
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", aep.MediaType)
		_ = json.NewEncoder(response).Encode(document)
	}))
	defer server.Close()
	document = testInspectDocument(didWebForServer(server.URL))

	client, err := New(Options{
		HTTPClient:       server.Client(),
		IdentityProvider: failingIdentityProvider{err: errors.New("provider unavailable")},
	})
	if err != nil {
		t.Fatal(err)
	}
	session, _ := client.Service(server.URL)
	if _, err := session.Identity(context.Background()); err == nil {
		t.Fatal("a failing identity provider was ignored")
	}

	client, err = New(Options{
		HTTPClient:       server.Client(),
		IdentityProvider: failingIdentityProvider{signerErr: errors.New("no signer")},
	})
	if err != nil {
		t.Fatal(err)
	}
	session, _ = client.Service(server.URL)
	if _, err := session.Enroll(context.Background(), EnrollOptions{}); err == nil {
		t.Fatal("a failing signer lookup was ignored")
	}
}

type failingIdentityProvider struct {
	err       error
	signerErr error
}

func (provider failingIdentityProvider) GetOrCreateIdentity(_ context.Context, request IdentityRequest) (ServiceIdentity, error) {
	if provider.err != nil {
		return ServiceIdentity{}, provider.err
	}
	return ServiceIdentity{
		AgentDID:          "did:web:agent.example:agents:1",
		IdentityMethod:    aep.IdentityMethodDIDWeb,
		ServiceDID:        request.ServiceDID,
		SigningAlgorithms: []aep.SigningAlgorithm{aep.SigningAlgorithmEdDSA},
	}, nil
}

func (provider failingIdentityProvider) SignerFor(context.Context, ServiceIdentity) (AssertionSigner, error) {
	return nil, provider.signerErr
}

// ---------------------------------------------------------------- Inspect flow

func TestInspectRejectsUnusableResponses(t *testing.T) {
	cases := map[string]func(*httptest.Server, http.ResponseWriter, *http.Request){
		"wrong media type": func(_ *httptest.Server, response http.ResponseWriter, _ *http.Request) {
			response.Header().Set("Content-Type", "text/plain")
			_, _ = response.Write([]byte("{}"))
		},
		"server error": func(_ *httptest.Server, response http.ResponseWriter, _ *http.Request) {
			response.WriteHeader(http.StatusInternalServerError)
		},
		"invalid JSON": func(_ *httptest.Server, response http.ResponseWriter, _ *http.Request) {
			response.Header().Set("Content-Type", aep.MediaType)
			_, _ = response.Write([]byte("{"))
		},
		"schema violation": func(_ *httptest.Server, response http.ResponseWriter, _ *http.Request) {
			response.Header().Set("Content-Type", aep.MediaType)
			_, _ = response.Write([]byte(`{"aep_version":"1.0"}`))
		},
		"304 without a cached document": func(_ *httptest.Server, response http.ResponseWriter, _ *http.Request) {
			response.WriteHeader(http.StatusNotModified)
		},
		"redirect without Location": func(_ *httptest.Server, response http.ResponseWriter, _ *http.Request) {
			response.WriteHeader(http.StatusFound)
		},
		"cross-origin redirect": func(_ *httptest.Server, response http.ResponseWriter, request *http.Request) {
			http.Redirect(response, request, "https://evil.example/.well-known/aep", http.StatusFound)
		},
	}
	for name, respond := range cases {
		var server *httptest.Server
		server = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			respond(server, response, request)
		}))
		client := testClient(t, server, newTestIdentityProvider(t))
		session, err := client.Service(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := session.Inspect(context.Background()); err == nil {
			t.Fatalf("%s was accepted", name)
		}
		server.Close()
	}
}

func TestInspectRejectsAnOversizedDocument(t *testing.T) {
	var document aep.InspectDocument
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", aep.MediaType)
		_ = json.NewEncoder(response).Encode(document)
	}))
	defer server.Close()
	document = testInspectDocument(didWebForServer(server.URL))

	client, err := New(Options{
		HTTPClient: server.Client(), IdentityProvider: newTestIdentityProvider(t), MaximumResponseBytes: 32,
	})
	if err != nil {
		t.Fatal(err)
	}
	session, _ := client.Service(server.URL)
	_, err = session.Inspect(context.Background())
	var inspectErr *InspectError
	if !errors.As(err, &inspectErr) || inspectErr.Code != InspectResponseTooLarge {
		t.Fatalf("an oversized Inspect document was accepted: %v", err)
	}
}

func TestInspectExceedsRedirectBudget(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, server.URL+aep.WellKnownPath+"?hop", http.StatusFound)
	}))
	defer server.Close()
	client := testClient(t, server, newTestIdentityProvider(t))
	session, _ := client.Service(server.URL)
	_, err := session.Inspect(context.Background())
	var inspectErr *InspectError
	if !errors.As(err, &inspectErr) || inspectErr.Code != InspectInvalidRedirect {
		t.Fatalf("the redirect budget was not enforced: %v", err)
	}
}

func TestInspectSurfacesContextCancellation(t *testing.T) {
	var document aep.InspectDocument
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", aep.MediaType)
		_ = json.NewEncoder(response).Encode(document)
	}))
	defer server.Close()
	document = testInspectDocument(didWebForServer(server.URL))
	client := testClient(t, server, newTestIdentityProvider(t))
	session, _ := client.Service(server.URL)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := session.Inspect(ctx)
	var inspectErr *InspectError
	if !errors.As(err, &inspectErr) || inspectErr.Code != InspectAborted {
		t.Fatalf("a cancelled Inspect was not reported as aborted: %v", err)
	}
}

func TestInspectErrorUnwrapsItsCause(t *testing.T) {
	cause := errors.New("underlying")
	err := inspectError(InspectHTTPError, 500, "fetch", cause)
	if !errors.Is(err, cause) {
		t.Fatal("the inspect error did not unwrap its cause")
	}
	var inspectErr *InspectError
	if !errors.As(err, &inspectErr) || !strings.Contains(inspectErr.Error(), "fetch") {
		t.Fatalf("unexpected inspect error: %v", err)
	}
	bare := &InspectError{Code: InspectHTTPError, Text: "plain"}
	if bare.Unwrap() != nil || bare.Error() != "plain" {
		t.Fatalf("unexpected bare inspect error: %v", bare)
	}
}

func TestInspectionCommandURLRejectsUnknownCommands(t *testing.T) {
	stub := newServiceStub(t, nil)
	inspection, err := stub.session.Inspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inspection.CommandURL(aep.CommandInspect); err == nil {
		t.Fatal("Inspect produced a command URL")
	}
	commandURL, err := inspection.CommandURL(aep.CommandEnroll)
	if err != nil || !strings.HasSuffix(commandURL.Path, "/aep/enroll") {
		t.Fatalf("unexpected command URL: %v, %v", commandURL, err)
	}
}

// ---------------------------------------------------------------- stores

func TestMemoryCredentialStoreRejectsUnusableRecords(t *testing.T) {
	store := NewMemoryCredentialStore()
	if err := store.SaveCredential(context.Background(), CredentialRecord{}); err == nil {
		t.Fatal("an empty record was stored")
	}
	if err := store.SaveCredential(context.Background(), CredentialRecord{
		CredentialID: "cred-1", ExpiresAt: time.Now().Add(time.Hour),
		GrantType: aep.GrantTypeOAuthBearer, Payload: json.RawMessage("{"),
		ServiceDID: "did:web:api.example.com",
	}); err == nil {
		t.Fatal("a malformed payload was stored")
	}
}

func TestMemoryCredentialStoreExpiresRecordsOnRead(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := now
	store := newMemoryCredentialStore(func() time.Time { return clock })

	expiry := now.Add(time.Hour)
	payload := `{"access_token":"t","credential_id":"cred-1","expires_at":"` +
		expiry.Format(time.RFC3339) + `","scopes":[],"token_type":"Bearer"}`
	record := CredentialRecord{
		CredentialID: "cred-1", ExpiresAt: expiry, GrantType: aep.GrantTypeOAuthBearer,
		IssuedAt: now, Payload: json.RawMessage(payload), ServiceDID: "did:web:api.example.com",
	}
	if err := store.SaveCredential(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if found, err := store.FindCredential(context.Background(), record.ServiceDID, "cred-1"); err != nil || found == nil {
		t.Fatalf("a live credential was not found: %#v, %v", found, err)
	}

	clock = expiry.Add(time.Second)
	if found, err := store.FindCredential(context.Background(), record.ServiceDID, "cred-1"); err != nil || found != nil {
		t.Fatalf("an expired credential was returned: %#v, %v", found, err)
	}
	listed, err := store.ListCredentials(context.Background(), record.ServiceDID)
	if err != nil || len(listed) != 0 {
		t.Fatalf("an expired credential was listed: %#v, %v", listed, err)
	}
	if found, err := store.FindCredential(context.Background(), record.ServiceDID, "absent"); err != nil || found != nil {
		t.Fatalf("an absent credential was returned: %#v, %v", found, err)
	}
}

func TestMemoryInspectCacheRoundTrip(t *testing.T) {
	cache := NewMemoryInspectCache()
	entry := InspectCacheEntry{
		CachedAt: time.Now(),
		Document: testInspectDocument("did:web:api.example.com"),
		ETag:     `"a"`,
		FinalURL: "https://api.example.com/.well-known/aep",
	}
	if err := cache.SaveInspect(context.Background(), "key", entry); err != nil {
		t.Fatal(err)
	}
	found, err := cache.FindInspect(context.Background(), "key")
	if err != nil || found == nil || found.ETag != `"a"` {
		t.Fatalf("the entry did not round trip: %#v, %v", found, err)
	}
	if err := cache.DeleteInspect(context.Background(), "key"); err != nil {
		t.Fatal(err)
	}
	found, err = cache.FindInspect(context.Background(), "key")
	if err != nil || found != nil {
		t.Fatalf("a deleted entry was returned: %#v, %v", found, err)
	}
}

func TestCredentialRecordRejectsUnusableCredentials(t *testing.T) {
	inspection := Inspection{
		Document:   aep.InspectDocument{Service: aep.ServiceIdentity{DID: "did:web:api.example.com"}},
		ServiceURL: mustURL(t, "https://api.example.com/"),
	}
	if _, err := credentialRecord(nil, nil, inspection, time.Now()); err == nil {
		t.Fatal("a nil credential produced a record")
	}
	if _, err := credentialRecord(
		aep.OAuthBearerGrantResponse{CredentialID: "cred-1", ExpiresAt: "soon"},
		json.RawMessage("{}"), inspection, time.Now(),
	); err == nil {
		t.Fatal("an unparseable expiry produced a record")
	}
	record, err := credentialRecord(
		aep.APIKeyGrantResponse{CredentialID: "cred-1", ExpiresAt: "2999-01-01T00:00:00Z"},
		json.RawMessage("{}"), inspection, time.Now(),
	)
	if err != nil || record.GrantType != aep.GrantTypeAPIKey {
		t.Fatalf("unexpected API-key record: %#v, %v", record, err)
	}
	record, err = credentialRecord(
		aep.BasicGrantResponse{CredentialID: "cred-1", ExpiresAt: "2999-01-01T00:00:00Z"},
		json.RawMessage("{}"), inspection, time.Now(),
	)
	if err != nil || record.GrantType != aep.GrantTypeBasic {
		t.Fatalf("unexpected Basic record: %#v, %v", record, err)
	}
}

func TestCredentialAccessorsCoverEveryGrantType(t *testing.T) {
	credentials := []aep.BuiltInGrantResponse{
		aep.OAuthBearerGrantResponse{CredentialID: "a", ExpiresAt: "1"},
		aep.APIKeyGrantResponse{CredentialID: "b", ExpiresAt: "2"},
		aep.BasicGrantResponse{CredentialID: "c", ExpiresAt: "3"},
	}
	for index, credential := range credentials {
		if credentialID(credential) == "" || credentialExpiresAt(credential) == "" {
			t.Fatalf("credential %d exposed no identifier or expiry", index)
		}
	}
	if credentialID(nil) != "" || credentialExpiresAt(nil) != "" {
		t.Fatal("a nil credential exposed values")
	}
}

func TestAuthenticationMethodHelpers(t *testing.T) {
	methods := []aep.AuthenticationMethod{"api-key", aep.AuthenticationMethodJWT}
	if authenticationMethodIndex(methods, aep.AuthenticationMethodJWT) != 1 {
		t.Fatal("method index lookup is wrong")
	}
	if authenticationMethodIndex(methods, "absent") != -1 {
		t.Fatal("an absent method reported an index")
	}
	if authenticationMethods(aep.InspectDocument{}) != nil {
		t.Fatal("an absent authentication block produced methods")
	}
	if !containsIdentityMethod([]aep.IdentityMethod{aep.IdentityMethodDIDWeb}, aep.IdentityMethodDIDWeb) {
		t.Fatal("identity method lookup is wrong")
	}
	if containsIdentityMethod(nil, aep.IdentityMethodDIDWeb) {
		t.Fatal("an empty list contained a method")
	}
}

func TestWaitForActiveRejectsUnusableIntervals(t *testing.T) {
	stub := newServiceStub(t, nil)
	if _, err := stub.session.WaitForActive(context.Background(), WaitOptions{Interval: -time.Second}); err == nil {
		t.Fatal("a negative interval was accepted")
	}
	if _, err := stub.session.WaitForActive(context.Background(), WaitOptions{Timeout: -time.Second}); err == nil {
		t.Fatal("a negative timeout was accepted")
	}
	result, err := stub.session.WaitForActive(context.Background(), WaitOptions{})
	if err != nil || result.Body.Status != aep.AgentActive {
		t.Fatalf("an active Service did not settle: %#v, %v", result.Body, err)
	}
}
