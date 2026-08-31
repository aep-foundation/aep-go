package platform

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	aep "github.com/aep-foundation/aep-go"
)

func TestMemoryIdentityStore(t *testing.T) {
	store := NewMemoryIdentityStore()
	ctx := context.Background()
	first := identityRecord("identity-1", "agent-1", "owner-1", "did:web:service-1", testClock)
	created, wasCreated, err := store.FindOrCreateIdentity(ctx, first.Principal, first.ServiceDID, func() (IdentityRecord, error) { return first, nil })
	if err != nil || !wasCreated || created.AgentIdentityID != first.AgentIdentityID {
		t.Fatalf("identity was not created: %#v, %t, %v", created, wasCreated, err)
	}
	created.SigningAlgorithms[0] = aep.SigningAlgorithmEdDSA
	existing, wasCreated, err := store.FindOrCreateIdentity(ctx, first.Principal, first.ServiceDID, func() (IdentityRecord, error) {
		return IdentityRecord{}, errors.New("must not run")
	})
	if err != nil || wasCreated || existing.SigningAlgorithms[0] != aep.SigningAlgorithmES256 {
		t.Fatalf("stored identity was not isolated: %#v, %t, %v", existing, wasCreated, err)
	}

	byDID, err := store.FindIdentityByAgentDID(ctx, first.AgentDID)
	if err != nil || byDID == nil || byDID.AgentIdentityID != first.AgentIdentityID {
		t.Fatalf("Agent DID lookup failed: %#v, %v", byDID, err)
	}
	byDIDID, err := store.FindIdentityByAgentDIDID(ctx, first.AgentDIDID)
	if err != nil || byDIDID == nil || byDIDID.AgentIdentityID != first.AgentIdentityID {
		t.Fatalf("Agent DID identifier lookup failed: %#v, %v", byDIDID, err)
	}
	if missing, err := store.GetIdentity(ctx, "missing"); err != nil || missing != nil {
		t.Fatalf("missing identity lookup returned data: %#v, %v", missing, err)
	}

	second := identityRecord("identity-2", "agent-2", "owner-1", "did:web:service-2", testClock.Add(time.Minute))
	third := identityRecord("identity-3", "agent-3", "owner-2", "did:web:service-3", testClock.Add(2*time.Minute))
	second.Status = ManagedAgentSuspended
	for _, record := range []IdentityRecord{second, third} {
		if _, _, err := store.FindOrCreateIdentity(ctx, record.Principal, record.ServiceDID, func() (IdentityRecord, error) { return record, nil }); err != nil {
			t.Fatal(err)
		}
	}
	listed, err := store.ListIdentities(ctx, "owner-1", IdentityListQuery{Descending: true, Limit: 1, Status: ManagedAgentSuspended})
	if err != nil || listed.Total != 1 || len(listed.Identities) != 1 || listed.Identities[0].AgentIdentityID != second.AgentIdentityID {
		t.Fatalf("filtered list is invalid: %#v, %v", listed, err)
	}
	empty, err := store.ListIdentities(ctx, "owner-1", IdentityListQuery{Offset: 10})
	if err != nil || empty.Total != 2 || len(empty.Identities) != 0 {
		t.Fatalf("offset list is invalid: %#v, %v", empty, err)
	}
	paged, err := store.ListIdentities(ctx, "owner-1", IdentityListQuery{Limit: 1, Offset: 1})
	if err != nil || paged.Total != 2 || len(paged.Identities) != 1 || paged.Identities[0].AgentIdentityID != second.AgentIdentityID {
		t.Fatalf("paged list is invalid: %#v, %v", paged, err)
	}

	updated, err := store.UpdateIdentity(ctx, first.AgentIdentityID, ManagedAgentTerminated, testClock.Add(time.Hour))
	if err != nil || updated == nil || updated.Status != ManagedAgentTerminated {
		t.Fatalf("identity update failed: %#v, %v", updated, err)
	}
	if missing, err := store.UpdateIdentity(ctx, "missing", ManagedAgentActive, testClock); err != nil || missing != nil {
		t.Fatalf("missing update returned a record: %#v, %v", missing, err)
	}
	if _, err := store.UpdateIdentity(ctx, first.AgentIdentityID, "future", testClock); err == nil {
		t.Fatal("invalid status was accepted")
	}
	if _, err := store.ListIdentities(ctx, "", IdentityListQuery{}); err == nil {
		t.Fatal("empty list principal was accepted")
	}
	if _, _, err := store.FindOrCreateIdentity(ctx, "", first.ServiceDID, func() (IdentityRecord, error) { return first, nil }); err == nil {
		t.Fatal("empty create principal was accepted")
	}
}

func TestMemoryIdentityStoreRejectsInvalidAndDuplicateRecords(t *testing.T) {
	store := NewMemoryIdentityStore()
	invalid := identityRecord("identity-1", "agent-1", "owner-1", "did:web:service-1", testClock)
	invalid.AgentDID = ""
	if _, _, err := store.FindOrCreateIdentity(context.Background(), invalid.Principal, invalid.ServiceDID, func() (IdentityRecord, error) { return invalid, nil }); err == nil {
		t.Fatal("invalid identity was accepted")
	}
	first := identityRecord("identity-1", "agent-1", "owner-1", "did:web:service-1", testClock)
	if _, _, err := store.FindOrCreateIdentity(context.Background(), first.Principal, first.ServiceDID, func() (IdentityRecord, error) { return first, nil }); err != nil {
		t.Fatal(err)
	}
	duplicate := identityRecord("identity-1", "agent-2", "owner-1", "did:web:service-2", testClock)
	if _, _, err := store.FindOrCreateIdentity(context.Background(), duplicate.Principal, duplicate.ServiceDID, func() (IdentityRecord, error) { return duplicate, nil }); err == nil {
		t.Fatal("duplicate identity identifier was accepted")
	}
}

func TestMemoryIdempotencyStore(t *testing.T) {
	now := testClock
	store := newMemoryIdempotencyStore(func() time.Time { return now })
	input := IdempotencyInput{IdempotencyKey: "key", Operation: IdempotentProvision, Principal: "owner", RequestHash: "hash"}
	executions := 0
	execute := func() (StoredResponse, error) {
		executions++
		return StoredResponse{Body: []byte(`{"ok":true}`), ContentType: aep.MediaType, Headers: http.Header{"X-Test": []string{"value"}}, Status: 200}, nil
	}
	created, err := store.ExecuteIdempotent(context.Background(), input, execute)
	if err != nil || created.State != IdempotencyCreated || executions != 1 {
		t.Fatalf("idempotent execution failed: %#v, %v", created, err)
	}
	created.Response.Headers.Set("X-Test", "changed")
	replayed, err := store.ExecuteIdempotent(context.Background(), input, execute)
	if err != nil || replayed.State != IdempotencyReplayed || replayed.Response.Headers.Get("X-Test") != "value" || executions != 1 {
		t.Fatalf("idempotent replay failed: %#v, %v", replayed, err)
	}
	conflicting := input
	conflicting.RequestHash = "different"
	conflict, err := store.ExecuteIdempotent(context.Background(), conflicting, execute)
	if err != nil || conflict.State != IdempotencyConflict || executions != 1 {
		t.Fatalf("idempotency conflict failed: %#v, %v", conflict, err)
	}
	now = now.Add(time.Hour)
	expired, err := store.ExecuteIdempotent(context.Background(), input, execute)
	if err != nil || expired.State != IdempotencyCreated || executions != 2 {
		t.Fatalf("expired record was retained: %#v, %v", expired, err)
	}
	if _, err := store.ExecuteIdempotent(context.Background(), IdempotencyInput{}, execute); err == nil {
		t.Fatal("invalid idempotency input was accepted")
	}
	if _, err := store.ExecuteIdempotent(context.Background(), IdempotencyInput{IdempotencyKey: "error", Operation: IdempotentSign, Principal: "owner", RequestHash: "hash"}, func() (StoredResponse, error) { return StoredResponse{}, errors.New("failed") }); err == nil {
		t.Fatal("execution error was discarded")
	}
	_ = NewMemoryIdempotencyStore()
}

func TestMemoryReplayStore(t *testing.T) {
	store := NewMemoryReplayStore()
	expiresAt := time.Now().Add(time.Minute)
	consumed, err := store.ConsumeReplay(context.Background(), "key", expiresAt)
	if err != nil || !consumed {
		t.Fatalf("replay key was not consumed: %t, %v", consumed, err)
	}
	consumed, err = store.ConsumeReplay(context.Background(), "key", expiresAt)
	if err != nil || consumed {
		t.Fatalf("replay key was consumed twice: %t, %v", consumed, err)
	}
	consumed, err = store.ConsumeReplay(context.Background(), "expired", time.Now().Add(-time.Second))
	if err != nil || consumed {
		t.Fatalf("expired replay key was consumed: %t, %v", consumed, err)
	}
	if _, err := store.ConsumeReplay(context.Background(), "", expiresAt); err == nil {
		t.Fatal("empty replay key was accepted")
	}
}

func identityRecord(identityID string, didID string, principal string, serviceDID string, createdAt time.Time) IdentityRecord {
	agentDID := "did:web:platform.example:agents:" + didID
	return IdentityRecord{
		AgentDID:          agentDID,
		AgentDIDID:        didID,
		AgentIdentityID:   identityID,
		CreatedAt:         createdAt,
		DIDDocumentURL:    "https://platform.example/agents/" + didID + "/did.json",
		KeyID:             agentDID,
		Principal:         principal,
		ServiceDID:        serviceDID,
		SigningAlgorithms: []aep.SigningAlgorithm{aep.SigningAlgorithmES256},
		Status:            ManagedAgentActive,
		UpdatedAt:         createdAt,
	}
}
