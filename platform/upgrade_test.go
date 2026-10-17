package platform

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	aep "github.com/aep-foundation/aep-go"
)

func TestReplayPublishedProvisionHash(t *testing.T) {
	store := newMemoryIdempotencyStore(func() time.Time { return testClock })
	// Captured at ExecuteIdempotent from the published v0.1.1 Provision path.
	old := IdempotencyInput{Principal: "owner", Operation: IdempotentProvision, IdempotencyKey: "upgrade", RequestHash: "eaac92220b5daffeea94a26614fddd0b5dad2dfe3a3af95aaf0affd78362595a"}
	_, err := store.ExecuteIdempotent(context.Background(), old, func() (StoredResponse, error) {
		return StoredResponse{Body: json.RawMessage(`{"agent_identity_id":"saved-identity"}`), ContentType: aep.MediaType, Status: 200, CreatedAt: testClock}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	options, authorizer, keys := testOptions(t, false)
	options.IdempotencyStore = store
	p, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	request := ProvisionRequest{ServiceDID: "did:web:service.example"}
	requestContext := RequestContext{Principal: "owner", IdempotencyKey: "upgrade"}
	result, err := p.Provision(context.Background(), request, requestContext)
	if err != nil || result.Status != 200 || result.Body.AgentIdentityID != "saved-identity" {
		t.Fatalf("upgrade replay: %#v, %v", result, err)
	}
	result, err = p.Provision(context.Background(), ProvisionRequest{ServiceDID: "did:web:other.example"}, requestContext)
	if err != nil || result.Status != 409 {
		t.Fatalf("changed request replayed: %#v, %v", result, err)
	}
	authorizer.allowed = false
	result, err = p.Provision(context.Background(), request, requestContext)
	if err != nil || result.Status != 404 {
		t.Fatalf("unauthorized replay: %#v, %v", result, err)
	}
	if len(keys.created) != 0 {
		t.Fatal("completed operation created another key")
	}
}

func TestIdempotencyInputMatchesVersions(t *testing.T) {
	old := IdempotencyInput{Principal: "owner", Operation: IdempotentSign, IdempotencyKey: "key", RequestHash: "legacy"}
	next := old
	next.CanonicalRequestHash = "canonical"
	if !old.Matches(next) || !next.Matches(old) {
		t.Fatal("mixed-version replay failed")
	}
	changed := next
	changed.RequestHash = "different-order"
	if !next.Matches(changed) {
		t.Fatal("canonical replay failed")
	}
	changed.CanonicalRequestHash = "different"
	if next.Matches(changed) {
		t.Fatal("changed request matched")
	}
	changed = old
	changed.RequestHash = "different"
	if old.Matches(changed) {
		t.Fatal("changed legacy request matched")
	}
	for _, mutate := range []func(*IdempotencyInput){func(v *IdempotencyInput) { v.Principal = "other" }, func(v *IdempotencyInput) { v.Operation = IdempotentProvision }, func(v *IdempotencyInput) { v.IdempotencyKey = "other" }} {
		changed = next
		mutate(&changed)
		if next.Matches(changed) {
			t.Fatal("different scope matched")
		}
	}
}
