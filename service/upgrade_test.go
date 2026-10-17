package service

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	aep "github.com/aep-foundation/aep-go"
)

func TestReplayPublishedEnrollmentHash(t *testing.T) {
	store := newMemoryIdempotencyStore(func() time.Time { return testNow })
	// Captured at ExecuteIdempotent from the published v0.1.1 Enroll path.
	old := IdempotencyInput{AgentDID: "did:web:agent.example", Command: IdempotentEnroll, IdempotencyKey: "upgrade", RequestHash: "sha256:31816bd47981c5fd4b3e4e6c74e54ce32951a8f424d480a453b104c2bb181e22"}
	_, err := store.ExecuteIdempotent(context.Background(), old, func() (StoredResponse, error) {
		return StoredResponse{Body: json.RawMessage(`{"status":"active"}`), ContentType: aep.MediaType, Status: 200, CreatedAt: testNow}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	s := newTestService(t, Options{IdempotencyStore: store, EnrollmentPolicy: testEnrollmentPolicy(func(aep.EnrollRequest, EnrollmentPolicyContext) (EnrollmentDecision, error) {
		t.Fatal("completed enrollment executed again")
		return EnrollmentDecision{}, nil
	})})
	body := []byte(`{"agent_did":"did:web:agent.example","claims":{"contact.email":"a@example.com"}}`)
	response, err := s.Enroll(context.Background(), body, commandOptions(aep.AssertionEnroll, "upgrade-1", "upgrade"))
	if err != nil || response.Status != 200 || response.Body.Status != aep.AgentActive {
		t.Fatalf("upgrade replay: %#v, %v", response, err)
	}
	response, err = s.Enroll(context.Background(), []byte(`{"agent_did":"did:web:agent.example","claims":{"contact.email":"different@example.com"}}`), commandOptions(aep.AssertionEnroll, "upgrade-2", "upgrade"))
	if err != nil || response.Status != 409 {
		t.Fatalf("changed request was replayed: %#v, %v", response, err)
	}
}

func TestIdempotencyInputMatchesVersions(t *testing.T) {
	old := IdempotencyInput{AgentDID: "agent", Command: IdempotentGrant, IdempotencyKey: "key", RequestHash: "legacy"}
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
	for _, mutate := range []func(*IdempotencyInput){func(v *IdempotencyInput) { v.AgentDID = "other" }, func(v *IdempotencyInput) { v.Command = IdempotentRevoke }, func(v *IdempotencyInput) { v.IdempotencyKey = "other" }} {
		changed = next
		mutate(&changed)
		if next.Matches(changed) {
			t.Fatal("different scope matched")
		}
	}
}
