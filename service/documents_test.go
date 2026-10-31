package service

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	aep "github.com/aep-foundation/aep-go"
)

func serviceDocument(id string) aep.ServiceDocument {
	return aep.ServiceDocument{ID: id, Type: "terms_of_service", Title: id, Enrollment: "required", Representations: []aep.DocumentRepresentation{{MediaType: "text/html", URL: "https://service.example/" + id}}}
}

func enrollDocuments(t *testing.T, instance *Service, key string, ids []string, claims *aep.ClaimValues) Result[aep.EnrollResponse] {
	t.Helper()
	body, err := json.Marshal(aep.EnrollRequest{AgentDID: "did:web:agent.example", AcknowledgedDocumentIDs: ids, Claims: claims})
	if err != nil {
		t.Fatal(err)
	}
	result, err := instance.Enroll(context.Background(), body, commandOptions(aep.AssertionEnroll, key, key))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestDocumentAcknowledgementDoesNotExpandDuringEnrollment(t *testing.T) {
	for _, test := range []struct {
		name    string
		ids     []string
		missing []string
	}{
		{"empty", []string{}, []string{"terms", "privacy"}},
		{"partial", []string{"terms"}, []string{"privacy"}},
		{"complete", []string{"terms", "privacy"}, nil},
		{"retired", []string{"retired"}, []string{"terms", "privacy"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var grants atomic.Int32
			instance := newTestService(t, Options{ServiceDocuments: []aep.ServiceDocument{serviceDocument("terms"), serviceDocument("privacy")}, GrantTypes: []GrantTypeDefinition{{GrantType: "custom-session", Handler: &testGrantHandler{grant: func(aep.GrantRequest, GrantContext) (json.RawMessage, error) {
				grants.Add(1)
				return json.RawMessage(`{"credential_id":"issued"}`), nil
			}}}}})
			result := enrollDocuments(t, instance, "enroll", test.ids, nil)
			if result.Status != 200 || result.Body.AcknowledgedDocumentIDs == nil || !slices.Equal(result.Body.AcknowledgedDocumentIDs, test.ids) {
				t.Fatalf("declaration changed: %#v", result)
			}
			grant, err := instance.Grant(context.Background(), []byte(`{"grant_type":"custom-session"}`), commandOptions(aep.AssertionGrant, "grant", "grant"))
			if err != nil {
				t.Fatal(err)
			}
			if len(test.missing) > 0 {
				if grant.Status != 422 || grant.Problem == nil || !slices.Equal(grant.Problem.RequiredDocumentIDs, test.missing) || grants.Load() != 0 {
					t.Fatalf("requirements did not block issuance: %#v", grant)
				}
			} else if grant.Status != 200 || grants.Load() != 1 {
				t.Fatalf("complete enrollment could not grant: %#v", grant)
			}
			stored, err := instance.enrollmentStore.FindEnrollment(context.Background(), "did:web:agent.example")
			if err != nil || stored == nil {
				t.Fatalf("missing enrollment: %v", err)
			}
			if slices.Contains(stored.AcknowledgedDocumentIDs, "retired") {
				t.Fatal("unknown ID persisted as accepted document")
			}
		})
	}
}

func TestDocumentDeclarationRequiredButNotAutomaticallyAccepted(t *testing.T) {
	var policies atomic.Int32
	instance := newTestService(t, Options{ServiceDocuments: []aep.ServiceDocument{serviceDocument("terms")}, EnrollmentPolicy: testEnrollmentPolicy(func(aep.EnrollRequest, EnrollmentPolicyContext) (EnrollmentDecision, error) {
		policies.Add(1)
		return EnrollmentDecision{Status: aep.EnrollmentActive}, nil
	})})
	result := enrollDocuments(t, instance, "missing", nil, nil)
	if result.Status != 422 || result.Problem == nil || !slices.Equal(result.Problem.RequiredDocumentIDs, []string{"terms"}) || policies.Load() != 0 {
		t.Fatalf("missing declaration accepted: %#v", result)
	}
	record, err := instance.enrollmentStore.FindEnrollment(context.Background(), "did:web:agent.example")
	if err != nil || record != nil {
		t.Fatalf("failed enrollment persisted: %#v, %v", record, err)
	}
}

func TestRepeatedEnrollmentPreservesIdentityClaimsAndLifecycle(t *testing.T) {
	for _, status := range []aep.AgentStatus{aep.AgentActive, aep.AgentPending, aep.AgentSuspended, aep.AgentTerminated, aep.AgentUnavailable} {
		t.Run(string(status), func(t *testing.T) {
			store := NewMemoryEnrollmentStore()
			email, name := "owner@example.com", "Owner"
			record := activeEnrollment("did:web:agent.example")
			record.Claims = &aep.ClaimValues{ContactEmail: &email}
			record.Status = status
			record.OwnerActionRequired = true
			record.RequirementsPending = []string{"manual-review"}
			record.VerificationPending = []string{"contact.email"}
			record.CreatedAt, record.Since = testNow.Add(-time.Hour), testNow.Add(-time.Minute)
			record.AcknowledgedDocumentIDs = []string{"terms"}
			record.RequiredDocumentIDs = []string{"terms"}
			if _, err := store.SaveEnrollment(context.Background(), record); err != nil {
				t.Fatal(err)
			}
			instance := newTestService(t, Options{EnrollmentStore: store, ServiceDocuments: []aep.ServiceDocument{serviceDocument("terms"), serviceDocument("privacy")}, Claims: &aep.InspectClaims{Required: []aep.ClaimName{aep.ClaimContactEmail}}})
			result := enrollDocuments(t, instance, "update", []string{"terms", "privacy"}, &aep.ClaimValues{PersonFirstName: &name})
			if result.Status != 200 || result.Body.Status != status {
				t.Fatalf("lifecycle changed: %#v", result)
			}
			after, err := store.FindEnrollment(context.Background(), record.AgentDID)
			if err != nil || after == nil {
				t.Fatal(err)
			}
			if after.EnrollmentID != record.EnrollmentID || !after.CreatedAt.Equal(record.CreatedAt) || !after.Since.Equal(record.Since) || after.Claims.ContactEmail == nil || *after.Claims.ContactEmail != email || after.Claims.PersonFirstName == nil || *after.Claims.PersonFirstName != name || !after.OwnerActionRequired || !slices.Equal(after.RequirementsPending, record.RequirementsPending) || !slices.Equal(after.VerificationPending, record.VerificationPending) || !slices.Equal(after.AcknowledgedDocumentIDs, []string{"terms", "privacy"}) || len(after.RequiredDocumentIDs) != 0 {
				t.Fatalf("enrollment was not merged safely: %#v", after)
			}
		})
	}
}

func TestRepeatedEnrollmentPolicyMayDeclineOrLeaveRecordUnchanged(t *testing.T) {
	unchanged := false
	for _, decision := range []EnrollmentDecision{{Status: aep.EnrollmentRejected}, {UpdateExisting: &unchanged}} {
		store := NewMemoryEnrollmentStore()
		record := activeEnrollment("did:web:agent.example")
		record.UpdatedAt = testNow.Add(-time.Hour)
		if _, err := store.SaveEnrollment(context.Background(), record); err != nil {
			t.Fatal(err)
		}
		instance := newTestService(t, Options{EnrollmentStore: store, ServiceDocuments: []aep.ServiceDocument{serviceDocument("terms")}, EnrollmentPolicy: testEnrollmentPolicy(func(aep.EnrollRequest, EnrollmentPolicyContext) (EnrollmentDecision, error) { return decision, nil })})
		result := enrollDocuments(t, instance, "update", []string{"terms"}, nil)
		if decision.Status == aep.EnrollmentRejected && (result.Status != 403 || result.Problem == nil || result.Problem.Code != aep.ErrorEnrollmentFailed) {
			t.Fatalf("policy rejection ignored: %#v", result)
		}
		if decision.UpdateExisting != nil && (result.Status != 200 || !slices.Equal(result.Body.AcknowledgedDocumentIDs, []string{"terms"})) {
			t.Fatalf("unchanged response lost declaration: %#v", result)
		}
		after, err := store.FindEnrollment(context.Background(), record.AgentDID)
		if err != nil || after == nil || !reflect.DeepEqual(*after, record) {
			t.Fatalf("policy mutated existing record: %#v, %v", after, err)
		}
	}
}

func TestDocumentReacknowledgementAndNewClaimsRequireExplicitEnroll(t *testing.T) {
	store := NewMemoryEnrollmentStore()
	record := activeEnrollment("did:web:agent.example")
	record.AcknowledgedDocumentIDs = []string{"terms"}
	record.RequiredDocumentIDs = []string{"terms"}
	if _, err := store.SaveEnrollment(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	var grants atomic.Int32
	handler := &testGrantHandler{grant: func(aep.GrantRequest, GrantContext) (json.RawMessage, error) {
		grants.Add(1)
		return json.RawMessage(`{"credential_id":"issued"}`), nil
	}}
	instance := newTestService(t, Options{
		EnrollmentStore:  store,
		ServiceDocuments: []aep.ServiceDocument{serviceDocument("terms")},
		Claims:           &aep.InspectClaims{Required: []aep.ClaimName{aep.ClaimContactEmail}},
		GrantTypes:       []GrantTypeDefinition{{GrantType: "custom-session", Handler: handler}},
	})
	grant, err := instance.Grant(context.Background(), []byte(`{"grant_type":"custom-session"}`), commandOptions(aep.AssertionGrant, "before", "before"))
	if err != nil || grant.Status != 422 || grant.Problem == nil || !slices.Equal(grant.Problem.RequirementsPending, []string{"contact.email", "service_documents"}) || grants.Load() != 0 {
		t.Fatalf("missing requirements did not block: %#v, %v", grant, err)
	}
	if result := enrollDocuments(t, instance, "missing-claim", []string{"terms"}, nil); result.Status != 422 {
		t.Fatalf("claim requirement bypassed: %#v", result)
	}
	email := "owner@example.com"
	if result := enrollDocuments(t, instance, "update", []string{"terms"}, &aep.ClaimValues{ContactEmail: &email}); result.Status != 200 {
		t.Fatalf("update failed: %#v", result)
	}
	if grants.Load() != 0 {
		t.Fatal("Enroll automatically granted a credential")
	}
	grant, err = instance.Grant(context.Background(), []byte(`{"grant_type":"custom-session"}`), commandOptions(aep.AssertionGrant, "after", "after"))
	if err != nil || grant.Status != 200 || grants.Load() != 1 {
		t.Fatalf("updated enrollment could not grant: %#v, %v", grant, err)
	}
}

func TestDocumentEnrollIdempotency(t *testing.T) {
	var policies atomic.Int32
	instance := newTestService(t, Options{ServiceDocuments: []aep.ServiceDocument{serviceDocument("terms")}, EnrollmentPolicy: testEnrollmentPolicy(func(aep.EnrollRequest, EnrollmentPolicyContext) (EnrollmentDecision, error) {
		policies.Add(1)
		return EnrollmentDecision{Status: aep.EnrollmentActive}, nil
	})})
	seedEnrollment(t, instance.enrollmentStore)
	body := []byte(`{"agent_did":"did:web:agent.example","acknowledged_document_ids":["terms"]}`)
	var wait sync.WaitGroup
	for i := range 8 {
		wait.Go(func() {
			result, err := instance.Enroll(context.Background(), body, commandOptions(aep.AssertionEnroll, fmt.Sprintf("retry-%d", i), "same-key"))
			if err != nil || result.Status != 200 || !slices.Equal(result.Body.AcknowledgedDocumentIDs, []string{"terms"}) {
				t.Errorf("retry failed: %#v, %v", result, err)
			}
		})
	}
	wait.Wait()
	if policies.Load() != 1 {
		t.Fatalf("policy evaluated %d times", policies.Load())
	}
	result, err := instance.Enroll(context.Background(), []byte(`{"agent_did":"did:web:agent.example","acknowledged_document_ids":[]}`), commandOptions(aep.AssertionEnroll, "conflict", "same-key"))
	if err != nil || result.Status != 409 || result.Problem == nil || result.Problem.Code != aep.ErrorIdempotencyConflict {
		t.Fatalf("changed acknowledgement reused key: %#v, %v", result, err)
	}
}

func TestDocumentConfigurationAndRejectedEnrollment(t *testing.T) {
	for _, docs := range [][]aep.ServiceDocument{nil, {}, {serviceDocument("terms")}} {
		instance := newTestService(t, Options{ServiceDocuments: docs, EnrollmentPolicy: NewStaticEnrollmentPolicy(EnrollmentDecision{Status: aep.EnrollmentRejected})})
		result := enrollDocuments(t, instance, "reject", []string{"terms"}, nil)
		if result.Status != 200 || result.Body.Status != aep.AgentRejected || result.Body.AcknowledgedDocumentIDs != nil {
			t.Fatalf("rejected acknowledgement: %#v", result)
		}
		record, err := instance.enrollmentStore.FindEnrollment(context.Background(), "did:web:agent.example")
		if err != nil || record == nil || len(record.AcknowledgedDocumentIDs) != 0 {
			t.Fatalf("rejected documents persisted: %#v, %v", record, err)
		}
	}
	instance := newTestService(t, Options{})
	result := enrollDocuments(t, instance, "unsupported", []string{"terms"}, nil)
	if result.Status != 200 || result.Body.AcknowledgedDocumentIDs != nil {
		t.Fatalf("unsupported extension was applied: %#v", result)
	}
}

func TestRepeatedEnrollmentHonorsExplicitEmptyPolicyLists(t *testing.T) {
	instance := newTestService(t, Options{EnrollmentPolicy: NewStaticEnrollmentPolicy(EnrollmentDecision{RequirementsPending: []string{}, VerificationPending: []string{}})})
	record := activeEnrollment("did:web:agent.example")
	record.RequirementsPending = []string{"manual-review"}
	record.VerificationPending = []string{"contact.email"}
	if _, err := instance.enrollmentStore.SaveEnrollment(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	result := enrollDocuments(t, instance, "clear-lists", nil, nil)
	if result.Status != 200 || len(result.Body.RequirementsPending) != 0 || len(result.Body.VerificationPending) != 0 {
		t.Fatalf("explicit empty lists ignored: %#v", result)
	}
}

func TestPolicyMetadataOmittedFalseAndEmpty(t *testing.T) {
	for _, initial := range []bool{true, false} {
		for _, value := range []*bool{nil, new(bool), boolPointer(true)} {
			t.Run(fmt.Sprintf("initial=%t/value=%v", initial, value), func(t *testing.T) {
				decision := EnrollmentDecision{OwnerActionRequired: value}
				if value != nil {
					decision.RequirementsPending = []string{}
					decision.VerificationPending = []string{}
				}
				instance := newTestService(t, Options{EnrollmentPolicy: NewStaticEnrollmentPolicy(decision)})
				if !initial {
					record := activeEnrollment("did:web:agent.example")
					record.OwnerActionRequired = true
					record.RequirementsPending = []string{"review"}
					record.VerificationPending = []string{"contact.email"}
					if _, err := instance.enrollmentStore.SaveEnrollment(context.Background(), record); err != nil {
						t.Fatal(err)
					}
				}
				result := enrollDocuments(t, instance, "metadata", nil, nil)
				if result.Status != 200 {
					t.Fatalf("unexpected result: %#v", result)
				}
				record, err := instance.enrollmentStore.FindEnrollment(context.Background(), "did:web:agent.example")
				if err != nil || record == nil {
					t.Fatal(err)
				}
				want := !initial
				if value != nil {
					want = *value
				}
				if record.OwnerActionRequired != want {
					t.Fatalf("owner action = %t, want %t", record.OwnerActionRequired, want)
				}
				if value == nil && !initial {
					if !slices.Equal(record.RequirementsPending, []string{"review"}) || !slices.Equal(record.VerificationPending, []string{"contact.email"}) {
						t.Fatal("omitted metadata cleared existing lists")
					}
				} else if len(record.RequirementsPending) != 0 || len(record.VerificationPending) != 0 {
					t.Fatal("explicit empty metadata not cleared")
				}
			})
		}
	}
}

func boolPointer(value bool) *bool { return &value }
