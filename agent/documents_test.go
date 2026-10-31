package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"testing"

	aep "github.com/aep-foundation/aep-go"
)

func TestEnrollDocumentDeclarationsAndEcho(t *testing.T) {
	for _, test := range []struct {
		name     string
		ids      []string
		response string
		valid    bool
	}{
		{"omitted", nil, `{"status":"active"}`, true},
		{"empty", []string{}, `{"status":"active","acknowledged_document_ids":[]}`, true},
		{"declared", []string{"Terms", "privacy"}, `{"status":"active","acknowledged_document_ids":["Terms","privacy"]}`, true},
		{"missing-echo", []string{"Terms"}, `{"status":"active"}`, false},
		{"empty-not-omitted", []string{}, `{"status":"active"}`, false},
		{"unexpected-echo", nil, `{"status":"active","acknowledged_document_ids":[]}`, false},
		{"expanded", []string{"Terms"}, `{"status":"active","acknowledged_document_ids":["Terms","new"]}`, false},
		{"changed-case", []string{"Terms"}, `{"status":"active","acknowledged_document_ids":["terms"]}`, false},
		{"rejected", []string{"Terms"}, `{"status":"rejected"}`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			stub := newServiceStub(t, func(response http.ResponseWriter, request *http.Request) bool {
				var body aep.EnrollRequest
				if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				if (body.AcknowledgedDocumentIDs == nil) != (test.ids == nil) || !slices.Equal(body.AcknowledgedDocumentIDs, test.ids) {
					t.Errorf("declaration changed: %#v", body)
				}
				response.Header().Set("Content-Type", aep.MediaType)
				_, _ = response.Write([]byte(test.response))
				return true
			})
			stub.document.Extensions = &aep.Extensions{Supported: []string{aep.ServiceDocumentsExtension}}
			_, err := stub.session.Enroll(context.Background(), EnrollOptions{AcknowledgedDocumentIDs: test.ids})
			if (err == nil) != test.valid {
				t.Fatalf("unexpected echo validation: %v", err)
			}
			if len(stub.requests) != 1 {
				t.Fatalf("enrollment chained requests: %d", len(stub.requests))
			}
		})
	}
}

func TestEnrollDocumentDeclarationRequiresAdvertisement(t *testing.T) {
	stub := newServiceStub(t, nil)
	if _, err := stub.session.Enroll(context.Background(), EnrollOptions{AcknowledgedDocumentIDs: []string{}}); err == nil || len(stub.requests) != 0 {
		t.Fatalf("unsupported acknowledgement sent: %v", err)
	}
}

func TestGrantPreservesDocumentRequirementsWithoutChaining(t *testing.T) {
	stub := newServiceStub(t, func(response http.ResponseWriter, request *http.Request) bool {
		if request.URL.Path != "/aep/grant" {
			return false
		}
		response.Header().Set("Content-Type", aep.ProblemMediaType)
		response.WriteHeader(422)
		_, _ = response.Write([]byte(`{"type":"urn:aep:error:requirements_unmet","title":"Requirements unmet","status":422,"code":"requirements_unmet","requirements_pending":["service_documents"],"required_document_ids":["terms"]}`))
		return true
	})
	if _, err := stub.session.Enroll(context.Background(), EnrollOptions{}); err != nil {
		t.Fatal(err)
	}
	stub.requests = nil
	_, err := stub.session.Grant(context.Background(), GrantOptions{GrantType: aep.GrantTypeOAuthBearer})
	var failure *CommandError
	if !errors.As(err, &failure) || failure.Problem == nil || !slices.Equal(failure.Problem.RequiredDocumentIDs, []string{"terms"}) {
		t.Fatalf("document requirement lost: %v", err)
	}
	for _, request := range stub.requests {
		if request.URL.Path == "/aep/enroll" {
			t.Fatal("Grant automatically invoked Enroll")
		}
	}
	if len(stub.requests) != 1 {
		t.Fatalf("expected Grant only, got %d", len(stub.requests))
	}
}
