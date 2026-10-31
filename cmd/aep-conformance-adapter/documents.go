package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	aep "github.com/aep-foundation/aep-go"
	"github.com/aep-foundation/aep-go/service"
)

func evaluateServiceDocuments(request adapterRequest) (bool, error) {
	switch request.Vector.ID {
	case "wire-shapes":
		var cases []struct {
			Name, Schema string
			Value        json.RawMessage
		}
		if err := json.Unmarshal(request.Case.Input["cases"], &cases); err != nil {
			return false, err
		}
		var expected []struct {
			Name  string
			Valid bool
		}
		if err := json.Unmarshal(request.Case.Expected["cases"], &expected); err != nil {
			return false, err
		}
		if len(cases) == 0 || len(cases) != len(expected) {
			return false, fmt.Errorf("invalid document cases")
		}
		for index, item := range cases {
			if item.Name != expected[index].Name || documentWireValid(item.Schema, item.Value) != expected[index].Valid {
				return false, fmt.Errorf("wire case: %s", item.Name)
			}
		}
		return true, nil
	case "structural-limits":
		return documentStructuralLimits(request)
	case "enrollment-lifecycle":
		return documentEnrollmentLifecycle(request)
	case "grant-guidance":
		return documentGrantGuidance(request)
	default:
		return false, fmt.Errorf("unsupported Service Documents vector: %s", request.Vector.ID)
	}
}

func documentWireValid(schema string, data []byte) bool {
	var err error
	switch schema {
	case "service-documents.schema.json":
		base, _ := json.Marshal(minimalInspectDocument("did:example:service"))
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(base, &fields)
		if err = json.Unmarshal(data, &fields); err == nil {
			var combined []byte
			combined, err = json.Marshal(fields)
			if err == nil {
				_, err = aep.ParseInspectDocument(combined)
			}
		}
	case "inspect-document.schema.json":
		_, err = aep.ParseInspectDocument(data)
	case "enroll-request.schema.json":
		_, err = aep.ParseEnrollRequest(data)
	case "enroll-response.schema.json":
		_, err = aep.ParseEnrollResponse(data)
	case "problem.schema.json":
		_, err = aep.ParseProblemDetails(data)
	case "portable-service-document.schema.json":
		var identity struct{ ID string }
		if err = json.Unmarshal(data, &identity); err == nil {
			_, err = aep.ParsePortableServiceDocument(data, identity.ID)
		}
	default:
		return false
	}
	return err == nil
}

func documentStructuralLimits(request adapterRequest) (bool, error) {
	var cases []struct {
		Name, Kind           string
		Count, Length, Depth int
		ContentCount         int `json:"content_count"`
		SummaryCount         int `json:"summary_count"`
	}
	if err := json.Unmarshal(request.Case.Input["cases"], &cases); err != nil {
		return false, err
	}
	var expected []struct {
		Name  string
		Valid bool
	}
	if err := json.Unmarshal(request.Case.Expected["cases"], &expected); err != nil {
		return false, err
	}
	if len(cases) == 0 || len(cases) != len(expected) {
		return false, fmt.Errorf("invalid structural cases")
	}
	for index, item := range cases {
		var descriptor aep.ServiceDocument
		if err := json.Unmarshal(request.Case.Input["descriptor"], &descriptor); err != nil {
			return false, err
		}
		document, err := aep.ParsePortableServiceDocument(request.Case.Input["document"], descriptor.ID)
		if err != nil {
			return false, err
		}
		var catalog []aep.ServiceDocument
		switch item.Kind {
		case "catalog":
			for i := 0; i < item.Count; i++ {
				entry := descriptor
				entry.ID = fmt.Sprintf("doc-%d", i)
				catalog = append(catalog, entry)
			}
		case "duplicate-ids":
			catalog = []aep.ServiceDocument{descriptor, descriptor}
		case "duplicate-media":
			descriptor.Representations = append(descriptor.Representations, descriptor.Representations[0])
			catalog = []aep.ServiceDocument{descriptor}
		case "blocks":
			block := document.Content[0]
			document.Content = make([]aep.DocumentBlock, item.ContentCount)
			for i := range document.Content {
				document.Content[i] = block
			}
			document.Summary = make([]aep.DocumentBlock, item.SummaryCount)
			for i := range document.Summary {
				document.Summary[i] = block
			}
		case "sections":
			for i := 0; i < item.Depth; i++ {
				document.Content = []aep.DocumentBlock{{Type: "section", Title: "Title", Blocks: document.Content}}
			}
		case "text":
			document.Content[0].Text = strings.Repeat("a", item.Length)
		case "list":
			items := make([]string, item.Count)
			for i := range items {
				items[i] = "Item"
			}
			document.Content = []aep.DocumentBlock{{Type: "bulleted_list", Items: items}}
		case "title":
			descriptor.Title = strings.Repeat("a", item.Length)
			catalog = []aep.ServiceDocument{descriptor}
		case "url":
			prefix := "https://example.com/"
			if item.Length < len(prefix) {
				return false, fmt.Errorf("invalid generated URL bound")
			}
			descriptor.Representations[0].URL = prefix + strings.Repeat("a", item.Length-len(prefix))
			catalog = []aep.ServiceDocument{descriptor}
		default:
			return false, fmt.Errorf("unknown structural kind: %s", item.Kind)
		}
		if catalog != nil {
			err = aep.ValidateServiceDocuments(catalog)
		} else {
			encoded, encodeErr := json.Marshal(document)
			if encodeErr != nil {
				return false, encodeErr
			}
			_, err = aep.ParsePortableServiceDocument(encoded, descriptor.ID)
		}
		if item.Name != expected[index].Name || (err == nil) != expected[index].Valid {
			return false, fmt.Errorf("structural case: %s", item.Name)
		}
	}
	return true, nil
}

var documentNow = time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)

func documentService(ids []string, required []aep.ClaimName, store service.EnrollmentStore, effects, issued *atomic.Int32, credentials service.ServiceCredentialStore) (*service.Service, error) {
	documents := make([]aep.ServiceDocument, 0, len(ids))
	for _, id := range ids {
		documents = append(documents, aep.ServiceDocument{ID: id, Title: id, Type: "terms_of_service", Enrollment: "required", Representations: []aep.DocumentRepresentation{{MediaType: "text/html", URL: "https://service.example/" + id}}})
	}
	grant, err := service.StoredAPIKeyGrantType(service.StoredCredentialGrantTypeOptions[aep.APIKeyGrantResponse]{
		Store:  credentials,
		Config: aep.GrantTypeConfig{Additional: aep.AdditionalMembers{"header_names": json.RawMessage(`["x-api-key"]`)}},
		Issue: func(context.Context, aep.GrantRequest, service.GrantContext) (aep.APIKeyGrantResponse, error) {
			issued.Add(1)
			return aep.APIKeyGrantResponse{APIKey: "example-conformance-credential-secret", CredentialID: "new-credential", Header: "x-api-key", Scopes: []string{}, ExpiresAt: documentNow.Add(time.Hour).Format(time.RFC3339)}, nil
		},
	})
	if err != nil {
		return nil, err
	}
	var assertions atomic.Int32
	return service.New(service.Options{
		ServiceDID: "did:web:service.example", IdentityMethods: []aep.IdentityMethod{"did:example"},
		ServiceDocuments: documents, Claims: &aep.InspectClaims{Required: required},
		EnrollmentStore: store, EnrollmentPolicy: conformanceEnrollmentPolicy{calls: effects},
		Clock: func() time.Time { return documentNow }, GrantTypes: []service.GrantTypeDefinition{grant},
		AuthenticationMethods: []aep.AuthenticationMethod{aep.AuthenticationMethod(aep.GrantTypeAPIKey)},
		Verifier: func(_ context.Context, assertion string, verification service.AssertionVerificationContext) (aep.ClientAssertionClaims, error) {
			header, err := aep.DecodeJWTUnverified(assertion)
			if err != nil {
				return aep.ClientAssertionClaims{}, err
			}
			keyID, ok := header.Header["kid"].(string)
			if !ok {
				return aep.ClientAssertionClaims{}, fmt.Errorf("missing assertion key ID")
			}
			did := strings.Split(keyID, "#")[0]
			return aep.ClientAssertionClaims{Audience: verification.ServiceDID, Issuer: did, Subject: did, Operation: verification.Operation, Resource: verification.Resource,
				IssuedAt: documentNow.Unix(), ExpiresAt: documentNow.Add(time.Minute).Unix(), JWTID: fmt.Sprintf("document-%d", assertions.Add(1))}, nil
		},
	})
}

func documentEnrollmentLifecycle(request adapterRequest) (bool, error) {
	var initial struct {
		AgentDID       string `json:"agent_did"`
		EnrollmentID   string `json:"enrollment_id"`
		Created, Since string
		Status         aep.AgentStatus
		Claims         *aep.ClaimValues
		IDs            []string `json:"acknowledged_document_ids"`
		Credentials    []string `json:"credential_ids"`
	}
	if err := json.Unmarshal(request.Case.Input["existing"], &initial); err != nil {
		return false, err
	}
	created, err := time.Parse(time.RFC3339, initial.Created)
	if err != nil {
		return false, err
	}
	since, err := time.Parse(time.RFC3339, initial.Since)
	if err != nil {
		return false, err
	}
	ids, err := requiredField[[]string](request.Case.Input, "current_required_ids")
	if err != nil {
		return false, err
	}
	states, err := requiredField[[]aep.AgentStatus](request.Case.Input, "lifecycle_states")
	if err != nil {
		return false, err
	}
	store := service.NewMemoryEnrollmentStore()
	original := service.EnrollmentRecord{AgentDID: initial.AgentDID, EnrollmentID: initial.EnrollmentID, CreatedAt: created, Since: since, UpdatedAt: created, Status: initial.Status, Claims: initial.Claims, AcknowledgedDocumentIDs: initial.IDs}
	ctx := context.Background()
	if _, err := store.SaveEnrollment(ctx, original); err != nil {
		return false, err
	}
	credentials := service.NewMemoryServiceCredentialStore()
	for _, id := range initial.Credentials {
		credential := aep.APIKeyGrantResponse{APIKey: "secret-" + id, CredentialID: id, Header: "x-api-key", Scopes: []string{}, ExpiresAt: documentNow.Add(time.Hour).Format(time.RFC3339)}
		if err := credentials.SaveCredential(ctx, service.ServiceCredentialRecord{AgentDID: initial.AgentDID, CredentialID: id, Credential: credential, CreatedAt: created, ExpiresAt: documentNow.Add(time.Hour), GrantType: aep.GrantTypeAPIKey}); err != nil {
			return false, err
		}
	}
	var effects, issued atomic.Int32
	instance, err := documentService(ids, nil, store, &effects, &issued, credentials)
	if err != nil {
		return false, err
	}
	var operations []struct {
		Name, Key string
		Claims    *aep.ClaimValues
		IDs       []string `json:"acknowledged_document_ids"`
		Mark      []string `json:"mark_required"`
	}
	if err := json.Unmarshal(request.Case.Input["operations"], &operations); err != nil {
		return false, err
	}
	var expected []map[string]json.RawMessage
	if err := json.Unmarshal(request.Case.Expected["operations"], &expected); err != nil {
		return false, err
	}
	if len(operations) == 0 || len(operations) != len(expected) {
		return false, fmt.Errorf("invalid operation cases")
	}
	for index, operation := range operations {
		before, err := store.FindEnrollment(ctx, initial.AgentDID)
		if err != nil || before == nil {
			return false, err
		}
		if operation.Mark != nil {
			before.RequiredDocumentIDs = operation.Mark
			if _, err := store.SaveEnrollment(ctx, *before); err != nil {
				return false, err
			}
		}
		priorEffects := effects.Load()
		body, err := json.Marshal(aep.EnrollRequest{AgentDID: initial.AgentDID, Claims: operation.Claims, AcknowledgedDocumentIDs: operation.IDs})
		if err != nil {
			return false, err
		}
		result, err := instance.Enroll(ctx, body, serviceCommandOptionsForAgent(aep.AssertionEnroll, operation.Key, initial.AgentDID))
		if err != nil {
			return false, err
		}
		after, err := store.FindEnrollment(ctx, initial.AgentDID)
		if err != nil || after == nil {
			return false, err
		}
		want := expected[index]
		status, err := requiredField[int](want, "http_status")
		if err != nil {
			return false, err
		}
		if result.Status != status {
			return false, fmt.Errorf("lifecycle %s: status %d", operation.Name, result.Status)
		}
		if value, ok := want["code"]; ok && (result.Problem == nil || !jsonEqual(result.Problem.Code, json.RawMessage(value))) {
			return false, nil
		}
		if value, ok := want["acknowledged_document_ids"]; ok && !jsonEqual(result.Body.AcknowledgedDocumentIDs, json.RawMessage(value)) {
			return false, nil
		}
		if value, ok := want["stored_ids"]; ok && !jsonEqual(after.AcknowledgedDocumentIDs, json.RawMessage(value)) {
			return false, nil
		}
		if value, ok := want["mutated"]; ok && !jsonEqual(!jsonEqual(before, after), json.RawMessage(value)) {
			return false, nil
		}
		if value, ok := want["policy_effects_repeated"]; ok && !jsonEqual(effects.Load() != priorEffects, json.RawMessage(value)) {
			return false, nil
		}
		if value, ok := want["requirement_satisfied"]; ok && !jsonEqual(!slices.Contains(after.RequiredDocumentIDs, "terms"), json.RawMessage(value)) {
			return false, nil
		}
		if index == 0 {
			grant, err := instance.Grant(ctx, []byte(`{"grant_type":"api-key"}`), serviceCommandOptionsForAgent(aep.AssertionGrant, "outstanding", initial.AgentDID))
			if err != nil || grant.Problem == nil || !jsonEqual(grant.Problem.RequiredDocumentIDs, request.Case.Expected["outstanding_ids_after_update"]) {
				return false, err
			}
		}
	}
	after, err := store.FindEnrollment(ctx, initial.AgentDID)
	if err != nil || after == nil {
		return false, err
	}
	if !jsonEqual(after.Claims, request.Case.Expected["claims"]) ||
		!jsonEqual(after.AgentDID == original.AgentDID && after.EnrollmentID == original.EnrollmentID, request.Case.Expected["identity_preserved"]) ||
		!jsonEqual(after.CreatedAt.Equal(original.CreatedAt), request.Case.Expected["creation_preserved"]) ||
		!jsonEqual(after.Since.Equal(original.Since), request.Case.Expected["unchanged_state_timestamp_preserved"]) {
		return false, nil
	}
	var activeIDs []string
	resource, _ := url.Parse("https://service.example/private")
	for _, id := range initial.Credentials {
		result, err := instance.AuthenticateProtectedResource(ctx, service.ProtectedResourceRequest{URL: resource, Method: http.MethodGet, Headers: http.Header{"X-Api-Key": []string{"secret-" + id}}})
		if err != nil || !result.Authenticated {
			return false, err
		}
		activeIDs = append(activeIDs, result.Principal.CredentialID)
	}
	if !jsonEqual(activeIDs, request.Case.Expected["credential_ids"]) {
		return false, nil
	}
	preserved := true
	for _, state := range states {
		after.Status = state
		if _, err := store.SaveEnrollment(ctx, *after); err != nil {
			return false, err
		}
		body, _ := json.Marshal(aep.EnrollRequest{AgentDID: initial.AgentDID, AcknowledgedDocumentIDs: []string{}})
		result, err := instance.Enroll(ctx, body, serviceCommandOptionsForAgent(aep.AssertionEnroll, string(state), initial.AgentDID))
		if err != nil {
			return false, err
		}
		saved, err := store.FindEnrollment(ctx, initial.AgentDID)
		if err != nil || saved == nil {
			return false, err
		}
		preserved = preserved && result.Status == 200 && saved.Status == state && saved.Since.Equal(original.Since)
	}
	return jsonEqual(preserved, request.Case.Expected["unrelated_lifecycle_states_preserved"]), nil
}

func documentGrantGuidance(request adapterRequest) (bool, error) {
	ids, err := requiredField[[]string](request.Case.Input, "required_document_ids")
	if err != nil {
		return false, err
	}
	claims, err := requiredField[[]aep.ClaimName](request.Case.Input, "missing_claims")
	if err != nil {
		return false, err
	}
	var requests []aep.EnrollRequest
	if err := json.Unmarshal(request.Case.Input["enroll_requests"], &requests); err != nil || len(requests) == 0 {
		return false, err
	}
	did := requests[0].AgentDID
	store := service.NewMemoryEnrollmentStore()
	if _, err := store.SaveEnrollment(context.Background(), service.EnrollmentRecord{AgentDID: did, EnrollmentID: "existing", Status: aep.AgentActive, CreatedAt: documentNow, UpdatedAt: documentNow, Since: documentNow}); err != nil {
		return false, err
	}
	var effects, issued atomic.Int32
	instance, err := documentService(ids, claims, store, &effects, &issued, service.NewMemoryServiceCredentialStore())
	if err != nil {
		return false, err
	}
	grant, err := instance.Grant(context.Background(), []byte(`{"grant_type":"api-key"}`), serviceCommandOptionsForAgent(aep.AssertionGrant, "grant", did))
	if err != nil || grant.Problem == nil || !jsonEqual(grant.Status, request.Case.Expected["grant_status"]) || !jsonEqual(issued.Load() != 0, request.Case.Expected["credential_issued"]) || !slices.Equal(grant.Problem.RequiredDocumentIDs, ids) {
		return false, err
	}
	wantRequirements := make([]string, 0, len(claims)+1)
	for _, claim := range claims {
		wantRequirements = append(wantRequirements, string(claim))
	}
	wantRequirements = append(wantRequirements, "service_documents")
	if grant.Problem.Code != aep.ErrorRequirementsUnmet || !slices.Equal(grant.Problem.RequirementsPending, wantRequirements) {
		return false, fmt.Errorf("Grant did not report both claim and document requirements")
	}
	unknown, err := instance.Grant(context.Background(), []byte(`{"grant_type":"api-key"}`), serviceCommandOptionsForAgent(aep.AssertionGrant, "unknown", "did:example:unknown"))
	if err != nil || unknown.Problem == nil {
		return false, err
	}
	var wantUnknown struct {
		Status    int `json:"http_status"`
		Code      aep.ErrorCode
		Disclosed bool `json:"requirements_disclosed"`
	}
	if err := json.Unmarshal(request.Case.Expected["unrecognized"], &wantUnknown); err != nil {
		return false, err
	}
	if unknown.Status != wantUnknown.Status || unknown.Problem.Code != wantUnknown.Code || (len(unknown.Problem.RequiredDocumentIDs) > 0 || len(unknown.Problem.RequirementsPending) > 0) != wantUnknown.Disclosed {
		return false, nil
	}
	var expected []map[string]json.RawMessage
	if err := json.Unmarshal(request.Case.Expected["enroll_requests"], &expected); err != nil {
		return false, err
	}
	if len(expected) != len(requests) {
		return false, fmt.Errorf("invalid enroll request cases")
	}
	for index, enroll := range requests {
		enrollStore := service.NewMemoryEnrollmentStore()
		instance, err := documentService(ids, claims, enrollStore, &effects, &issued, service.NewMemoryServiceCredentialStore())
		if err != nil {
			return false, err
		}
		body, _ := json.Marshal(enroll)
		result, err := instance.Enroll(context.Background(), body, serviceCommandOptionsForAgent(aep.AssertionEnroll, fmt.Sprint(index), did))
		if err != nil {
			return false, err
		}
		if !jsonEqual(result.Status, expected[index]["http_status"]) {
			return false, nil
		}
		if value, ok := expected[index]["code"]; ok && (result.Problem == nil || !jsonEqual(result.Problem.Code, value)) {
			return false, nil
		}
		if value, ok := expected[index]["acknowledged_document_ids"]; ok && !jsonEqual(result.Body.AcknowledgedDocumentIDs, value) {
			return false, nil
		}
		if value, ok := expected[index]["missing_documents_accepted"]; ok {
			stored, err := enrollStore.FindEnrollment(context.Background(), did)
			if err != nil || stored == nil {
				return false, err
			}
			accepted := slices.ContainsFunc(ids, func(id string) bool { return slices.Contains(stored.AcknowledgedDocumentIDs, id) })
			if !jsonEqual(accepted, value) {
				return false, nil
			}
		}
	}
	return true, nil
}
