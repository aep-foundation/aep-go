package aep

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
)

func documentFixture() ServiceDocument {
	return ServiceDocument{ID: "terms", Type: "terms_of_service", Title: "Terms", Enrollment: "required", Representations: []DocumentRepresentation{{MediaType: "text/html", URL: "https://example.com/terms"}}}
}

func TestDocumentDeclarationsPreserveEmptyAndOmitted(t *testing.T) {
	for _, input := range []string{
		`{"agent_did":"did:example:agent"}`,
		`{"agent_did":"did:example:agent","acknowledged_document_ids":[]}`,
		`{"agent_did":"did:example:agent","acknowledged_document_ids":["Terms","terms"]}`,
	} {
		request, err := ParseEnrollRequest([]byte(input))
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), "acknowledged_document_ids") != strings.Contains(input, "acknowledged_document_ids") {
			t.Fatalf("lost declaration presence: %s", encoded)
		}
		response := EnrollResponse{Status: AgentActive, AcknowledgedDocumentIDs: request.AcknowledgedDocumentIDs}
		body, err := json.Marshal(response)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseEnrollResponse(body)
		if err != nil || !slices.Equal(parsed.AcknowledgedDocumentIDs, request.AcknowledgedDocumentIDs) || (parsed.AcknowledgedDocumentIDs == nil) != (request.AcknowledgedDocumentIDs == nil) {
			t.Fatalf("invalid echo round trip: %s, %v", body, err)
		}
	}
	for _, value := range []string{`null`, `"terms"`, `[null]`, `[1]`, `["terms","terms"]`, `[""]`, `[" terms"]`, `["terms\n"]`, `["` + strings.Repeat("x", 33) + `"]`, `["a","b","c","d","e","f","g","h"]`} {
		if _, err := ParseEnrollRequest([]byte(`{"agent_did":"did:example:agent","acknowledged_document_ids":` + value + `}`)); err == nil {
			t.Errorf("accepted %s", value)
		}
		if _, err := ParseEnrollResponse([]byte(`{"status":"active","acknowledged_document_ids":` + value + `}`)); err == nil {
			t.Errorf("accepted response %s", value)
		}
	}
}

func TestServiceDocumentBoundsAndOpenTypes(t *testing.T) {
	document := documentFixture()
	document.Type = "vendor_terms"
	if err := ValidateServiceDocuments([]ServiceDocument{document}); err != nil {
		t.Fatal(err)
	}
	if !slices.IsSorted(PreferredServiceDocumentTypes()) {
		t.Fatal("registry recommendations must be alphabetized")
	}
	for name, mutate := range map[string]func(*ServiceDocument){
		"missing html":    func(d *ServiceDocument) { d.Representations[0].MediaType = "application/json" },
		"duplicate media": func(d *ServiceDocument) { d.Representations = append(d.Representations, d.Representations[0]) },
		"http":            func(d *ServiceDocument) { d.Representations[0].URL = "http://example.com/terms" },
		"userinfo":        func(d *ServiceDocument) { d.Representations[0].URL = "https://user@example.com/terms" },
		"long url": func(d *ServiceDocument) {
			d.Representations[0].URL = "https://example.com/" + strings.Repeat("a", 2048)
		},
		"nonascii url": func(d *ServiceDocument) { d.Representations[0].URL = "https://example.com/é" },
		"type":         func(d *ServiceDocument) { d.Type = "Terms" },
		"title":        func(d *ServiceDocument) { d.Title = strings.Repeat("é", 257) },
		"enrollment":   func(d *ServiceDocument) { d.Enrollment = "optional" },
	} {
		t.Run(name, func(t *testing.T) {
			d := documentFixture()
			mutate(&d)
			if ValidateServiceDocument(d) == nil {
				t.Fatal("accepted invalid descriptor")
			}
		})
	}
	if ValidateServiceDocuments([]ServiceDocument{}) == nil || ValidateServiceDocuments([]ServiceDocument{document, document}) == nil {
		t.Fatal("accepted invalid catalog")
	}
	document.Title = strings.Repeat("é", 256)
	if err := ValidateServiceDocument(document); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{`null`, `{}`, `{"id":"terms","type":"terms_of_service","title":"Terms","enrollment":"required","representations":[null]}`} {
		var value ServiceDocument
		if json.Unmarshal([]byte(input), &value) == nil {
			t.Errorf("accepted %s", input)
		}
	}
}

func TestDocumentEnrollmentRequirementWireValues(t *testing.T) {
	for _, enrollment := range []string{"required", "not-required"} {
		document := documentFixture()
		document.Enrollment = enrollment
		if err := ValidateServiceDocument(document); err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		var parsed ServiceDocument
		if err := json.Unmarshal(body, &parsed); err != nil || parsed.Enrollment != enrollment {
			t.Fatalf("enrollment did not round trip: %s, %v", body, err)
		}
	}
}

func TestDocumentRequirementErrorScope(t *testing.T) {
	valid := `{"type":"urn:aep:error:requirements_unmet","title":"Required","status":422,"code":"requirements_unmet","requirements_pending":["service_documents"],"required_document_ids":["terms"]}`
	if _, err := ParseProblemDetails([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{
		strings.ReplaceAll(valid, "requirements_unmet", "not_recognized"),
		strings.Replace(valid, "422", "400", 1),
		strings.Replace(valid, `["service_documents"]`, `["contact.email"]`, 1),
		strings.Replace(valid, `["terms"]`, `[]`, 1),
		strings.Replace(valid, `["terms"]`, `null`, 1),
		strings.Replace(valid, `,"required_document_ids":["terms"]`, ``, 1),
	} {
		if _, err := ParseProblemDetails([]byte(input)); err == nil {
			t.Errorf("accepted %s", input)
		}
	}
}

func TestPortableDocumentValidation(t *testing.T) {
	valid := `{"format":"aep-service-document","version":"1.0","id":"terms","summary":[{"type":"paragraph","text":"Summary"}],"content":[{"type":"section","title":"Full terms","blocks":[{"type":"paragraph","text":"Text"},{"type":"numbered_list","items":["First","Second"]},{"type":"bulleted_list","items":["Bullet"]}]}],"future":"ignored"}`
	if _, err := ParsePortableServiceDocument([]byte(valid), "terms"); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{strings.Replace(valid, `"summary":[{"type":"paragraph","text":"Summary"}]`, `"summary":null`, 1), strings.Replace(valid, `"text":"Text"`, `"text":""`, 1), strings.Replace(valid, `"items":["First","Second"]`, `"items":[]`, 1), strings.Replace(valid, `"version":"1.0"`, `"version":"2.0"`, 1), strings.Replace(valid, `"type":"paragraph"`, `"type":"unknown"`, 1)} {
		if _, err := ParsePortableServiceDocument([]byte(input), "terms"); err == nil {
			t.Errorf("accepted invalid portable document %s", input)
		}
	}
	if _, err := ParsePortableServiceDocument([]byte(valid), "other"); err == nil {
		t.Fatal("accepted mismatched id")
	}
	if _, err := ParsePortableServiceDocument([]byte(strings.Replace(valid, `"version":"1.0"`, `"version":"2.0"`, 1)), "terms"); !errors.Is(err, ErrUnsupportedServiceDocument) {
		t.Fatalf("unsupported version: %v", err)
	}
	if _, err := ParsePortableServiceDocument([]byte(strings.Repeat(" ", MaxServiceDocumentBytes+1)), "terms"); err == nil {
		t.Fatal("accepted oversized body")
	}
	for _, depth := range []int{8, 9} {
		block := DocumentBlock{Type: "paragraph", Text: "Text"}
		for range depth {
			block = DocumentBlock{Type: "section", Title: "Section", Blocks: []DocumentBlock{block}}
		}
		body, _ := json.Marshal(PortableServiceDocument{Format: "aep-service-document", Version: "1.0", ID: "terms", Content: []DocumentBlock{block}})
		_, err := ParsePortableServiceDocument(body, "terms")
		if (err == nil) != (depth == 8) {
			t.Fatalf("depth %d: %v", depth, err)
		}
	}
	for _, count := range []int{1024, 1025} {
		blocks := make([]DocumentBlock, count)
		for index := range blocks {
			blocks[index] = DocumentBlock{Type: "paragraph", Text: "Text"}
		}
		body, _ := json.Marshal(PortableServiceDocument{Format: "aep-service-document", Version: "1.0", ID: "terms", Content: blocks})
		_, err := ParsePortableServiceDocument(body, "terms")
		if (err == nil) != (count == 1024) {
			t.Fatalf("blocks %d: %v", count, err)
		}
	}
}

func TestDocumentURLSchemes(t *testing.T) {
	for _, value := range []string{"http://localhost:8080/terms", "http://127.0.0.1/terms", "http://[::1]/terms", "https://192.168.1.10/terms"} {
		if err := ValidateDocumentURL(value); err != nil {
			t.Errorf("rejected %s: %v", value, err)
		}
	}
	for _, value := range []string{"http://example.com/terms", "http://localhost.example.com/terms", "http://192.168.1.10/terms", "http://user@localhost/terms", "ftp://localhost/terms"} {
		if err := ValidateDocumentURL(value); err == nil {
			t.Errorf("accepted %s", value)
		}
	}
}
