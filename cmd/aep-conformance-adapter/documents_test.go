package main

import (
	"encoding/json"
	"testing"
)

func TestServiceDocumentWireVectorChecksExpectations(t *testing.T) {
	request := adapterRequest{Role: "service"}
	request.Vector.Category, request.Vector.ID = "service-documents", "wire-shapes"
	request.Case.Input = map[string]json.RawMessage{"cases": json.RawMessage(`[
		{"name":"empty","schema":"enroll-request.schema.json","value":{"agent_did":"did:example:agent","acknowledged_document_ids":[]}},
		{"name":"null","schema":"enroll-request.schema.json","value":{"agent_did":"did:example:agent","acknowledged_document_ids":null}}
	]`)}
	request.Case.Expected = map[string]json.RawMessage{"cases": json.RawMessage(`[{"name":"empty","valid":true},{"name":"null","valid":false}]`)}
	if result := evaluate(request); result.Status != "passed" {
		t.Fatalf("%#v", result)
	}
	request.Case.Expected["cases"] = json.RawMessage(`[{"name":"empty","valid":false},{"name":"null","valid":false}]`)
	if evaluate(request).Status == "passed" {
		t.Fatal("ignored altered wire expectation")
	}
	request.Vector.ID = "unknown"
	if evaluate(request).Status == "passed" {
		t.Fatal("accepted unsupported document vector")
	}
}

func TestServiceDocumentStructuralVectorChecksBoundary(t *testing.T) {
	request := adapterRequest{Role: "service"}
	request.Vector.Category, request.Vector.ID = "service-documents", "structural-limits"
	request.Case.Input = map[string]json.RawMessage{
		"descriptor": json.RawMessage(`{"id":"terms","type":"terms_of_service","title":"Terms","enrollment":"required","representations":[{"media_type":"text/html","url":"https://example.com/terms"}]}`),
		"document":   json.RawMessage(`{"format":"aep-service-document","version":"1.0","id":"terms","content":[{"type":"paragraph","text":"Terms"}]}`),
		"cases":      json.RawMessage(`[{"name":"seven","kind":"catalog","count":7},{"name":"eight","kind":"catalog","count":8}]`),
	}
	request.Case.Expected = map[string]json.RawMessage{"cases": json.RawMessage(`[{"name":"seven","valid":true},{"name":"eight","valid":false}]`)}
	if result := evaluate(request); result.Status != "passed" {
		t.Fatalf("%#v", result)
	}
	request.Case.Expected["cases"] = json.RawMessage(`[{"name":"seven","valid":true},{"name":"eight","valid":true}]`)
	if evaluate(request).Status == "passed" {
		t.Fatal("ignored altered boundary expectation")
	}
}
