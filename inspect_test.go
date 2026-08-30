package aep

import (
	"encoding/json"
	"errors"
	"testing"
)

func minimalInspectDocument() InspectDocument {
	return InspectDocument{
		AEPVersion: Version,
		Bindings:   Bindings{Supported: []Binding{BindingHTTP}},
		Claims:     &InspectClaims{Required: []ClaimName{ClaimContactEmail}},
		Commands: Commands{
			Supported:  []Command{CommandEnroll, CommandGrant, CommandInspect, CommandRevoke, CommandStatus},
			GrantTypes: []GrantType{GrantTypeOAuthBearer, GrantTypeAPIKey, GrantTypeBasic},
		},
		Core:     Core{SigningAlgorithms: []SigningAlgorithm{SigningAlgorithmEdDSA, SigningAlgorithmES256}},
		HTTP:     HTTPConfiguration{EndpointBase: "/aep/"},
		Identity: Identity{Methods: []IdentityMethod{IdentityMethodDIDWeb}},
		Service:  ServiceIdentity{DID: "did:web:api.example.com"},
	}
}

func TestProtocolConstants(t *testing.T) {
	if Version != "1.0" || MediaType != "application/aep+json" || WellKnownPath != "/.well-known/aep" {
		t.Fatal("unexpected AEP constants")
	}
	claims := RegisteredClaims()
	claims[0] = "changed"
	if RegisteredClaims()[0] != ClaimContactAddressPrimary {
		t.Fatal("registered Claim catalog was mutable")
	}
}

func TestInspectDocument(t *testing.T) {
	document := minimalInspectDocument()
	document.AEPVersion = "1.7"
	document.Commands.Supported = []Command{CommandInspect, "future-command"}
	document.Identity.Methods = nil
	document.Additional = AdditionalMembers{"future_section": json.RawMessage(`{"enabled":true}`)}
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseInspectDocument(data)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.AEPVersion != "1.7" || parsed.Additional["future_section"] == nil {
		t.Fatalf("unexpected parsed document: %#v", parsed)
	}
	if !IsVersionCompatible("1.7", Version) || IsVersionCompatible("2.0", Version) || IsVersionCompatible("01.0", Version) {
		t.Fatal("version compatibility mismatch")
	}
}

func TestInspectDocumentRelationships(t *testing.T) {
	valid := minimalInspectDocument()
	valid.Authentication = &Authentication{Methods: []AuthenticationMethod{
		AuthenticationMethodJWT, "oauth-bearer", "api-key", "basic",
	}}
	valid.HTTP.OpenAPI = &OpenAPIReference{
		URL: "/openapi.json", PathMatching: OpenAPIPathMatching{TrailingSlash: "strict"},
	}
	if err := ValidateInspectDocument(valid); err != nil {
		t.Fatalf("valid Inspect document: %v", err)
	}

	document := minimalInspectDocument()
	document.Identity.Methods = nil
	document.Commands.GrantTypes = nil
	err := ValidateInspectDocument(document)
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("expected ValidationError, got %v", err)
	}
	assertIssue(t, validation.Issues, "$.identity.methods")
	assertIssue(t, validation.Issues, "$.commands.grant_types")

	document = minimalInspectDocument()
	document.Authentication = &Authentication{
		Methods:    []AuthenticationMethod{AuthenticationMethodJWT},
		Additional: AdditionalMembers{"future": json.RawMessage("true")},
	}
	document.HTTP.OpenAPI = &OpenAPIReference{
		URL:          "/openapi.json",
		PathMatching: OpenAPIPathMatching{TrailingSlash: "strict", Additional: AdditionalMembers{"future": json.RawMessage("true")}},
	}
	err = ValidateInspectDocument(document)
	if !errors.As(err, &validation) {
		t.Fatalf("expected ValidationError, got %v", err)
	}
	assertIssue(t, validation.Issues, "$.authentication.future")
	assertIssue(t, validation.Issues, "$.http.openapi.path_matching.future")
}

func TestInspectRejectsNullOptionalObject(t *testing.T) {
	data, err := json.Marshal(minimalInspectDocument())
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatal(err)
	}
	object["claims"] = nil
	data, err = json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseInspectDocument(data); err == nil {
		t.Fatal("expected null claims to fail")
	}
}

func assertIssue(t *testing.T, issues []ValidationIssue, path string) {
	t.Helper()
	for _, issue := range issues {
		if issue.Path == path {
			return
		}
	}
	t.Fatalf("missing issue for %s: %#v", path, issues)
}
