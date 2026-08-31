package aep

import "testing"

func TestOpenAPIHelpers(t *testing.T) {
	match, err := MatchOpenAPIPath([]string{"/v1/orders/{id}", "/v1/{kind}/123"}, OpenAPIPathMatchOptions{
		Method: "get", Path: "/v1/orders/123", TrailingSlash: "strict",
	})
	if err != nil || match.Method != "GET" || match.Template != "/v1/orders/{id}" {
		t.Fatalf("unexpected OpenAPI path match: %#v, %v", match, err)
	}
	resolved, err := ResolveOpenAPIURL("https://api.example.com/discovery/aep", "../openapi.json", false)
	if err != nil || resolved.String() != "https://api.example.com/openapi.json" {
		t.Fatalf("unexpected OpenAPI URL: %v, %v", resolved, err)
	}
}

func TestOpenAPIHelpersRejectUnsafeOrAmbiguousInputs(t *testing.T) {
	if _, err := MatchOpenAPIPath([]string{"/items/{id}", "/items/{name}"}, OpenAPIPathMatchOptions{Method: "GET", Path: "/items/1", TrailingSlash: "strict"}); err == nil {
		t.Fatal("equivalent OpenAPI templates were accepted")
	}
	for _, reference := range []string{"http://api.example.com/openapi.json", "https://user@api.example.com/openapi.json"} {
		if _, err := ResolveOpenAPIURL("https://api.example.com/.well-known/aep", reference, false); err == nil {
			t.Fatalf("unsafe OpenAPI URL was accepted: %s", reference)
		}
	}
}

func TestOpenAPIPathLiteralPrecedenceResolvesEarlierAmbiguity(t *testing.T) {
	match, err := MatchOpenAPIPath(
		[]string{"/{kind}/item", "/{type}/item", "/orders/item"},
		OpenAPIPathMatchOptions{Method: "GET", Path: "/orders/item", TrailingSlash: "strict"},
	)
	if err != nil || match.Template != "/orders/item" {
		t.Fatalf("unexpected OpenAPI path match: %#v, %v", match, err)
	}
}
