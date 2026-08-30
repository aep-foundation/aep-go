package aep

import "testing"

func TestHTTPHelpers(t *testing.T) {
	for _, base := range []string{"/aep", "/aep/", ""} {
		path, err := CommandPath(CommandEnroll, base)
		if err != nil || path != "/aep/enroll" {
			t.Fatalf("CommandPath(%q) = %q, %v", base, path, err)
		}
	}
	if _, err := CommandPath(CommandInspect, "/aep/"); err == nil {
		t.Fatal("Inspect must not have a command endpoint path")
	}
	if _, err := CommandPath(CommandStatus, "aep"); err == nil {
		t.Fatal("relative endpoint base was accepted")
	}
}

func TestAuthorizationCarriers(t *testing.T) {
	header, value, err := RenderProtectedResourceAuthorization(ProtectedResourceAuthorization{
		Carrier: ProtectedResourceDedicated, Scheme: CredentialSchemeBearer, Credentials: "token",
	})
	if err != nil || header != AuthorizationHeader || value != "Bearer token" {
		t.Fatalf("unexpected authorization rendering: %q %q %v", header, value, err)
	}
	parsed, err := ParseProtectedResourceAuthorization("basic credentials", ProtectedResourceDedicated)
	if err != nil || parsed.Scheme != CredentialSchemeBasic || parsed.Credentials != "credentials" {
		t.Fatalf("unexpected authorization parsing: %#v %v", parsed, err)
	}
	if _, err := ParseProtectedResourceAuthorization("Bearer secret, Basic other", ProtectedResourceDedicated); err == nil {
		t.Fatal("ambiguous dedicated field was accepted")
	}
	if _, _, err := RenderProtectedResourceAuthorization(ProtectedResourceAuthorization{Scheme: CredentialSchemeAEP}); err == nil {
		t.Fatal("empty credentials were accepted")
	}
	if _, err := ParseProtectedResourceAuthorization("Payment secret", ProtectedResourceStandard); err == nil {
		t.Fatal("unknown scheme was accepted")
	}
	path, err := CommandPathFromInspect(minimalInspectDocument(), CommandStatus)
	if err != nil || path != "/aep/status" {
		t.Fatalf("unexpected Inspect command path: %q, %v", path, err)
	}
}
