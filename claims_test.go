package aep

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestClaimValues(t *testing.T) {
	data := []byte(`{
		"contact.address.primary": {
			"country": "US",
			"first_name": "Grace",
			"last_name": "Hopper",
			"line1": "123 Market Street",
			"line3": "Attention: Receiving",
			"postcode": "94105",
			"future_field": "accepted"
		},
		"contact.email": "owner@example.com",
		"contact.mobile": "+14155550100",
		"person.birthdate": "1990-04-12",
		"custom.future_claim": {"value":"accepted"}
	}`)
	claims, err := ParseClaimValues(data)
	if err != nil {
		t.Fatal(err)
	}
	if claims.ContactAddressPrimary == nil || claims.ContactAddressPrimary.Additional["future_field"] == nil {
		t.Fatal("address extension was not retained")
	}
	if claims.Additional["custom.future_claim"] == nil {
		t.Fatal("private claim was not retained")
	}
	encoded, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip map[string]any
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if _, ok := roundTrip["custom.future_claim"]; !ok {
		t.Fatal("private claim was not serialized")
	}
}

func TestClaimValidation(t *testing.T) {
	for _, email := range []string{
		"owner@example.com",
		"first.last+tag@example-domain.com",
		`"quoted local"@example.com`,
		"owner@[192.0.2.1]",
		"owner@[IPv6:2001:db8::1]",
	} {
		claims := ClaimValues{ContactEmail: &email}
		if err := ValidateClaimValues(claims); err != nil {
			t.Errorf("valid email %q: %v", email, err)
		}
	}
	for _, email := range []string{
		".owner@example.com",
		"owner..name@example.com",
		"owner@-example.com",
		"owner@[256.0.2.1]",
		"ownér@example.com",
	} {
		claims := ClaimValues{ContactEmail: &email}
		if err := ValidateClaimValues(claims); err == nil {
			t.Errorf("invalid email accepted: %q", email)
		}
	}
}

func TestClaimValidationRejectsLegacyAndNull(t *testing.T) {
	data := []byte(`{"contact.address.primary":{"country":"US","first_name":"Grace","last_name":"Hopper","line1":"Rural Route 5","postal_code":"94105"}}`)
	_, err := ParseClaimValues(data)
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("expected ValidationError, got %v", err)
	}
	assertIssue(t, validation.Issues, "$.contact.address.primary.postal_code")
	if _, err := ParseClaimValues([]byte(`{"contact.email":null}`)); err == nil {
		t.Fatal("expected null registered claim to fail")
	}
	if _, err := ParseClaimValues([]byte(`null`)); err == nil {
		t.Fatal("expected null Claim Values document to fail")
	}
}

func TestClaimNegotiation(t *testing.T) {
	requested := &InspectClaims{
		Required:  []ClaimName{ClaimContactEmail, "example.future.required"},
		Preferred: []ClaimName{ClaimContactMobile, "example.future.preferred"},
		Optional:  []ClaimName{ClaimPersonUsername, "example.future.optional"},
	}
	evaluation := EvaluateClaimSupport(requested, RegisteredClaims())
	if evaluation.CanSatisfyRequired || len(evaluation.UnsupportedRequired) != 1 || evaluation.SupportedOptional[0] != ClaimPersonUsername {
		t.Fatalf("unexpected evaluation: %#v", evaluation)
	}
	email := "a@b"
	values := &ClaimValues{ContactEmail: &email}
	missing := MissingRequiredClaimNames([]ClaimName{ClaimContactEmail, ClaimPersonFirstName}, values)
	if len(missing) != 1 || missing[0] != ClaimPersonFirstName {
		t.Fatalf("unexpected missing claims: %#v", missing)
	}
}
