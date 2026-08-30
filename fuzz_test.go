package aep

import (
	"encoding/json"
	"testing"
)

func FuzzParseInspectDocument(fuzz *testing.F) {
	seed, err := json.Marshal(minimalInspectDocument())
	if err != nil {
		fuzz.Fatal(err)
	}
	fuzz.Add(seed)
	fuzz.Add([]byte(`null`))
	fuzz.Add([]byte(`{"aep_version":"1.0"}`))
	fuzz.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = ParseInspectDocument(data)
	})
}

func FuzzParseClaimValues(fuzz *testing.F) {
	fuzz.Add([]byte(`{"contact.email":"agent@example.com"}`))
	fuzz.Add([]byte(`{"contact.address.primary":{"country":"US","first_name":"A","last_name":"B","line1":"1 Main"}}`))
	fuzz.Add([]byte(`[]`))
	fuzz.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = ParseClaimValues(data)
	})
}

func FuzzAuthorizationCarrier(fuzz *testing.F) {
	fuzz.Add("AEP compact-jws")
	fuzz.Add("Bearer token")
	fuzz.Add("")
	fuzz.Fuzz(func(_ *testing.T, value string) {
		_, _ = ParseProtectedResourceAuthorization(value, ProtectedResourceDedicated)
	})
}
