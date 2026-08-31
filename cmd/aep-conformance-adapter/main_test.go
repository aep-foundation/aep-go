package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEvaluateSharedVector(t *testing.T) {
	request := adapterRequest{Role: "agent", Sequence: 7}
	request.Vector.Category = "claims"
	request.Vector.ID = "minimal-email"
	request.Case.Input = map[string]json.RawMessage{
		"claim_values": json.RawMessage(`{"contact.email":"a@b"}`),
	}
	request.Case.Expected = map[string]json.RawMessage{
		"valid": json.RawMessage(`true`),
	}

	response := evaluate(request)
	if response.Status != "passed" || response.Sequence != 7 || response.ProtocolVersion != "1" {
		t.Fatalf("unexpected adapter response: %#v", response)
	}
}

func TestEvaluateUnknownVectorFails(t *testing.T) {
	request := adapterRequest{Role: "service"}
	request.Vector.Category = "unknown"
	request.Vector.ID = "unknown"

	response := evaluate(request)
	if response.Status != "failed" || !strings.Contains(response.Message, "no Service operation maps vector") {
		t.Fatalf("unexpected adapter response: %#v", response)
	}
}

func TestTruncateBoundsMessages(t *testing.T) {
	if got := truncate("abcdef", 3); got != "abc" {
		t.Fatalf("truncate() = %q, want %q", got, "abc")
	}
}
