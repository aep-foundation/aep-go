package aep

import "testing"

func TestVersion(t *testing.T) {
	if Version != "1.0" {
		t.Fatalf("Version = %q, want %q", Version, "1.0")
	}
}
