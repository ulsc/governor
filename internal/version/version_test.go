package version

import "testing"

func TestVersionDefault(t *testing.T) {
	if Version == "" {
		t.Fatal("Version must not be empty")
	}
	if Version != "dev" {
		t.Fatalf("expected default Version to be %q, got %q", "dev", Version)
	}
}
