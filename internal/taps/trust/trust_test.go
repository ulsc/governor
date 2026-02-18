package trust

import (
	"testing"

	"governor/internal/taps"
)

func TestValidatePack(t *testing.T) {
	policy := Normalize(Policy{
		APIVersion: APIVersion,
		Mode:       ModeStrict,
		TrustedSources: []TrustedSource{{
			Name: "acme/checks",
			URL:  "https://example.com/acme/checks.git",
		}},
		Requirements: Requirements{RequireDigest: true, RequireLockEntry: true},
		PinnedPacks:  []PinnedPack{{Pack: "web", Source: "acme/checks", Version: "1.0.0", Digest: "abc", Commit: "c1"}},
	})

	lock := taps.LockedPack{Name: "web", Source: "acme/checks", Version: "1.0.0", Digest: "abc", Commit: "c1"}
	candidate := taps.LocatedPack{Name: "web", TapName: "acme/checks", TapURL: "https://example.com/acme/checks.git", Version: "1.0.0", Digest: "abc", Commit: "c1"}
	res := ValidatePack(lock, true, candidate, policy)
	if !res.Passed {
		t.Fatalf("expected pass, got errors: %+v", res.Errors)
	}
}

func TestValidatePack_FailsOnPinMismatch(t *testing.T) {
	policy := Normalize(Policy{
		APIVersion: APIVersion,
		Mode:       ModeStrict,
		PinnedPacks: []PinnedPack{{
			Pack:    "web",
			Version: "1.0.0",
			Digest:  "abc",
		}},
	})
	candidate := taps.LocatedPack{Name: "web", TapName: "acme/checks", Version: "2.0.0", Digest: "def"}
	res := ValidatePack(taps.LockedPack{}, false, candidate, policy)
	if res.Passed {
		t.Fatal("expected fail")
	}
	if len(res.Errors) == 0 {
		t.Fatal("expected at least one error")
	}
}

func TestShouldBlock(t *testing.T) {
	res := ValidationResult{Passed: false, Errors: []string{"x"}}
	if ShouldBlock(ModeWarn, false, res) {
		t.Fatal("warn mode should not block")
	}
	if !ShouldBlock(ModeStrict, false, res) {
		t.Fatal("strict mode should block")
	}
}
