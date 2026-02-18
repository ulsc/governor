package taps

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCompareVersion(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want int
	}{
		{name: "higher major", a: "2.0.0", b: "1.9.9", want: 1},
		{name: "higher minor", a: "1.3.0", b: "1.2.9", want: 1},
		{name: "higher patch", a: "1.2.4", b: "1.2.3", want: 1},
		{name: "pre less than release", a: "1.2.3-rc1", b: "1.2.3", want: -1},
		{name: "equal", a: "v1.2.3", b: "1.2.3", want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CompareVersion(tt.a, tt.b)
			if got != tt.want {
				t.Fatalf("CompareVersion(%q, %q)=%d want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestIsMajorUpgrade(t *testing.T) {
	if !IsMajorUpgrade("1.2.3", "2.0.0") {
		t.Fatal("expected major upgrade")
	}
	if IsMajorUpgrade("1.2.3", "1.3.0") {
		t.Fatal("did not expect major upgrade")
	}
}

func TestSaveAndLoadLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "checks.lock.yaml")
	lock := LockFile{
		Packs: []LockedPack{{
			Name:      "owasp",
			Source:    "acme/checks",
			SourceURL: "https://github.com/acme/checks.git",
			Version:   "1.2.3",
			Digest:    "abc123",
			LockedAt:  time.Date(2026, 2, 18, 0, 0, 0, 0, time.UTC),
		}},
	}
	if err := SaveLock(path, lock); err != nil {
		t.Fatalf("save lock: %v", err)
	}
	loaded, err := LoadLock(path)
	if err != nil {
		t.Fatalf("load lock: %v", err)
	}
	if loaded.APIVersion != LockAPIVersion {
		t.Fatalf("unexpected api version: %s", loaded.APIVersion)
	}
	if len(loaded.Packs) != 1 {
		t.Fatalf("expected 1 pack, got %d", len(loaded.Packs))
	}
	if loaded.Packs[0].Name != "owasp" {
		t.Fatalf("unexpected pack name: %s", loaded.Packs[0].Name)
	}
}

func TestDiscoverPacksAndResolveLockedPack(t *testing.T) {
	tapRoot := t.TempDir()
	packDir := filepath.Join(tapRoot, "packs", "owasp")
	if err := os.MkdirAll(packDir, 0o755); err != nil {
		t.Fatalf("mkdir pack: %v", err)
	}
	if err := os.WriteFile(filepath.Join(packDir, "pack.yaml"), []byte("name: owasp\nversion: 1.2.0\n"), 0o644); err != nil {
		t.Fatalf("write pack: %v", err)
	}
	if err := os.WriteFile(filepath.Join(packDir, "auth.check.yaml"), []byte("id: auth\n"), 0o644); err != nil {
		t.Fatalf("write check: %v", err)
	}

	cfg := &Config{Taps: []Tap{{Name: "acme/checks", URL: "https://example.com/acme/checks.git", Path: tapRoot}}}
	packs, err := DiscoverPacks(cfg)
	if err != nil {
		t.Fatalf("discover packs: %v", err)
	}
	if len(packs) != 1 {
		t.Fatalf("expected 1 pack, got %d", len(packs))
	}
	if packs[0].Digest == "" {
		t.Fatal("expected non-empty digest")
	}

	resolved, err := ResolveLockedPack(packs, LockedPack{Name: "owasp", Source: "acme/checks", Version: "1.2.0", Digest: packs[0].Digest})
	if err != nil {
		t.Fatalf("resolve lock: %v", err)
	}
	if resolved.Name != "owasp" {
		t.Fatalf("unexpected resolved pack: %s", resolved.Name)
	}
}

func TestSelectLatestPack(t *testing.T) {
	candidates := []LocatedPack{
		{Name: "owasp", TapName: "a", Version: "1.2.0"},
		{Name: "owasp", TapName: "b", Version: "1.3.0"},
	}
	best, err := SelectLatestPack(candidates)
	if err != nil {
		t.Fatalf("select latest: %v", err)
	}
	if best.TapName != "b" {
		t.Fatalf("expected tap b, got %s", best.TapName)
	}
}
