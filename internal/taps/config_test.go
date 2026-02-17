package taps

import (
	"path/filepath"
	"testing"
)

func TestLoadConfig_EmptyWhenMissing(t *testing.T) {
	dir := t.TempDir()
	cfg, err := LoadConfig(filepath.Join(dir, "taps.yaml"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Taps) != 0 {
		t.Fatalf("expected empty taps, got %d", len(cfg.Taps))
	}
}

func TestSaveAndLoadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "taps.yaml")

	cfg := &Config{
		Taps: []Tap{
			{Name: "acme/checks", URL: "https://github.com/acme/checks.git"},
		},
	}
	if err := SaveConfig(path, cfg); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(loaded.Taps) != 1 {
		t.Fatalf("expected 1 tap, got %d", len(loaded.Taps))
	}
	if loaded.Taps[0].Name != "acme/checks" {
		t.Fatalf("expected tap name acme/checks, got %q", loaded.Taps[0].Name)
	}
}

func TestResolveSource_GitHubShorthand(t *testing.T) {
	tests := []struct {
		input    string
		wantName string
		wantURL  string
	}{
		{"acme/checks", "acme/checks", "https://github.com/acme/checks.git"},
		{"git@github.com:acme/checks.git", "acme/checks", "git@github.com:acme/checks.git"},
		{"https://gitlab.com/team/checks.git", "team/checks", "https://gitlab.com/team/checks.git"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			name, url := ResolveSource(tt.input)
			if name != tt.wantName {
				t.Errorf("ResolveSource(%q) name = %q, want %q", tt.input, name, tt.wantName)
			}
			if url != tt.wantURL {
				t.Errorf("ResolveSource(%q) url = %q, want %q", tt.input, url, tt.wantURL)
			}
		})
	}
}

func TestFindTap(t *testing.T) {
	cfg := &Config{
		Taps: []Tap{
			{Name: "acme/checks", URL: "https://github.com/acme/checks.git"},
		},
	}
	tap, ok := FindTap(cfg, "acme/checks")
	if !ok {
		t.Fatal("expected to find tap")
	}
	if tap.Name != "acme/checks" {
		t.Errorf("expected acme/checks, got %q", tap.Name)
	}

	_, ok = FindTap(cfg, "nonexistent")
	if ok {
		t.Fatal("expected not to find tap")
	}
}

func TestRemoveTap(t *testing.T) {
	cfg := &Config{
		Taps: []Tap{
			{Name: "acme/checks", URL: "https://github.com/acme/checks.git"},
			{Name: "other/repo", URL: "https://github.com/other/repo.git"},
		},
	}
	removed := RemoveTap(cfg, "acme/checks")
	if !removed {
		t.Fatal("expected to remove tap")
	}
	if len(cfg.Taps) != 1 {
		t.Fatalf("expected 1 tap after removal, got %d", len(cfg.Taps))
	}
	if cfg.Taps[0].Name != "other/repo" {
		t.Errorf("expected remaining tap other/repo, got %q", cfg.Taps[0].Name)
	}

	removed = RemoveTap(cfg, "nonexistent")
	if removed {
		t.Fatal("expected not to remove nonexistent tap")
	}
}
