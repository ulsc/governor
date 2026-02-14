package app

import (
	"testing"

	"governor/internal/model"
)

func TestDedupeFindings_MergesAcrossTracks(t *testing.T) {
	in := []model.Finding{
		{Title: "Hardcoded API key", Category: "secrets", Severity: "high", Evidence: "x", SourceTrack: "secrets_config", Confidence: 0.6, FileRefs: []string{"a.env"}},
		{Title: "Hardcoded API key", Category: "secrets", Severity: "critical", Evidence: "x", SourceTrack: "appsec", Confidence: 0.9, FileRefs: []string{"a.env"}},
	}

	out := dedupeFindings(in)
	if len(out) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out))
	}
	if out[0].Severity != "critical" {
		t.Fatalf("expected critical severity, got %s", out[0].Severity)
	}
	if out[0].Confidence != 0.9 {
		t.Fatalf("expected confidence 0.9, got %f", out[0].Confidence)
	}
	if out[0].SourceTrack != "appsec,secrets_config" {
		t.Fatalf("unexpected source tracks: %s", out[0].SourceTrack)
	}
}

func TestShouldCleanupWorkspace_DefaultAlwaysCleans(t *testing.T) {
	if !shouldCleanupWorkspace(nil, nil, false) {
		t.Fatal("expected cleanup on success by default")
	}
	if !shouldCleanupWorkspace(nil, []string{"warn"}, false) {
		t.Fatal("expected cleanup on warning by default")
	}
	if !shouldCleanupWorkspace(assertErr{}, nil, false) {
		t.Fatal("expected cleanup on failure by default")
	}
}

func TestShouldCleanupWorkspace_KeepOnError(t *testing.T) {
	if !shouldCleanupWorkspace(nil, nil, true) {
		t.Fatal("expected cleanup on success when keep-on-error is enabled")
	}
	if shouldCleanupWorkspace(nil, []string{"warn"}, true) {
		t.Fatal("expected no cleanup on warning when keep-on-error is enabled")
	}
	if shouldCleanupWorkspace(assertErr{}, nil, true) {
		t.Fatal("expected no cleanup on failure when keep-on-error is enabled")
	}
}

type assertErr struct{}

func (assertErr) Error() string { return "err" }

// ── dedupeKey ───────────────────────────────────────────────────────

func TestDedupeKey_NormalizesFields(t *testing.T) {
	f := model.Finding{
		Title:    "  SQL Injection  ",
		Category: "  SQL_INJECTION  ",
		Evidence: "some evidence text",
		FileRefs: []string{"b.go", "a.go"},
	}
	key := dedupeKey(f)
	// title and category should be lowered and trimmed
	if key != "sql injection|sql_injection|a.go,b.go|some evidence text" {
		t.Fatalf("unexpected dedupeKey: %q", key)
	}
}

func TestDedupeKey_TruncatesEvidence(t *testing.T) {
	long := ""
	for i := 0; i < 250; i++ {
		long += "x"
	}
	f := model.Finding{Title: "T", Category: "C", Evidence: long}
	key := dedupeKey(f)
	// evidence portion should be truncated to 200 chars
	parts := splitDedupeKey(key)
	if len(parts) != 4 {
		t.Fatalf("expected 4 parts, got %d", len(parts))
	}
	if len(parts[3]) != 200 {
		t.Fatalf("expected evidence truncated to 200, got %d", len(parts[3]))
	}
}

func TestDedupeKey_SortsFileRefs(t *testing.T) {
	f := model.Finding{Title: "T", Category: "C", FileRefs: []string{"z.go", "a.go", "m.go"}}
	key := dedupeKey(f)
	parts := splitDedupeKey(key)
	if parts[2] != "a.go,m.go,z.go" {
		t.Fatalf("expected sorted file refs, got %q", parts[2])
	}
}

func splitDedupeKey(key string) []string {
	var parts []string
	for _, p := range splitPipe(key) {
		parts = append(parts, p)
	}
	return parts
}

func splitPipe(s string) []string {
	result := []string{}
	current := ""
	for _, ch := range s {
		if ch == '|' {
			result = append(result, current)
			current = ""
		} else {
			current += string(ch)
		}
	}
	result = append(result, current)
	return result
}

// ── mergeSourceTracks ───────────────────────────────────────────────

func TestMergeSourceTracks_MergesAndDedupes(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want string
	}{
		{"simple merge", "appsec", "secrets_config", "appsec,secrets_config"},
		{"dedup", "appsec,secrets_config", "appsec", "appsec,secrets_config"},
		{"whitespace", "  appsec  ", "  secrets_config  ", "appsec,secrets_config"},
		{"empty a", "", "secrets_config", "secrets_config"},
		{"empty b", "appsec", "", "appsec"},
		{"both empty", "", "", ""},
		{"sorted output", "z_track,a_track", "m_track", "a_track,m_track,z_track"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeSourceTracks(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("mergeSourceTracks(%q, %q) = %q, want %q", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// ── severityWeight ──────────────────────────────────────────────────

func TestSeverityWeight_AllLevels(t *testing.T) {
	tests := []struct {
		sev  string
		want int
	}{
		{"critical", 0},
		{"high", 1},
		{"medium", 2},
		{"low", 3},
		{"info", 4},
		{"unknown", 4},
		{"", 4},
		{"  HIGH  ", 1},
		{"CRITICAL", 0},
	}
	for _, tt := range tests {
		t.Run(tt.sev, func(t *testing.T) {
			got := severityWeight(tt.sev)
			if got != tt.want {
				t.Errorf("severityWeight(%q) = %d, want %d", tt.sev, got, tt.want)
			}
		})
	}
}

// ── buildSeverityCounts ─────────────────────────────────────────────

func TestBuildSeverityCounts_MixedSeverities(t *testing.T) {
	findings := []model.Finding{
		{Severity: "critical"},
		{Severity: "high"},
		{Severity: "high"},
		{Severity: "medium"},
		{Severity: "low"},
		{Severity: "info"},
		{Severity: "unknown_sev"},
		{Severity: "  HIGH  "},
	}
	counts := buildSeverityCounts(findings)
	if counts["critical"] != 1 {
		t.Errorf("critical: got %d, want 1", counts["critical"])
	}
	if counts["high"] != 3 {
		t.Errorf("high: got %d, want 3", counts["high"])
	}
	if counts["medium"] != 1 {
		t.Errorf("medium: got %d, want 1", counts["medium"])
	}
	if counts["low"] != 1 {
		t.Errorf("low: got %d, want 1", counts["low"])
	}
	if counts["info"] != 2 {
		t.Errorf("info (including unknown): got %d, want 2", counts["info"])
	}
}

func TestBuildSeverityCounts_Empty(t *testing.T) {
	counts := buildSeverityCounts(nil)
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if counts[sev] != 0 {
			t.Errorf("%s: got %d, want 0", sev, counts[sev])
		}
	}
}

// ── buildCategoryCounts ─────────────────────────────────────────────

func TestBuildCategoryCounts_MixedCategories(t *testing.T) {
	findings := []model.Finding{
		{Category: "secrets"},
		{Category: "secrets"},
		{Category: "rce"},
		{Category: ""},
		{Category: "  SECRETS  "},
	}
	counts := buildCategoryCounts(findings)
	if counts["secrets"] != 3 {
		t.Errorf("secrets: got %d, want 3", counts["secrets"])
	}
	if counts["rce"] != 1 {
		t.Errorf("rce: got %d, want 1", counts["rce"])
	}
	if counts["general"] != 1 {
		t.Errorf("general (empty category): got %d, want 1", counts["general"])
	}
}

func TestBuildCategoryCounts_Empty(t *testing.T) {
	counts := buildCategoryCounts(nil)
	if len(counts) != 0 {
		t.Errorf("expected empty map, got %v", counts)
	}
}
