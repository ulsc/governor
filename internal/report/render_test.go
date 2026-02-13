package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"governor/internal/model"
)

func TestRenderMarkdown_BasicSections(t *testing.T) {
	r := model.AuditReport{
		RunMetadata:      model.RunMetadata{RunID: "20260213-000000", DurationMS: 1234},
		InputSummary:     model.InputSummary{InputPath: "/tmp/app", InputType: "folder", WorkspacePath: "/tmp/app"},
		CountsBySeverity: map[string]int{"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
		Findings: []model.Finding{{
			ID: "f1", Title: "Auth bypass", Severity: "critical", Category: "auth", SourceTrack: "appsec",
			Evidence: "route lacks auth", Impact: "account takeover", Remediation: "enforce middleware",
		}},
		WorkerSummaries: []model.WorkerResult{{Track: "appsec", Status: "success", FindingCount: 1, DurationMS: 100}},
	}

	md := RenderMarkdown(r)
	checks := []string{
		"# Governor Security Audit",
		"## Executive Summary",
		"## Worker Results",
		"## Findings",
		"[CRITICAL] Auth bypass",
	}
	for _, c := range checks {
		if !strings.Contains(md, c) {
			t.Fatalf("expected markdown to contain %q", c)
		}
	}
}

func TestRenderHTML_BasicSections(t *testing.T) {
	r := model.AuditReport{
		RunMetadata:      model.RunMetadata{RunID: "20260213-000000", DurationMS: 1234},
		InputSummary:     model.InputSummary{InputPath: "/tmp/app", InputType: "folder", WorkspacePath: "/tmp/app"},
		CountsBySeverity: map[string]int{"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
		Findings: []model.Finding{{
			ID: "f1", Title: "Auth bypass", Severity: "critical", Category: "auth", SourceTrack: "appsec",
			Evidence: "route lacks auth", Impact: "account takeover", Remediation: "enforce middleware",
		}},
		WorkerSummaries: []model.WorkerResult{{Track: "appsec", Status: "success", FindingCount: 1, DurationMS: 100}},
	}

	html := RenderHTML(r)
	checks := []string{
		"<!doctype html>",
		"Governor Security Audit",
		"Executive Summary",
		"Worker Results",
		"Findings",
		"Auth bypass",
		"badge-critical",
	}
	for _, c := range checks {
		if !strings.Contains(html, c) {
			t.Fatalf("expected HTML to contain %q", c)
		}
	}
}

func TestRenderHTML_EscapesUnsafeContent(t *testing.T) {
	r := model.AuditReport{
		RunMetadata:      model.RunMetadata{RunID: "run", DurationMS: 1},
		InputSummary:     model.InputSummary{InputPath: "/tmp/app", InputType: "folder", WorkspacePath: "/tmp/app"},
		CountsBySeverity: map[string]int{"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
		Findings: []model.Finding{{
			ID: "f1", Title: "<script>alert(1)</script>", Severity: "high", Category: "xss", SourceTrack: "appsec",
			Evidence: "x < y\nz & q", Impact: "impact", Remediation: "fix",
		}},
	}

	html := RenderHTML(r)
	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Fatalf("expected unsafe script payload to be escaped")
	}
	if !strings.Contains(html, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatalf("expected escaped script payload in output")
	}
	if !strings.Contains(html, "x &lt; y<br>z &amp; q") {
		t.Fatalf("expected multiline evidence to be escaped and joined with <br>")
	}
}

func TestWriteHTML_RedactsAndPersists(t *testing.T) {
	outDir := t.TempDir()
	outPath := filepath.Join(outDir, "audit.html")

	r := model.AuditReport{
		RunMetadata:      model.RunMetadata{RunID: "run", DurationMS: 1},
		InputSummary:     model.InputSummary{InputPath: "/tmp/app", InputType: "folder", WorkspacePath: "/tmp/app"},
		CountsBySeverity: map[string]int{"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
		Findings: []model.Finding{{
			ID: "f1", Title: "Credential in source", Severity: "high", Category: "secrets", SourceTrack: "appsec",
			Evidence: "password=supersecret12", Impact: "credential leak", Remediation: "rotate and remove",
		}},
	}

	if err := WriteHTML(outPath, r); err != nil {
		t.Fatalf("WriteHTML returned error: %v", err)
	}

	content, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read HTML artifact: %v", err)
	}
	artifact := string(content)
	if !strings.Contains(artifact, "Governor Security Audit") {
		t.Fatalf("expected HTML artifact header")
	}
	if strings.Contains(artifact, "supersecret12") {
		t.Fatalf("expected secret value to be redacted")
	}
	if !strings.Contains(artifact, "password=[REDACTED]") {
		t.Fatalf("expected redacted token marker in HTML artifact")
	}
}
