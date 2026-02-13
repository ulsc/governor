package cmd

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"governor/internal/app"
	"governor/internal/model"
)

func TestPrintAuditSummary_IncludesHTMLPath(t *testing.T) {
	report := model.AuditReport{
		RunMetadata: model.RunMetadata{
			RunID:         "20260213-123456",
			EnabledChecks: 2,
			BuiltInChecks: 2,
			CustomChecks:  0,
		},
	}
	paths := app.ArtifactPaths{
		RunDir:       "/tmp/run",
		MarkdownPath: "/tmp/run/audit.md",
		JSONPath:     "/tmp/run/audit.json",
		HTMLPath:     "/tmp/run/audit.html",
	}

	out := captureStdout(t, func() {
		printAuditSummary(report, paths)
	})

	if !strings.Contains(out, "audit html:     /tmp/run/audit.html") {
		t.Fatalf("expected summary to include HTML artifact path, got:\n%s", out)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	os.Stdout = w
	defer func() {
		os.Stdout = oldStdout
	}()

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()

	fn()
	_ = w.Close()
	out := <-done
	_ = r.Close()

	return out
}
