package matrix

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"governor/internal/safefile"
)

type TargetSummary struct {
	Name         string `json:"name"`
	Path         string `json:"path"`
	Status       string `json:"status"`
	RunDir       string `json:"run_dir,omitempty"`
	JSONPath     string `json:"json_path,omitempty"`
	MarkdownPath string `json:"markdown_path,omitempty"`
	HTMLPath     string `json:"html_path,omitempty"`
	Findings     int    `json:"findings"`
	Errors       int    `json:"errors"`
	ExitCode     int    `json:"exit_code"`
	DurationMS   int64  `json:"duration_ms"`
}

type Summary struct {
	APIVersion    string          `json:"api_version"`
	ConfigPath    string          `json:"config_path"`
	StartedAt     time.Time       `json:"started_at"`
	CompletedAt   time.Time       `json:"completed_at"`
	DurationMS    int64           `json:"duration_ms"`
	Passed        bool            `json:"passed"`
	FailedTargets int             `json:"failed_targets"`
	TotalFindings int             `json:"total_findings"`
	Targets       []TargetSummary `json:"targets"`
}

func WriteSummary(outDir string, summary Summary) (jsonPath string, markdownPath string, err error) {
	jsonPath = filepath.Join(outDir, "matrix-summary.json")
	markdownPath = filepath.Join(outDir, "matrix-summary.md")

	b, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return "", "", fmt.Errorf("marshal matrix summary: %w", err)
	}
	if err := safefile.WriteFileAtomic(jsonPath, b, 0o600); err != nil {
		return "", "", fmt.Errorf("write matrix summary json: %w", err)
	}
	if err := safefile.WriteFileAtomic(markdownPath, []byte(RenderSummaryMarkdown(summary)), 0o600); err != nil {
		return "", "", fmt.Errorf("write matrix summary markdown: %w", err)
	}
	return jsonPath, markdownPath, nil
}

func RenderSummaryMarkdown(summary Summary) string {
	var b strings.Builder
	b.WriteString("# Matrix Summary\n\n")
	status := "pass"
	if !summary.Passed {
		status = "fail"
	}
	b.WriteString(fmt.Sprintf("- Status: **%s**\n", status))
	b.WriteString(fmt.Sprintf("- Config: `%s`\n", summary.ConfigPath))
	b.WriteString(fmt.Sprintf("- Duration: `%d ms`\n", summary.DurationMS))
	b.WriteString(fmt.Sprintf("- Failed targets: %d\n", summary.FailedTargets))
	b.WriteString(fmt.Sprintf("- Total findings: %d\n\n", summary.TotalFindings))
	b.WriteString("## Targets\n\n")
	for _, target := range summary.Targets {
		b.WriteString(fmt.Sprintf("- `%s`: status=%s, findings=%d, exit=%d, duration=%dms\n", target.Name, target.Status, target.Findings, target.ExitCode, target.DurationMS))
	}
	return b.String()
}
