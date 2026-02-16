package scan

import (
	"encoding/json"
	"fmt"
	"strings"

	"governor/internal/model"
)

// FormatHuman formats findings as human-readable text for stdout.
func FormatHuman(findings []model.Finding) string {
	if len(findings) == 0 {
		return "No findings.\n"
	}

	var b strings.Builder
	for _, f := range findings {
		sev := strings.ToUpper(strings.TrimSpace(f.Severity))
		if sev == "" {
			sev = "UNKNOWN"
		}
		b.WriteString(fmt.Sprintf("[%-8s] %s\n", sev, f.Title))
		if len(f.FileRefs) > 0 {
			b.WriteString(fmt.Sprintf("  file: %s\n", strings.Join(f.FileRefs, ", ")))
		}
		evidence := strings.TrimSpace(f.Evidence)
		if evidence != "" {
			if len(evidence) > 120 {
				evidence = evidence[:120] + "..."
			}
			evidence = strings.ReplaceAll(evidence, "\n", " ")
			b.WriteString(fmt.Sprintf("  evidence: %s\n", evidence))
		}
		if strings.TrimSpace(f.Remediation) != "" {
			rem := strings.TrimSpace(f.Remediation)
			rem = strings.ReplaceAll(rem, "\n", " ")
			if len(rem) > 200 {
				rem = rem[:200] + "..."
			}
			b.WriteString(fmt.Sprintf("  remediation: %s\n", rem))
		}
		b.WriteString("\n")
	}

	b.WriteString(fmt.Sprintf("%d finding(s) detected.\n", len(findings)))
	return b.String()
}

// FormatJSON formats findings as a JSON array.
func FormatJSON(findings []model.Finding) (string, error) {
	if findings == nil {
		findings = []model.Finding{}
	}
	b, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal findings: %w", err)
	}
	return string(b), nil
}
