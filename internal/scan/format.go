package scan

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
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

// severityOrder maps normalized severity strings to their sort rank (lower = more severe).
var severityOrder = map[string]int{
	"critical": 0,
	"high":     1,
	"medium":   2,
	"low":      3,
	"info":     4,
}

// Lipgloss styles for each severity level.
var (
	styleCritical    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15")).Background(lipgloss.Color("9"))
	styleHigh        = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("9"))
	styleMedium      = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("11"))
	styleLow         = lipgloss.NewStyle().Faint(true)
	styleInfo        = lipgloss.NewStyle().Faint(true)
	styleFileRef     = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
	styleRemediation = lipgloss.NewStyle().Faint(true)
)

// styleSeverity applies the appropriate lipgloss style to a severity label.
func styleSeverity(sev string) string {
	label := strings.ToUpper(sev)
	switch strings.ToLower(sev) {
	case "critical":
		return styleCritical.Render(label)
	case "high":
		return styleHigh.Render(label)
	case "medium":
		return styleMedium.Render(label)
	case "low":
		return styleLow.Render(label)
	case "info":
		return styleInfo.Render(label)
	default:
		return label
	}
}

// FormatHumanColorized formats findings as color-coded, severity-sorted terminal output.
// When verbose is true, evidence is included for each finding.
func FormatHumanColorized(findings []model.Finding, verbose bool) string {
	if len(findings) == 0 {
		return "No findings.\n"
	}

	// Sort findings by severity (critical first).
	sorted := make([]model.Finding, len(findings))
	copy(sorted, findings)
	sort.SliceStable(sorted, func(i, j int) bool {
		oi := severityOrder[strings.ToLower(strings.TrimSpace(sorted[i].Severity))]
		oj := severityOrder[strings.ToLower(strings.TrimSpace(sorted[j].Severity))]
		return oi < oj
	})

	// Count findings per severity for the summary header.
	counts := make(map[string]int)
	for _, f := range sorted {
		key := strings.ToLower(strings.TrimSpace(f.Severity))
		if key == "" {
			key = "unknown"
		}
		counts[key]++
	}

	var b strings.Builder

	// Summary header.
	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if c, ok := counts[sev]; ok && c > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c, sev))
		}
	}
	b.WriteString(fmt.Sprintf("governor audit complete — %d findings (%s)\n\n", len(sorted), strings.Join(parts, ", ")))

	// Render each finding.
	for _, f := range sorted {
		sev := strings.ToLower(strings.TrimSpace(f.Severity))
		if sev == "" {
			sev = "unknown"
		}
		b.WriteString(fmt.Sprintf("  %s  %s\n", styleSeverity(sev), f.Title))

		if len(f.FileRefs) > 0 {
			b.WriteString(fmt.Sprintf("    %s\n", styleFileRef.Render(strings.Join(f.FileRefs, ", "))))
		}

		if verbose {
			evidence := strings.TrimSpace(f.Evidence)
			if evidence != "" {
				if len(evidence) > 120 {
					evidence = evidence[:120] + "..."
				}
				evidence = strings.ReplaceAll(evidence, "\n", " ")
				b.WriteString(fmt.Sprintf("    evidence: %s\n", evidence))
			}
		}

		if strings.TrimSpace(f.Remediation) != "" {
			rem := strings.TrimSpace(f.Remediation)
			rem = strings.ReplaceAll(rem, "\n", " ")
			if len(rem) > 200 {
				rem = rem[:200] + "..."
			}
			b.WriteString(fmt.Sprintf("    %s\n", styleRemediation.Render("→ "+rem)))
		}

		b.WriteString("\n")
	}

	return b.String()
}
