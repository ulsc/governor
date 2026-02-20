package fix

import (
	"encoding/json"
	"fmt"
	"strings"

	"governor/internal/model"
	"governor/internal/redact"
	"governor/internal/safefile"
)

func writeJSON(path string, report model.FixReport) error {
	report = redactFixReport(report)
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal fix report: %w", err)
	}
	if err := safefile.WriteFileAtomic(path, b, 0o600); err != nil {
		return fmt.Errorf("write fix json: %w", err)
	}
	return nil
}

func writeMarkdown(path string, report model.FixReport) error {
	report = redactFixReport(report)
	content := renderMarkdown(report)
	if err := safefile.WriteFileAtomic(path, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write fix markdown: %w", err)
	}
	return nil
}

func renderMarkdown(report model.FixReport) string {
	var b strings.Builder

	b.WriteString("# Governor Fix Suggestions\n\n")
	b.WriteString(fmt.Sprintf("- Generated at: `%s`\n", report.GeneratedAt.UTC().Format("2006-01-02T15:04:05Z")))
	b.WriteString(fmt.Sprintf("- Source audit: `%s`\n", safeInline(report.SourceAudit)))
	if strings.TrimSpace(report.SourceRunID) != "" {
		b.WriteString(fmt.Sprintf("- Source run id: `%s`\n", safeInline(report.SourceRunID)))
	}
	if strings.TrimSpace(report.AIProfile) != "" {
		b.WriteString(fmt.Sprintf("- AI profile: `%s`\n", safeInline(report.AIProfile)))
	}
	if strings.TrimSpace(report.AIProvider) != "" {
		b.WriteString(fmt.Sprintf("- AI provider: `%s`\n", safeInline(report.AIProvider)))
	}
	if strings.TrimSpace(report.AIModel) != "" {
		b.WriteString(fmt.Sprintf("- AI model: `%s`\n", safeInline(report.AIModel)))
	}
	b.WriteString(fmt.Sprintf("- Findings selected: %d of %d\n", report.Selected, report.TotalFindings))
	b.WriteString(fmt.Sprintf("- Suggestions: %d\n\n", len(report.Suggestions)))

	if len(report.Warnings) > 0 {
		b.WriteString("## Warnings\n")
		for _, warning := range report.Warnings {
			b.WriteString(fmt.Sprintf("- %s\n", safeInline(warning)))
		}
		b.WriteString("\n")
	}
	if len(report.Errors) > 0 {
		b.WriteString("## Errors\n")
		for _, msg := range report.Errors {
			b.WriteString(fmt.Sprintf("- %s\n", safeInline(msg)))
		}
		b.WriteString("\n")
	}

	if len(report.Suggestions) == 0 {
		b.WriteString("No fix suggestions generated.\n")
		return b.String()
	}

	b.WriteString("## Suggestions\n\n")
	for i, suggestion := range report.Suggestions {
		b.WriteString(fmt.Sprintf("### %d. %s\n", i+1, safeInline(suggestion.Title)))
		if strings.TrimSpace(suggestion.FindingID) != "" {
			b.WriteString(fmt.Sprintf("- Finding ID: `%s`\n", safeInline(suggestion.FindingID)))
		}
		if strings.TrimSpace(suggestion.SourceTrack) != "" {
			b.WriteString(fmt.Sprintf("- Check: `%s`\n", safeInline(suggestion.SourceTrack)))
		}
		if strings.TrimSpace(suggestion.Priority) != "" {
			b.WriteString(fmt.Sprintf("- Priority: `%s`\n", safeInline(strings.ToLower(suggestion.Priority))))
		}
		if suggestion.Confidence > 0 {
			b.WriteString(fmt.Sprintf("- Confidence: `%.2f`\n", suggestion.Confidence))
		}
		if strings.TrimSpace(suggestion.Summary) != "" {
			b.WriteString(fmt.Sprintf("- Summary: %s\n", safeInline(suggestion.Summary)))
		}

		if len(suggestion.Files) > 0 {
			b.WriteString("\n#### File Changes\n")
			for _, file := range suggestion.Files {
				line := "- `" + safeInline(file.Path) + "`"
				if strings.TrimSpace(file.ChangeType) != "" {
					line += " (" + safeInline(strings.ToLower(file.ChangeType)) + ")"
				}
				b.WriteString(line + "\n")
				for idx, instruction := range file.Instructions {
					b.WriteString(fmt.Sprintf("  %d. %s\n", idx+1, safeInline(instruction)))
				}
				for _, loc := range file.CodeLocations {
					b.WriteString(fmt.Sprintf("  - Location hint: `%s`\n", safeInline(loc)))
				}
			}
		}

		if len(suggestion.ValidationSteps) > 0 {
			b.WriteString("\n#### Validation Steps\n")
			for idx, step := range suggestion.ValidationSteps {
				b.WriteString(fmt.Sprintf("%d. %s\n", idx+1, safeInline(step)))
			}
		}

		if len(suggestion.RiskNotes) > 0 {
			b.WriteString("\n#### Risk Notes\n")
			for _, note := range suggestion.RiskNotes {
				b.WriteString(fmt.Sprintf("- %s\n", safeInline(note)))
			}
		}

		b.WriteString("\n")
	}

	return b.String()
}

func redactFixReport(in model.FixReport) model.FixReport {
	in.SourceAudit = redact.Text(in.SourceAudit)
	in.OutDir = redact.Text(in.OutDir)
	in.Warnings = redact.Strings(in.Warnings)
	in.Errors = redact.Strings(in.Errors)
	if len(in.Suggestions) == 0 {
		return in
	}

	suggestions := make([]model.FixSuggestion, 0, len(in.Suggestions))
	for _, suggestion := range in.Suggestions {
		suggestion.Title = redact.Text(suggestion.Title)
		suggestion.Summary = redact.Text(suggestion.Summary)
		suggestion.ValidationSteps = redact.Strings(suggestion.ValidationSteps)
		suggestion.RiskNotes = redact.Strings(suggestion.RiskNotes)
		if len(suggestion.Files) > 0 {
			files := make([]model.FixFileChange, 0, len(suggestion.Files))
			for _, file := range suggestion.Files {
				file.Path = redact.Text(file.Path)
				file.Instructions = redact.Strings(file.Instructions)
				file.CodeLocations = redact.Strings(file.CodeLocations)
				files = append(files, file)
			}
			suggestion.Files = files
		}
		suggestions = append(suggestions, suggestion)
	}
	in.Suggestions = suggestions
	return in
}

func safeInline(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.ReplaceAll(raw, "\n", " ")
	raw = strings.ReplaceAll(raw, "\r", " ")
	raw = strings.ReplaceAll(raw, "\t", " ")
	if len(raw) > 400 {
		raw = raw[:400] + "..."
	}
	return raw
}
