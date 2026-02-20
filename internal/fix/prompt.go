package fix

import (
	"fmt"
	"strings"

	"governor/internal/model"
	"governor/internal/sanitize"
)

func buildPrompt(report model.AuditReport, findings []model.Finding) string {
	var b strings.Builder

	b.WriteString("You are Governor fix suggestion worker.\n\n")
	b.WriteString("Task:\n")
	b.WriteString("- Generate file-specific fix suggestions for the findings below.\n")
	b.WriteString("- Return JSON only that matches the provided output schema.\n")
	b.WriteString("- Do not produce unified diffs, patch hunks, or full file rewrites.\n")
	b.WriteString("- Provide concrete, ordered edit steps for each affected file.\n")
	b.WriteString("- Keep fixes minimal and security-focused.\n")
	b.WriteString("- Never include plaintext secrets or token values.\n\n")

	b.WriteString("Output quality rules:\n")
	b.WriteString("- Every suggestion must map back to a finding_id.\n")
	b.WriteString("- Use repository-relative file paths in files[].path.\n")
	b.WriteString("- Use concise imperative steps in files[].instructions.\n")
	b.WriteString("- Include validation_steps for tests or runtime verification.\n")
	b.WriteString("- Include risk_notes when a change might alter behavior.\n")
	b.WriteString("- Confidence must be between 0 and 1.\n\n")

	b.WriteString("Source audit context:\n")
	b.WriteString(fmt.Sprintf("- Run ID: %s\n", strings.TrimSpace(report.RunMetadata.RunID)))
	b.WriteString(fmt.Sprintf("- Input path: %s\n", sanitize.PathInline(report.InputSummary.InputPath)))
	b.WriteString(fmt.Sprintf("- Findings in this request: %d\n\n", len(findings)))

	b.WriteString("Findings:\n")
	for idx, finding := range findings {
		b.WriteString(fmt.Sprintf("%d) finding_id=%s\n", idx+1, sanitize.PathInline(strings.TrimSpace(finding.ID))))
		b.WriteString(fmt.Sprintf("   title=%s\n", sanitize.PathInline(strings.TrimSpace(finding.Title))))
		b.WriteString(fmt.Sprintf("   severity=%s category=%s check=%s confidence=%.2f exploitability=%s\n",
			strings.ToLower(strings.TrimSpace(finding.Severity)),
			strings.ToLower(strings.TrimSpace(finding.Category)),
			sanitize.PathInline(strings.TrimSpace(finding.SourceTrack)),
			finding.Confidence,
			strings.ToLower(strings.TrimSpace(finding.Exploitability)),
		))
		if len(finding.FileRefs) > 0 {
			fileRefs := make([]string, 0, len(finding.FileRefs))
			for _, fileRef := range finding.FileRefs {
				fileRef = sanitize.PathInline(fileRef)
				if strings.TrimSpace(fileRef) == "" {
					continue
				}
				fileRefs = append(fileRefs, fileRef)
			}
			if len(fileRefs) > 0 {
				b.WriteString("   file_refs=" + strings.Join(fileRefs, ", ") + "\n")
			}
		}
		if len(finding.AttackPath) > 0 {
			attackPath := make([]string, 0, len(finding.AttackPath))
			for _, step := range finding.AttackPath {
				step = sanitize.PathInline(step)
				if strings.TrimSpace(step) == "" {
					continue
				}
				attackPath = append(attackPath, step)
			}
			if len(attackPath) > 0 {
				b.WriteString("   attack_path=" + strings.Join(attackPath, " -> ") + "\n")
			}
		}
		if evidence := compactText(finding.Evidence, 260); evidence != "" {
			b.WriteString("   evidence=" + evidence + "\n")
		}
		if remediation := compactText(finding.Remediation, 260); remediation != "" {
			b.WriteString("   current_remediation=" + remediation + "\n")
		}
		b.WriteString("\n")
	}

	return b.String()
}

func compactText(raw string, limit int) string {
	raw = sanitize.PathInline(raw)
	raw = strings.Join(strings.Fields(raw), " ")
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	if limit > 0 && len(raw) > limit {
		return raw[:limit] + "..."
	}
	return raw
}
