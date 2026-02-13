package prompt

import (
	"fmt"
	"strings"

	"governor/internal/checks"
	"governor/internal/model"
	"governor/internal/sanitize"
)

const Version = "v1.0.0"

func BuildForCheck(check checks.Definition, manifest model.InputManifest) string {
	check = checks.NormalizeDefinition(check)

	base := fmt.Sprintf(`You are Governor security worker "%s".

Task:
- Audit this source code for security findings in your assigned track.
- Focus only on real, actionable issues.
- Return JSON only that matches the provided output schema.

Repository context:
- Root path: %s
- Included files: %d
- Included bytes: %d
- Input type: %s

Severity scale:
- critical, high, medium, low, info

Finding quality rules:
- Include file paths in file_refs when available.
- Always include "file_refs" (use [] when no file path is available).
- Always include "confidence" between 0 and 1.
- Include concise evidence and realistic remediation steps.
- Never include plaintext secrets or token values; redact sensitive values.
- Avoid duplicates.
- If no findings, return findings: [] with a short summary.
`, check.ID, sanitize.PathInline(manifest.RootPath), manifest.IncludedFiles, manifest.IncludedBytes, manifest.InputType)

	fileHints := make([]string, 0, min(25, len(manifest.Files)))
	for i, f := range manifest.Files {
		if i >= 25 {
			break
		}
		fileHints = append(fileHints, "- "+sanitize.PathInline(f.Path))
	}

	checkDetails := fmt.Sprintf(`Check metadata:
- ID: %s
- Name: %s
- Description: %s
- Source: %s
- Status: %s
`, valueOrFallback(check.ID, "unknown"), valueOrFallback(check.Name, "unnamed"), valueOrFallback(check.Description, "none"), check.Source, check.Status)

	scope := ""
	if len(check.Scope.IncludeGlobs) > 0 || len(check.Scope.ExcludeGlobs) > 0 {
		scope += "Scope hints:\n"
		if len(check.Scope.IncludeGlobs) > 0 {
			scope += "- Include globs:\n"
			for _, g := range check.Scope.IncludeGlobs {
				scope += "  - " + g + "\n"
			}
		}
		if len(check.Scope.ExcludeGlobs) > 0 {
			scope += "- Exclude globs:\n"
			for _, g := range check.Scope.ExcludeGlobs {
				scope += "  - " + g + "\n"
			}
		}
		scope += "\n"
	}

	instructions := "Check-specific instructions:\n" + strings.TrimSpace(check.Instructions) + "\n"
	return base + "\n" + checkDetails + "\n" + scope + instructions + "\nKey files sample:\n" + strings.Join(fileHints, "\n") + "\n"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func valueOrFallback(value string, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}
