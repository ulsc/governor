package checks

import (
	"fmt"
	"sort"
	"strings"
)

type Template struct {
	ID             string
	Name           string
	Engine         Engine
	Description    string
	Instructions   string
	Rule           Rule
	CategoriesHint []string
	SeverityHint   string
	ConfidenceHint float64
	IncludeGlobs   []string
	ExcludeGlobs   []string
}

func Templates() []Template {
	templates := []Template{
		{
			ID:          "blank",
			Name:        "Blank Custom Check",
			Engine:      EngineAI,
			Description: "General custom check scaffold.",
			Instructions: `Audit for meaningful, actionable security issues for this track.
- Prioritize concrete vulnerabilities over style issues.
- Include realistic remediation aligned to this codebase.`,
			CategoriesHint: []string{"custom"},
			SeverityHint:   "medium",
			ConfidenceHint: 0.8,
			IncludeGlobs:   []string{"**/*"},
			ExcludeGlobs:   []string{"**/node_modules/**", "**/vendor/**"},
		},
		{
			ID:          "authz-missing-checks",
			Name:        "Authorization Enforcement",
			Engine:      EngineAI,
			Description: "Detect sensitive routes/actions missing authorization checks.",
			Instructions: `Identify privileged routes/actions and verify authorization checks are enforced.
- Confirm role/permission checks execute before sensitive operations.
- Flag IDOR patterns where user-scoped resources are not ownership-validated.`,
			CategoriesHint: []string{"auth", "authorization"},
			SeverityHint:   "high",
			ConfidenceHint: 0.85,
			IncludeGlobs:   []string{"**/*.go", "**/*.ts", "**/*.js", "**/*.py"},
			ExcludeGlobs:   []string{"**/node_modules/**", "**/vendor/**"},
		},
		{
			ID:          "secrets-handling",
			Name:        "Secrets Handling",
			Engine:      EngineAI,
			Description: "Detect hardcoded secrets and unsafe secret handling patterns.",
			Instructions: `Find hardcoded credentials, tokens, or private keys and unsafe secret flows.
- Check config defaults and environment handling for secret leakage.
- Flag secrets in source, logs, templates, and sample artifacts.`,
			CategoriesHint: []string{"secrets", "configuration"},
			SeverityHint:   "high",
			ConfidenceHint: 0.85,
			IncludeGlobs:   []string{"**/*"},
			ExcludeGlobs:   []string{"**/node_modules/**", "**/vendor/**", "**/*.png", "**/*.jpg"},
		},
		{
			ID:          "input-validation",
			Name:        "Input Validation and Injection",
			Engine:      EngineAI,
			Description: "Detect injection-prone code paths and missing input validation.",
			Instructions: `Review request and parser boundaries for injection and validation issues.
- Flag SQL/NoSQL/command/template injection sinks with untrusted input.
- Validate canonicalization and strict typing for attacker-controlled fields.`,
			CategoriesHint: []string{"input_validation", "injection"},
			SeverityHint:   "high",
			ConfidenceHint: 0.8,
			IncludeGlobs:   []string{"**/*.go", "**/*.ts", "**/*.js", "**/*.py", "**/*.java"},
			ExcludeGlobs:   []string{"**/node_modules/**", "**/vendor/**"},
		},
		{
			ID:          "dependency-supply-chain",
			Name:        "Dependency and Supply Chain",
			Engine:      EngineAI,
			Description: "Detect risky dependency and build pipeline trust issues.",
			Instructions: `Inspect dependency, package source, and CI/CD trust boundaries.
- Flag unpinned or unsafe package/tooling sources.
- Identify high-risk pipeline patterns that permit tampering or credential misuse.`,
			CategoriesHint: []string{"dependencies", "supply_chain", "ci_cd"},
			SeverityHint:   "medium",
			ConfidenceHint: 0.75,
			IncludeGlobs:   []string{"**/go.mod", "**/go.sum", "**/package.json", "**/package-lock.json", "**/pnpm-lock.yaml", "**/requirements*.txt", "**/.github/workflows/**"},
			ExcludeGlobs:   []string{"**/node_modules/**", "**/vendor/**"},
		},
		{
			ID:          "config-hardening",
			Name:        "Security Configuration Hardening",
			Engine:      EngineAI,
			Description: "Detect insecure defaults and missing hardening controls.",
			Instructions: `Audit configuration for insecure defaults and weak hardening posture.
- Check auth/session, TLS/transport, CORS, and security headers where applicable.
- Flag broad permissions and dangerous toggles in deploy/runtime config.`,
			CategoriesHint: []string{"configuration", "hardening"},
			SeverityHint:   "medium",
			ConfidenceHint: 0.75,
			IncludeGlobs:   []string{"**/*.yaml", "**/*.yml", "**/*.json", "**/*.toml", "**/*.env*", "**/*.go", "**/*.ts"},
			ExcludeGlobs:   []string{"**/node_modules/**", "**/vendor/**"},
		},
		{
			ID:          "web-headers",
			Name:        "Web Security Headers",
			Engine:      EngineAI,
			Description: "Detect missing or unsafe HTTP security header configuration.",
			Instructions: `Review web middleware/server configuration for security headers.
- Check for HSTS, CSP, X-Frame-Options/frame-ancestors, and secure cookie attributes.
- Flag unsafe defaults that increase XSS/clickjacking risk.`,
			CategoriesHint: []string{"web", "headers", "configuration"},
			SeverityHint:   "medium",
			ConfidenceHint: 0.7,
			IncludeGlobs:   []string{"**/*.go", "**/*.ts", "**/*.js", "**/*.py", "**/*.java"},
			ExcludeGlobs:   []string{"**/node_modules/**", "**/vendor/**"},
		},
		{
			ID:          "prompt-injection-rule",
			Name:        "Prompt Injection (Deterministic Rule)",
			Engine:      EngineRule,
			Description: "Deterministic prompt-injection and jailbreak-phrase detection.",
			Rule: Rule{
				Target: RuleTargetFileContent,
				Detectors: []RuleDetector{
					{
						ID:          "ignore-previous-instructions",
						Kind:        RuleDetectorContains,
						Pattern:     "ignore previous instructions",
						Title:       "Prompt injection override phrase detected",
						Category:    "prompt_injection",
						Severity:    "high",
						Confidence:  0.75,
						MaxMatches:  5,
						Remediation: "Treat prompt content as untrusted input and enforce strict policy controls.",
					},
					{
						ID:          "reveal-system-prompt",
						Kind:        RuleDetectorContains,
						Pattern:     "reveal the system prompt",
						Title:       "System prompt exfiltration phrase detected",
						Category:    "prompt_injection",
						Severity:    "high",
						Confidence:  0.8,
						MaxMatches:  5,
						Remediation: "Block directives requesting hidden prompts or privileged model configuration.",
					},
				},
			},
			CategoriesHint: []string{"prompt_injection", "input_validation"},
			SeverityHint:   "high",
			ConfidenceHint: 0.75,
			IncludeGlobs:   []string{"**/*.md", "**/*.txt", "**/*.yaml", "**/*.yml", "**/*.json", "**/*.go", "**/*.ts", "**/*.js", "**/*.py"},
			ExcludeGlobs:   []string{"**/node_modules/**", "**/vendor/**"},
		},
	}
	sort.Slice(templates, func(i, j int) bool {
		return templates[i].ID < templates[j].ID
	})
	return templates
}

func LookupTemplate(id string) (Template, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	if id == "" {
		id = "blank"
	}
	for _, template := range Templates() {
		if template.ID == id {
			return template, true
		}
	}
	return Template{}, false
}

func TemplateIDs() []string {
	templates := Templates()
	out := make([]string, 0, len(templates))
	for _, template := range templates {
		out = append(out, template.ID)
	}
	return out
}

func ParseStatus(raw string) (Status, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return StatusDraft, nil
	case string(StatusDraft):
		return StatusDraft, nil
	case string(StatusEnabled):
		return StatusEnabled, nil
	case string(StatusDisabled):
		return StatusDisabled, nil
	default:
		return "", fmt.Errorf("status must be draft|enabled|disabled")
	}
}
