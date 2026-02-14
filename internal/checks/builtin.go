package checks

func Builtins() []Definition {
	return []Definition{
		{
			APIVersion: APIVersion,
			ID:         "appsec",
			Name:       "Application Security",
			Status:     StatusEnabled,
			Source:     SourceBuiltin,
			Engine:     EngineAI,
			Description: "Authentication, authorization, input validation, data exposure, " +
				"and exploitable application logic flaws.",
			Instructions: `Track focus: application security
- Authentication and authorization flaws
- Input validation issues and injection risk
- Data exposure and insecure direct object access
- Dangerous deserialization / SSRF / command execution paths`,
			CategoriesHint: []string{"auth", "input_validation", "data_exposure", "rce"},
			SeverityHint:   "high",
			ConfidenceHint: 0.8,
			Origin: Origin{
				Method: "builtin",
			},
		},
		{
			APIVersion: APIVersion,
			ID:         "deps_supply_chain",
			Name:       "Dependencies and Supply Chain",
			Status:     StatusEnabled,
			Source:     SourceBuiltin,
			Engine:     EngineAI,
			Description: "Dependency, lockfile, package source, and CI/CD supply-chain " +
				"security risk indicators.",
			Instructions: `Track focus: dependency and supply-chain security
- Risky dependency usage and lockfile hygiene
- Unpinned tooling/package sources
- Insecure CI/CD scripts affecting supply chain trust
- Build/runtime package risk indicators in repo configuration`,
			CategoriesHint: []string{"supply_chain", "dependencies", "ci_cd"},
			SeverityHint:   "medium",
			ConfidenceHint: 0.7,
			Origin: Origin{
				Method: "builtin",
			},
		},
		{
			APIVersion: APIVersion,
			ID:         "secrets_config",
			Name:       "Secrets and Security Configuration",
			Status:     StatusEnabled,
			Source:     SourceBuiltin,
			Engine:     EngineAI,
			Description: "Hardcoded secrets, insecure defaults, unsafe environment handling, " +
				"and missing protection headers.",
			Instructions: `Track focus: secrets and security configuration
- Hardcoded secrets/tokens/keys
- Insecure default configs and env handling
- Missing transport/security headers for web apps
- Overly broad permissions in config/infra files`,
			CategoriesHint: []string{"secrets", "configuration"},
			SeverityHint:   "high",
			ConfidenceHint: 0.8,
			Origin: Origin{
				Method: "builtin",
			},
		},
		{
			APIVersion: APIVersion,
			ID:         "prompt_injection",
			Name:       "Prompt Injection Signals",
			Status:     StatusEnabled,
			Source:     SourceBuiltin,
			Engine:     EngineRule,
			Description: "Deterministic detection of prompt-injection and jailbreak override " +
				"phrases in prompts, policy docs, and prompt-bearing source files.",
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
						Remediation: "Treat prompt content as untrusted input and enforce policy guardrails before model execution.",
						MaxMatches:  5,
					},
					{
						ID:          "reveal-system-prompt",
						Kind:        RuleDetectorContains,
						Pattern:     "reveal the system prompt",
						Title:       "System-prompt exfiltration phrase detected",
						Category:    "prompt_injection",
						Severity:    "high",
						Confidence:  0.8,
						Remediation: "Block instructions requesting hidden prompts or privileged model configuration details.",
						MaxMatches:  5,
					},
					{
						ID:          "jailbreak-override-pattern",
						Kind:        RuleDetectorRegex,
						Pattern:     `(?i)(disregard|forget|bypass).{0,80}(policy|guardrail|safety|instruction)`,
						Title:       "Jailbreak override pattern detected",
						Category:    "prompt_injection",
						Severity:    "medium",
						Confidence:  0.7,
						Remediation: "Introduce strict prompt filtering and deny model directives that attempt to bypass policy controls.",
						MaxMatches:  5,
					},
				},
			},
			Scope: Scope{
				IncludeGlobs: []string{
					"**/*.md",
					"**/*.txt",
					"**/*.yaml",
					"**/*.yml",
					"**/*.json",
					"**/*.go",
					"**/*.ts",
					"**/*.js",
					"**/*.py",
				},
				ExcludeGlobs: []string{
					"**/node_modules/**",
					"**/vendor/**",
				},
			},
			CategoriesHint: []string{"prompt_injection", "input_validation"},
			SeverityHint:   "high",
			ConfidenceHint: 0.75,
			Origin: Origin{
				Method: "builtin",
			},
		},
	}
}
