package checks

func Builtins() []Definition {
	return []Definition{
		{
			APIVersion: APIVersion,
			ID:         "appsec",
			Name:       "Application Security",
			Status:     StatusEnabled,
			Source:     SourceBuiltin,
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
	}
}
