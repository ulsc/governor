package policy

import (
	"fmt"
	"strings"
	"time"
)

func Validate(p Policy) error {
	switch strings.TrimSpace(p.APIVersion) {
	case APIVersion, APIVersionV2:
		// supported
	default:
		return fmt.Errorf("unsupported policy api_version %q", p.APIVersion)
	}
	if err := validateGate("defaults", p.Defaults); err != nil {
		return err
	}
	for i, rule := range p.Rules {
		prefix := fmt.Sprintf("rules[%d]", i)
		if err := validateGate(prefix+".enforce", rule.Enforce); err != nil {
			return err
		}
		if err := validateMatchSpec(prefix+".when", rule.When); err != nil {
			return err
		}
	}
	seenWaiver := map[string]struct{}{}
	for i, waiver := range p.Waivers {
		if waiver.ID == "" {
			return fmt.Errorf("waivers[%d].id is required", i)
		}
		if waiver.Reason == "" {
			return fmt.Errorf("waivers[%d].reason is required", i)
		}
		key := strings.ToLower(waiver.ID)
		if _, exists := seenWaiver[key]; exists {
			return fmt.Errorf("duplicate waiver id %q", waiver.ID)
		}
		seenWaiver[key] = struct{}{}
		if waiver.Expires != "" {
			if _, err := time.Parse("2006-01-02", waiver.Expires); err != nil {
				return fmt.Errorf("waivers[%d].expires must be YYYY-MM-DD", i)
			}
		}
		if err := validateMatchSpec(fmt.Sprintf("waivers[%d].match", i), waiver.Match); err != nil {
			return err
		}
	}
	return nil
}

func validateGate(prefix string, gate Gate) error {
	if gate.FailOnSeverity != "" && !isValidSeverity(gate.FailOnSeverity) {
		return fmt.Errorf("%s.fail_on_severity must be one of critical|high|medium|low|info|none", prefix)
	}
	if gate.FailOnExploitability != "" && !isValidExploitability(gate.FailOnExploitability) {
		return fmt.Errorf("%s.fail_on_exploitability must be one of confirmed-path|reachable|theoretical|none", prefix)
	}
	if gate.MaxSuppressionRatio != nil {
		if *gate.MaxSuppressionRatio != -1 && (*gate.MaxSuppressionRatio < 0 || *gate.MaxSuppressionRatio > 1) {
			return fmt.Errorf("%s.max_suppression_ratio must be between 0.0 and 1.0 (or -1 to disable)", prefix)
		}
	}
	if gate.MaxNewFindings != nil && *gate.MaxNewFindings < -1 {
		return fmt.Errorf("%s.max_new_findings must be >= -1", prefix)
	}
	if gate.MaxNewReachableFindings != nil && *gate.MaxNewReachableFindings < -1 {
		return fmt.Errorf("%s.max_new_reachable_findings must be >= -1", prefix)
	}
	if gate.MinConfidenceForBlock != nil {
		if *gate.MinConfidenceForBlock != -1 && (*gate.MinConfidenceForBlock < 0 || *gate.MinConfidenceForBlock > 1) {
			return fmt.Errorf("%s.min_confidence_for_block must be between 0.0 and 1.0 (or -1 to disable)", prefix)
		}
	}
	for _, c := range gate.RequireChecks {
		if strings.TrimSpace(c) == "" {
			return fmt.Errorf("%s.require_checks cannot include empty values", prefix)
		}
	}
	for _, c := range gate.ForbidChecks {
		if strings.TrimSpace(c) == "" {
			return fmt.Errorf("%s.forbid_checks cannot include empty values", prefix)
		}
	}
	return nil
}

func validateMatchSpec(prefix string, spec MatchSpec) error {
	for _, p := range spec.Paths {
		if strings.TrimSpace(p) == "" {
			return fmt.Errorf("%s.paths cannot include empty values", prefix)
		}
	}
	for _, c := range spec.Categories {
		if strings.TrimSpace(c) == "" {
			return fmt.Errorf("%s.categories cannot include empty values", prefix)
		}
	}
	for _, c := range spec.Checks {
		if strings.TrimSpace(c) == "" {
			return fmt.Errorf("%s.checks cannot include empty values", prefix)
		}
	}
	return nil
}

func isValidSeverity(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical", "high", "medium", "low", "info", "none":
		return true
	default:
		return false
	}
}

func isValidExploitability(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "confirmed-path", "reachable", "theoretical", "none":
		return true
	default:
		return false
	}
}
