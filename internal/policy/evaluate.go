package policy

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"governor/internal/diff"
	"governor/internal/model"
)

func EffectiveGate(p Policy, report model.AuditReport) model.PolicyGate {
	effective := model.PolicyGate{
		FailOnSeverity:               "none",
		FailOnExploitability:         "none",
		MaxSuppressionRatio:          -1,
		MaxNewFindings:               -1,
		MaxNewReachableFindings:      -1,
		MinConfidenceForBlock:        -1,
		RequireAttackPathForBlocking: false,
		RequireChecks:                nil,
		ForbidChecks:                 nil,
	}
	applyGate(&effective, p.Defaults)
	for _, rule := range p.Rules {
		if !matchRule(rule.When, report) {
			continue
		}
		applyGate(&effective, rule.Enforce)
	}
	effective.RequireChecks = uniqueLowerPreserve(effective.RequireChecks)
	effective.ForbidChecks = uniqueLowerPreserve(effective.ForbidChecks)
	return effective
}

func Evaluate(path string, p Policy, report model.AuditReport, dr *diff.DiffReport) model.PolicyDecision {
	effective := EffectiveGate(p, report)
	decision := model.PolicyDecision{
		Path:       strings.TrimSpace(path),
		APIVersion: p.APIVersion,
		Passed:     true,
		Effective:  effective,
		Violations: make([]model.PolicyViolation, 0, 8),
		Warnings:   make([]string, 0, 2),
	}

	violations := evaluateViolations(effective, report, dr)
	for i := range violations {
		if waiverID := matchingWaiver(p.Waivers, violations[i], time.Now().UTC()); waiverID != "" {
			violations[i].Waived = true
			violations[i].WaiverID = waiverID
		}
		if !violations[i].Waived {
			decision.Passed = false
		}
	}
	decision.Violations = violations
	return decision
}

func evaluateViolations(gate model.PolicyGate, report model.AuditReport, dr *diff.DiffReport) []model.PolicyViolation {
	out := make([]model.PolicyViolation, 0, 8)
	filteredFindings := filterBlockingCandidates(report.Findings, gate)

	if isValidSeverity(gate.FailOnSeverity) && gate.FailOnSeverity != "none" {
		threshold := severityWeight(gate.FailOnSeverity)
		count := 0
		var first model.Finding
		for _, finding := range filteredFindings {
			if severityWeight(finding.Severity) <= threshold {
				if count == 0 {
					first = finding
				}
				count++
			}
		}
		if count > 0 {
			out = append(out, model.PolicyViolation{
				Code:     "fail_on_severity",
				Message:  fmt.Sprintf("%d finding(s) meet or exceed fail_on_severity=%s", count, gate.FailOnSeverity),
				Severity: first.Severity,
				Category: first.Category,
				CheckID:  first.SourceTrack,
				FileRefs: append([]string{}, first.FileRefs...),
			})
		}
	}

	if isValidExploitability(gate.FailOnExploitability) && gate.FailOnExploitability != "none" {
		threshold := exploitabilityWeight(gate.FailOnExploitability)
		count := 0
		var first model.Finding
		for _, finding := range filteredFindings {
			if exploitabilityWeight(finding.Exploitability) <= threshold {
				if count == 0 {
					first = finding
				}
				count++
			}
		}
		if count > 0 {
			out = append(out, model.PolicyViolation{
				Code:     "fail_on_exploitability",
				Message:  fmt.Sprintf("%d finding(s) meet or exceed fail_on_exploitability=%s", count, gate.FailOnExploitability),
				Severity: first.Severity,
				Category: first.Category,
				CheckID:  first.SourceTrack,
				FileRefs: append([]string{}, first.FileRefs...),
			})
		}
	}

	if gate.MaxSuppressionRatio >= 0 {
		total := len(report.Findings) + report.SuppressedCount
		if total > 0 {
			ratio := float64(report.SuppressedCount) / float64(total)
			if ratio > gate.MaxSuppressionRatio {
				out = append(out, model.PolicyViolation{
					Code:    "max_suppression_ratio",
					Message: fmt.Sprintf("suppression ratio %.2f exceeds max_suppression_ratio=%.2f", ratio, gate.MaxSuppressionRatio),
				})
			}
		}
	}

	checkSet := map[string]struct{}{}
	for _, id := range report.RunMetadata.CheckIDs {
		id = strings.ToLower(strings.TrimSpace(id))
		if id != "" {
			checkSet[id] = struct{}{}
		}
	}

	for _, required := range gate.RequireChecks {
		required = strings.ToLower(strings.TrimSpace(required))
		if required == "" {
			continue
		}
		if _, ok := checkSet[required]; !ok {
			out = append(out, model.PolicyViolation{
				Code:    "require_check",
				Message: fmt.Sprintf("required check %q was not enabled", required),
				CheckID: required,
			})
		}
	}

	for _, forbidden := range gate.ForbidChecks {
		forbidden = strings.ToLower(strings.TrimSpace(forbidden))
		if forbidden == "" {
			continue
		}
		if _, ok := checkSet[forbidden]; ok {
			out = append(out, model.PolicyViolation{
				Code:    "forbid_check",
				Message: fmt.Sprintf("forbidden check %q was enabled", forbidden),
				CheckID: forbidden,
			})
		}
	}

	if gate.MaxNewFindings >= 0 {
		newCount := len(report.Findings)
		if dr != nil {
			newCount = dr.Summary.NewCount
		}
		if newCount > gate.MaxNewFindings {
			out = append(out, model.PolicyViolation{
				Code:    "max_new_findings",
				Message: fmt.Sprintf("new findings %d exceed max_new_findings=%d", newCount, gate.MaxNewFindings),
			})
		}
	}

	if gate.MaxNewReachableFindings >= 0 {
		candidates := report.Findings
		if dr != nil {
			candidates = dr.New
		}
		filtered := filterBlockingCandidates(candidates, gate)
		newReachable := 0
		var first model.Finding
		for _, finding := range filtered {
			if exploitabilityWeight(finding.Exploitability) <= exploitabilityWeight("reachable") {
				if newReachable == 0 {
					first = finding
				}
				newReachable++
			}
		}
		if newReachable > gate.MaxNewReachableFindings {
			out = append(out, model.PolicyViolation{
				Code:     "max_new_reachable_findings",
				Message:  fmt.Sprintf("new reachable findings %d exceed max_new_reachable_findings=%d", newReachable, gate.MaxNewReachableFindings),
				Severity: first.Severity,
				Category: first.Category,
				CheckID:  first.SourceTrack,
				FileRefs: append([]string{}, first.FileRefs...),
			})
		}
	}

	return out
}

func applyGate(eff *model.PolicyGate, overlay Gate) {
	if eff == nil {
		return
	}
	if sev := strings.ToLower(strings.TrimSpace(overlay.FailOnSeverity)); sev != "" {
		eff.FailOnSeverity = sev
	}
	if overlay.MaxSuppressionRatio != nil {
		eff.MaxSuppressionRatio = *overlay.MaxSuppressionRatio
	}
	if overlay.MaxNewFindings != nil {
		eff.MaxNewFindings = *overlay.MaxNewFindings
	}
	if overlay.MaxNewReachableFindings != nil {
		eff.MaxNewReachableFindings = *overlay.MaxNewReachableFindings
	}
	if overlay.MinConfidenceForBlock != nil {
		eff.MinConfidenceForBlock = *overlay.MinConfidenceForBlock
	}
	if overlay.RequireAttackPathForBlocking != nil {
		eff.RequireAttackPathForBlocking = *overlay.RequireAttackPathForBlocking
	}
	if mode := strings.ToLower(strings.TrimSpace(overlay.FailOnExploitability)); mode != "" {
		eff.FailOnExploitability = mode
	}
	if len(overlay.RequireChecks) > 0 {
		eff.RequireChecks = append([]string{}, overlay.RequireChecks...)
	}
	if len(overlay.ForbidChecks) > 0 {
		eff.ForbidChecks = append([]string{}, overlay.ForbidChecks...)
	}
}

func matchRule(spec MatchSpec, report model.AuditReport) bool {
	pathSet := map[string]struct{}{}
	categorySet := map[string]struct{}{}
	checkSet := map[string]struct{}{}

	for _, finding := range report.Findings {
		cat := strings.ToLower(strings.TrimSpace(finding.Category))
		if cat != "" {
			categorySet[cat] = struct{}{}
		}
		for _, ref := range finding.FileRefs {
			ref = strings.TrimSpace(ref)
			if ref != "" {
				pathSet[ref] = struct{}{}
			}
		}
		for _, track := range splitCSV(finding.SourceTrack) {
			checkSet[track] = struct{}{}
		}
	}
	for _, id := range report.RunMetadata.CheckIDs {
		id = strings.ToLower(strings.TrimSpace(id))
		if id != "" {
			checkSet[id] = struct{}{}
		}
	}

	if len(spec.Paths) > 0 {
		matched := false
		for _, pattern := range spec.Paths {
			for p := range pathSet {
				if globMatch(pattern, p) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}

	if len(spec.Categories) > 0 {
		matched := false
		for _, cat := range spec.Categories {
			if _, ok := categorySet[strings.ToLower(cat)]; ok {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	if len(spec.Checks) > 0 {
		matched := false
		for _, check := range spec.Checks {
			check = strings.ToLower(strings.TrimSpace(check))
			for enabled := range checkSet {
				if globMatch(check, enabled) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

func matchingWaiver(waivers []Waiver, v model.PolicyViolation, now time.Time) string {
	for _, waiver := range waivers {
		if waiver.IsExpired(now) {
			continue
		}
		if waiverMatches(waiver.Match, v) {
			return waiver.ID
		}
	}
	return ""
}

func waiverMatches(spec MatchSpec, v model.PolicyViolation) bool {
	if len(spec.Checks) > 0 {
		if strings.TrimSpace(v.CheckID) == "" {
			return false
		}
		matched := false
		for _, pattern := range spec.Checks {
			if globMatch(pattern, v.CheckID) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	if len(spec.Categories) > 0 {
		matched := false
		for _, cat := range spec.Categories {
			if strings.EqualFold(strings.TrimSpace(cat), strings.TrimSpace(v.Category)) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	if len(spec.Paths) > 0 {
		if len(v.FileRefs) == 0 {
			return false
		}
		matched := false
		for _, pattern := range spec.Paths {
			for _, ref := range v.FileRefs {
				if globMatch(pattern, ref) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}

	if len(spec.Paths) == 0 && len(spec.Categories) == 0 && len(spec.Checks) == 0 {
		return true
	}
	return true
}

func globMatch(pattern, value string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	value = strings.ToLower(strings.TrimSpace(value))
	if pattern == "" {
		return false
	}
	if strings.Contains(pattern, "**") {
		parts := strings.SplitN(pattern, "**", 2)
		prefix := parts[0]
		suffix := parts[1]
		if prefix != "" && !strings.HasPrefix(value, prefix) {
			return false
		}
		if suffix == "" {
			return true
		}
		for i := 0; i <= len(value); i++ {
			tail := value[i:]
			if ok, _ := filepath.Match(strings.TrimPrefix(suffix, "/"), strings.TrimPrefix(tail, "/")); ok {
				return true
			}
		}
		return false
	}
	ok, _ := filepath.Match(pattern, value)
	return ok
}

func splitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.ToLower(strings.TrimSpace(part))
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func uniqueLowerPreserve(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, item := range in {
		item = strings.ToLower(strings.TrimSpace(item))
		if item == "" {
			continue
		}
		if _, exists := seen[item]; exists {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func severityWeight(sev string) int {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

func exploitabilityWeight(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "confirmed-path":
		return 0
	case "reachable":
		return 1
	case "theoretical":
		return 2
	default:
		return 3
	}
}

func filterBlockingCandidates(findings []model.Finding, gate model.PolicyGate) []model.Finding {
	if len(findings) == 0 {
		return nil
	}
	out := make([]model.Finding, 0, len(findings))
	for _, finding := range findings {
		if gate.MinConfidenceForBlock >= 0 && finding.Confidence < gate.MinConfidenceForBlock {
			continue
		}
		if gate.RequireAttackPathForBlocking && !hasAttackPath(finding.AttackPath) {
			continue
		}
		out = append(out, finding)
	}
	return out
}

func hasAttackPath(path []string) bool {
	for _, step := range path {
		if strings.TrimSpace(step) != "" {
			return true
		}
	}
	return false
}
