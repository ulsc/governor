package diff

import (
	"sort"
	"strings"

	"governor/internal/model"
)

// DiffSummary holds aggregate counts for a baseline comparison.
type DiffSummary struct {
	NewCount            int            `json:"new_count"`
	FixedCount          int            `json:"fixed_count"`
	UnchangedCount      int            `json:"unchanged_count"`
	NewReachableCount   int            `json:"new_reachable_count,omitempty"`
	SeverityDelta       map[string]int `json:"severity_delta,omitempty"`
	ExploitabilityDelta map[string]int `json:"exploitability_delta,omitempty"`
}

// DiffReport is the result of comparing a current audit against a baseline.
type DiffReport struct {
	New       []model.Finding `json:"new"`
	Fixed     []model.Finding `json:"fixed"`
	Unchanged []model.Finding `json:"unchanged"`
	Summary   DiffSummary     `json:"summary"`
}

// Compare produces a DiffReport identifying new, fixed, and unchanged findings
// relative to a baseline audit report.
func Compare(baseline, current model.AuditReport) DiffReport {
	baseKeys := make(map[string]model.Finding, len(baseline.Findings))
	for _, f := range baseline.Findings {
		baseKeys[findingKey(f)] = f
	}

	currKeys := make(map[string]model.Finding, len(current.Findings))
	for _, f := range current.Findings {
		currKeys[findingKey(f)] = f
	}

	var newFindings, fixed, unchanged []model.Finding

	for key, f := range currKeys {
		if _, inBase := baseKeys[key]; inBase {
			unchanged = append(unchanged, f)
		} else {
			newFindings = append(newFindings, f)
		}
	}

	for key, f := range baseKeys {
		if _, inCurr := currKeys[key]; !inCurr {
			fixed = append(fixed, f)
		}
	}

	sortFindings(newFindings)
	sortFindings(fixed)
	sortFindings(unchanged)

	return DiffReport{
		New:       newFindings,
		Fixed:     fixed,
		Unchanged: unchanged,
		Summary: DiffSummary{
			NewCount:            len(newFindings),
			FixedCount:          len(fixed),
			UnchangedCount:      len(unchanged),
			NewReachableCount:   countReachableFindings(newFindings),
			SeverityDelta:       severityDelta(baseline.Findings, current.Findings),
			ExploitabilityDelta: exploitabilityDelta(baseline.Findings, current.Findings),
		},
	}
}

func findingKey(f model.Finding) string {
	refs := append([]string{}, f.FileRefs...)
	sort.Strings(refs)
	evidence := strings.ToLower(strings.TrimSpace(f.Evidence))
	if len(evidence) > 200 {
		evidence = evidence[:200]
	}
	return strings.ToLower(strings.TrimSpace(f.Title)) + "|" +
		strings.ToLower(strings.TrimSpace(f.Category)) + "|" +
		strings.Join(refs, ",") + "|" + evidence
}

func sortFindings(findings []model.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		wi := severityWeight(findings[i].Severity)
		wj := severityWeight(findings[j].Severity)
		if wi != wj {
			return wi < wj
		}
		return findings[i].Title < findings[j].Title
	})
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

func countReachableFindings(findings []model.Finding) int {
	n := 0
	for _, finding := range findings {
		if exploitabilityWeight(finding.Exploitability) <= exploitabilityWeight("reachable") {
			n++
		}
	}
	return n
}

func severityDelta(baseline, current []model.Finding) map[string]int {
	labels := []string{"critical", "high", "medium", "low", "info"}
	out := make(map[string]int, len(labels))
	baseCounts := countBySeverity(baseline)
	currCounts := countBySeverity(current)
	for _, label := range labels {
		delta := currCounts[label] - baseCounts[label]
		if delta != 0 {
			out[label] = delta
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func countBySeverity(findings []model.Finding) map[string]int {
	out := make(map[string]int, 5)
	for _, finding := range findings {
		label := strings.ToLower(strings.TrimSpace(finding.Severity))
		switch label {
		case "critical", "high", "medium", "low", "info":
			out[label]++
		default:
			out["info"]++
		}
	}
	return out
}

func exploitabilityDelta(baseline, current []model.Finding) map[string]int {
	labels := []string{"confirmed-path", "reachable", "theoretical", "unknown"}
	out := make(map[string]int, len(labels))
	baseCounts := countByExploitability(baseline)
	currCounts := countByExploitability(current)
	for _, label := range labels {
		delta := currCounts[label] - baseCounts[label]
		if delta != 0 {
			out[label] = delta
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func countByExploitability(findings []model.Finding) map[string]int {
	out := make(map[string]int, 4)
	for _, finding := range findings {
		label := normalizeExploitability(finding.Exploitability)
		if label == "" {
			label = "unknown"
		}
		out[label]++
	}
	return out
}

func exploitabilityWeight(value string) int {
	switch normalizeExploitability(value) {
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

func normalizeExploitability(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "confirmed-path":
		return "confirmed-path"
	case "reachable":
		return "reachable"
	case "theoretical":
		return "theoretical"
	default:
		return ""
	}
}
