package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type DiagnosticSeverity string

const (
	DiagnosticInfo    DiagnosticSeverity = "info"
	DiagnosticWarning DiagnosticSeverity = "warning"
	DiagnosticError   DiagnosticSeverity = "error"
)

type Diagnostic struct {
	Code     string             `json:"code"`
	Severity DiagnosticSeverity `json:"severity"`
	CheckID  string             `json:"check_id,omitempty"`
	Path     string             `json:"path,omitempty"`
	Message  string             `json:"message"`
	Hint     string             `json:"hint,omitempty"`
}

type LocatedDefinition struct {
	ID         string     `json:"id"`
	Path       string     `json:"path"`
	Definition Definition `json:"definition"`
}

type DiagnosticSummary struct {
	Info    int `json:"info"`
	Warning int `json:"warning"`
	Error   int `json:"error"`
}

type DoctorReport struct {
	SearchedDirs []string            `json:"searched_dirs"`
	Effective    []LocatedDefinition `json:"effective"`
	Shadowed     []LocatedDefinition `json:"shadowed"`
	Diagnostics  []Diagnostic        `json:"diagnostics"`
	Summary      DiagnosticSummary   `json:"summary"`
}

func BuildDoctorReport(dirs []string) (DoctorReport, error) {
	dirs = uniquePaths(dirs)
	report := DoctorReport{
		SearchedDirs: dirs,
		Effective:    make([]LocatedDefinition, 0, 16),
		Shadowed:     make([]LocatedDefinition, 0, 16),
		Diagnostics:  make([]Diagnostic, 0, 32),
	}

	seen := make(map[string]string, 16)
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				report.Diagnostics = append(report.Diagnostics, Diagnostic{
					Code:     "checks_dir_missing",
					Severity: DiagnosticInfo,
					Path:     dir,
					Message:  "checks directory does not exist",
					Hint:     "create checks with `governor checks init` or `governor checks add`",
				})
				continue
			}
			return DoctorReport{}, fmt.Errorf("read checks dir %s: %w", dir, err)
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if !strings.HasSuffix(name, ".check.yaml") && !strings.HasSuffix(name, ".check.yml") {
				continue
			}

			path := filepath.Join(dir, name)
			def, loadErr := ReadDefinition(path)
			if loadErr != nil {
				report.Diagnostics = append(report.Diagnostics, Diagnostic{
					Code:     "check_invalid",
					Severity: DiagnosticError,
					Path:     path,
					Message:  loadErr.Error(),
					Hint:     "fix YAML/field constraints and rerun `governor checks validate`",
				})
				continue
			}
			def.Source = SourceCustom
			located := LocatedDefinition{
				ID:         def.ID,
				Path:       path,
				Definition: def,
			}

			if winnerPath, exists := seen[def.ID]; exists {
				report.Shadowed = append(report.Shadowed, located)
				report.Diagnostics = append(report.Diagnostics, Diagnostic{
					Code:     "check_shadowed",
					Severity: DiagnosticWarning,
					CheckID:  def.ID,
					Path:     path,
					Message:  fmt.Sprintf("check %q is shadowed by %s", def.ID, winnerPath),
					Hint:     "rename the check ID or remove duplicate definitions",
				})
			} else {
				seen[def.ID] = path
				report.Effective = append(report.Effective, located)
			}

			report.Diagnostics = append(report.Diagnostics, authoringDiagnostics(def, path)...)
		}
	}

	sort.Slice(report.Effective, func(i, j int) bool { return report.Effective[i].ID < report.Effective[j].ID })
	sort.Slice(report.Shadowed, func(i, j int) bool {
		if report.Shadowed[i].ID != report.Shadowed[j].ID {
			return report.Shadowed[i].ID < report.Shadowed[j].ID
		}
		return report.Shadowed[i].Path < report.Shadowed[j].Path
	})
	sort.Slice(report.Diagnostics, func(i, j int) bool {
		ri := diagnosticSeverityRank(report.Diagnostics[i].Severity)
		rj := diagnosticSeverityRank(report.Diagnostics[j].Severity)
		if ri != rj {
			return ri < rj
		}
		if report.Diagnostics[i].CheckID != report.Diagnostics[j].CheckID {
			return report.Diagnostics[i].CheckID < report.Diagnostics[j].CheckID
		}
		if report.Diagnostics[i].Path != report.Diagnostics[j].Path {
			return report.Diagnostics[i].Path < report.Diagnostics[j].Path
		}
		return report.Diagnostics[i].Code < report.Diagnostics[j].Code
	})

	for _, diag := range report.Diagnostics {
		switch diag.Severity {
		case DiagnosticError:
			report.Summary.Error++
		case DiagnosticWarning:
			report.Summary.Warning++
		default:
			report.Summary.Info++
		}
	}

	return report, nil
}

type ExplainInvalidCandidate struct {
	Path  string `json:"path"`
	Error string `json:"error"`
}

type ExplainResult struct {
	CheckID      string                    `json:"check_id"`
	SearchedDirs []string                  `json:"searched_dirs"`
	Effective    *LocatedDefinition        `json:"effective,omitempty"`
	Shadowed     []LocatedDefinition       `json:"shadowed,omitempty"`
	Invalid      []ExplainInvalidCandidate `json:"invalid_candidates,omitempty"`
}

func ExplainCheck(dirs []string, id string) (ExplainResult, error) {
	id, err := normalizeAndValidateCheckID(id)
	if err != nil {
		return ExplainResult{}, err
	}

	dirs = uniquePaths(dirs)
	result := ExplainResult{
		CheckID:      id,
		SearchedDirs: dirs,
		Shadowed:     make([]LocatedDefinition, 0, 4),
		Invalid:      make([]ExplainInvalidCandidate, 0, 4),
	}

	for _, dir := range dirs {
		candidates := []string{
			filepath.Join(dir, id+".check.yaml"),
			filepath.Join(dir, id+".check.yml"),
		}
		for _, path := range candidates {
			if _, statErr := os.Lstat(path); statErr != nil {
				if os.IsNotExist(statErr) {
					continue
				}
				return ExplainResult{}, fmt.Errorf("read check %s: %w", path, statErr)
			}

			def, loadErr := ReadDefinition(path)
			if loadErr != nil {
				result.Invalid = append(result.Invalid, ExplainInvalidCandidate{
					Path:  path,
					Error: loadErr.Error(),
				})
				continue
			}
			def.Source = SourceCustom

			located := LocatedDefinition{
				ID:         def.ID,
				Path:       path,
				Definition: def,
			}
			if result.Effective == nil {
				result.Effective = &located
			} else {
				result.Shadowed = append(result.Shadowed, located)
			}
		}
	}
	sort.Slice(result.Shadowed, func(i, j int) bool { return result.Shadowed[i].Path < result.Shadowed[j].Path })
	sort.Slice(result.Invalid, func(i, j int) bool { return result.Invalid[i].Path < result.Invalid[j].Path })
	return result, nil
}

func authoringDiagnostics(def Definition, path string) []Diagnostic {
	out := make([]Diagnostic, 0, 4)

	if strings.TrimSpace(def.Description) == "" {
		out = append(out, Diagnostic{
			Code:     "missing_description",
			Severity: DiagnosticInfo,
			CheckID:  def.ID,
			Path:     path,
			Message:  "check description is empty",
			Hint:     "add a concise description to improve maintainability",
		})
	}

	if len(strings.Fields(strings.TrimSpace(def.Instructions))) < 12 {
		out = append(out, Diagnostic{
			Code:     "short_instructions",
			Severity: DiagnosticWarning,
			CheckID:  def.ID,
			Path:     path,
			Message:  "instructions are very short and may produce low-signal results",
			Hint:     "add concrete scope, risk patterns, and expected evidence",
		})
	}

	if len(def.Scope.IncludeGlobs) == 0 && len(def.Scope.ExcludeGlobs) == 0 {
		out = append(out, Diagnostic{
			Code:     "unscoped_check",
			Severity: DiagnosticWarning,
			CheckID:  def.ID,
			Path:     path,
			Message:  "check has no include/exclude scope hints",
			Hint:     "add include/exclude globs for better signal and performance",
		})
	}

	if hasVeryBroadInclude(def.Scope.IncludeGlobs) && len(def.Scope.ExcludeGlobs) == 0 {
		out = append(out, Diagnostic{
			Code:     "overbroad_scope",
			Severity: DiagnosticWarning,
			CheckID:  def.ID,
			Path:     path,
			Message:  "scope includes very broad globs without exclusions",
			Hint:     "add exclusions such as vendor, node_modules, and build artifacts",
		})
	}

	if def.Status == StatusDraft {
		out = append(out, Diagnostic{
			Code:     "draft_status",
			Severity: DiagnosticInfo,
			CheckID:  def.ID,
			Path:     path,
			Message:  "check is draft and will not run unless explicitly included",
			Hint:     "enable check with `governor checks enable <id>` when ready",
		})
	}

	return out
}

func hasVeryBroadInclude(globs []string) bool {
	for _, glob := range globs {
		g := strings.TrimSpace(glob)
		if g == "" {
			continue
		}
		if g == "*" || g == "**" || g == "**/*" {
			return true
		}
	}
	return false
}

func diagnosticSeverityRank(severity DiagnosticSeverity) int {
	switch severity {
	case DiagnosticError:
		return 0
	case DiagnosticWarning:
		return 1
	default:
		return 2
	}
}
