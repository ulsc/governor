package checkstui

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"governor/internal/checks"
)

type sourceFilter string

const (
	sourceAll     sourceFilter = "all"
	sourceCustom  sourceFilter = "custom"
	sourceBuiltin sourceFilter = "builtin"
)

type statusFilter string

const (
	statusAll      statusFilter = "all"
	statusEnabled  statusFilter = "enabled"
	statusDraft    statusFilter = "draft"
	statusDisabled statusFilter = "disabled"
)

type sortKey string

const (
	sortByID       sortKey = "id"
	sortByStatus   sortKey = "status"
	sortBySource   sortKey = "source"
	sortBySeverity sortKey = "severity"
	sortByPath     sortKey = "path"
)

type sortState struct {
	Key  sortKey
	Desc bool
}

type row struct {
	ID         string
	Name       string
	Status     checks.Status
	Source     checks.Source
	Severity   string
	Categories []string
	Path       string

	Effective bool
	Shadowed  bool
	Invalid   bool
	Mutable   bool

	DiagError   int
	DiagWarning int
	DiagInfo    int
}

type snapshot struct {
	SearchedDirs []string
	Rows         []row
	Effective    int
	Shadowed     int
	Summary      checks.DiagnosticSummary
}

type rowDiagnostics struct {
	errorCount   int
	warningCount int
	infoCount    int
}

func loadSnapshot(checksDir string) (snapshot, error) {
	dirs, err := checks.ResolveReadDirs(checksDir)
	if err != nil {
		return snapshot{}, err
	}
	report, err := checks.BuildDoctorReport(dirs)
	if err != nil {
		return snapshot{}, err
	}

	diagByPath := map[string]rowDiagnostics{}
	for _, diag := range report.Diagnostics {
		path := strings.TrimSpace(diag.Path)
		if path == "" {
			continue
		}
		c := diagByPath[path]
		switch diag.Severity {
		case checks.DiagnosticError:
			c.errorCount++
		case checks.DiagnosticWarning:
			c.warningCount++
		default:
			c.infoCount++
		}
		diagByPath[path] = c
	}

	rows := make([]row, 0, len(checks.Builtins())+len(report.Effective)+len(report.Shadowed)+len(report.Diagnostics))
	for _, builtin := range checks.Builtins() {
		def := checks.NormalizeDefinition(builtin)
		rows = append(rows, row{
			ID:         def.ID,
			Name:       def.Name,
			Status:     def.Status,
			Source:     checks.SourceBuiltin,
			Severity:   strings.TrimSpace(def.SeverityHint),
			Categories: append([]string{}, def.CategoriesHint...),
			Path:       "(builtin)",
			Effective:  true,
			Mutable:    false,
		})
	}

	for _, item := range report.Effective {
		def := checks.NormalizeDefinition(item.Definition)
		diags := diagByPath[item.Path]
		rows = append(rows, row{
			ID:          def.ID,
			Name:        def.Name,
			Status:      def.Status,
			Source:      checks.SourceCustom,
			Severity:    strings.TrimSpace(def.SeverityHint),
			Categories:  append([]string{}, def.CategoriesHint...),
			Path:        item.Path,
			Effective:   true,
			Mutable:     true,
			DiagError:   diags.errorCount,
			DiagWarning: diags.warningCount,
			DiagInfo:    diags.infoCount,
		})
	}
	for _, item := range report.Shadowed {
		def := checks.NormalizeDefinition(item.Definition)
		diags := diagByPath[item.Path]
		rows = append(rows, row{
			ID:          def.ID,
			Name:        def.Name,
			Status:      def.Status,
			Source:      checks.SourceCustom,
			Severity:    strings.TrimSpace(def.SeverityHint),
			Categories:  append([]string{}, def.CategoriesHint...),
			Path:        item.Path,
			Shadowed:    true,
			Mutable:     false,
			DiagError:   diags.errorCount,
			DiagWarning: diags.warningCount,
			DiagInfo:    diags.infoCount,
		})
	}

	for _, diag := range report.Diagnostics {
		if diag.Code != "check_invalid" {
			continue
		}
		path := strings.TrimSpace(diag.Path)
		id := strings.TrimSuffix(filepath.Base(path), ".check.yaml")
		id = strings.TrimSuffix(id, ".check.yml")
		if strings.TrimSpace(id) == "" {
			id = "invalid-check"
		}
		diags := diagByPath[path]
		rows = append(rows, row{
			ID:          id,
			Name:        "(invalid check file)",
			Status:      checks.StatusDisabled,
			Source:      checks.SourceCustom,
			Path:        path,
			Invalid:     true,
			Mutable:     false,
			DiagError:   diags.errorCount,
			DiagWarning: diags.warningCount,
			DiagInfo:    diags.infoCount,
		})
	}

	sort.Slice(rows, func(i, j int) bool {
		return compareRows(rows[i], rows[j], sortState{Key: sortByID})
	})

	return snapshot{
		SearchedDirs: report.SearchedDirs,
		Rows:         rows,
		Effective:    len(report.Effective),
		Shadowed:     len(report.Shadowed),
		Summary:      report.Summary,
	}, nil
}

func compareRows(a, b row, s sortState) bool {
	if s.Key == "" {
		s.Key = sortByID
	}

	cmp := 0
	switch s.Key {
	case sortByStatus:
		cmp = compareInt(statusRank(a.Status), statusRank(b.Status))
	case sortBySource:
		cmp = compareInt(sourceRank(a.Source), sourceRank(b.Source))
	case sortBySeverity:
		cmp = compareInt(severityRank(a.Severity), severityRank(b.Severity))
	case sortByPath:
		cmp = compareText(a.Path, b.Path)
	default:
		cmp = compareText(a.ID, b.ID)
	}
	if cmp == 0 {
		cmp = compareText(a.ID, b.ID)
	}
	if cmp == 0 {
		cmp = compareText(a.Path, b.Path)
	}
	if cmp == 0 {
		cmp = compareText(string(a.Source), string(b.Source))
	}

	if s.Desc {
		cmp = -cmp
	}
	return cmp < 0
}

func compareText(a, b string) int {
	ta := strings.ToLower(strings.TrimSpace(a))
	tb := strings.ToLower(strings.TrimSpace(b))
	switch {
	case ta < tb:
		return -1
	case ta > tb:
		return 1
	default:
		return 0
	}
}

func compareInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func statusRank(status checks.Status) int {
	switch status {
	case checks.StatusEnabled:
		return 0
	case checks.StatusDraft:
		return 1
	case checks.StatusDisabled:
		return 2
	default:
		return 3
	}
}

func sourceRank(source checks.Source) int {
	switch source {
	case checks.SourceCustom:
		return 0
	case checks.SourceBuiltin:
		return 1
	default:
		return 2
	}
}

func severityRank(raw string) int {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	case "info":
		return 4
	default:
		return 5
	}
}

func matchesFilters(r row, search string, source sourceFilter, status statusFilter) bool {
	switch source {
	case sourceBuiltin:
		if r.Source != checks.SourceBuiltin {
			return false
		}
	case sourceCustom:
		if r.Source != checks.SourceCustom {
			return false
		}
	}
	switch status {
	case statusEnabled:
		if r.Status != checks.StatusEnabled {
			return false
		}
	case statusDraft:
		if r.Status != checks.StatusDraft {
			return false
		}
	case statusDisabled:
		if r.Status != checks.StatusDisabled {
			return false
		}
	}
	query := strings.ToLower(strings.TrimSpace(search))
	if query == "" {
		return true
	}
	haystack := strings.ToLower(strings.Join([]string{
		r.ID,
		r.Name,
		r.Path,
		r.Severity,
		strings.Join(r.Categories, ","),
	}, " "))
	return strings.Contains(haystack, query)
}

func cycleStatusFilter(current statusFilter) statusFilter {
	switch current {
	case statusEnabled:
		return statusDraft
	case statusDraft:
		return statusDisabled
	case statusDisabled:
		return statusAll
	default:
		return statusEnabled
	}
}

func cycleSourceFilter(current sourceFilter) sourceFilter {
	switch current {
	case sourceCustom:
		return sourceBuiltin
	case sourceBuiltin:
		return sourceAll
	default:
		return sourceCustom
	}
}

func describeSort(s sortState) string {
	order := "asc"
	if s.Desc {
		order = "desc"
	}
	return fmt.Sprintf("%s/%s", s.Key, order)
}
