package checkstui

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"governor/internal/checks"
)

type row struct {
	ID       string
	Name     string
	Status   checks.Status
	Source   checks.Source
	Path     string
	Shadowed bool
	Invalid  bool
}

type uiModel struct {
	checksDir string
	dirs      []string
	rows      []row
	cursor    int
	message   string
}

func newModel(opts Options) (uiModel, error) {
	dirs, rows, err := loadRows(opts.ChecksDir)
	if err != nil {
		return uiModel{}, err
	}
	return uiModel{
		checksDir: opts.ChecksDir,
		dirs:      dirs,
		rows:      rows,
		message:   "q quit | j/k move | r refresh",
	}, nil
}

func (m uiModel) Init() tea.Cmd {
	return nil
}

func (m uiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "j", "down":
			if m.cursor < len(m.rows)-1 {
				m.cursor++
			}
		case "k", "up":
			if m.cursor > 0 {
				m.cursor--
			}
		case "r":
			dirs, rows, err := loadRows(m.checksDir)
			if err != nil {
				m.message = "refresh failed: " + err.Error()
				return m, nil
			}
			m.dirs = dirs
			m.rows = rows
			if m.cursor >= len(m.rows) {
				m.cursor = max(0, len(m.rows)-1)
			}
			m.message = "refreshed checks"
		}
	}
	return m, nil
}

func (m uiModel) View() string {
	var b strings.Builder
	b.WriteString("Governor Checks Workspace\n")
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("dirs: %s\n", strings.Join(m.dirs, ", ")))
	b.WriteString(fmt.Sprintf("rows: %d\n", len(m.rows)))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("%-2s %-24s %-10s %-8s %-36s %s\n", "", "ID", "STATUS", "SOURCE", "NAME", "PATH"))

	if len(m.rows) == 0 {
		b.WriteString("(no checks found)\n")
	} else {
		for i, r := range m.rows {
			prefix := " "
			if i == m.cursor {
				prefix = ">"
			}
			flags := make([]string, 0, 2)
			if r.Shadowed {
				flags = append(flags, "shadowed")
			}
			if r.Invalid {
				flags = append(flags, "invalid")
			}
			id := r.ID
			if len(flags) > 0 {
				id += " [" + strings.Join(flags, ",") + "]"
			}
			b.WriteString(fmt.Sprintf(
				"%-2s %-24s %-10s %-8s %-36s %s\n",
				prefix,
				truncate(id, 24),
				r.Status,
				r.Source,
				truncate(r.Name, 36),
				truncate(r.Path, 64),
			))
		}
	}
	b.WriteString("\n")
	b.WriteString(m.message)
	b.WriteString("\n")
	return b.String()
}

func loadRows(checksDir string) ([]string, []row, error) {
	dirs, err := checks.ResolveReadDirs(checksDir)
	if err != nil {
		return nil, nil, err
	}
	report, err := checks.BuildDoctorReport(dirs)
	if err != nil {
		return nil, nil, err
	}

	out := make([]row, 0, len(checks.Builtins())+len(report.Effective)+len(report.Shadowed)+len(report.Diagnostics))
	for _, builtin := range checks.Builtins() {
		builtin = checks.NormalizeDefinition(builtin)
		out = append(out, row{
			ID:     builtin.ID,
			Name:   builtin.Name,
			Status: builtin.Status,
			Source: checks.SourceBuiltin,
			Path:   "(builtin)",
		})
	}
	for _, item := range report.Effective {
		def := checks.NormalizeDefinition(item.Definition)
		out = append(out, row{
			ID:     def.ID,
			Name:   def.Name,
			Status: def.Status,
			Source: checks.SourceCustom,
			Path:   item.Path,
		})
	}
	for _, item := range report.Shadowed {
		def := checks.NormalizeDefinition(item.Definition)
		out = append(out, row{
			ID:       def.ID,
			Name:     def.Name,
			Status:   def.Status,
			Source:   checks.SourceCustom,
			Path:     item.Path,
			Shadowed: true,
		})
	}

	for _, diag := range report.Diagnostics {
		if diag.Code != "check_invalid" {
			continue
		}
		id := strings.TrimSuffix(filepath.Base(diag.Path), ".check.yaml")
		id = strings.TrimSuffix(id, ".check.yml")
		if strings.TrimSpace(id) == "" {
			id = "invalid-check"
		}
		out = append(out, row{
			ID:      id,
			Name:    "(invalid check file)",
			Status:  checks.StatusDisabled,
			Source:  checks.SourceCustom,
			Path:    diag.Path,
			Invalid: true,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return out[i].Path < out[j].Path
	})
	return report.SearchedDirs, out, nil
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	if n < 4 {
		return s[:n]
	}
	return s[:n-3] + "..."
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

var errNoRows = errors.New("no rows")

