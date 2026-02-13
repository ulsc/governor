package checkstui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"governor/internal/checks"
)

var (
	titleStyle      = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	headerStyle     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("229"))
	selectedStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("45"))
	infoStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	warningStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	errorStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	mutedStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	successStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	searchModeStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("81"))
)

func (m uiModel) View() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("Governor Checks Workspace"))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("dirs: %s\n", strings.Join(m.snapshot.SearchedDirs, ", ")))
	b.WriteString(fmt.Sprintf("effective: %d  shadowed: %d  diagnostics: error=%d warning=%d info=%d\n",
		m.snapshot.Effective,
		m.snapshot.Shadowed,
		m.snapshot.Summary.Error,
		m.snapshot.Summary.Warning,
		m.snapshot.Summary.Info,
	))
	b.WriteString(fmt.Sprintf("filters: search=%q status=%s source=%s sort=%s\n",
		m.search,
		m.statusFilter,
		m.sourceFilter,
		describeSort(m.sort),
	))
	b.WriteString("\n")

	b.WriteString(headerStyle.Render(fmt.Sprintf("%-2s %-22s %-9s %-8s %-8s %-8s %s",
		"",
		"ID",
		"STATUS",
		"SOURCE",
		"SEV",
		"DIAGS",
		"PATH",
	)))
	b.WriteString("\n")

	if len(m.filtered) == 0 {
		b.WriteString(mutedStyle.Render("(no matching checks)"))
		b.WriteString("\n")
	} else {
		limit := m.bodyHeight()
		start := 0
		if m.cursor >= limit {
			start = m.cursor - limit + 1
		}
		end := min(len(m.filtered), start+limit)
		for i := start; i < end; i++ {
			rowIdx := m.filtered[i]
			r := m.snapshot.Rows[rowIdx]
			prefix := " "
			style := infoStyle
			if i == m.cursor {
				prefix = ">"
				style = selectedStyle
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
				id += "[" + strings.Join(flags, ",") + "]"
			}
			diag := fmt.Sprintf("e%d/w%d", r.DiagError, r.DiagWarning)

			line := fmt.Sprintf(
				"%-2s %-22s %-9s %-8s %-8s %-8s %s",
				prefix,
				truncate(id, 22),
				truncate(string(r.Status), 9),
				truncate(string(r.Source), 8),
				truncate(firstNonEmpty(r.Severity, "-"), 8),
				diag,
				truncate(r.Path, max(20, m.width-66)),
			)
			b.WriteString(style.Render(line))
			b.WriteString("\n")
		}
	}

	if m.showDetails {
		b.WriteString("\n")
		b.WriteString(headerStyle.Render("Details"))
		b.WriteString("\n")
		if selected, ok := m.selectedRow(); ok {
			b.WriteString(fmt.Sprintf("id: %s\n", selected.ID))
			b.WriteString(fmt.Sprintf("name: %s\n", selected.Name))
			b.WriteString(fmt.Sprintf("status/source: %s / %s\n", selected.Status, selected.Source))
			b.WriteString(fmt.Sprintf("severity: %s\n", firstNonEmpty(selected.Severity, "-")))
			if len(selected.Categories) > 0 {
				b.WriteString(fmt.Sprintf("categories: %s\n", strings.Join(selected.Categories, ", ")))
			} else {
				b.WriteString("categories: -\n")
			}
			b.WriteString(fmt.Sprintf("path: %s\n", selected.Path))
			flags := []string{}
			if selected.Effective {
				flags = append(flags, "effective")
			}
			if selected.Shadowed {
				flags = append(flags, "shadowed")
			}
			if selected.Invalid {
				flags = append(flags, "invalid")
			}
			if selected.Mutable {
				flags = append(flags, "mutable")
			}
			if len(flags) == 0 {
				flags = append(flags, "none")
			}
			b.WriteString(fmt.Sprintf("flags: %s\n", strings.Join(flags, ", ")))
			b.WriteString(fmt.Sprintf("diagnostics: error=%d warning=%d info=%d\n",
				selected.DiagError,
				selected.DiagWarning,
				selected.DiagInfo,
			))
		} else {
			b.WriteString(mutedStyle.Render("no row selected"))
			b.WriteString("\n")
		}
	}

	b.WriteString("\n")
	if m.mode == modeSearch {
		b.WriteString(searchModeStyle.Render(m.statusLine()))
	} else {
		style := mutedStyle
		if strings.Contains(strings.ToLower(m.message), "failed") {
			style = errorStyle
		} else if strings.Contains(strings.ToLower(m.message), "reloaded") {
			style = successStyle
		} else if strings.Contains(strings.ToLower(m.message), "warning") {
			style = warningStyle
		}
		b.WriteString(style.Render(m.statusLine()))
	}
	b.WriteString("\n")

	return b.String()
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func styleForStatus(status checks.Status) lipgloss.Style {
	switch status {
	case checks.StatusEnabled:
		return successStyle
	case checks.StatusDraft:
		return warningStyle
	case checks.StatusDisabled:
		return mutedStyle
	default:
		return infoStyle
	}
}

func truncate(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if maxLen <= 0 {
		return ""
	}
	if len(s) <= maxLen {
		return s
	}
	if maxLen < 4 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
