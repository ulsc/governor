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
	dimStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("238"))
	criticalStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	highStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("208"))
	mediumStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	lowStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("39"))
)

func (m uiModel) View() string {
	var b strings.Builder

	// Title and summary
	b.WriteString(titleStyle.Render("Governor Checks Workspace"))
	b.WriteString("\n")
	b.WriteString(mutedStyle.Render("  dirs: " + strings.Join(m.snapshot.SearchedDirs, ", ")))
	b.WriteString("\n")

	// Summary stats with color
	summaryParts := []string{
		fmt.Sprintf("effective: %s", successStyle.Render(fmt.Sprintf("%d", m.snapshot.Effective))),
		fmt.Sprintf("shadowed: %s", mutedStyle.Render(fmt.Sprintf("%d", m.snapshot.Shadowed))),
	}
	if m.snapshot.Summary.Error > 0 {
		summaryParts = append(summaryParts, fmt.Sprintf("errors: %s", errorStyle.Render(fmt.Sprintf("%d", m.snapshot.Summary.Error))))
	}
	if m.snapshot.Summary.Warning > 0 {
		summaryParts = append(summaryParts, fmt.Sprintf("warnings: %s", warningStyle.Render(fmt.Sprintf("%d", m.snapshot.Summary.Warning))))
	}
	b.WriteString("  " + strings.Join(summaryParts, dimStyle.Render(" | ")))
	b.WriteString("\n")

	// Active filters
	filterParts := []string{}
	if m.search != "" {
		filterParts = append(filterParts, fmt.Sprintf("search=%s", searchModeStyle.Render(fmt.Sprintf("%q", m.search))))
	}
	if m.statusFilter != statusAll {
		filterParts = append(filterParts, fmt.Sprintf("status=%s", string(m.statusFilter)))
	}
	if m.sourceFilter != sourceAll {
		filterParts = append(filterParts, fmt.Sprintf("source=%s", string(m.sourceFilter)))
	}
	if len(filterParts) > 0 {
		b.WriteString("  " + mutedStyle.Render("filters: ") + strings.Join(filterParts, " "))
		b.WriteString("\n")
	}
	b.WriteString("\n")

	// Table header
	b.WriteString(headerStyle.Render(fmt.Sprintf("  %-22s %-9s %-8s %-8s %-8s %s",
		"ID",
		"STATUS",
		"SOURCE",
		"SEV",
		"DIAGS",
		"PATH",
	)))
	b.WriteString("\n")

	if len(m.filtered) == 0 {
		b.WriteString(mutedStyle.Render("  (no matching checks)"))
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
			isCursor := i == m.cursor

			// Cursor indicator
			prefix := "  "
			if isCursor {
				prefix = selectedStyle.Render("> ")
			}

			// ID with flags
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
			idStr := truncate(id, 22)
			if isCursor {
				idStr = selectedStyle.Render(idStr)
			} else {
				idStr = infoStyle.Render(idStr)
			}

			// Color-coded status
			statusStr := coloredStatus(r.Status)

			// Color-coded source
			sourceStr := truncate(string(r.Source), 8)
			if r.Source == checks.SourceBuiltin {
				sourceStr = mutedStyle.Render(sourceStr)
			} else {
				sourceStr = infoStyle.Render(sourceStr)
			}

			// Color-coded severity
			sevStr := coloredSeverity(firstNonEmpty(r.Severity, "-"), 8)

			// Diagnostics with color
			diagStr := diagBadge(r.DiagError, r.DiagWarning)

			// Path
			pathStr := mutedStyle.Render(truncate(r.Path, max(20, m.width-66)))

			b.WriteString(fmt.Sprintf("%s%-22s %-9s %-8s %-8s %-8s %s",
				prefix,
				idStr,
				statusStr,
				sourceStr,
				sevStr,
				diagStr,
				pathStr,
			))
			b.WriteString("\n")
		}

		// Row count indicator
		b.WriteString(mutedStyle.Render(fmt.Sprintf("  showing %d-%d of %d", start+1, end, len(m.filtered))))
		b.WriteString("\n")
	}

	// Details panel
	if m.showDetails {
		b.WriteString("\n")
		b.WriteString(headerStyle.Render("Details"))
		b.WriteString("\n")
		if selected, ok := m.selectedRow(); ok {
			b.WriteString(fmt.Sprintf("  id:         %s\n", selected.ID))
			b.WriteString(fmt.Sprintf("  name:       %s\n", selected.Name))
			b.WriteString(fmt.Sprintf("  status:     %s\n", coloredStatus(selected.Status)))
			b.WriteString(fmt.Sprintf("  source:     %s\n", selected.Source))
			b.WriteString(fmt.Sprintf("  severity:   %s\n", coloredSeverity(firstNonEmpty(selected.Severity, "-"), 0)))
			if len(selected.Categories) > 0 {
				b.WriteString(fmt.Sprintf("  categories: %s\n", strings.Join(selected.Categories, ", ")))
			} else {
				b.WriteString(fmt.Sprintf("  categories: %s\n", mutedStyle.Render("-")))
			}
			b.WriteString(fmt.Sprintf("  path:       %s\n", selected.Path))
			flagParts := []string{}
			if selected.Effective {
				flagParts = append(flagParts, successStyle.Render("effective"))
			}
			if selected.Shadowed {
				flagParts = append(flagParts, warningStyle.Render("shadowed"))
			}
			if selected.Invalid {
				flagParts = append(flagParts, errorStyle.Render("invalid"))
			}
			if selected.Mutable {
				flagParts = append(flagParts, infoStyle.Render("mutable"))
			}
			if len(flagParts) == 0 {
				flagParts = append(flagParts, mutedStyle.Render("none"))
			}
			b.WriteString(fmt.Sprintf("  flags:      %s\n", strings.Join(flagParts, ", ")))
			diagParts := []string{}
			if selected.DiagError > 0 {
				diagParts = append(diagParts, errorStyle.Render(fmt.Sprintf("%d error", selected.DiagError)))
			}
			if selected.DiagWarning > 0 {
				diagParts = append(diagParts, warningStyle.Render(fmt.Sprintf("%d warning", selected.DiagWarning)))
			}
			if selected.DiagInfo > 0 {
				diagParts = append(diagParts, infoStyle.Render(fmt.Sprintf("%d info", selected.DiagInfo)))
			}
			if len(diagParts) == 0 {
				diagParts = append(diagParts, mutedStyle.Render("none"))
			}
			b.WriteString(fmt.Sprintf("  diagnostics: %s\n", strings.Join(diagParts, ", ")))
		} else {
			b.WriteString(mutedStyle.Render("  no row selected"))
			b.WriteString("\n")
		}
	}

	// Status / help bar
	b.WriteString("\n")
	switch m.mode {
	case modeSearch:
		b.WriteString(searchModeStyle.Render(m.statusLine()))
	case modeConfirmStatus, modeDuplicateID, modeDuplicateName:
		b.WriteString(warningStyle.Render(m.statusLine()))
	default:
		style := mutedStyle
		if strings.Contains(strings.ToLower(m.message), "failed") {
			style = errorStyle
		} else if strings.Contains(strings.ToLower(m.message), "reloaded") || strings.Contains(strings.ToLower(m.message), "created") || strings.Contains(strings.ToLower(m.message), "updated") {
			style = successStyle
		} else if strings.Contains(strings.ToLower(m.message), "warning") {
			style = warningStyle
		}
		b.WriteString(style.Render(m.statusLine()))
	}
	b.WriteString("\n")

	return b.String()
}

func coloredStatus(status checks.Status) string {
	s := truncate(string(status), 9)
	switch status {
	case checks.StatusEnabled:
		return successStyle.Render(s)
	case checks.StatusDraft:
		return warningStyle.Render(s)
	case checks.StatusDisabled:
		return mutedStyle.Render(s)
	default:
		return infoStyle.Render(s)
	}
}

func coloredSeverity(severity string, maxLen int) string {
	s := severity
	if maxLen > 0 {
		s = truncate(s, maxLen)
	}
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return criticalStyle.Render(s)
	case "high":
		return highStyle.Render(s)
	case "medium":
		return mediumStyle.Render(s)
	case "low":
		return lowStyle.Render(s)
	case "info":
		return infoStyle.Render(s)
	default:
		return mutedStyle.Render(s)
	}
}

func diagBadge(errors, warnings int) string {
	if errors == 0 && warnings == 0 {
		return dimStyle.Render("e0/w0")
	}
	parts := []string{}
	if errors > 0 {
		parts = append(parts, errorStyle.Render(fmt.Sprintf("e%d", errors)))
	} else {
		parts = append(parts, dimStyle.Render("e0"))
	}
	if warnings > 0 {
		parts = append(parts, warningStyle.Render(fmt.Sprintf("w%d", warnings)))
	} else {
		parts = append(parts, dimStyle.Render("w0"))
	}
	return strings.Join(parts, dimStyle.Render("/"))
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
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
