package comment

import (
	"bytes"
	"fmt"
	"strings"
	"unicode"

	"governor/internal/diff"
	"governor/internal/model"
)

// Options configures PR comment generation.
type Options struct {
	ShowSuppressed bool
}

// Generate produces a markdown PR comment from an audit report and optional diff.
// If diffReport is nil, all findings are shown without new/fixed/unchanged breakdown.
func Generate(report model.AuditReport, diffReport *diff.DiffReport, _ Options) string {
	var b bytes.Buffer

	b.WriteString("## Governor Security Audit\n\n")

	if diffReport != nil {
		generateWithDiff(&b, report, *diffReport)
	} else {
		generateWithoutDiff(&b, report)
	}

	return b.String()
}

func generateWithDiff(b *bytes.Buffer, report model.AuditReport, dr diff.DiffReport) {
	parts := make([]string, 0, 4)
	if dr.Summary.NewCount > 0 {
		parts = append(parts, fmt.Sprintf("**%d new finding(s)**", dr.Summary.NewCount))
	} else {
		parts = append(parts, "**0 new findings**")
	}
	if dr.Summary.FixedCount > 0 {
		parts = append(parts, fmt.Sprintf("%d fixed", dr.Summary.FixedCount))
	}
	if dr.Summary.UnchangedCount > 0 {
		parts = append(parts, fmt.Sprintf("%d unchanged", dr.Summary.UnchangedCount))
	}
	if report.SuppressedCount > 0 {
		parts = append(parts, fmt.Sprintf("%d suppressed", report.SuppressedCount))
	}
	b.WriteString(strings.Join(parts, " | ") + "\n\n")

	if len(dr.New) > 0 {
		b.WriteString("### New Findings\n\n")
		b.WriteString("| Severity | Title | Check | File |\n")
		b.WriteString("|----------|-------|-------|------|\n")
		for _, f := range dr.New {
			file := firstFileRef(f)
			fmt.Fprintf(b, "| %s | %s | %s | %s |\n",
				titleCase(f.Severity), sanitize(f.Title), f.SourceTrack, file)
		}
		b.WriteString("\n")
	}

	if len(dr.Fixed) > 0 {
		b.WriteString("### Fixed (since baseline)\n\n")
		b.WriteString("| Title | Check |\n")
		b.WriteString("|-------|-------|\n")
		for _, f := range dr.Fixed {
			fmt.Fprintf(b, "| %s | %s |\n", sanitize(f.Title), f.SourceTrack)
		}
		b.WriteString("\n")
	}

	if len(dr.Unchanged) > 0 {
		fmt.Fprintf(b, "<details><summary>%d unchanged finding(s)</summary>\n\n", len(dr.Unchanged))
		b.WriteString("| Severity | Title | Check |\n")
		b.WriteString("|----------|-------|-------|\n")
		for _, f := range dr.Unchanged {
			fmt.Fprintf(b, "| %s | %s | %s |\n",
				titleCase(f.Severity), sanitize(f.Title), f.SourceTrack)
		}
		b.WriteString("\n</details>\n")
	}
}

func generateWithoutDiff(b *bytes.Buffer, report model.AuditReport) {
	total := len(report.Findings)
	fmt.Fprintf(b, "**%d finding(s)**", total)
	if report.SuppressedCount > 0 {
		fmt.Fprintf(b, " | %d suppressed", report.SuppressedCount)
	}
	b.WriteString("\n\n")

	if total == 0 {
		b.WriteString("No security findings detected.\n")
		return
	}

	b.WriteString("| Severity | Title | Check | File |\n")
	b.WriteString("|----------|-------|-------|------|\n")
	for _, f := range report.Findings {
		file := firstFileRef(f)
		fmt.Fprintf(b, "| %s | %s | %s | %s |\n",
			titleCase(f.Severity), sanitize(f.Title), f.SourceTrack, file)
	}
}

func firstFileRef(f model.Finding) string {
	if len(f.FileRefs) == 0 {
		return ""
	}
	return f.FileRefs[0]
}

func sanitize(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 100 {
		return s[:100] + "..."
	}
	return s
}

func titleCase(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return s
	}
	runes := []rune(s)
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}
