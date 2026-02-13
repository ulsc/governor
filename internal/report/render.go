package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"sort"
	"strings"

	"governor/internal/model"
	"governor/internal/redact"
)

func WriteJSON(path string, report model.AuditReport) error {
	report = redactReport(report)
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal audit report: %w", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("write audit json: %w", err)
	}
	return nil
}

func WriteMarkdown(path string, report model.AuditReport) error {
	report = redactReport(report)
	content := RenderMarkdown(report)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write audit markdown: %w", err)
	}
	return nil
}

func WriteHTML(path string, report model.AuditReport) error {
	report = redactReport(report)
	content := RenderHTML(report)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write audit html: %w", err)
	}
	return nil
}

func RenderHTML(report model.AuditReport) string {
	var b bytes.Buffer

	b.WriteString("<!doctype html>\n")
	b.WriteString("<html lang=\"en\">\n")
	b.WriteString("<head>\n")
	b.WriteString("  <meta charset=\"utf-8\">\n")
	b.WriteString("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	b.WriteString("  <title>Governor Security Audit</title>\n")
	b.WriteString("  <style>\n")
	b.WriteString("    :root {\n")
	b.WriteString("      color-scheme: light;\n")
	b.WriteString("      --bg: #f3f6fb;\n")
	b.WriteString("      --surface: #ffffff;\n")
	b.WriteString("      --border: #d7dee9;\n")
	b.WriteString("      --text: #102033;\n")
	b.WriteString("      --muted: #4f6278;\n")
	b.WriteString("      --critical: #b91c1c;\n")
	b.WriteString("      --high: #c2410c;\n")
	b.WriteString("      --medium: #b45309;\n")
	b.WriteString("      --low: #1d4ed8;\n")
	b.WriteString("      --info: #0f766e;\n")
	b.WriteString("      --ok: #047857;\n")
	b.WriteString("      --warn: #b45309;\n")
	b.WriteString("      --err: #b91c1c;\n")
	b.WriteString("    }\n")
	b.WriteString("    * { box-sizing: border-box; }\n")
	b.WriteString("    body {\n")
	b.WriteString("      margin: 0;\n")
	b.WriteString("      font-family: \"Segoe UI\", \"Helvetica Neue\", Arial, sans-serif;\n")
	b.WriteString("      background: radial-gradient(circle at top right, #e8f0ff, #f3f6fb 45%);\n")
	b.WriteString("      color: var(--text);\n")
	b.WriteString("      line-height: 1.5;\n")
	b.WriteString("    }\n")
	b.WriteString("    .page {\n")
	b.WriteString("      max-width: 1100px;\n")
	b.WriteString("      margin: 0 auto;\n")
	b.WriteString("      padding: 28px 20px 40px;\n")
	b.WriteString("    }\n")
	b.WriteString("    .hero {\n")
	b.WriteString("      background: linear-gradient(140deg, #102033, #1e3550);\n")
	b.WriteString("      color: #f8fbff;\n")
	b.WriteString("      border-radius: 16px;\n")
	b.WriteString("      padding: 20px 24px;\n")
	b.WriteString("      border: 1px solid #1f3b58;\n")
	b.WriteString("      margin-bottom: 20px;\n")
	b.WriteString("    }\n")
	b.WriteString("    .hero h1 {\n")
	b.WriteString("      margin: 0;\n")
	b.WriteString("      font-size: 28px;\n")
	b.WriteString("      letter-spacing: 0.3px;\n")
	b.WriteString("    }\n")
	b.WriteString("    .hero p {\n")
	b.WriteString("      margin: 8px 0 0;\n")
	b.WriteString("      color: #dbe8f7;\n")
	b.WriteString("    }\n")
	b.WriteString("    section {\n")
	b.WriteString("      background: var(--surface);\n")
	b.WriteString("      border: 1px solid var(--border);\n")
	b.WriteString("      border-radius: 14px;\n")
	b.WriteString("      padding: 18px;\n")
	b.WriteString("      margin-bottom: 16px;\n")
	b.WriteString("      box-shadow: 0 8px 24px rgba(16, 32, 51, 0.05);\n")
	b.WriteString("    }\n")
	b.WriteString("    h2 {\n")
	b.WriteString("      margin: 0 0 14px;\n")
	b.WriteString("      font-size: 20px;\n")
	b.WriteString("      color: #0c2138;\n")
	b.WriteString("    }\n")
	b.WriteString("    h3 {\n")
	b.WriteString("      margin: 0;\n")
	b.WriteString("      font-size: 17px;\n")
	b.WriteString("    }\n")
	b.WriteString("    h4 {\n")
	b.WriteString("      margin: 0 0 6px;\n")
	b.WriteString("      font-size: 14px;\n")
	b.WriteString("      color: #1b334d;\n")
	b.WriteString("    }\n")
	b.WriteString("    .meta-list {\n")
	b.WriteString("      margin: 0;\n")
	b.WriteString("      padding-left: 18px;\n")
	b.WriteString("    }\n")
	b.WriteString("    .meta-list li { margin-bottom: 4px; }\n")
	b.WriteString("    .summary-grid {\n")
	b.WriteString("      display: grid;\n")
	b.WriteString("      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));\n")
	b.WriteString("      gap: 12px;\n")
	b.WriteString("      margin-top: 14px;\n")
	b.WriteString("    }\n")
	b.WriteString("    .stat-card {\n")
	b.WriteString("      border: 1px solid var(--border);\n")
	b.WriteString("      border-radius: 12px;\n")
	b.WriteString("      padding: 12px;\n")
	b.WriteString("      background: #fbfcff;\n")
	b.WriteString("    }\n")
	b.WriteString("    .stat-card .label {\n")
	b.WriteString("      margin: 0;\n")
	b.WriteString("      font-size: 12px;\n")
	b.WriteString("      text-transform: uppercase;\n")
	b.WriteString("      letter-spacing: 0.08em;\n")
	b.WriteString("      color: var(--muted);\n")
	b.WriteString("    }\n")
	b.WriteString("    .stat-card .value {\n")
	b.WriteString("      margin: 6px 0 0;\n")
	b.WriteString("      font-size: 24px;\n")
	b.WriteString("      font-weight: 700;\n")
	b.WriteString("      color: #0e2238;\n")
	b.WriteString("    }\n")
	b.WriteString("    .critical .value { color: var(--critical); }\n")
	b.WriteString("    .high .value { color: var(--high); }\n")
	b.WriteString("    .medium .value { color: var(--medium); }\n")
	b.WriteString("    .low .value { color: var(--low); }\n")
	b.WriteString("    .info .value { color: var(--info); }\n")
	b.WriteString("    table {\n")
	b.WriteString("      width: 100%;\n")
	b.WriteString("      border-collapse: collapse;\n")
	b.WriteString("      font-size: 14px;\n")
	b.WriteString("    }\n")
	b.WriteString("    th, td {\n")
	b.WriteString("      border-bottom: 1px solid var(--border);\n")
	b.WriteString("      padding: 8px;\n")
	b.WriteString("      text-align: left;\n")
	b.WriteString("      vertical-align: top;\n")
	b.WriteString("    }\n")
	b.WriteString("    th {\n")
	b.WriteString("      color: var(--muted);\n")
	b.WriteString("      font-size: 12px;\n")
	b.WriteString("      text-transform: uppercase;\n")
	b.WriteString("      letter-spacing: 0.08em;\n")
	b.WriteString("    }\n")
	b.WriteString("    .status {\n")
	b.WriteString("      display: inline-block;\n")
	b.WriteString("      padding: 2px 8px;\n")
	b.WriteString("      border-radius: 999px;\n")
	b.WriteString("      font-size: 12px;\n")
	b.WriteString("      font-weight: 600;\n")
	b.WriteString("      text-transform: uppercase;\n")
	b.WriteString("    }\n")
	b.WriteString("    .status-success { background: #ecfdf5; color: var(--ok); }\n")
	b.WriteString("    .status-warning { background: #fffbeb; color: var(--warn); }\n")
	b.WriteString("    .status-failed { background: #fef2f2; color: var(--err); }\n")
	b.WriteString("    .status-other { background: #eff6ff; color: #1d4ed8; }\n")
	b.WriteString("    .warnings {\n")
	b.WriteString("      margin: 0;\n")
	b.WriteString("      padding-left: 18px;\n")
	b.WriteString("      color: #7f1d1d;\n")
	b.WriteString("    }\n")
	b.WriteString("    .finding {\n")
	b.WriteString("      border: 1px solid var(--border);\n")
	b.WriteString("      border-radius: 12px;\n")
	b.WriteString("      padding: 14px;\n")
	b.WriteString("      margin-bottom: 12px;\n")
	b.WriteString("      background: #fcfdff;\n")
	b.WriteString("    }\n")
	b.WriteString("    .finding-header {\n")
	b.WriteString("      display: flex;\n")
	b.WriteString("      flex-wrap: wrap;\n")
	b.WriteString("      align-items: center;\n")
	b.WriteString("      gap: 8px;\n")
	b.WriteString("      margin-bottom: 8px;\n")
	b.WriteString("    }\n")
	b.WriteString("    .badge {\n")
	b.WriteString("      display: inline-block;\n")
	b.WriteString("      font-size: 12px;\n")
	b.WriteString("      font-weight: 700;\n")
	b.WriteString("      border-radius: 999px;\n")
	b.WriteString("      padding: 4px 8px;\n")
	b.WriteString("      text-transform: uppercase;\n")
	b.WriteString("      letter-spacing: 0.06em;\n")
	b.WriteString("    }\n")
	b.WriteString("    .badge-critical { background: #fef2f2; color: var(--critical); }\n")
	b.WriteString("    .badge-high { background: #fff7ed; color: var(--high); }\n")
	b.WriteString("    .badge-medium { background: #fffbeb; color: var(--medium); }\n")
	b.WriteString("    .badge-low { background: #eff6ff; color: var(--low); }\n")
	b.WriteString("    .badge-info { background: #f0fdfa; color: var(--info); }\n")
	b.WriteString("    .badge-unknown { background: #f1f5f9; color: #334155; }\n")
	b.WriteString("    .finding-meta {\n")
	b.WriteString("      display: grid;\n")
	b.WriteString("      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));\n")
	b.WriteString("      gap: 6px;\n")
	b.WriteString("      margin: 10px 0;\n")
	b.WriteString("      font-size: 14px;\n")
	b.WriteString("    }\n")
	b.WriteString("    .finding-meta div {\n")
	b.WriteString("      border-left: 3px solid #e2e8f0;\n")
	b.WriteString("      padding-left: 8px;\n")
	b.WriteString("    }\n")
	b.WriteString("    .label-inline {\n")
	b.WriteString("      display: block;\n")
	b.WriteString("      color: var(--muted);\n")
	b.WriteString("      font-size: 12px;\n")
	b.WriteString("      text-transform: uppercase;\n")
	b.WriteString("      letter-spacing: 0.06em;\n")
	b.WriteString("    }\n")
	b.WriteString("    .file-refs {\n")
	b.WriteString("      margin: 6px 0 10px;\n")
	b.WriteString("      padding-left: 18px;\n")
	b.WriteString("      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;\n")
	b.WriteString("      font-size: 13px;\n")
	b.WriteString("    }\n")
	b.WriteString("    .text-block {\n")
	b.WriteString("      margin-top: 10px;\n")
	b.WriteString("      padding: 10px;\n")
	b.WriteString("      border: 1px solid #e2e8f0;\n")
	b.WriteString("      border-radius: 10px;\n")
	b.WriteString("      background: #ffffff;\n")
	b.WriteString("    }\n")
	b.WriteString("    .text-block p {\n")
	b.WriteString("      margin: 0;\n")
	b.WriteString("      white-space: normal;\n")
	b.WriteString("      font-size: 14px;\n")
	b.WriteString("      color: #132a43;\n")
	b.WriteString("    }\n")
	b.WriteString("    .muted { color: var(--muted); }\n")
	b.WriteString("    .empty { color: var(--muted); margin: 0; }\n")
	b.WriteString("    code {\n")
	b.WriteString("      background: #edf2ff;\n")
	b.WriteString("      color: #1e3a8a;\n")
	b.WriteString("      padding: 1px 5px;\n")
	b.WriteString("      border-radius: 6px;\n")
	b.WriteString("      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;\n")
	b.WriteString("      font-size: 12px;\n")
	b.WriteString("    }\n")
	b.WriteString("    @media (max-width: 700px) {\n")
	b.WriteString("      .hero h1 { font-size: 24px; }\n")
	b.WriteString("      section { padding: 14px; }\n")
	b.WriteString("      th:nth-child(5), td:nth-child(5) { display: none; }\n")
	b.WriteString("    }\n")
	b.WriteString("  </style>\n")
	b.WriteString("</head>\n")
	b.WriteString("<body>\n")
	b.WriteString("  <main class=\"page\">\n")
	b.WriteString("    <header class=\"hero\">\n")
	b.WriteString("      <h1>Governor Security Audit</h1>\n")
	b.WriteString(fmt.Sprintf("      <p>Run <code>%s</code> completed in %d ms</p>\n", htmlInline(report.RunMetadata.RunID), report.RunMetadata.DurationMS))
	b.WriteString("    </header>\n")

	b.WriteString("    <section>\n")
	b.WriteString("      <h2>Executive Summary</h2>\n")
	b.WriteString("      <ul class=\"meta-list\">\n")
	b.WriteString(fmt.Sprintf("        <li><strong>Input:</strong> <code>%s</code> (%s)</li>\n", htmlInline(report.InputSummary.InputPath), htmlInline(report.InputSummary.InputType)))
	b.WriteString(fmt.Sprintf("        <li><strong>Workspace:</strong> <code>%s</code></li>\n", htmlInline(report.InputSummary.WorkspacePath)))
	if strings.TrimSpace(report.RunMetadata.CodexRequestedBin) != "" {
		b.WriteString(fmt.Sprintf("        <li><strong>Codex requested:</strong> <code>%s</code></li>\n", htmlInline(report.RunMetadata.CodexRequestedBin)))
	}
	if strings.TrimSpace(report.RunMetadata.CodexBin) != "" {
		b.WriteString(fmt.Sprintf("        <li><strong>Codex resolved:</strong> <code>%s</code></li>\n", htmlInline(report.RunMetadata.CodexBin)))
	}
	if strings.TrimSpace(report.RunMetadata.CodexVersion) != "" {
		b.WriteString(fmt.Sprintf("        <li><strong>Codex version:</strong> <code>%s</code></li>\n", htmlInline(report.RunMetadata.CodexVersion)))
	}
	if strings.TrimSpace(report.RunMetadata.CodexSHA256) != "" {
		b.WriteString(fmt.Sprintf("        <li><strong>Codex SHA-256:</strong> <code>%s</code></li>\n", htmlInline(report.RunMetadata.CodexSHA256)))
	}
	if strings.TrimSpace(report.RunMetadata.ExecutionMode) != "" {
		modeLine := report.RunMetadata.ExecutionMode
		if strings.TrimSpace(report.RunMetadata.CodexSandbox) != "" {
			modeLine += " / sandbox=" + report.RunMetadata.CodexSandbox
		}
		b.WriteString(fmt.Sprintf("        <li><strong>Execution:</strong> <code>%s</code></li>\n", htmlInline(modeLine)))
	}
	if report.RunMetadata.EnabledChecks > 0 {
		b.WriteString(fmt.Sprintf("        <li><strong>Checks:</strong> %d (builtin=%d custom=%d)</li>\n",
			report.RunMetadata.EnabledChecks,
			report.RunMetadata.BuiltInChecks,
			report.RunMetadata.CustomChecks,
		))
		if len(report.RunMetadata.CheckIDs) > 0 {
			b.WriteString(fmt.Sprintf("        <li><strong>Check IDs:</strong> <code>%s</code></li>\n", htmlInline(strings.Join(report.RunMetadata.CheckIDs, ", "))))
		}
	}
	b.WriteString("      </ul>\n")
	b.WriteString("      <div class=\"summary-grid\">\n")
	b.WriteString(fmt.Sprintf("        <div class=\"stat-card\"><p class=\"label\">Total findings</p><p class=\"value\">%d</p></div>\n", len(report.Findings)))
	b.WriteString(fmt.Sprintf("        <div class=\"stat-card critical\"><p class=\"label\">Critical</p><p class=\"value\">%d</p></div>\n", report.CountsBySeverity["critical"]))
	b.WriteString(fmt.Sprintf("        <div class=\"stat-card high\"><p class=\"label\">High</p><p class=\"value\">%d</p></div>\n", report.CountsBySeverity["high"]))
	b.WriteString(fmt.Sprintf("        <div class=\"stat-card medium\"><p class=\"label\">Medium</p><p class=\"value\">%d</p></div>\n", report.CountsBySeverity["medium"]))
	b.WriteString(fmt.Sprintf("        <div class=\"stat-card low\"><p class=\"label\">Low</p><p class=\"value\">%d</p></div>\n", report.CountsBySeverity["low"]))
	b.WriteString(fmt.Sprintf("        <div class=\"stat-card info\"><p class=\"label\">Info</p><p class=\"value\">%d</p></div>\n", report.CountsBySeverity["info"]))
	b.WriteString("      </div>\n")
	b.WriteString("    </section>\n")

	b.WriteString("    <section>\n")
	b.WriteString("      <h2>Worker Results</h2>\n")
	if len(report.WorkerSummaries) == 0 {
		b.WriteString("      <p class=\"empty\">No worker results were reported.</p>\n")
	} else {
		b.WriteString("      <table>\n")
		b.WriteString("        <thead><tr><th>Track</th><th>Status</th><th>Findings</th><th>Duration</th><th>Error</th></tr></thead>\n")
		b.WriteString("        <tbody>\n")
		for _, ws := range report.WorkerSummaries {
			status := strings.TrimSpace(ws.Status)
			if status == "" {
				status = "unknown"
			}
			errorText := "none"
			if strings.TrimSpace(ws.Error) != "" {
				errorText = sanitizeInline(ws.Error)
			}
			b.WriteString(fmt.Sprintf(
				"          <tr><td><code>%s</code></td><td><span class=\"status %s\">%s</span></td><td>%d</td><td>%d ms</td><td>%s</td></tr>\n",
				htmlInline(ws.Track),
				statusClass(status),
				htmlInline(status),
				ws.FindingCount,
				ws.DurationMS,
				htmlInline(errorText),
			))
		}
		b.WriteString("        </tbody>\n")
		b.WriteString("      </table>\n")
	}
	b.WriteString("    </section>\n")

	if len(report.Errors) > 0 {
		b.WriteString("    <section>\n")
		b.WriteString("      <h2>Warnings</h2>\n")
		b.WriteString("      <ul class=\"warnings\">\n")
		for _, e := range report.Errors {
			b.WriteString(fmt.Sprintf("        <li>%s</li>\n", htmlInline(e)))
		}
		b.WriteString("      </ul>\n")
		b.WriteString("    </section>\n")
	}

	b.WriteString("    <section>\n")
	b.WriteString("      <h2>Findings</h2>\n")
	if len(report.Findings) == 0 {
		b.WriteString("      <p class=\"empty\">No findings were reported by workers.</p>\n")
		b.WriteString("    </section>\n")
		b.WriteString("  </main>\n")
		b.WriteString("</body>\n")
		b.WriteString("</html>\n")
		return b.String()
	}

	sorted := make([]model.Finding, len(report.Findings))
	copy(sorted, report.Findings)
	sort.SliceStable(sorted, func(i, j int) bool {
		ri := severityRank(sorted[i].Severity)
		rj := severityRank(sorted[j].Severity)
		if ri != rj {
			return ri < rj
		}
		if sorted[i].Category != sorted[j].Category {
			return sorted[i].Category < sorted[j].Category
		}
		return sorted[i].Title < sorted[j].Title
	})

	for _, f := range sorted {
		sev := strings.ToLower(strings.TrimSpace(f.Severity))
		if sev == "" {
			sev = "unknown"
		}

		b.WriteString("      <article class=\"finding\">\n")
		b.WriteString("        <div class=\"finding-header\">\n")
		b.WriteString(fmt.Sprintf("          <span class=\"badge badge-%s\">%s</span>\n", severityClass(sev), htmlInline(sev)))
		b.WriteString(fmt.Sprintf("          <h3>%s</h3>\n", htmlInline(f.Title)))
		b.WriteString("        </div>\n")
		b.WriteString("        <div class=\"finding-meta\">\n")
		b.WriteString(fmt.Sprintf("          <div><span class=\"label-inline\">ID</span><code>%s</code></div>\n", htmlInline(f.ID)))
		b.WriteString(fmt.Sprintf("          <div><span class=\"label-inline\">Category</span><code>%s</code></div>\n", htmlInline(f.Category)))
		b.WriteString(fmt.Sprintf("          <div><span class=\"label-inline\">Source Track</span><code>%s</code></div>\n", htmlInline(f.SourceTrack)))
		if f.Confidence > 0 {
			b.WriteString(fmt.Sprintf("          <div><span class=\"label-inline\">Confidence</span><code>%.2f</code></div>\n", f.Confidence))
		}
		b.WriteString("        </div>\n")
		if len(f.FileRefs) > 0 {
			b.WriteString("        <h4>File Refs</h4>\n")
			b.WriteString("        <ul class=\"file-refs\">\n")
			for _, file := range f.FileRefs {
				b.WriteString(fmt.Sprintf("          <li>%s</li>\n", htmlInline(file)))
			}
			b.WriteString("        </ul>\n")
		}
		b.WriteString("        <div class=\"text-block\">\n")
		b.WriteString("          <h4>Evidence</h4>\n")
		b.WriteString(fmt.Sprintf("          <p>%s</p>\n", htmlMultiline(f.Evidence)))
		b.WriteString("        </div>\n")
		b.WriteString("        <div class=\"text-block\">\n")
		b.WriteString("          <h4>Impact</h4>\n")
		b.WriteString(fmt.Sprintf("          <p>%s</p>\n", htmlMultiline(f.Impact)))
		b.WriteString("        </div>\n")
		b.WriteString("        <div class=\"text-block\">\n")
		b.WriteString("          <h4>Remediation</h4>\n")
		b.WriteString(fmt.Sprintf("          <p>%s</p>\n", htmlMultiline(f.Remediation)))
		b.WriteString("        </div>\n")
		b.WriteString("      </article>\n")
	}
	b.WriteString("    </section>\n")
	b.WriteString("  </main>\n")
	b.WriteString("</body>\n")
	b.WriteString("</html>\n")
	return b.String()
}

func RenderMarkdown(report model.AuditReport) string {
	var b bytes.Buffer

	b.WriteString("# Governor Security Audit\n\n")
	b.WriteString("## Executive Summary\n\n")
	b.WriteString(fmt.Sprintf("- Run ID: `%s`\n", report.RunMetadata.RunID))
	b.WriteString(fmt.Sprintf("- Input: `%s` (%s)\n", sanitizeInline(report.InputSummary.InputPath), sanitizeInline(report.InputSummary.InputType)))
	b.WriteString(fmt.Sprintf("- Workspace: `%s`\n", sanitizeInline(report.InputSummary.WorkspacePath)))
	b.WriteString(fmt.Sprintf("- Duration: `%d ms`\n", report.RunMetadata.DurationMS))
	if strings.TrimSpace(report.RunMetadata.CodexRequestedBin) != "" {
		b.WriteString(fmt.Sprintf("- Codex requested: `%s`\n", sanitizeInline(report.RunMetadata.CodexRequestedBin)))
	}
	if strings.TrimSpace(report.RunMetadata.CodexBin) != "" {
		b.WriteString(fmt.Sprintf("- Codex resolved: `%s`\n", sanitizeInline(report.RunMetadata.CodexBin)))
	}
	if strings.TrimSpace(report.RunMetadata.CodexVersion) != "" {
		b.WriteString(fmt.Sprintf("- Codex version: `%s`\n", sanitizeInline(report.RunMetadata.CodexVersion)))
	}
	if strings.TrimSpace(report.RunMetadata.CodexSHA256) != "" {
		b.WriteString(fmt.Sprintf("- Codex sha256: `%s`\n", sanitizeInline(report.RunMetadata.CodexSHA256)))
	}
	if strings.TrimSpace(report.RunMetadata.ExecutionMode) != "" {
		modeLine := report.RunMetadata.ExecutionMode
		if strings.TrimSpace(report.RunMetadata.CodexSandbox) != "" {
			modeLine += " / sandbox=" + report.RunMetadata.CodexSandbox
		}
		b.WriteString(fmt.Sprintf("- Execution: `%s`\n", sanitizeInline(modeLine)))
	}
	if report.RunMetadata.EnabledChecks > 0 {
		b.WriteString(fmt.Sprintf("- Checks: `%d` (builtin=%d custom=%d)\n",
			report.RunMetadata.EnabledChecks,
			report.RunMetadata.BuiltInChecks,
			report.RunMetadata.CustomChecks,
		))
		if len(report.RunMetadata.CheckIDs) > 0 {
			b.WriteString(fmt.Sprintf("- Check IDs: `%s`\n", strings.Join(report.RunMetadata.CheckIDs, ", ")))
		}
	}
	b.WriteString(fmt.Sprintf("- Total findings: **%d**\n", len(report.Findings)))
	b.WriteString(fmt.Sprintf("- Severity: critical=%d, high=%d, medium=%d, low=%d, info=%d\n\n",
		report.CountsBySeverity["critical"],
		report.CountsBySeverity["high"],
		report.CountsBySeverity["medium"],
		report.CountsBySeverity["low"],
		report.CountsBySeverity["info"],
	))

	b.WriteString("## Worker Results\n\n")
	for _, ws := range report.WorkerSummaries {
		line := fmt.Sprintf("- `%s`: status=%s, findings=%d, duration=%dms", ws.Track, ws.Status, ws.FindingCount, ws.DurationMS)
		if ws.Error != "" {
			line += ", error=" + sanitizeInline(ws.Error)
		}
		line += "\n"
		b.WriteString(line)
	}
	b.WriteString("\n")

	if len(report.Errors) > 0 {
		b.WriteString("## Warnings\n\n")
		for _, e := range report.Errors {
			b.WriteString("- " + sanitizeInline(e) + "\n")
		}
		b.WriteString("\n")
	}

	if len(report.Findings) == 0 {
		b.WriteString("## Findings\n\nNo findings were reported by workers.\n")
		return b.String()
	}

	b.WriteString("## Findings\n\n")
	sorted := make([]model.Finding, len(report.Findings))
	copy(sorted, report.Findings)
	sort.SliceStable(sorted, func(i, j int) bool {
		ri := severityRank(sorted[i].Severity)
		rj := severityRank(sorted[j].Severity)
		if ri != rj {
			return ri < rj
		}
		if sorted[i].Category != sorted[j].Category {
			return sorted[i].Category < sorted[j].Category
		}
		return sorted[i].Title < sorted[j].Title
	})

	for _, f := range sorted {
		b.WriteString(fmt.Sprintf("### [%s] %s\n\n", strings.ToUpper(f.Severity), f.Title))
		b.WriteString(fmt.Sprintf("- ID: `%s`\n", f.ID))
		b.WriteString(fmt.Sprintf("- Category: `%s`\n", f.Category))
		b.WriteString(fmt.Sprintf("- Source Track: `%s`\n", f.SourceTrack))
		if len(f.FileRefs) > 0 {
			b.WriteString("- File Refs:\n")
			for _, file := range f.FileRefs {
				b.WriteString(fmt.Sprintf("  - `%s`\n", file))
			}
		}
		if f.Confidence > 0 {
			b.WriteString(fmt.Sprintf("- Confidence: `%.2f`\n", f.Confidence))
		}
		b.WriteString("- Evidence:\n")
		b.WriteString(indentBlock(redact.Text(f.Evidence)))
		b.WriteString("- Impact:\n")
		b.WriteString(indentBlock(redact.Text(f.Impact)))
		b.WriteString("- Remediation:\n")
		b.WriteString(indentBlock(redact.Text(f.Remediation)))
		b.WriteString("\n")
	}

	return b.String()
}

func redactReport(in model.AuditReport) model.AuditReport {
	in.Errors = redact.Strings(in.Errors)

	if len(in.Findings) > 0 {
		findings := make([]model.Finding, 0, len(in.Findings))
		for _, f := range in.Findings {
			f.Title = redact.Text(f.Title)
			f.Evidence = redact.Text(f.Evidence)
			f.Impact = redact.Text(f.Impact)
			f.Remediation = redact.Text(f.Remediation)
			findings = append(findings, f)
		}
		in.Findings = findings
	}
	if len(in.WorkerSummaries) > 0 {
		workers := make([]model.WorkerResult, 0, len(in.WorkerSummaries))
		for _, w := range in.WorkerSummaries {
			w.Error = redact.Text(w.Error)
			w.RawOutput = redact.Text(w.RawOutput)
			workers = append(workers, w)
		}
		in.WorkerSummaries = workers
	}
	return in
}

func sanitizeInline(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 300 {
		return s[:300] + "..."
	}
	return s
}

func indentBlock(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "  - (none provided)\n"
	}
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = "  - " + strings.TrimSpace(lines[i])
	}
	return strings.Join(lines, "\n") + "\n"
}

func htmlInline(s string) string {
	return html.EscapeString(sanitizeInline(s))
}

func htmlMultiline(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "<span class=\"muted\">(none provided)</span>"
	}
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = html.EscapeString(strings.TrimSpace(lines[i]))
	}
	return strings.Join(lines, "<br>")
}

func severityClass(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	case "info":
		return "info"
	default:
		return "unknown"
	}
}

func statusClass(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "success":
		return "status-success"
	case "warning":
		return "status-warning"
	case "failed", "error", "timeout", "cancelled":
		return "status-failed"
	default:
		return "status-other"
	}
}

func severityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
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
