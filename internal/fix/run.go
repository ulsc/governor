package fix

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"governor/internal/ai"
	"governor/internal/model"
	"governor/internal/redact"
	"governor/internal/safefile"
)

const (
	defaultMaxSuggestions = 50
)

var executeTrack = ai.ExecuteTrack

type Options struct {
	AuditPath string
	OutDir    string

	AIRuntime ai.Runtime

	AIRequestedBin string
	AIBin          string
	AIVersion      string
	AISHA256       string

	Filters model.FixFilters
}

type ArtifactPaths struct {
	FixDir        string
	SchemaPath    string
	RawOutputPath string
	LogPath       string
	JSONPath      string
	MarkdownPath  string
}

type aiFixOutput struct {
	Summary     string            `json:"summary"`
	Notes       []string          `json:"notes,omitempty"`
	Suggestions []aiFixSuggestion `json:"suggestions"`
}

type aiFixSuggestion struct {
	FindingID       string            `json:"finding_id"`
	Title           string            `json:"title"`
	SourceTrack     string            `json:"source_track,omitempty"`
	Priority        string            `json:"priority,omitempty"`
	Summary         string            `json:"summary"`
	Files           []aiFixFileChange `json:"files,omitempty"`
	ValidationSteps []string          `json:"validation_steps,omitempty"`
	RiskNotes       []string          `json:"risk_notes,omitempty"`
	Confidence      float64           `json:"confidence,omitempty"`
}

type aiFixFileChange struct {
	Path          string   `json:"path"`
	ChangeType    string   `json:"change_type,omitempty"`
	Instructions  []string `json:"instructions,omitempty"`
	CodeLocations []string `json:"code_locations,omitempty"`
}

func Run(ctx context.Context, opts Options) (model.FixReport, ArtifactPaths, error) {
	auditPath := strings.TrimSpace(opts.AuditPath)
	if auditPath == "" {
		return model.FixReport{}, ArtifactPaths{}, fmt.Errorf("audit path is required")
	}
	auditAbs, err := filepath.Abs(auditPath)
	if err != nil {
		return model.FixReport{}, ArtifactPaths{}, fmt.Errorf("resolve audit path: %w", err)
	}
	report, err := loadAuditReport(auditAbs)
	if err != nil {
		return model.FixReport{}, ArtifactPaths{}, err
	}

	filters := normalizeFilters(opts.Filters)
	selectedFindings := filterFindings(report.Findings, filters)
	warnings := make([]string, 0, 4)
	if len(report.Findings) > 0 && len(selectedFindings) == 0 {
		warnings = append(warnings, "no findings matched the selected fix filters")
	}

	outRoot, err := resolveOutRoot(opts.OutDir, auditAbs)
	if err != nil {
		return model.FixReport{}, ArtifactPaths{}, err
	}
	fixDir, err := safefile.EnsureDir(filepath.Join(outRoot, "fix"), 0o700, false)
	if err != nil {
		return model.FixReport{}, ArtifactPaths{}, fmt.Errorf("create fix output directory: %w", err)
	}

	paths := ArtifactPaths{
		FixDir:        fixDir,
		SchemaPath:    filepath.Join(fixDir, "fix-output-schema.json"),
		RawOutputPath: filepath.Join(fixDir, "fix-ai-output.json"),
		LogPath:       filepath.Join(fixDir, "fix-worker.log"),
		JSONPath:      filepath.Join(fixDir, "fix-suggestions.json"),
		MarkdownPath:  filepath.Join(fixDir, "fix-suggestions.md"),
	}
	if err := writeOutputSchema(paths.SchemaPath); err != nil {
		return model.FixReport{}, ArtifactPaths{}, err
	}

	fixReport := model.FixReport{
		GeneratedAt:    time.Now().UTC(),
		SourceAudit:    auditAbs,
		OutDir:         fixDir,
		SourceRunID:    strings.TrimSpace(report.RunMetadata.RunID),
		AIProfile:      strings.TrimSpace(opts.AIRuntime.Profile),
		AIProvider:     strings.TrimSpace(opts.AIRuntime.Provider),
		AIModel:        strings.TrimSpace(opts.AIRuntime.Model),
		AIAuthMode:     strings.TrimSpace(opts.AIRuntime.AuthMode),
		AIRequestedBin: strings.TrimSpace(opts.AIRequestedBin),
		AIBin:          strings.TrimSpace(valueOr(opts.AIBin, opts.AIRuntime.Bin)),
		AIVersion:      strings.TrimSpace(opts.AIVersion),
		AISHA256:       strings.TrimSpace(opts.AISHA256),
		ExecutionMode:  strings.TrimSpace(opts.AIRuntime.ExecutionMode),
		AISandbox:      strings.TrimSpace(opts.AIRuntime.SandboxMode),
		Filters:        filters,
		TotalFindings:  len(report.Findings),
		Selected:       len(selectedFindings),
		Suggestions:    []model.FixSuggestion{},
		Warnings:       warnings,
		Errors:         []string{},
	}

	if len(selectedFindings) == 0 {
		if err := writeJSON(paths.JSONPath, fixReport); err != nil {
			return model.FixReport{}, paths, err
		}
		if err := writeMarkdown(paths.MarkdownPath, fixReport); err != nil {
			return model.FixReport{}, paths, err
		}
		return fixReport, paths, nil
	}

	workspace := resolveWorkspace(report.InputSummary.InputPath)
	promptText := buildPrompt(report, selectedFindings)
	rawOutput, execErr := executeTrack(ctx, opts.AIRuntime, ai.ExecutionInput{
		Workspace:  workspace,
		SchemaPath: paths.SchemaPath,
		OutputPath: paths.RawOutputPath,
		PromptText: promptText,
		Env:        os.Environ(),
	})
	if logErr := writeWorkerLog(paths.LogPath, rawOutput, execErr); logErr != nil {
		fixReport.Warnings = append(fixReport.Warnings, logErr.Error())
	}

	payload, parseErr := parseAIOutput(paths.RawOutputPath)
	switch {
	case execErr != nil && parseErr != nil:
		return model.FixReport{}, paths, fmt.Errorf("generate fix suggestions: %w; parse ai output: %v", execErr, parseErr)
	case execErr != nil:
		fixReport.Warnings = append(fixReport.Warnings, fmt.Sprintf("ai execution warning: %v", execErr))
	case parseErr != nil:
		return model.FixReport{}, paths, fmt.Errorf("parse fix suggestions: %w", parseErr)
	}

	if len(payload.Notes) > 0 {
		fixReport.Warnings = append(fixReport.Warnings, redact.Strings(payload.Notes)...)
	}
	fixReport.Suggestions = mapSuggestions(payload.Suggestions, selectedFindings)
	if len(fixReport.Suggestions) == 0 {
		fixReport.Warnings = append(fixReport.Warnings, "ai output contained no valid suggestions")
	}

	if err := writeJSON(paths.JSONPath, fixReport); err != nil {
		return model.FixReport{}, paths, err
	}
	if err := writeMarkdown(paths.MarkdownPath, fixReport); err != nil {
		return model.FixReport{}, paths, err
	}
	return fixReport, paths, nil
}

func normalizeFilters(filters model.FixFilters) model.FixFilters {
	if filters.MaxSuggestions <= 0 {
		filters.MaxSuggestions = defaultMaxSuggestions
	}
	filters.OnlyFindingIDs = uniqueNormalized(filters.OnlyFindingIDs, false)
	filters.OnlySeverities = uniqueNormalized(filters.OnlySeverities, true)
	filters.OnlyChecks = uniqueNormalized(filters.OnlyChecks, true)
	return filters
}

func filterFindings(findings []model.Finding, filters model.FixFilters) []model.Finding {
	if len(findings) == 0 {
		return nil
	}
	idSet := make(map[string]struct{}, len(filters.OnlyFindingIDs))
	for _, id := range filters.OnlyFindingIDs {
		idSet[strings.TrimSpace(id)] = struct{}{}
	}
	sevSet := make(map[string]struct{}, len(filters.OnlySeverities))
	for _, sev := range filters.OnlySeverities {
		sevSet[strings.ToLower(strings.TrimSpace(sev))] = struct{}{}
	}
	checkSet := make(map[string]struct{}, len(filters.OnlyChecks))
	for _, check := range filters.OnlyChecks {
		checkSet[strings.ToLower(strings.TrimSpace(check))] = struct{}{}
	}

	selected := make([]model.Finding, 0, len(findings))
	for _, finding := range findings {
		if len(idSet) > 0 {
			if _, ok := idSet[strings.TrimSpace(finding.ID)]; !ok {
				continue
			}
		}
		if len(sevSet) > 0 {
			if _, ok := sevSet[strings.ToLower(strings.TrimSpace(finding.Severity))]; !ok {
				continue
			}
		}
		if len(checkSet) > 0 && !matchesCheckFilter(finding.SourceTrack, checkSet) {
			continue
		}
		selected = append(selected, finding)
	}

	sort.SliceStable(selected, func(i, j int) bool {
		wi := severityWeight(selected[i].Severity)
		wj := severityWeight(selected[j].Severity)
		if wi != wj {
			return wi < wj
		}
		return strings.ToLower(selected[i].Title) < strings.ToLower(selected[j].Title)
	})
	if len(selected) > filters.MaxSuggestions {
		selected = selected[:filters.MaxSuggestions]
	}
	return selected
}

func matchesCheckFilter(sourceTrack string, checkSet map[string]struct{}) bool {
	sourceTrack = strings.TrimSpace(strings.ToLower(sourceTrack))
	if sourceTrack == "" {
		return false
	}
	if _, ok := checkSet[sourceTrack]; ok {
		return true
	}
	parts := strings.Split(sourceTrack, ",")
	for _, part := range parts {
		part = strings.TrimSpace(strings.ToLower(part))
		if part == "" {
			continue
		}
		if _, ok := checkSet[part]; ok {
			return true
		}
	}
	return false
}

func mapSuggestions(in []aiFixSuggestion, selected []model.Finding) []model.FixSuggestion {
	if len(in) == 0 {
		return nil
	}
	selectedByID := make(map[string]model.Finding, len(selected))
	for _, finding := range selected {
		id := strings.TrimSpace(finding.ID)
		if id == "" {
			continue
		}
		selectedByID[id] = finding
	}

	out := make([]model.FixSuggestion, 0, len(in))
	for _, item := range in {
		suggestion := model.FixSuggestion{
			FindingID:       strings.TrimSpace(item.FindingID),
			Title:           strings.TrimSpace(item.Title),
			SourceTrack:     strings.TrimSpace(item.SourceTrack),
			Priority:        normalizePriority(item.Priority),
			Summary:         strings.TrimSpace(item.Summary),
			ValidationSteps: sanitizeLines(item.ValidationSteps),
			RiskNotes:       sanitizeLines(item.RiskNotes),
			Confidence:      clamp(item.Confidence, 0, 1),
		}

		if baseFinding, ok := selectedByID[suggestion.FindingID]; ok {
			if suggestion.Title == "" {
				suggestion.Title = strings.TrimSpace(baseFinding.Title)
			}
			if suggestion.SourceTrack == "" {
				suggestion.SourceTrack = strings.TrimSpace(baseFinding.SourceTrack)
			}
			if suggestion.Priority == "" {
				suggestion.Priority = derivePriority(baseFinding)
			}
			if suggestion.Confidence == 0 && baseFinding.Confidence > 0 {
				suggestion.Confidence = clamp(baseFinding.Confidence, 0, 1)
			}
		}
		if suggestion.Title == "" || suggestion.FindingID == "" {
			continue
		}
		if suggestion.Priority == "" {
			suggestion.Priority = "medium"
		}

		if len(item.Files) > 0 {
			files := make([]model.FixFileChange, 0, len(item.Files))
			for _, file := range item.Files {
				path := strings.TrimSpace(file.Path)
				if path == "" {
					continue
				}
				files = append(files, model.FixFileChange{
					Path:          filepath.ToSlash(path),
					ChangeType:    normalizeChangeType(file.ChangeType),
					Instructions:  sanitizeLines(file.Instructions),
					CodeLocations: sanitizeLines(file.CodeLocations),
				})
			}
			suggestion.Files = files
		}

		out = append(out, suggestion)
	}
	return out
}

func parseAIOutput(path string) (aiFixOutput, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return aiFixOutput{}, fmt.Errorf("read ai output: %w", err)
	}
	var out aiFixOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		return aiFixOutput{}, fmt.Errorf("parse ai output: %w", err)
	}
	return out, nil
}

func writeWorkerLog(path string, raw []byte, execErr error) error {
	logText := strings.TrimSpace(string(raw))
	if execErr != nil {
		if logText != "" {
			logText += "\n"
		}
		logText += "[governor] ai execution error: " + execErr.Error()
	}
	if strings.TrimSpace(logText) == "" {
		logText = "[governor] no ai worker output"
	}
	logText = redact.Text(logText) + "\n"
	if err := safefile.WriteFileAtomic(path, []byte(logText), 0o600); err != nil {
		return fmt.Errorf("write fix worker log: %w", err)
	}
	return nil
}

func loadAuditReport(path string) (model.AuditReport, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return model.AuditReport{}, fmt.Errorf("read audit report %s: %w", path, err)
	}
	var report model.AuditReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return model.AuditReport{}, fmt.Errorf("parse audit report %s: %w", path, err)
	}
	return report, nil
}

func resolveOutRoot(rawOut string, auditAbs string) (string, error) {
	rawOut = strings.TrimSpace(rawOut)
	if rawOut == "" {
		return filepath.Dir(auditAbs), nil
	}
	abs, err := filepath.Abs(rawOut)
	if err != nil {
		return "", fmt.Errorf("resolve output path: %w", err)
	}
	return abs, nil
}

func resolveWorkspace(inputPath string) string {
	inputPath = strings.TrimSpace(inputPath)
	if inputPath != "" {
		if info, err := os.Stat(inputPath); err == nil {
			if info.IsDir() {
				return inputPath
			}
			return filepath.Dir(inputPath)
		}
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return cwd
}

func writeOutputSchema(path string) error {
	const schema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["summary", "suggestions"],
  "properties": {
    "summary": {"type": "string"},
    "notes": {"type": "array", "items": {"type": "string"}},
    "suggestions": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["finding_id", "title", "summary", "files", "validation_steps", "confidence"],
        "properties": {
          "finding_id": {"type": "string"},
          "title": {"type": "string"},
          "source_track": {"type": "string"},
          "priority": {"type": "string"},
          "summary": {"type": "string"},
          "files": {
            "type": "array",
            "items": {
              "type": "object",
              "additionalProperties": false,
              "required": ["path", "instructions"],
              "properties": {
                "path": {"type": "string"},
                "change_type": {"type": "string"},
                "instructions": {"type": "array", "items": {"type": "string"}},
                "code_locations": {"type": "array", "items": {"type": "string"}}
              }
            }
          },
          "validation_steps": {"type": "array", "items": {"type": "string"}},
          "risk_notes": {"type": "array", "items": {"type": "string"}},
          "confidence": {"type": "number"}
        }
      }
    }
  }
}`
	if err := safefile.WriteFileAtomic(path, []byte(schema), 0o600); err != nil {
		return fmt.Errorf("write fix output schema: %w", err)
	}
	return nil
}

func uniqueNormalized(in []string, lower bool) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, item := range in {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		key := item
		if lower {
			key = strings.ToLower(item)
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	return out
}

func sanitizeLines(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, item := range in {
		item = strings.TrimSpace(item)
		item = strings.ReplaceAll(item, "\n", " ")
		item = strings.ReplaceAll(item, "\r", " ")
		if item == "" {
			continue
		}
		out = append(out, item)
	}
	return out
}

func normalizePriority(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return ""
	}
}

func normalizeChangeType(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "modify":
		return "modify"
	case "add":
		return "add"
	case "remove":
		return "remove"
	case "config":
		return "config"
	default:
		return ""
	}
}

func derivePriority(finding model.Finding) string {
	switch strings.ToLower(strings.TrimSpace(finding.Severity)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low", "info":
		return "low"
	default:
		return "medium"
	}
}

func severityWeight(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
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

func clamp(value float64, min float64, max float64) float64 {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func valueOr(primary, fallback string) string {
	primary = strings.TrimSpace(primary)
	if primary != "" {
		return primary
	}
	return strings.TrimSpace(fallback)
}
