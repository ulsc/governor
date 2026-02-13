package extractor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"governor/internal/checks"
	"governor/internal/envsafe"
)

const (
	maxTotalInputBytes = 20 * 1024 * 1024
	maxPerFileBytes    = 8 * 1024 * 1024
	maxSnippetChars    = 12000
	maxPromptChars     = 220000
	pdfTimeout         = 30 * time.Second
)

type Options struct {
	Inputs    []string
	ChecksDir string
	CodexBin  string
	MaxChecks int
	Replace   bool
	Mode      string
	Sandbox   string
	AllowPDF  bool
}

type Result struct {
	Created  []string
	Skipped  []string
	Warnings []string
}

type extractorOutput struct {
	Checks []candidateCheck `json:"checks"`
}

type candidateCheck struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Instructions   string   `json:"instructions"`
	IncludeGlobs   []string `json:"include_globs"`
	ExcludeGlobs   []string `json:"exclude_globs"`
	CategoriesHint []string `json:"categories_hint"`
	SeverityHint   string   `json:"severity_hint"`
	ConfidenceHint float64  `json:"confidence_hint"`
}

func Run(ctx context.Context, opts Options) (Result, error) {
	if len(opts.Inputs) == 0 {
		return Result{}, fmt.Errorf("at least one --input is required")
	}
	if strings.TrimSpace(opts.CodexBin) == "" {
		opts.CodexBin = "codex"
	}
	if opts.MaxChecks <= 0 {
		opts.MaxChecks = 10
	}
	if normalizeExecutionMode(opts.Mode) == "" {
		opts.Mode = "sandboxed"
	}
	if normalizeSandboxMode(opts.Sandbox) == "" {
		opts.Sandbox = "read-only"
	}

	checksDir, err := checks.ResolveWriteDir(opts.ChecksDir)
	if err != nil {
		return Result{}, err
	}
	if err := checks.EnsureDir(checksDir); err != nil {
		return Result{}, fmt.Errorf("create checks dir: %w", err)
	}

	docs, warnings, err := loadInputs(opts.Inputs, opts.AllowPDF)
	if err != nil {
		return Result{}, err
	}
	if len(docs) == 0 {
		return Result{Warnings: warnings}, fmt.Errorf("no supported documents found")
	}

	promptText := buildPrompt(docs, opts.MaxChecks)
	out, err := runExtractorModel(ctx, opts.CodexBin, opts.Mode, opts.Sandbox, promptText)
	if err != nil {
		return Result{Warnings: warnings}, err
	}

	created := make([]string, 0, len(out.Checks))
	skipped := make([]string, 0, len(out.Checks))
	for _, cand := range out.Checks {
		def := checks.NormalizeDefinition(checks.Definition{
			APIVersion:     checks.APIVersion,
			ID:             cand.ID,
			Name:           cand.Name,
			Status:         checks.StatusDraft,
			Source:         checks.SourceCustom,
			Description:    cand.Description,
			Instructions:   cand.Instructions,
			CategoriesHint: cand.CategoriesHint,
			SeverityHint:   cand.SeverityHint,
			ConfidenceHint: cand.ConfidenceHint,
			Scope: checks.Scope{
				IncludeGlobs: cand.IncludeGlobs,
				ExcludeGlobs: cand.ExcludeGlobs,
			},
			Origin: checks.Origin{
				Method: "extracted",
				Inputs: docs.paths(),
			},
		})

		path, writeErr := checks.WriteDefinition(checksDir, def, opts.Replace)
		if writeErr != nil {
			warnings = append(warnings, fmt.Sprintf("skip %q: %v", def.ID, writeErr))
			skipped = append(skipped, def.ID)
			continue
		}
		created = append(created, path)
	}

	if len(created) == 0 {
		return Result{
			Created:  created,
			Skipped:  skipped,
			Warnings: warnings,
		}, fmt.Errorf("extractor produced no saved checks")
	}
	return Result{
		Created:  created,
		Skipped:  skipped,
		Warnings: warnings,
	}, nil
}

func runExtractorModel(ctx context.Context, codexBin string, mode string, sandbox string, promptText string) (extractorOutput, error) {
	tmpDir, err := os.MkdirTemp("", "governor-check-extract-*")
	if err != nil {
		return extractorOutput{}, fmt.Errorf("create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	schemaPath := filepath.Join(tmpDir, "extractor-schema.json")
	outputPath := filepath.Join(tmpDir, "extractor-output.json")
	logPath := filepath.Join(tmpDir, "extractor.log")
	if err := os.WriteFile(schemaPath, []byte(extractorSchema), 0o600); err != nil {
		return extractorOutput{}, fmt.Errorf("write extractor schema: %w", err)
	}

	args := []string{
		"exec",
		"--skip-git-repo-check",
	}
	if normalizeExecutionMode(mode) == "sandboxed" {
		args = append(args, "-s", normalizeSandboxMode(sandbox))
	}
	args = append(args,
		"--output-schema", schemaPath,
		"-o", outputPath,
		"--color", "never",
		"-",
	)
	cmd := exec.CommandContext(ctx, codexBin, args...)
	cmd.Stdin = strings.NewReader(promptText)
	cmd.Env = buildExtractorEnv(os.Environ())
	logBytes, runErr := cmd.CombinedOutput()
	_ = os.WriteFile(logPath, logBytes, 0o600)
	if runErr != nil {
		return extractorOutput{}, fmt.Errorf("extract checks with codex: %w (log: %s)", runErr, logPath)
	}

	payload, err := os.ReadFile(outputPath)
	if err != nil {
		return extractorOutput{}, fmt.Errorf("read extractor output: %w", err)
	}

	var out extractorOutput
	if err := json.Unmarshal(payload, &out); err != nil {
		return extractorOutput{}, fmt.Errorf("parse extractor output: %w", err)
	}
	return out, nil
}

func normalizeExecutionMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "sandboxed":
		return "sandboxed"
	case "host":
		return "host"
	default:
		return ""
	}
}

func normalizeSandboxMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "read-only":
		return "read-only"
	case "workspace-write":
		return "workspace-write"
	case "danger-full-access":
		return "danger-full-access"
	default:
		return ""
	}
}

func buildExtractorEnv(in []string) []string {
	return envsafe.CodexEnv(in)
}

type docSet []doc

type doc struct {
	path    string
	content string
}

type inputLimitError struct {
	msg string
}

func (e inputLimitError) Error() string {
	return e.msg
}

func limitError(format string, args ...any) error {
	return inputLimitError{msg: fmt.Sprintf(format, args...)}
}

func isLimitError(err error) bool {
	var target inputLimitError
	return errors.As(err, &target)
}

func (d docSet) paths() []string {
	out := make([]string, 0, len(d))
	for _, item := range d {
		out = append(out, item.path)
	}
	sort.Strings(out)
	return out
}

func loadInputs(inputs []string, allowPDF bool) (docSet, []string, error) {
	return loadInputsWithLimit(inputs, maxTotalInputBytes, allowPDF)
}

func loadInputsWithLimit(inputs []string, totalLimit int, allowPDF bool) (docSet, []string, error) {
	if totalLimit <= 0 {
		return nil, nil, fmt.Errorf("total input byte limit must be > 0")
	}

	out := make(docSet, 0, 32)
	warnings := make([]string, 0, 8)
	seen := map[string]struct{}{}
	total := 0

	addDoc := func(path string) error {
		abs, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		if _, ok := seen[abs]; ok {
			return nil
		}

		remaining := totalLimit - total
		if remaining <= 0 {
			return limitError("input document text exceeds %d bytes", totalLimit)
		}

		text, bytesUsed, err := readDocBounded(abs, remaining, allowPDF)
		if err != nil {
			return err
		}
		total += bytesUsed
		if total > totalLimit {
			return limitError("input document text exceeds %d bytes", totalLimit)
		}

		seen[abs] = struct{}{}
		out = append(out, doc{path: abs, content: text})
		return nil
	}

	for _, raw := range inputs {
		path := strings.TrimSpace(raw)
		if path == "" {
			continue
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil, warnings, fmt.Errorf("resolve input path %q: %w", path, err)
		}
		info, err := os.Lstat(abs)
		if err != nil {
			return nil, warnings, fmt.Errorf("stat input path %q: %w", abs, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, warnings, fmt.Errorf("symlink inputs are not allowed: %s", abs)
		}

		if info.IsDir() {
			root := abs
			walkErr := filepath.WalkDir(abs, func(p string, d os.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if p == root {
					return nil
				}
				if isDirEntrySymlink(d) {
					warnings = append(warnings, fmt.Sprintf("skip %s: symlink entries are not allowed", p))
					if d.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
				if d.IsDir() {
					return nil
				}
				readErr := addDoc(p)
				if readErr != nil {
					if isLimitError(readErr) {
						return readErr
					}
					warnings = append(warnings, fmt.Sprintf("skip %s: %v", p, readErr))
					return nil
				}
				return nil
			})
			if walkErr != nil {
				return nil, warnings, walkErr
			}
			continue
		}

		readErr := addDoc(abs)
		if readErr != nil {
			return nil, warnings, fmt.Errorf("read input %s: %w", abs, readErr)
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out, warnings, nil
}

func readDocBounded(path string, remaining int, allowPDF bool) (string, int, error) {
	if remaining <= 0 {
		return "", 0, limitError("input document text exceeds %d bytes", maxTotalInputBytes)
	}

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".md", ".txt":
		b, err := readRegularFileBounded(path, remaining)
		if err != nil {
			return "", 0, err
		}
		return strings.TrimSpace(string(b)), len(b), nil
	case ".pdf":
		if !allowPDF {
			return "", 0, fmt.Errorf("pdf extraction is disabled; pass --allow-pdf to enable")
		}
		b, err := readPDFFromToolBounded(path, remaining)
		if err != nil {
			return "", 0, err
		}
		return strings.TrimSpace(string(b)), len(b), nil
	default:
		return "", 0, fmt.Errorf("unsupported extension %q", ext)
	}
}

func readRegularFileBounded(path string, remaining int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("symlink entries are not allowed")
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("unsupported non-regular file")
	}
	if info.Size() > maxPerFileBytes {
		return nil, limitError("input file %s exceeds per-file limit (%d bytes)", path, maxPerFileBytes)
	}
	if info.Size() > int64(remaining) {
		return nil, limitError("input document text exceeds %d bytes", maxTotalInputBytes)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	limited := io.LimitReader(f, int64(remaining)+1)
	b, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(b) > remaining {
		return nil, limitError("input document text exceeds %d bytes", maxTotalInputBytes)
	}
	return b, nil
}

func readPDFFromToolBounded(path string, remaining int) ([]byte, error) {
	if _, err := exec.LookPath("pdftotext"); err != nil {
		return nil, fmt.Errorf("pdf unsupported without pdftotext in PATH")
	}

	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("symlink entries are not allowed")
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("unsupported non-regular file")
	}
	if info.Size() > maxPerFileBytes {
		return nil, limitError("input file %s exceeds per-file limit (%d bytes)", path, maxPerFileBytes)
	}

	outFile, err := os.CreateTemp("", "governor-pdf-text-*.txt")
	if err != nil {
		return nil, fmt.Errorf("create temp extraction file: %w", err)
	}
	outPath := outFile.Name()
	_ = outFile.Close()
	defer func() { _ = os.Remove(outPath) }()

	ctx, cancel := context.WithTimeout(context.Background(), pdfTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "pdftotext", "-layout", "-nopgbrk", path, outPath)
	toolOut, err := cmd.CombinedOutput()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("pdftotext timed out after %s", pdfTimeout)
		}
		toolMsg := strings.TrimSpace(string(toolOut))
		if len(toolMsg) > 200 {
			toolMsg = toolMsg[:200] + "..."
		}
		if toolMsg == "" {
			return nil, fmt.Errorf("pdftotext failed: %w", err)
		}
		return nil, fmt.Errorf("pdftotext failed: %w (%s)", err, toolMsg)
	}

	return readRegularFileBounded(outPath, remaining)
}

func isDirEntrySymlink(d os.DirEntry) bool {
	if d.Type()&os.ModeSymlink != 0 {
		return true
	}
	info, err := d.Info()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeSymlink != 0
}

func buildPrompt(docs docSet, maxChecks int) string {
	var b strings.Builder
	b.WriteString("You are a security policy-to-check extractor.\n")
	b.WriteString("Generate high-signal security audit checks from these enterprise documents.\n")
	b.WriteString("Return JSON only that matches the provided schema.\n\n")
	b.WriteString("Rules:\n")
	b.WriteString("- Produce practical checks with concrete instructions.\n")
	b.WriteString("- Use IDs that are lowercase slug-style and stable.\n")
	b.WriteString("- Avoid duplicates/overlap.\n")
	b.WriteString(fmt.Sprintf("- Generate at most %d checks.\n\n", maxChecks))

	for _, doc := range docs {
		content := strings.TrimSpace(doc.content)
		if len(content) > maxSnippetChars {
			content = content[:maxSnippetChars]
		}
		b.WriteString("Document: " + doc.path + "\n")
		b.WriteString(content + "\n\n")
	}

	out := b.String()
	if len(out) > maxPromptChars {
		return out[:maxPromptChars]
	}
	return out
}

const extractorSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["checks"],
  "properties": {
    "checks": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["id", "name", "description", "instructions", "include_globs", "exclude_globs", "categories_hint", "severity_hint", "confidence_hint"],
        "properties": {
          "id": {"type": "string"},
          "name": {"type": "string"},
          "description": {"type": "string"},
          "instructions": {"type": "string"},
          "include_globs": {"type": "array", "items": {"type": "string"}},
          "exclude_globs": {"type": "array", "items": {"type": "string"}},
          "categories_hint": {"type": "array", "items": {"type": "string"}},
          "severity_hint": {"type": "string"},
          "confidence_hint": {"type": "number"}
        }
      }
    }
  }
}`
