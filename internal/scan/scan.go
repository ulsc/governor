package scan

import (
	"context"
	"fmt"
	"os"

	"governor/internal/checks"
	"governor/internal/model"
	"governor/internal/worker"
)

// Options configures a scan run.
type Options struct {
	Files          []string
	ChecksDir      string
	NoCustomChecks bool
	OnlyIDs        []string
	SkipIDs        []string
}

// Result holds the output of a scan run.
type Result struct {
	Findings []model.Finding
	Checks   int
}

// Run resolves rule-engine checks and scans the given files.
func Run(ctx context.Context, opts Options) (Result, error) {
	for _, f := range opts.Files {
		info, err := os.Stat(f)
		if err != nil {
			return Result{}, fmt.Errorf("stat %s: %w", f, err)
		}
		if info.IsDir() {
			return Result{}, fmt.Errorf("%s is a directory (use `governor audit` for directories)", f)
		}
	}

	selection, err := checks.ResolveAuditSelection(checks.AuditSelectionOptions{
		ChecksDir:      opts.ChecksDir,
		NoCustomChecks: opts.NoCustomChecks,
		OnlyIDs:        opts.OnlyIDs,
		SkipIDs:        opts.SkipIDs,
		EngineFilter:   checks.EngineRule,
	})
	if err != nil {
		return Result{}, fmt.Errorf("resolve checks: %w", err)
	}

	var allFindings []model.Finding
	for _, checkDef := range selection.Checks {
		findings, scanErr := worker.ScanFiles(ctx, opts.Files, checkDef)
		if scanErr != nil {
			return Result{}, fmt.Errorf("scan check %s: %w", checkDef.ID, scanErr)
		}
		allFindings = append(allFindings, findings...)
	}

	return Result{
		Findings: allFindings,
		Checks:   len(selection.Checks),
	}, nil
}
