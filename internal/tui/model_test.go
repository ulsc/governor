package tui

import (
	"strings"
	"testing"
	"time"

	"governor/internal/progress"
)

func TestOrderedTracks_PrioritizesRunningThenFailed(t *testing.T) {
	m := uiModel{
		workers: map[string]workerState{
			"z-success": {Track: "z-success", Status: "success"},
			"a-running": {Track: "a-running", Status: "running"},
			"m-failed":  {Track: "m-failed", Status: "failed"},
			"b-pending": {Track: "b-pending", Status: "pending"},
		},
	}

	got := m.orderedTracks()
	if len(got) != 4 {
		t.Fatalf("expected 4 tracks, got %d", len(got))
	}
	if got[0] != "a-running" {
		t.Fatalf("expected running track first, got %v", got)
	}
	if got[1] != "m-failed" {
		t.Fatalf("expected failed track second, got %v", got)
	}
}

func TestVisibleEventLines_FilterAndPause(t *testing.T) {
	m := uiModel{
		logLines: []eventLine{
			{Track: "", Severity: "info", Text: "run started"},
			{Track: "appsec", Severity: "warning", Text: "warning"},
			{Track: "secrets", Severity: "error", Text: "failed"},
		},
		eventFilter: "appsec",
	}

	filtered := m.visibleEventLines()
	if len(filtered) != 2 {
		t.Fatalf("expected 2 lines (global + appsec), got %d", len(filtered))
	}

	m.pauseEvents = true
	m.pausedLines = []eventLine{{Track: "appsec", Severity: "info", Text: "paused snapshot"}}
	filteredPaused := m.visibleEventLines()
	if len(filteredPaused) != 1 {
		t.Fatalf("expected paused snapshot to be used, got %d", len(filteredPaused))
	}
	if filteredPaused[0].Text != "paused snapshot" {
		t.Fatalf("unexpected paused line: %+v", filteredPaused[0])
	}
}

func TestNoColorEnabled(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	if !noColorEnabled() {
		t.Fatal("expected NO_COLOR to enable no-color mode")
	}
}

func TestApplyEvent_RunAndWorkerLifecycle(t *testing.T) {
	m := newModel(nil)
	base := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)

	m.applyEvent(progress.Event{Type: progress.EventRunStarted, RunID: "run-1", At: base})
	m.applyEvent(progress.Event{Type: progress.EventWorkerStarted, Track: "appsec", At: base.Add(1 * time.Second)})
	m.applyEvent(progress.Event{Type: progress.EventWorkerHeartbeat, Track: "appsec", DurationMS: 1500, At: base.Add(2 * time.Second)})
	m.applyEvent(progress.Event{
		Type:         progress.EventWorkerFinished,
		Track:        "appsec",
		Status:       "failed",
		FindingCount: 2,
		DurationMS:   2100,
		Error:        "worker error",
		At:           base.Add(3 * time.Second),
	})
	m.applyEvent(progress.Event{
		Type:         progress.EventRunFinished,
		Status:       "failed",
		FindingCount: 2,
		DurationMS:   4000,
		Error:        "run error",
		At:           base.Add(4 * time.Second),
	})

	if !m.done {
		t.Fatal("expected model to be marked done after run_finished")
	}
	if m.runID != "run-1" {
		t.Fatalf("expected run id run-1, got %q", m.runID)
	}
	if m.runStatus != "failed" {
		t.Fatalf("expected run status failed, got %q", m.runStatus)
	}
	if m.runError != "run error" {
		t.Fatalf("expected run error to be captured, got %q", m.runError)
	}
	if m.findings != 2 {
		t.Fatalf("expected finding count 2, got %d", m.findings)
	}
	if m.finishedAt.IsZero() {
		t.Fatal("expected finishedAt to be set")
	}

	worker, ok := m.workers["appsec"]
	if !ok {
		t.Fatal("expected appsec worker state to exist")
	}
	if worker.Status != "failed" {
		t.Fatalf("expected worker status failed, got %q", worker.Status)
	}
	if worker.FindingCount != 2 {
		t.Fatalf("expected worker findings 2, got %d", worker.FindingCount)
	}
	if worker.DurationMS != 2100 {
		t.Fatalf("expected worker duration 2100ms, got %d", worker.DurationMS)
	}
	if worker.Error != "worker error" {
		t.Fatalf("expected worker error propagated, got %q", worker.Error)
	}
	if worker.StartedAt.IsZero() {
		t.Fatal("expected worker startedAt to be set")
	}

	if len(m.logLines) == 0 {
		t.Fatal("expected lifecycle events to append log lines")
	}
	last := m.logLines[len(m.logLines)-1]
	if last.Severity != "error" {
		t.Fatalf("expected final log severity error, got %q", last.Severity)
	}
	if !strings.Contains(last.Text, "run finished status=failed") {
		t.Fatalf("unexpected final log text: %q", last.Text)
	}
}

func TestProgressBarAndCompletionBanner_RenderExpectedSummaries(t *testing.T) {
	m := uiModel{
		noColor: true,
		width:   80,
		workers: map[string]workerState{
			"ok":      {Track: "ok", Status: "success"},
			"warn":    {Track: "warn", Status: "warning"},
			"failed":  {Track: "failed", Status: "failed"},
			"running": {Track: "running", Status: "running"},
		},
		runError: "fatal run error",
		findings: 5,
		startedAt: time.Date(2026, time.January, 2, 3, 4, 0, 0, time.UTC),
		finishedAt: time.Date(2026, time.January, 2, 3, 4, 8, 0, time.UTC),
	}

	bar := m.progressBar(4, 1, 1, 1, 1, 0)
	if !strings.Contains(bar, "75%") || !strings.Contains(bar, "(3/4)") {
		t.Fatalf("unexpected progress bar summary: %q", bar)
	}
	emptyBar := m.progressBar(0, 0, 0, 0, 0, 0)
	if !strings.Contains(emptyBar, "[no workers]") {
		t.Fatalf("expected no-worker progress message, got %q", emptyBar)
	}

	banner := m.completionBanner()
	if !strings.Contains(banner, "FAILED") {
		t.Fatalf("expected failed completion banner, got %q", banner)
	}
	if !strings.Contains(banner, "5 findings") {
		t.Fatalf("expected finding count in banner, got %q", banner)
	}
	if !strings.Contains(banner, "8s") {
		t.Fatalf("expected elapsed duration in banner, got %q", banner)
	}
	if !strings.Contains(banner, "fatal run error") {
		t.Fatalf("expected run error in banner, got %q", banner)
	}
}

func TestEventFilterCycleAndSeverityHelpers(t *testing.T) {
	m := uiModel{
		workers: map[string]workerState{
			"appsec":  {Track: "appsec", Status: "running"},
			"secrets": {Track: "secrets", Status: "success"},
		},
		logLines: []eventLine{
			{Track: "", Severity: "info", Text: "run started"},
			{Track: "appsec", Severity: "warning", Text: "worker warning"},
			{Track: "secrets", Severity: "error", Text: "worker failed"},
		},
	}

	if next := m.nextEventFilter(); next != "appsec" {
		t.Fatalf("expected first filter to cycle to appsec, got %q", next)
	}
	m.eventFilter = "appsec"
	if next := m.nextEventFilter(); next != "secrets" {
		t.Fatalf("expected second filter to cycle to secrets, got %q", next)
	}
	m.eventFilter = "secrets"
	if next := m.nextEventFilter(); next != "" {
		t.Fatalf("expected third filter to cycle back to all, got %q", next)
	}

	m.eventFilter = "appsec"
	visible := m.visibleEventLines()
	if len(visible) != 2 {
		t.Fatalf("expected global + appsec lines with filter, got %d", len(visible))
	}
	if visible[0].Track != "" || visible[1].Track != "appsec" {
		t.Fatalf("unexpected filtered lines order/content: %+v", visible)
	}

	if got := eventSeverity(progress.Event{Type: progress.EventRunWarning}); got != "warning" {
		t.Fatalf("expected run warning severity warning, got %q", got)
	}
	if got := eventSeverity(progress.Event{Type: progress.EventWorkerFinished, Status: "failed"}); got != "error" {
		t.Fatalf("expected failed worker severity error, got %q", got)
	}
	if got := eventSeverity(progress.Event{Type: progress.EventRunFinished, Status: "partial"}); got != "warning" {
		t.Fatalf("expected partial run severity warning, got %q", got)
	}
	if got := eventSeverity(progress.Event{Type: progress.EventRunFinished, Status: "success"}); got != "info" {
		t.Fatalf("expected successful run severity info, got %q", got)
	}
}
