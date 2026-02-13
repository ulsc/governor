package tui

import "testing"

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
