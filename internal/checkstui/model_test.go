package checkstui

import (
	"os"
	"path/filepath"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"governor/internal/checks"
)

func TestMatchesFilters_SearchStatusSource(t *testing.T) {
	row := row{
		ID:         "authz-check",
		Name:       "Authz Check",
		Status:     checks.StatusEnabled,
		Source:     checks.SourceCustom,
		Severity:   "high",
		Categories: []string{"auth", "idor"},
		Path:       "/tmp/authz.check.yaml",
	}
	if !matchesFilters(row, "authz", sourceCustom, statusEnabled) {
		t.Fatal("expected row to match custom/enabled/authz filters")
	}
	if matchesFilters(row, "secrets", sourceCustom, statusEnabled) {
		t.Fatal("expected row not to match unrelated search term")
	}
	if matchesFilters(row, "authz", sourceBuiltin, statusEnabled) {
		t.Fatal("expected row not to match builtin source filter")
	}
	if matchesFilters(row, "authz", sourceCustom, statusDraft) {
		t.Fatal("expected row not to match draft status filter")
	}
}

func TestModel_StatusAndDuplicateActions(t *testing.T) {
	repoRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoRoot, ".git"), 0o700); err != nil {
		t.Fatalf("create .git: %v", err)
	}
	homeRoot := filepath.Join(t.TempDir(), "home")
	t.Setenv("HOME", homeRoot)

	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(repoRoot); err != nil {
		t.Fatalf("chdir repo: %v", err)
	}
	defer func() {
		_ = os.Chdir(oldWD)
	}()

	repoChecks := filepath.Join(repoRoot, ".governor", "checks")
	if _, err := checks.WriteDefinition(repoChecks, checks.Definition{
		APIVersion:   checks.APIVersion,
		ID:           "status-check",
		Name:         "Status Check",
		Status:       checks.StatusDraft,
		Source:       checks.SourceCustom,
		Description:  "description",
		Instructions: "This instruction text is intentionally long enough to pass minimum checks.",
	}, false); err != nil {
		t.Fatalf("write check: %v", err)
	}

	m, err := newModel(Options{})
	if err != nil {
		t.Fatalf("newModel: %v", err)
	}
	selectRowByID(t, &m, "status-check")

	m = m.startStatusConfirmation(checks.StatusEnabled)
	if m.mode != modeConfirmStatus {
		t.Fatalf("expected mode %q, got %q", modeConfirmStatus, m.mode)
	}
	m = m.handleConfirmStatusMode(tea.KeyMsg{Type: tea.KeyEnter})
	if m.mode != modeBrowse {
		t.Fatalf("expected mode %q after confirm, got %q", modeBrowse, m.mode)
	}

	updated, err := checks.ReadDefinition(filepath.Join(repoChecks, "status-check.check.yaml"))
	if err != nil {
		t.Fatalf("read updated check: %v", err)
	}
	if updated.Status != checks.StatusEnabled {
		t.Fatalf("expected enabled status, got %s", updated.Status)
	}

	selectRowByID(t, &m, "status-check")
	m = m.startDuplicateFlow()
	if m.mode != modeDuplicateID {
		t.Fatalf("expected mode %q, got %q", modeDuplicateID, m.mode)
	}
	m.duplicateID = "status-check-copy"
	m = m.handleDuplicateIDMode(tea.KeyMsg{Type: tea.KeyEnter})
	if m.mode != modeDuplicateName {
		t.Fatalf("expected mode %q, got %q", modeDuplicateName, m.mode)
	}
	m.duplicateName = "Status Check Copy"
	m = m.handleDuplicateNameMode(tea.KeyMsg{Type: tea.KeyEnter})
	if m.mode != modeBrowse {
		t.Fatalf("expected mode %q after duplicate, got %q", modeBrowse, m.mode)
	}

	dup, err := checks.ReadDefinition(filepath.Join(repoChecks, "status-check-copy.check.yaml"))
	if err != nil {
		t.Fatalf("read duplicate check: %v", err)
	}
	if dup.Status != checks.StatusDraft {
		t.Fatalf("expected draft duplicate, got %s", dup.Status)
	}
	if dup.Source != checks.SourceCustom {
		t.Fatalf("expected custom duplicate, got %s", dup.Source)
	}
}

func TestModel_StatusChangeRejectsReadonlyRow(t *testing.T) {
	m, err := newModel(Options{})
	if err != nil {
		t.Fatalf("newModel: %v", err)
	}
	selectRowByID(t, &m, "appsec")
	m = m.startStatusConfirmation(checks.StatusDisabled)
	if m.mode != modeBrowse {
		t.Fatalf("expected browse mode for read-only row, got %q", m.mode)
	}
	if m.pendingStatus != nil {
		t.Fatal("expected no pending action for read-only row")
	}
}

func selectRowByID(t *testing.T, m *uiModel, id string) {
	t.Helper()
	for idx, rowIndex := range m.filtered {
		if m.snapshot.Rows[rowIndex].ID == id {
			m.cursor = idx
			return
		}
	}
	t.Fatalf("row %q not found", id)
}
