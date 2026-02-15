package checkstui

import (
	"strings"
	"testing"

	"governor/internal/checks"
)

func TestView_RendersEmptyStateAndNoSelectionDetails(t *testing.T) {
	m := uiModel{
		snapshot: snapshot{
			SearchedDirs: []string{"/tmp/repo/.governor/checks"},
			Rows:         nil,
			Effective:    0,
			Shadowed:     0,
		},
		filtered:     nil,
		cursor:       0,
		showDetails:  true,
		sourceFilter: sourceAll,
		statusFilter: statusAll,
		sort:         sortState{Key: sortByID},
		message:      "idle",
		mode:         modeBrowse,
		width:        120,
		height:       36,
	}

	view := m.View()
	if !strings.Contains(view, "Governor Checks Workspace") {
		t.Fatalf("expected title in view, got: %q", view)
	}
	if !strings.Contains(view, "(no matching checks)") {
		t.Fatalf("expected empty-table message in view, got: %q", view)
	}
	if !strings.Contains(view, "no row selected") {
		t.Fatalf("expected no-selection details message in view, got: %q", view)
	}
	if !strings.Contains(view, "idle") {
		t.Fatalf("expected status message in view, got: %q", view)
	}
}

func TestView_RendersSelectedRowDetailsAndDiagnostics(t *testing.T) {
	m := uiModel{
		snapshot: snapshot{
			SearchedDirs: []string{"/tmp/repo/.governor/checks"},
			Rows: []row{
				{
					ID:          "custom-authz",
					Name:        "Custom AuthZ",
					Status:      checks.StatusEnabled,
					Source:      checks.SourceCustom,
					Severity:    "high",
					Categories:  []string{"auth", "idor"},
					Path:        "/tmp/repo/.governor/checks/custom-authz.check.yaml",
					Effective:   true,
					Mutable:     true,
					DiagError:   1,
					DiagWarning: 2,
					DiagInfo:    1,
				},
			},
			Effective: 1,
			Shadowed:  0,
		},
		filtered:     []int{0},
		cursor:       0,
		showDetails:  true,
		sourceFilter: sourceAll,
		statusFilter: statusAll,
		sort:         sortState{Key: sortByID},
		message:      "reloaded checks",
		mode:         modeBrowse,
		width:        140,
		height:       40,
	}

	view := m.View()
	expectedFragments := []string{
		"custom-authz",
		"Custom AuthZ",
		"categories: auth, idor",
		"diagnostics: ",
		"1 error",
		"2 warning",
		"1 info",
		"showing 1-1 of 1",
	}
	for _, fragment := range expectedFragments {
		if !strings.Contains(view, fragment) {
			t.Fatalf("expected fragment %q in view output, got: %q", fragment, view)
		}
	}
}

func TestView_SearchModeUsesSearchPromptStatusLine(t *testing.T) {
	m := uiModel{
		snapshot: snapshot{
			SearchedDirs: []string{"/tmp/repo/.governor/checks"},
			Rows: []row{
				{
					ID:       "appsec",
					Name:     "Application Security",
					Status:   checks.StatusEnabled,
					Source:   checks.SourceBuiltin,
					Severity: "high",
					Path:     "(builtin)",
					Effective: true,
				},
			},
			Effective: 1,
		},
		filtered:     []int{0},
		cursor:       0,
		showDetails:  false,
		sourceFilter: sourceAll,
		statusFilter: statusAll,
		search:       "auth",
		searchBuf:    "authz",
		sort:         sortState{Key: sortByID},
		message:      "search applied",
		mode:         modeSearch,
		width:        120,
		height:       30,
	}

	view := m.View()
	if !strings.Contains(view, `filters: search="auth"`) {
		t.Fatalf("expected active search filter in view, got: %q", view)
	}
	if !strings.Contains(view, "search: authz_") {
		t.Fatalf("expected search-mode status line, got: %q", view)
	}
}
