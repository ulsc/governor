package doctor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildReport_NoConfigAndNoRuntime(t *testing.T) {
	repo := t.TempDir()
	home := filepath.Join(t.TempDir(), "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatalf("mkdir home: %v", err)
	}
	t.Setenv("HOME", home)
	t.Setenv("PATH", "")

	report := BuildReport(context.Background(), Options{CWD: repo})
	if len(report.Checks) == 0 {
		t.Fatal("expected checks in report")
	}
	if report.Summary.Warning == 0 && report.Summary.Fail == 0 {
		t.Fatalf("expected warning or fail summary, got %+v", report.Summary)
	}
}

func TestBuildReport_ConfigLoadFail(t *testing.T) {
	repo := t.TempDir()
	home := filepath.Join(t.TempDir(), "home")
	if err := os.MkdirAll(filepath.Join(home, ".governor"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Setenv("HOME", home)
	if err := os.WriteFile(filepath.Join(home, ".governor", "config.yaml"), []byte("workers: ["), 0o600); err != nil {
		t.Fatalf("write bad config: %v", err)
	}

	report := BuildReport(context.Background(), Options{CWD: repo})
	found := false
	for _, chk := range report.Checks {
		if chk.ID == "config.load" {
			found = true
			if chk.Status != StatusFail {
				t.Fatalf("expected config.load fail, got %s", chk.Status)
			}
		}
	}
	if !found {
		t.Fatal("config.load check missing")
	}
}

func TestReportFailed(t *testing.T) {
	r := Report{Summary: Summary{Pass: 1, Warning: 1, Fail: 0}}
	if r.Failed(false) {
		t.Fatal("warnings should not fail when strict=false")
	}
	if !r.Failed(true) {
		t.Fatal("warnings should fail when strict=true")
	}
}
