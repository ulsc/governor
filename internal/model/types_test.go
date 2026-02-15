package model

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestFindingJSONOmitemptyAndOptionalFields(t *testing.T) {
	base := Finding{
		ID:          "F-1",
		Title:       "Hardcoded Credential",
		Severity:    "high",
		Category:    "secrets",
		Evidence:    "credential found in source",
		Impact:      "account takeover",
		Remediation: "move to environment variable",
		SourceTrack: "appsec",
	}

	payload, err := json.Marshal(base)
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}

	jsonStr := string(payload)
	for _, want := range []string{
		`"id":"F-1"`,
		`"title":"Hardcoded Credential"`,
		`"severity":"high"`,
		`"category":"secrets"`,
		`"source_track":"appsec"`,
	} {
		if !strings.Contains(jsonStr, want) {
			t.Fatalf("expected JSON to include %s, got %s", want, jsonStr)
		}
	}
	for _, omitted := range []string{
		`"file_refs":`,
		`"confidence":`,
		`"cwe":`,
		`"owasp":`,
		`"suppressed":`,
		`"suppression_reason":`,
		`"suppression_source":`,
	} {
		if strings.Contains(jsonStr, omitted) {
			t.Fatalf("expected JSON to omit %s, got %s", omitted, jsonStr)
		}
	}
	if !strings.Contains(jsonStr, `"created_at":"0001-01-01T00:00:00Z"`) {
		t.Fatalf("expected zero created_at timestamp to be serialized, got %s", jsonStr)
	}

	optional := base
	optional.FileRefs = []string{"cmd/main.go:42"}
	optional.Confidence = 0.91
	optional.CWE = "CWE-798"
	optional.OWASP = "A07:2021"
	optional.CreatedAt = time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	optional.Suppressed = true
	optional.SuppressionReason = "accepted risk"
	optional.SuppressionSource = "inline"

	payload, err = json.Marshal(optional)
	if err != nil {
		t.Fatalf("marshal optional finding: %v", err)
	}

	jsonStr = string(payload)
	for _, want := range []string{
		`"file_refs":["cmd/main.go:42"]`,
		`"confidence":0.91`,
		`"cwe":"CWE-798"`,
		`"owasp":"A07:2021"`,
		`"created_at":`,
		`"suppressed":true`,
		`"suppression_reason":"accepted risk"`,
		`"suppression_source":"inline"`,
	} {
		if !strings.Contains(jsonStr, want) {
			t.Fatalf("expected JSON to include %s, got %s", want, jsonStr)
		}
	}
}

func TestWorkerResultJSONRoundTrip(t *testing.T) {
	started := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	completed := started.Add(1500 * time.Millisecond)

	want := WorkerResult{
		Track:        "appsec",
		Status:       "done",
		DurationMS:   1500,
		StartedAt:    started,
		CompletedAt:  completed,
		FindingCount: 1,
		Findings: []Finding{
			{
				ID:          "F-1",
				Title:       "Issue",
				Severity:    "medium",
				Category:    "security",
				Evidence:    "evidence",
				Impact:      "impact",
				Remediation: "fix",
				SourceTrack: "appsec",
			},
		},
		RawOutput:  `{"summary":"ok"}`,
		LogPath:    "/tmp/run/worker.log",
		OutputPath: "/tmp/run/worker-output.json",
	}

	payload, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal worker result: %v", err)
	}

	jsonStr := string(payload)
	for _, wantKey := range []string{
		`"track":"appsec"`,
		`"duration_ms":1500`,
		`"finding_count":1`,
		`"started_at":`,
		`"completed_at":`,
	} {
		if !strings.Contains(jsonStr, wantKey) {
			t.Fatalf("expected JSON to include %s, got %s", wantKey, jsonStr)
		}
	}
	if strings.Contains(jsonStr, `"error":`) {
		t.Fatalf("expected empty error field to be omitted, got %s", jsonStr)
	}

	var got WorkerResult
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatalf("unmarshal worker result: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round-trip mismatch:\nwant: %+v\ngot:  %+v", want, got)
	}
}

func TestInputManifestJSONRoundTrip(t *testing.T) {
	want := InputManifest{
		RootPath:      "/tmp/workspace",
		InputPath:     "/tmp/input",
		InputType:     "folder",
		IncludedFiles: 2,
		IncludedBytes: 128,
		SkippedFiles:  1,
		SkippedByReason: map[string]int{
			"binary": 1,
		},
		Files: []ManifestFile{
			{Path: "main.go", Size: 64},
			{Path: "README.md", Size: 64},
		},
		GeneratedAt: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC),
	}

	payload, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}

	jsonStr := string(payload)
	for _, wantKey := range []string{
		`"root_path":"`,
		`"input_path":"`,
		`"input_type":"folder"`,
		`"skipped_by_reason":`,
		`"generated_at":`,
	} {
		if !strings.Contains(jsonStr, wantKey) {
			t.Fatalf("expected JSON to include %s, got %s", wantKey, jsonStr)
		}
	}

	var got InputManifest
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round-trip mismatch:\nwant: %+v\ngot:  %+v", want, got)
	}
}

func TestAuditReportJSONRoundTrip(t *testing.T) {
	report := AuditReport{
		RunMetadata: RunMetadata{
			RunID:         "run-123",
			StartedAt:     time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC),
			CompletedAt:   time.Date(2026, time.January, 2, 3, 5, 5, 0, time.UTC),
			DurationMS:    60_000,
			PromptVersion: "v1",
			AIRequired:    true,
			AIUsed:        true,
			Workers:       3,
			CheckIDs:      []string{"check-1", "check-2"},
		},
		InputSummary: InputSummary{
			InputType:     "folder",
			InputPath:     "/tmp/input",
			WorkspacePath: "/tmp/workspace",
			ManifestPath:  "/tmp/workspace/manifest.json",
			IncludedFiles: 10,
			IncludedBytes: 2048,
			SkippedFiles:  2,
		},
		Findings: []Finding{
			{
				ID:          "F-1",
				Title:       "Issue",
				Severity:    "high",
				Category:    "security",
				Evidence:    "evidence",
				Impact:      "impact",
				Remediation: "fix",
				SourceTrack: "appsec",
			},
		},
		SuppressedFindings: []Finding{
			{
				ID:                "F-2",
				Title:             "Suppressed Issue",
				Severity:          "low",
				Category:          "security",
				Evidence:          "evidence",
				Impact:            "impact",
				Remediation:       "fix",
				SourceTrack:       "appsec",
				Suppressed:        true,
				SuppressionReason: "accepted risk",
				SuppressionSource: "inline",
			},
		},
		SuppressedCount: 1,
		CountsBySeverity: map[string]int{
			"high": 1,
		},
		CountsByCategory: map[string]int{
			"security": 2,
		},
		WorkerSummaries: []WorkerResult{
			{
				Track:       "appsec",
				Status:      "done",
				DurationMS:  150,
				StartedAt:   time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC),
				CompletedAt: time.Date(2026, time.January, 2, 3, 4, 5, 150_000_000, time.UTC),
			},
		},
		Errors: []string{"non-fatal worker warning"},
	}

	payload, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}

	jsonStr := string(payload)
	for _, wantKey := range []string{
		`"run_metadata":`,
		`"input_summary":`,
		`"counts_by_severity":`,
		`"counts_by_category":`,
		`"worker_summaries":`,
	} {
		if !strings.Contains(jsonStr, wantKey) {
			t.Fatalf("expected JSON to include %s, got %s", wantKey, jsonStr)
		}
	}

	var got AuditReport
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if !reflect.DeepEqual(got, report) {
		t.Fatalf("round-trip mismatch:\nwant: %+v\ngot:  %+v", report, got)
	}
}
