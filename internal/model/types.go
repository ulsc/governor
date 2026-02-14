package model

import "time"

type WorkerTrack string

const (
	TrackAppSec       WorkerTrack = "appsec"
	TrackDependencies WorkerTrack = "deps_supply_chain"
	TrackSecrets      WorkerTrack = "secrets_config"
)

var DefaultTracks = []WorkerTrack{TrackAppSec, TrackDependencies, TrackSecrets}

type Finding struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Severity    string    `json:"severity"`
	Category    string    `json:"category"`
	Evidence    string    `json:"evidence"`
	Impact      string    `json:"impact"`
	Remediation string    `json:"remediation"`
	FileRefs    []string  `json:"file_refs,omitempty"`
	Confidence  float64   `json:"confidence,omitempty"`
	CWE         string    `json:"cwe,omitempty"`
	OWASP       string    `json:"owasp,omitempty"`
	SourceTrack string    `json:"source_track"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
}

type WorkerResult struct {
	Track        string    `json:"track"`
	Status       string    `json:"status"`
	DurationMS   int64     `json:"duration_ms"`
	StartedAt    time.Time `json:"started_at"`
	CompletedAt  time.Time `json:"completed_at"`
	FindingCount int       `json:"finding_count"`
	Findings     []Finding `json:"findings,omitempty"`
	RawOutput    string    `json:"raw_output,omitempty"`
	LogPath      string    `json:"log_path,omitempty"`
	OutputPath   string    `json:"output_path,omitempty"`
	Error        string    `json:"error,omitempty"`
}

type ManifestFile struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
}

type InputManifest struct {
	RootPath        string         `json:"root_path"`
	InputPath       string         `json:"input_path"`
	InputType       string         `json:"input_type"`
	IncludedFiles   int            `json:"included_files"`
	IncludedBytes   int64          `json:"included_bytes"`
	SkippedFiles    int            `json:"skipped_files"`
	SkippedByReason map[string]int `json:"skipped_by_reason"`
	Files           []ManifestFile `json:"files"`
	GeneratedAt     time.Time      `json:"generated_at"`
}

type RunMetadata struct {
	RunID          string    `json:"run_id"`
	StartedAt      time.Time `json:"started_at"`
	CompletedAt    time.Time `json:"completed_at"`
	DurationMS     int64     `json:"duration_ms"`
	PromptVersion  string    `json:"prompt_version"`
	AIProfile      string    `json:"ai_profile,omitempty"`
	AIProvider     string    `json:"ai_provider,omitempty"`
	AIModel        string    `json:"ai_model,omitempty"`
	AIAuthMode     string    `json:"ai_auth_mode,omitempty"`
	AIRequestedBin string    `json:"ai_requested_bin,omitempty"`
	AIBin          string    `json:"ai_bin,omitempty"`
	AIVersion      string    `json:"ai_version,omitempty"`
	AISHA256       string    `json:"ai_sha256,omitempty"`
	ExecutionMode  string    `json:"execution_mode,omitempty"`
	AISandbox      string    `json:"ai_sandbox,omitempty"`
	AIRequired     bool      `json:"ai_required"`
	AIUsed         bool      `json:"ai_used"`
	Workers        int       `json:"workers"`
	EnabledChecks  int       `json:"enabled_checks,omitempty"`
	BuiltInChecks  int       `json:"builtin_checks,omitempty"`
	CustomChecks   int       `json:"custom_checks,omitempty"`
	AIChecks       int       `json:"ai_checks,omitempty"`
	RuleChecks     int       `json:"rule_checks,omitempty"`
	CheckIDs       []string  `json:"check_ids,omitempty"`
}

type InputSummary struct {
	InputType     string `json:"input_type"`
	InputPath     string `json:"input_path"`
	WorkspacePath string `json:"workspace_path"`
	ManifestPath  string `json:"manifest_path"`
	IncludedFiles int    `json:"included_files"`
	IncludedBytes int64  `json:"included_bytes"`
	SkippedFiles  int    `json:"skipped_files"`
}

type AuditReport struct {
	RunMetadata      RunMetadata    `json:"run_metadata"`
	InputSummary     InputSummary   `json:"input_summary"`
	Findings         []Finding      `json:"findings"`
	CountsBySeverity map[string]int `json:"counts_by_severity"`
	CountsByCategory map[string]int `json:"counts_by_category"`
	WorkerSummaries  []WorkerResult `json:"worker_summaries"`
	Errors           []string       `json:"errors,omitempty"`
}
