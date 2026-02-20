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
	ID                string    `json:"id"`
	Title             string    `json:"title"`
	Severity          string    `json:"severity"`
	Category          string    `json:"category"`
	Evidence          string    `json:"evidence"`
	Impact            string    `json:"impact"`
	Remediation       string    `json:"remediation"`
	FileRefs          []string  `json:"file_refs,omitempty"`
	Confidence        float64   `json:"confidence,omitempty"`
	CWE               string    `json:"cwe,omitempty"`
	OWASP             string    `json:"owasp,omitempty"`
	AttackPath        []string  `json:"attack_path,omitempty"`
	EntryPoints       []string  `json:"entry_points,omitempty"`
	Sinks             []string  `json:"sinks,omitempty"`
	Guards            []string  `json:"guards_detected,omitempty"`
	ReachabilityScore float64   `json:"reachability_score,omitempty"`
	Exploitability    string    `json:"exploitability,omitempty"`
	SourceTrack       string    `json:"source_track"`
	CreatedAt         time.Time `json:"created_at,omitempty"`

	Suppressed        bool   `json:"suppressed,omitempty"`
	SuppressionReason string `json:"suppression_reason,omitempty"`
	SuppressionSource string `json:"suppression_source,omitempty"`
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
	RootPath                string         `json:"root_path"`
	InputPath               string         `json:"input_path"`
	InputType               string         `json:"input_type"`
	IncludedFiles           int            `json:"included_files"`
	IncludedBytes           int64          `json:"included_bytes"`
	SkippedFiles            int            `json:"skipped_files"`
	SecurityRelevantSkipped int            `json:"security_relevant_skipped,omitempty"`
	SkippedByReason         map[string]int `json:"skipped_by_reason"`
	Files                   []ManifestFile `json:"files"`
	GeneratedAt             time.Time      `json:"generated_at"`
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
	ScanMode       string    `json:"scan_mode,omitempty"`
	PolicyPath     string    `json:"policy_path,omitempty"`
	PolicyVersion  string    `json:"policy_version,omitempty"`
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
	RunMetadata        RunMetadata     `json:"run_metadata"`
	InputSummary       InputSummary    `json:"input_summary"`
	Findings           []Finding       `json:"findings"`
	SuppressedFindings []Finding       `json:"suppressed_findings,omitempty"`
	SuppressedCount    int             `json:"suppressed_count,omitempty"`
	CountsBySeverity   map[string]int  `json:"counts_by_severity"`
	CountsByCategory   map[string]int  `json:"counts_by_category"`
	WorkerSummaries    []WorkerResult  `json:"worker_summaries"`
	Errors             []string        `json:"errors,omitempty"`
	PolicyDecision     *PolicyDecision `json:"policy_decision,omitempty"`
}

type PolicyGate struct {
	FailOnSeverity               string   `json:"fail_on_severity,omitempty"`
	FailOnExploitability         string   `json:"fail_on_exploitability,omitempty"`
	MaxSuppressionRatio          float64  `json:"max_suppression_ratio,omitempty"`
	MaxNewFindings               int      `json:"max_new_findings,omitempty"`
	MaxNewReachableFindings      int      `json:"max_new_reachable_findings,omitempty"`
	MinConfidenceForBlock        float64  `json:"min_confidence_for_block,omitempty"`
	RequireAttackPathForBlocking bool     `json:"require_attack_path_for_blocking,omitempty"`
	RequireChecks                []string `json:"require_checks,omitempty"`
	ForbidChecks                 []string `json:"forbid_checks,omitempty"`
}

type PolicyViolation struct {
	Code     string   `json:"code"`
	Message  string   `json:"message"`
	Severity string   `json:"severity,omitempty"`
	Category string   `json:"category,omitempty"`
	CheckID  string   `json:"check_id,omitempty"`
	FileRefs []string `json:"file_refs,omitempty"`
	Waived   bool     `json:"waived,omitempty"`
	WaiverID string   `json:"waiver_id,omitempty"`
}

type PolicyDecision struct {
	Path       string            `json:"path,omitempty"`
	APIVersion string            `json:"api_version,omitempty"`
	Passed     bool              `json:"passed"`
	Effective  PolicyGate        `json:"effective"`
	Violations []PolicyViolation `json:"violations,omitempty"`
	Warnings   []string          `json:"warnings,omitempty"`
}

type FixFilters struct {
	OnlyFindingIDs []string `json:"only_finding_ids,omitempty"`
	OnlySeverities []string `json:"only_severities,omitempty"`
	OnlyChecks     []string `json:"only_checks,omitempty"`
	MaxSuggestions int      `json:"max_suggestions,omitempty"`
}

type FixFileChange struct {
	Path          string   `json:"path"`
	ChangeType    string   `json:"change_type,omitempty"`
	Instructions  []string `json:"instructions,omitempty"`
	CodeLocations []string `json:"code_locations,omitempty"`
}

type FixSuggestion struct {
	FindingID       string          `json:"finding_id"`
	Title           string          `json:"title"`
	SourceTrack     string          `json:"source_track,omitempty"`
	Priority        string          `json:"priority,omitempty"`
	Summary         string          `json:"summary"`
	Files           []FixFileChange `json:"files,omitempty"`
	ValidationSteps []string        `json:"validation_steps,omitempty"`
	RiskNotes       []string        `json:"risk_notes,omitempty"`
	Confidence      float64         `json:"confidence,omitempty"`
}

type FixReport struct {
	GeneratedAt    time.Time       `json:"generated_at"`
	SourceAudit    string          `json:"source_audit"`
	OutDir         string          `json:"out_dir"`
	SourceRunID    string          `json:"source_run_id,omitempty"`
	AIProfile      string          `json:"ai_profile,omitempty"`
	AIProvider     string          `json:"ai_provider,omitempty"`
	AIModel        string          `json:"ai_model,omitempty"`
	AIAuthMode     string          `json:"ai_auth_mode,omitempty"`
	AIRequestedBin string          `json:"ai_requested_bin,omitempty"`
	AIBin          string          `json:"ai_bin,omitempty"`
	AIVersion      string          `json:"ai_version,omitempty"`
	AISHA256       string          `json:"ai_sha256,omitempty"`
	ExecutionMode  string          `json:"execution_mode,omitempty"`
	AISandbox      string          `json:"ai_sandbox,omitempty"`
	Filters        FixFilters      `json:"filters"`
	TotalFindings  int             `json:"total_findings"`
	Selected       int             `json:"selected_findings"`
	Suggestions    []FixSuggestion `json:"suggestions"`
	Warnings       []string        `json:"warnings,omitempty"`
	Errors         []string        `json:"errors,omitempty"`
}
