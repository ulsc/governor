package doctor

type Status string

const (
	StatusPass Status = "pass"
	StatusWarn Status = "warning"
	StatusFail Status = "fail"
)

type CheckResult struct {
	ID       string            `json:"id"`
	Status   Status            `json:"status"`
	Message  string            `json:"message"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

type Summary struct {
	Pass    int `json:"pass"`
	Warning int `json:"warning"`
	Fail    int `json:"fail"`
}

type Report struct {
	Checks   []CheckResult `json:"checks"`
	Warnings []string      `json:"warnings,omitempty"`
	Errors   []string      `json:"errors,omitempty"`
	Summary  Summary       `json:"summary"`
}

func (r Report) Failed(strict bool) bool {
	if r.Summary.Fail > 0 {
		return true
	}
	return strict && r.Summary.Warning > 0
}
