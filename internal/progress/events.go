package progress

import "time"

type EventType string

const (
	EventRunStarted      EventType = "run_started"
	EventRunWarning      EventType = "run_warning"
	EventRunFinished     EventType = "run_finished"
	EventWorkerStarted   EventType = "worker_started"
	EventWorkerHeartbeat EventType = "worker_heartbeat"
	EventWorkerOutput    EventType = "worker_output_ready"
	EventWorkerFinished  EventType = "worker_finished"
)

type Event struct {
	Type         EventType `json:"type"`
	At           time.Time `json:"at"`
	RunID        string    `json:"run_id,omitempty"`
	Track        string    `json:"track,omitempty"`
	Status       string    `json:"status,omitempty"`
	Message      string    `json:"message,omitempty"`
	Error        string    `json:"error,omitempty"`
	FindingCount int       `json:"finding_count,omitempty"`
	DurationMS   int64     `json:"duration_ms,omitempty"`
}
