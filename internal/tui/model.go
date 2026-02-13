package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"governor/internal/progress"
)

var (
	titleStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	helpStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	headerStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("229"))
	okStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	warnStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	errorStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	runningStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("45"))
	idleStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
)

type workerState struct {
	Track        string
	Status       string
	FindingCount int
	DurationMS   int64
	StartedAt    time.Time
	Error        string
}

type eventMsg struct {
	event progress.Event
	ok    bool
}

type uiModel struct {
	events <-chan progress.Event

	runID      string
	runStatus  string
	runError   string
	startedAt  time.Time
	finishedAt time.Time
	findings   int

	showDetails bool
	done        bool

	workers map[string]workerState
	order   []string

	logLines []string
	tick     int
}

func newModel(events <-chan progress.Event) uiModel {
	return uiModel{
		events:      events,
		runStatus:   "running",
		workers:     make(map[string]workerState),
		order:       []string{},
		showDetails: true,
		logLines:    make([]string, 0, 24),
	}
}

func waitForEvent(ch <-chan progress.Event) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-ch
		return eventMsg{event: ev, ok: ok}
	}
}

type tickMsg time.Time

func nextTick() tea.Cmd {
	return tea.Tick(250*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m uiModel) Init() tea.Cmd {
	return tea.Batch(waitForEvent(m.events), nextTick())
}

func (m uiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "d":
			m.showDetails = !m.showDetails
		case "q", "ctrl+c":
			if m.done {
				return m, tea.Quit
			}
		}
		return m, nil
	case eventMsg:
		if !msg.ok {
			m.done = true
			return m, tea.Quit
		}
		m.applyEvent(msg.event)
		if m.done {
			return m, tea.Quit
		}
		return m, waitForEvent(m.events)
	case tickMsg:
		m.tick++
		if m.done {
			return m, nil
		}
		return m, nextTick()
	default:
		return m, nil
	}
}

func (m uiModel) View() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("Governor Audit"))
	b.WriteString("\n")
	if m.runStatus == "running" {
		b.WriteString(fmt.Sprintf("Active: %s\n", runningStyle.Render(m.runningFrame())))
	}
	b.WriteString(fmt.Sprintf("Run: %s\n", valueOrDash(m.runID)))
	b.WriteString(fmt.Sprintf("Status: %s\n", styleStatus(m.runStatus).Render(strings.ToUpper(valueOrDash(m.runStatus)))))
	b.WriteString(fmt.Sprintf("Findings: %d\n", m.findings))
	b.WriteString(fmt.Sprintf("Elapsed: %s\n", m.elapsedString()))
	b.WriteString("\n")

	b.WriteString(headerStyle.Render(fmt.Sprintf("%-22s %-11s %-9s %-10s", "Track", "Status", "Findings", "Duration")))
	b.WriteString("\n")

	for idx, track := range m.orderedTracks() {
		w := m.workers[track]
		baseStatus := w.Status
		if strings.TrimSpace(baseStatus) == "" {
			baseStatus = "pending"
		}
		displayStatus := m.workerStatusDisplay(baseStatus, idx)
		durationMS := m.workerDurationMS(w, baseStatus)
		line := fmt.Sprintf("%-22s %-11s %-9d %-10s", track, displayStatus, w.FindingCount, durationString(durationMS))
		b.WriteString(styleStatus(baseStatus).Render(line))
		b.WriteString("\n")
	}

	if m.showDetails {
		b.WriteString("\n")
		b.WriteString(headerStyle.Render("Recent Events"))
		b.WriteString("\n")
		if len(m.logLines) == 0 {
			b.WriteString(idleStyle.Render("No events yet."))
			b.WriteString("\n")
		} else {
			for _, line := range m.logLines {
				b.WriteString(line)
				b.WriteString("\n")
			}
		}
	}

	b.WriteString("\n")
	if m.done {
		b.WriteString(helpStyle.Render("Press q to close"))
	} else {
		b.WriteString(helpStyle.Render("d toggle details"))
	}
	b.WriteString("\n")

	return b.String()
}

func (m *uiModel) applyEvent(e progress.Event) {
	switch e.Type {
	case progress.EventRunStarted:
		m.runID = e.RunID
		m.runStatus = "running"
		if !e.At.IsZero() {
			m.startedAt = e.At
		}
		m.appendEventLine(e, fmt.Sprintf("run started (%s)", valueOrDash(e.RunID)))
	case progress.EventRunWarning:
		m.appendEventLine(e, fmt.Sprintf("warning: %s", firstNonEmpty(e.Message, e.Error)))
	case progress.EventWorkerStarted:
		w := m.ensureWorker(e.Track)
		w.Status = "running"
		if !e.At.IsZero() {
			w.StartedAt = e.At
		}
		m.workers[e.Track] = w
		m.appendEventLine(e, fmt.Sprintf("%s started", e.Track))
	case progress.EventWorkerHeartbeat:
		w := m.ensureWorker(e.Track)
		w.Status = "running"
		if w.StartedAt.IsZero() {
			if !e.At.IsZero() {
				w.StartedAt = e.At.Add(-time.Duration(e.DurationMS) * time.Millisecond)
			}
		}
		if e.DurationMS > 0 {
			w.DurationMS = e.DurationMS
		}
		m.workers[e.Track] = w
		m.appendEventLine(e, fmt.Sprintf("%s running (%s)", e.Track, durationString(e.DurationMS)))
	case progress.EventWorkerOutput:
		w := m.ensureWorker(e.Track)
		if w.Status == "" || w.Status == "pending" {
			w.Status = "running"
		}
		if w.StartedAt.IsZero() && !e.At.IsZero() {
			w.StartedAt = e.At
		}
		m.workers[e.Track] = w
		m.appendEventLine(e, fmt.Sprintf("%s output ready", e.Track))
	case progress.EventWorkerFinished:
		w := m.ensureWorker(e.Track)
		w.Status = firstNonEmpty(e.Status, w.Status)
		w.FindingCount = e.FindingCount
		w.DurationMS = e.DurationMS
		if w.StartedAt.IsZero() && !e.At.IsZero() && e.DurationMS > 0 {
			w.StartedAt = e.At.Add(-time.Duration(e.DurationMS) * time.Millisecond)
		}
		w.Error = firstNonEmpty(e.Error, w.Error)
		m.workers[e.Track] = w
		msg := fmt.Sprintf("%s finished status=%s findings=%d duration=%s", e.Track, firstNonEmpty(e.Status, "unknown"), e.FindingCount, durationString(e.DurationMS))
		if strings.TrimSpace(e.Error) != "" {
			msg += " error=" + strings.TrimSpace(e.Error)
		}
		m.appendEventLine(e, msg)
	case progress.EventRunFinished:
		m.runStatus = firstNonEmpty(e.Status, "success")
		m.runError = strings.TrimSpace(e.Error)
		m.findings = e.FindingCount
		if !e.At.IsZero() {
			m.finishedAt = e.At
		}
		m.done = true
		msg := fmt.Sprintf("run finished status=%s findings=%d duration=%s", firstNonEmpty(e.Status, "unknown"), e.FindingCount, durationString(e.DurationMS))
		if m.runError != "" {
			msg += " error=" + m.runError
		}
		m.appendEventLine(e, msg)
	}
}

func (m *uiModel) ensureWorker(track string) workerState {
	if track == "" {
		return workerState{}
	}
	w, ok := m.workers[track]
	if !ok {
		w = workerState{
			Track:  track,
			Status: "pending",
		}
	}
	return w
}

func (m uiModel) orderedTracks() []string {
	out := append([]string{}, m.order...)
	seen := make(map[string]struct{}, len(out))
	for _, track := range out {
		seen[track] = struct{}{}
	}
	for track := range m.workers {
		if _, ok := seen[track]; !ok {
			out = append(out, track)
		}
	}
	if len(out) > len(m.order) {
		head := out[:len(m.order)]
		tail := out[len(m.order):]
		sort.Strings(tail)
		out = append(head, tail...)
	}
	return out
}

func (m uiModel) elapsedString() string {
	if m.startedAt.IsZero() {
		return "0s"
	}
	end := time.Now().UTC()
	if !m.finishedAt.IsZero() {
		end = m.finishedAt
	}
	return end.Sub(m.startedAt).Round(time.Second).String()
}

func (m *uiModel) appendEventLine(e progress.Event, text string) {
	ts := e.At
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	line := fmt.Sprintf("[%s] %s", ts.Format("15:04:05"), strings.TrimSpace(text))
	m.logLines = append(m.logLines, line)
	if len(m.logLines) > 12 {
		m.logLines = m.logLines[len(m.logLines)-12:]
	}
}

func durationString(ms int64) string {
	if ms <= 0 {
		return "0s"
	}
	return (time.Duration(ms) * time.Millisecond).Round(time.Millisecond).String()
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" {
			return v
		}
	}
	return ""
}

func valueOrDash(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "-"
	}
	return v
}

func styleStatus(status string) lipgloss.Style {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "success":
		return okStyle
	case "warning", "partial", "timeout":
		return warnStyle
	case "failed":
		return errorStyle
	case "running":
		return runningStyle
	default:
		return idleStyle
	}
}

func (m uiModel) runningFrame() string {
	frames := []string{"-", "\\", "|", "/"}
	if len(frames) == 0 {
		return "."
	}
	return frames[m.tick%len(frames)]
}

func (m uiModel) workerStatusDisplay(status string, idx int) string {
	if strings.EqualFold(strings.TrimSpace(status), "running") {
		return "running " + m.workerFrame(idx)
	}
	return strings.TrimSpace(status)
}

func (m uiModel) workerFrame(idx int) string {
	frames := []string{"-", "\\", "|", "/"}
	if len(frames) == 0 {
		return "."
	}
	return frames[(m.tick+idx)%len(frames)]
}

func (m uiModel) workerDurationMS(w workerState, status string) int64 {
	if strings.EqualFold(strings.TrimSpace(status), "running") && !w.StartedAt.IsZero() {
		return time.Since(w.StartedAt).Milliseconds()
	}
	return w.DurationMS
}
