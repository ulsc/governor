package tui

import (
	"fmt"
	"os"
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

type eventLine struct {
	At       time.Time
	Track    string
	Severity string
	Text     string
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

	logLines    []eventLine
	pausedLines []eventLine
	pauseEvents bool
	eventFilter string
	width       int
	height      int
	noColor     bool
	tick        int
}

func newModel(events <-chan progress.Event) uiModel {
	return uiModel{
		events:      events,
		runStatus:   "running",
		workers:     make(map[string]workerState),
		order:       []string{},
		showDetails: true,
		logLines:    make([]eventLine, 0, 48),
		width:       120,
		height:      36,
		noColor:     noColorEnabled(),
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
	case tea.WindowSizeMsg:
		if msg.Width > 20 {
			m.width = msg.Width
		}
		if msg.Height > 10 {
			m.height = msg.Height
		}
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "d":
			m.showDetails = !m.showDetails
		case "p":
			m.pauseEvents = !m.pauseEvents
			if m.pauseEvents {
				m.pausedLines = append([]eventLine{}, m.logLines...)
			}
		case "f":
			m.eventFilter = m.nextEventFilter()
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

	b.WriteString(m.render(titleStyle, "Governor Audit"))
	b.WriteString("\n")
	if m.runStatus == "running" {
		b.WriteString(fmt.Sprintf("Active: %s\n", m.render(runningStyle, m.runningFrame())))
	}
	b.WriteString(fmt.Sprintf("Run: %s\n", valueOrDash(m.runID)))
	b.WriteString(fmt.Sprintf("Status: %s\n", m.render(styleStatus(m.runStatus), strings.ToUpper(valueOrDash(m.runStatus)))))
	b.WriteString(fmt.Sprintf("Findings: %d\n", m.findings))
	b.WriteString(fmt.Sprintf("Elapsed: %s\n", m.elapsedString()))

	totalWorkers, running, success, warning, failed, pending := m.workerSummary()
	b.WriteString(fmt.Sprintf("Workers: total=%d running=%d success=%d warning=%d failed=%d pending=%d\n", totalWorkers, running, success, warning, failed, pending))
	b.WriteString("\n")

	b.WriteString(m.render(headerStyle, fmt.Sprintf("%-20s %-12s %-9s %-10s %-3s", "Track", "Status", "Findings", "Duration", "Err")))
	b.WriteString("\n")

	for idx, track := range m.orderedTracks() {
		w := m.workers[track]
		baseStatus := w.Status
		if strings.TrimSpace(baseStatus) == "" {
			baseStatus = "pending"
		}
		displayStatus := m.workerStatusDisplay(baseStatus, idx)
		durationMS := m.workerDurationMS(w, baseStatus)
		errBadge := "-"
		if strings.TrimSpace(w.Error) != "" {
			errBadge = "!"
		}
		line := fmt.Sprintf("%-20s %-12s %-9d %-10s %-3s", track, displayStatus, w.FindingCount, durationString(durationMS), errBadge)
		b.WriteString(m.render(styleStatus(baseStatus), line))
		b.WriteString("\n")
	}

	if m.showDetails {
		b.WriteString("\n")
		eventTitle := "Recent Events"
		if m.pauseEvents {
			eventTitle += " [paused]"
		}
		if strings.TrimSpace(m.eventFilter) != "" {
			eventTitle += " filter=" + m.eventFilter
		}
		b.WriteString(m.render(headerStyle, eventTitle))
		b.WriteString("\n")
		lines := m.visibleEventLines()
		if len(lines) == 0 {
			b.WriteString(m.render(idleStyle, "No events yet."))
			b.WriteString("\n")
		} else {
			limit := m.eventPanelHeight()
			start := max(0, len(lines)-limit)
			for _, line := range lines[start:] {
				severity := strings.ToUpper(line.Severity)
				if severity == "" {
					severity = "INFO"
				}
				prefix := fmt.Sprintf("[%s] [%s]", line.At.Format("15:04:05"), severity)
				if strings.TrimSpace(line.Track) != "" {
					prefix += " [" + line.Track + "]"
				}
				rendered := prefix + " " + line.Text
				switch strings.ToLower(strings.TrimSpace(line.Severity)) {
				case "error":
					rendered = m.render(errorStyle, rendered)
				case "warning":
					rendered = m.render(warnStyle, rendered)
				default:
					rendered = m.render(idleStyle, rendered)
				}
				b.WriteString(rendered)
				b.WriteString("\n")
			}
		}
	}

	b.WriteString("\n")
	if m.done {
		b.WriteString(m.render(helpStyle, "Press q to close | d details | p pause events | f filter track"))
	} else {
		b.WriteString(m.render(helpStyle, "d toggle details | p pause events | f filter track"))
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
		if w.StartedAt.IsZero() && !e.At.IsZero() {
			w.StartedAt = e.At.Add(-time.Duration(e.DurationMS) * time.Millisecond)
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
		w = workerState{Track: track, Status: "pending"}
	}
	return w
}

func (m uiModel) orderedTracks() []string {
	tracks := make([]string, 0, len(m.workers))
	for track := range m.workers {
		tracks = append(tracks, track)
	}
	sort.Slice(tracks, func(i, j int) bool {
		a := m.workers[tracks[i]]
		b := m.workers[tracks[j]]
		ra := workerRank(firstNonEmpty(a.Status, "pending"))
		rb := workerRank(firstNonEmpty(b.Status, "pending"))
		if ra != rb {
			return ra < rb
		}
		return tracks[i] < tracks[j]
	})
	return tracks
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
	line := eventLine{
		At:       ts,
		Track:    strings.TrimSpace(e.Track),
		Severity: eventSeverity(e),
		Text:     strings.TrimSpace(text),
	}
	m.logLines = append(m.logLines, line)
	if len(m.logLines) > 160 {
		m.logLines = m.logLines[len(m.logLines)-160:]
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

func (m uiModel) workerSummary() (total int, running int, success int, warning int, failed int, pending int) {
	for _, w := range m.workers {
		total++
		s := strings.ToLower(strings.TrimSpace(firstNonEmpty(w.Status, "pending")))
		switch s {
		case "running":
			running++
		case "success":
			success++
		case "warning", "partial", "timeout":
			warning++
		case "failed":
			failed++
		default:
			pending++
		}
	}
	return
}

func workerRank(status string) int {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "running":
		return 0
	case "failed":
		return 1
	case "warning", "partial", "timeout":
		return 2
	case "pending", "":
		return 3
	case "success":
		return 4
	default:
		return 5
	}
}

func eventSeverity(e progress.Event) string {
	switch e.Type {
	case progress.EventRunWarning:
		return "warning"
	case progress.EventWorkerFinished:
		s := strings.ToLower(strings.TrimSpace(e.Status))
		if s == "failed" {
			return "error"
		}
		if s == "warning" || s == "partial" || s == "timeout" {
			return "warning"
		}
		if strings.TrimSpace(e.Error) != "" {
			return "error"
		}
	case progress.EventRunFinished:
		s := strings.ToLower(strings.TrimSpace(e.Status))
		if s == "failed" || strings.TrimSpace(e.Error) != "" {
			return "error"
		}
		if s == "warning" || s == "partial" {
			return "warning"
		}
	}
	return "info"
}

func (m uiModel) visibleEventLines() []eventLine {
	source := m.logLines
	if m.pauseEvents {
		source = m.pausedLines
	}
	if strings.TrimSpace(m.eventFilter) == "" {
		return source
	}
	out := make([]eventLine, 0, len(source))
	for _, line := range source {
		if line.Track == "" || line.Track == m.eventFilter {
			out = append(out, line)
		}
	}
	return out
}

func (m uiModel) nextEventFilter() string {
	tracks := m.orderedTracks()
	if len(tracks) == 0 {
		return ""
	}
	options := make([]string, 0, len(tracks)+1)
	options = append(options, "")
	options = append(options, tracks...)
	for i, item := range options {
		if item == m.eventFilter {
			return options[(i+1)%len(options)]
		}
	}
	return options[0]
}

func (m uiModel) eventPanelHeight() int {
	base := 14
	if m.done {
		base++
	}
	if m.showDetails {
		return max(4, m.height-base)
	}
	return 0
}

func noColorEnabled() bool {
	if strings.TrimSpace(os.Getenv("NO_COLOR")) != "" {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("TERM")), "dumb") {
		return true
	}
	return false
}

func (m uiModel) render(style lipgloss.Style, text string) string {
	if m.noColor {
		return text
	}
	return style.Render(text)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
