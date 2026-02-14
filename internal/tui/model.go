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
	helpKeyStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("45")).Bold(true)
	headerStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("229"))
	okStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	warnStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	errorStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	runningStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("45"))
	idleStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	dimStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("238"))
	boldStyle    = lipgloss.NewStyle().Bold(true)
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

	// Title
	b.WriteString(m.render(titleStyle, "Governor Audit"))
	b.WriteString("\n")

	// Run metadata
	b.WriteString(fmt.Sprintf("  Run:      %s\n", valueOrDash(m.runID)))
	statusLabel := strings.ToUpper(valueOrDash(m.runStatus))
	if m.runStatus == "running" {
		statusLabel += " " + m.runningFrame()
	}
	b.WriteString(fmt.Sprintf("  Status:   %s\n", m.render(styleStatus(m.runStatus), statusLabel)))
	b.WriteString(fmt.Sprintf("  Elapsed:  %s\n", m.elapsedString()))
	findingsLabel := fmt.Sprintf("%d", m.findings)
	if m.findings > 0 {
		findingsLabel = m.render(warnStyle, findingsLabel)
	}
	b.WriteString(fmt.Sprintf("  Findings: %s\n", findingsLabel))

	// Progress bar
	totalWorkers, running, success, warning, failed, pending := m.workerSummary()
	b.WriteString("  ")
	b.WriteString(m.progressBar(totalWorkers, success, warning, failed, running, pending))
	b.WriteString("\n")

	// Worker summary counts
	parts := []string{}
	if running > 0 {
		parts = append(parts, m.render(runningStyle, fmt.Sprintf("%d running", running)))
	}
	if success > 0 {
		parts = append(parts, m.render(okStyle, fmt.Sprintf("%d ok", success)))
	}
	if warning > 0 {
		parts = append(parts, m.render(warnStyle, fmt.Sprintf("%d warn", warning)))
	}
	if failed > 0 {
		parts = append(parts, m.render(errorStyle, fmt.Sprintf("%d fail", failed)))
	}
	if pending > 0 {
		parts = append(parts, m.render(idleStyle, fmt.Sprintf("%d pending", pending)))
	}
	if len(parts) > 0 {
		b.WriteString("  ")
		b.WriteString(strings.Join(parts, m.render(dimStyle, " | ")))
		b.WriteString("\n")
	}
	b.WriteString("\n")

	// Worker table
	b.WriteString(m.render(headerStyle, fmt.Sprintf("  %-20s %-12s %-9s %-10s %s", "TRACK", "STATUS", "FINDS", "DURATION", "ERR")))
	b.WriteString("\n")

	for idx, track := range m.orderedTracks() {
		w := m.workers[track]
		baseStatus := w.Status
		if strings.TrimSpace(baseStatus) == "" {
			baseStatus = "pending"
		}
		displayStatus := m.workerStatusDisplay(baseStatus, idx)
		durationMS := m.workerDurationMS(w, baseStatus)
		errBadge := m.render(dimStyle, "-")
		if strings.TrimSpace(w.Error) != "" {
			errBadge = m.render(errorStyle, "!")
		}
		findingStr := fmt.Sprintf("%d", w.FindingCount)
		if w.FindingCount > 0 && baseStatus != "running" {
			findingStr = m.render(warnStyle, findingStr)
		}
		trackName := track
		line := fmt.Sprintf("  %-20s %-12s %-9s %-10s %s",
			trackName,
			m.render(styleStatus(baseStatus), displayStatus),
			findingStr,
			durationString(durationMS),
			errBadge,
		)
		b.WriteString(line)
		b.WriteString("\n")
	}

	// Completion banner
	if m.done {
		b.WriteString("\n")
		b.WriteString(m.completionBanner())
	}

	// Event log
	if m.showDetails {
		b.WriteString("\n")
		eventTitle := "Recent Events"
		if m.pauseEvents {
			eventTitle += " " + m.render(warnStyle, "[paused]")
		}
		if strings.TrimSpace(m.eventFilter) != "" {
			eventTitle += " " + m.render(runningStyle, "filter="+m.eventFilter)
		}
		b.WriteString(m.render(headerStyle, eventTitle))
		b.WriteString("\n")
		lines := m.visibleEventLines()
		if len(lines) == 0 {
			b.WriteString(m.render(idleStyle, "  No events yet."))
			b.WriteString("\n")
		} else {
			limit := m.eventPanelHeight()
			start := max(0, len(lines)-limit)
			for _, line := range lines[start:] {
				severity := strings.ToUpper(line.Severity)
				if severity == "" {
					severity = "INFO"
				}
				prefix := fmt.Sprintf("  %s %s", m.render(dimStyle, line.At.Format("15:04:05")), m.severityBadge(severity))
				if strings.TrimSpace(line.Track) != "" {
					prefix += " " + m.render(dimStyle, line.Track)
				}
				rendered := prefix + " " + line.Text
				switch strings.ToLower(strings.TrimSpace(line.Severity)) {
				case "error":
					rendered = prefix + " " + m.render(errorStyle, line.Text)
				case "warning":
					rendered = prefix + " " + m.render(warnStyle, line.Text)
				default:
					rendered = prefix + " " + m.render(idleStyle, line.Text)
				}
				b.WriteString(rendered)
				b.WriteString("\n")
			}
		}
	}

	// Help bar
	b.WriteString("\n")
	if m.done {
		b.WriteString(m.renderHelp([][2]string{{"q", "close"}, {"d", "details"}, {"p", "pause"}, {"f", "filter"}}))
	} else {
		b.WriteString(m.renderHelp([][2]string{{"d", "details"}, {"p", "pause"}, {"f", "filter"}}))
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
	frames := []string{"\u28F7", "\u28EF", "\u28DF", "\u28BF", "\u287F", "\u28FE", "\u28FD", "\u28FB"}
	if len(frames) == 0 {
		return "."
	}
	return frames[m.tick%len(frames)]
}

func (m uiModel) progressBar(total, success, warning, failed, running, pending int) string {
	if total == 0 {
		return m.render(dimStyle, "[no workers]")
	}
	barWidth := 30
	if m.width < 60 {
		barWidth = 15
	}

	done := success + warning + failed
	pct := 0
	if total > 0 {
		pct = (done * 100) / total
	}

	filled := 0
	if total > 0 {
		filled = (done * barWidth) / total
	}
	if filled > barWidth {
		filled = barWidth
	}

	bar := strings.Repeat("\u2588", filled) + strings.Repeat("\u2591", barWidth-filled)
	pctStr := fmt.Sprintf("%3d%%", pct)

	if m.noColor {
		return fmt.Sprintf("[%s] %s (%d/%d)", bar, pctStr, done, total)
	}

	coloredBar := ""
	pos := 0
	// Green for success
	successCells := 0
	if total > 0 {
		successCells = (success * barWidth) / total
	}
	if successCells > 0 {
		coloredBar += okStyle.Render(strings.Repeat("\u2588", successCells))
		pos += successCells
	}
	// Yellow for warning
	warnCells := 0
	if total > 0 {
		warnCells = (warning * barWidth) / total
	}
	if warnCells > 0 {
		coloredBar += warnStyle.Render(strings.Repeat("\u2588", warnCells))
		pos += warnCells
	}
	// Red for failed
	failCells := 0
	if total > 0 {
		failCells = (failed * barWidth) / total
	}
	if failCells > 0 {
		coloredBar += errorStyle.Render(strings.Repeat("\u2588", failCells))
		pos += failCells
	}
	// Remaining filled (rounding)
	if pos < filled {
		coloredBar += okStyle.Render(strings.Repeat("\u2588", filled-pos))
	}
	// Unfilled
	if filled < barWidth {
		coloredBar += dimStyle.Render(strings.Repeat("\u2591", barWidth-filled))
	}

	return fmt.Sprintf("[%s] %s (%d/%d)", coloredBar, pctStr, done, total)
}

func (m uiModel) completionBanner() string {
	_, _, success, warning, failed, _ := m.workerSummary()
	var style lipgloss.Style
	var icon string
	if failed > 0 {
		style = errorStyle
		icon = "FAILED"
	} else if warning > 0 {
		style = warnStyle
		icon = "COMPLETED WITH WARNINGS"
	} else if success > 0 {
		style = okStyle
		icon = "COMPLETED"
	} else {
		style = idleStyle
		icon = "DONE"
	}
	banner := fmt.Sprintf("  %s  %d findings in %s", icon, m.findings, m.elapsedString())
	if m.runError != "" {
		banner += "  error: " + m.runError
	}
	return m.render(style, banner) + "\n"
}

func (m uiModel) severityBadge(severity string) string {
	padded := fmt.Sprintf("%-5s", severity)
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "ERROR":
		return m.render(errorStyle, padded)
	case "WARN", "WARNING":
		return m.render(warnStyle, padded)
	default:
		return m.render(idleStyle, padded)
	}
}

func (m uiModel) renderHelp(keys [][2]string) string {
	parts := make([]string, 0, len(keys))
	for _, kv := range keys {
		if m.noColor {
			parts = append(parts, kv[0]+" "+kv[1])
		} else {
			parts = append(parts, helpKeyStyle.Render(kv[0])+" "+helpStyle.Render(kv[1]))
		}
	}
	sep := m.render(dimStyle, " \u2502 ")
	if m.noColor {
		sep = " | "
	}
	return strings.Join(parts, sep)
}

func (m uiModel) workerStatusDisplay(status string, idx int) string {
	if strings.EqualFold(strings.TrimSpace(status), "running") {
		return "running " + m.workerFrame(idx)
	}
	return strings.TrimSpace(status)
}

func (m uiModel) workerFrame(idx int) string {
	frames := []string{"\u28F7", "\u28EF", "\u28DF", "\u28BF", "\u287F", "\u28FE", "\u28FD", "\u28FB"}
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
