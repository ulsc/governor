package checkstui

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"governor/internal/checks"
)

type inputMode string

const (
	modeBrowse        inputMode = "browse"
	modeSearch        inputMode = "search"
	modeConfirmStatus inputMode = "confirm-status"
	modeDuplicateID   inputMode = "duplicate-id"
	modeDuplicateName inputMode = "duplicate-name"
)

var checkIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,63}$`)

type pendingStatusAction struct {
	row    row
	status checks.Status
}

type uiModel struct {
	checksDir string

	snapshot snapshot

	mode      inputMode
	search    string
	searchBuf string

	sourceFilter sourceFilter
	statusFilter statusFilter
	sort         sortState

	filtered []int
	cursor   int

	pendingStatus *pendingStatusAction
	duplicateFrom row
	duplicateID   string
	duplicateName string

	showDetails bool
	message     string
	width       int
	height      int
}

func newModel(opts Options) (uiModel, error) {
	snap, err := loadSnapshot(opts.ChecksDir)
	if err != nil {
		return uiModel{}, err
	}
	m := uiModel{
		checksDir:    opts.ChecksDir,
		snapshot:     snap,
		mode:         modeBrowse,
		sourceFilter: sourceAll,
		statusFilter: statusAll,
		sort:         sortState{Key: sortByID},
		showDetails:  true,
		width:        120,
		height:       36,
		message:      "q quit | / search | s status | o source | 1..5 sort | e/d status | n duplicate | p path | h details | r refresh",
	}
	m.rebuildFiltered()
	return m, nil
}

func (m uiModel) Init() tea.Cmd {
	return nil
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
		if m.mode == modeBrowse && (msg.String() == "q" || msg.String() == "ctrl+c") {
			return m, tea.Quit
		}
		switch m.mode {
		case modeSearch:
			return m.handleSearchMode(msg), nil
		case modeConfirmStatus:
			return m.handleConfirmStatusMode(msg), nil
		case modeDuplicateID:
			return m.handleDuplicateIDMode(msg), nil
		case modeDuplicateName:
			return m.handleDuplicateNameMode(msg), nil
		default:
			return m.handleBrowseMode(msg), nil
		}
	default:
		return m, nil
	}
}

func (m uiModel) handleBrowseMode(msg tea.KeyMsg) uiModel {
	switch msg.String() {
	case "j", "down":
		if m.cursor < len(m.filtered)-1 {
			m.cursor++
		}
	case "k", "up":
		if m.cursor > 0 {
			m.cursor--
		}
	case "g":
		m.cursor = 0
	case "G":
		if len(m.filtered) > 0 {
			m.cursor = len(m.filtered) - 1
		}
	case "pgdown":
		step := max(1, m.bodyHeight()-4)
		m.cursor = min(len(m.filtered)-1, m.cursor+step)
	case "pgup":
		step := max(1, m.bodyHeight()-4)
		m.cursor = max(0, m.cursor-step)
	case "/":
		m.mode = modeSearch
		m.searchBuf = m.search
		m.message = "search mode: type query and press Enter (Esc to cancel)"
	case "s":
		m.statusFilter = cycleStatusFilter(m.statusFilter)
		m.cursor = 0
		m.rebuildFiltered()
		m.message = "status filter: " + string(m.statusFilter)
	case "o":
		m.sourceFilter = cycleSourceFilter(m.sourceFilter)
		m.cursor = 0
		m.rebuildFiltered()
		m.message = "source filter: " + string(m.sourceFilter)
	case "x":
		m.search = ""
		m.searchBuf = ""
		m.statusFilter = statusAll
		m.sourceFilter = sourceAll
		m.cursor = 0
		m.rebuildFiltered()
		m.message = "cleared filters"
	case "1":
		m.toggleSort(sortByID)
	case "2":
		m.toggleSort(sortByStatus)
	case "3":
		m.toggleSort(sortBySource)
	case "4":
		m.toggleSort(sortBySeverity)
	case "5":
		m.toggleSort(sortByPath)
	case "h":
		m.showDetails = !m.showDetails
	case "r":
		if err := m.reload(); err != nil {
			m.message = "refresh failed: " + err.Error()
			return m
		}
		m.message = "reloaded checks"
	case "p":
		selected, ok := m.selectedRow()
		if !ok {
			m.message = "no row selected"
			return m
		}
		m.message = "path: " + selected.Path
	case "e":
		return m.startStatusConfirmation(checks.StatusEnabled)
	case "d":
		return m.startStatusConfirmation(checks.StatusDisabled)
	case "n":
		return m.startDuplicateFlow()
	}
	return m
}

func (m uiModel) handleSearchMode(msg tea.KeyMsg) uiModel {
	switch msg.String() {
	case "enter":
		m.mode = modeBrowse
		m.search = strings.TrimSpace(m.searchBuf)
		m.cursor = 0
		m.rebuildFiltered()
		m.message = "search applied"
	case "esc":
		m.mode = modeBrowse
		m.searchBuf = m.search
		m.message = "search canceled"
	case "backspace":
		m.searchBuf = trimLastRune(m.searchBuf)
	default:
		if msg.Type == tea.KeyRunes {
			m.searchBuf += string(msg.Runes)
		}
	}
	return m
}

func (m uiModel) handleConfirmStatusMode(msg tea.KeyMsg) uiModel {
	switch msg.String() {
	case "enter":
		if m.pendingStatus == nil {
			m.mode = modeBrowse
			m.message = "no pending action"
			return m
		}
		pending := *m.pendingStatus
		if err := m.applyStatusChange(pending.row, pending.status); err != nil {
			m.mode = modeBrowse
			m.pendingStatus = nil
			m.message = "status update failed: " + err.Error()
			return m
		}
		m.mode = modeBrowse
		m.pendingStatus = nil
		m.message = fmt.Sprintf("updated %s -> %s", pending.row.ID, pending.status)
	case "esc":
		m.mode = modeBrowse
		m.pendingStatus = nil
		m.message = "status update canceled"
	}
	return m
}

func (m uiModel) handleDuplicateIDMode(msg tea.KeyMsg) uiModel {
	switch msg.String() {
	case "enter":
		id := strings.TrimSpace(strings.ToLower(m.duplicateID))
		if !checkIDPattern.MatchString(id) {
			m.message = "invalid id: use 2-64 chars [a-z0-9_-], start with alnum"
			return m
		}
		m.duplicateID = id
		baseName := strings.TrimSpace(m.duplicateFrom.Name)
		if baseName == "" {
			baseName = m.duplicateFrom.ID
		}
		m.duplicateName = baseName + " Copy"
		m.mode = modeDuplicateName
		m.message = "duplicate: enter check name (Enter to create as draft)"
	case "esc":
		m.mode = modeBrowse
		m.duplicateID = ""
		m.duplicateName = ""
		m.message = "duplicate canceled"
	case "backspace":
		m.duplicateID = trimLastRune(m.duplicateID)
	default:
		if msg.Type == tea.KeyRunes {
			m.duplicateID += string(msg.Runes)
		}
	}
	return m
}

func (m uiModel) handleDuplicateNameMode(msg tea.KeyMsg) uiModel {
	switch msg.String() {
	case "enter":
		name := strings.TrimSpace(m.duplicateName)
		createdID := m.duplicateID
		if err := m.duplicateAsDraft(m.duplicateFrom, m.duplicateID, name); err != nil {
			m.mode = modeBrowse
			m.message = "duplicate failed: " + err.Error()
			return m
		}
		m.mode = modeBrowse
		m.duplicateID = ""
		m.duplicateName = ""
		m.message = "created draft duplicate: " + createdID
	case "esc":
		m.mode = modeBrowse
		m.duplicateID = ""
		m.duplicateName = ""
		m.message = "duplicate canceled"
	case "backspace":
		m.duplicateName = trimLastRune(m.duplicateName)
	default:
		if msg.Type == tea.KeyRunes {
			m.duplicateName += string(msg.Runes)
		}
	}
	return m
}

func (m uiModel) reload() error {
	snap, err := loadSnapshot(m.checksDir)
	if err != nil {
		return err
	}
	m.snapshot = snap
	if m.cursor >= len(m.filtered) {
		m.cursor = max(0, len(m.filtered)-1)
	}
	m.rebuildFiltered()
	return nil
}

func (m uiModel) startStatusConfirmation(status checks.Status) uiModel {
	selected, ok := m.selectedRow()
	if !ok {
		m.message = "no row selected"
		return m
	}
	if !selected.Mutable {
		m.message = "selected row is read-only (built-in, shadowed, or invalid)"
		return m
	}
	m.pendingStatus = &pendingStatusAction{
		row:    selected,
		status: status,
	}
	m.mode = modeConfirmStatus
	m.message = fmt.Sprintf("confirm: set %s -> %s ? (Enter confirm, Esc cancel)", selected.ID, status)
	return m
}

func (m uiModel) startDuplicateFlow() uiModel {
	selected, ok := m.selectedRow()
	if !ok {
		m.message = "no row selected"
		return m
	}
	if selected.Invalid {
		m.message = "cannot duplicate invalid check entry"
		return m
	}
	m.duplicateFrom = selected
	m.duplicateID = suggestedDuplicateID(selected.ID)
	m.duplicateName = ""
	m.mode = modeDuplicateID
	m.message = "duplicate: enter new check id"
	return m
}

func (m *uiModel) applyStatusChange(selected row, status checks.Status) error {
	if _, err := checks.UpdateStatusInDirs(m.snapshot.SearchedDirs, selected.ID, status); err != nil {
		return err
	}
	return m.reload()
}

func (m *uiModel) duplicateAsDraft(selected row, id string, name string) error {
	base, err := definitionForRow(selected)
	if err != nil {
		return err
	}
	base.ID = strings.TrimSpace(strings.ToLower(id))
	if strings.TrimSpace(name) != "" {
		base.Name = strings.TrimSpace(name)
	} else {
		base.Name = base.ID
	}
	base.Status = checks.StatusDraft
	base.Source = checks.SourceCustom

	dir, err := checks.ResolveWriteDir(m.checksDir)
	if err != nil {
		return err
	}
	if _, err := checks.WriteDefinition(dir, base, false); err != nil {
		return err
	}
	return m.reload()
}

func definitionForRow(selected row) (checks.Definition, error) {
	if selected.Source == checks.SourceBuiltin {
		for _, builtin := range checks.Builtins() {
			builtin = checks.NormalizeDefinition(builtin)
			if builtin.ID == selected.ID {
				return builtin, nil
			}
		}
		return checks.Definition{}, fmt.Errorf("builtin check %q not found", selected.ID)
	}
	if strings.TrimSpace(selected.Path) == "" {
		return checks.Definition{}, fmt.Errorf("check %q has no path", selected.ID)
	}
	def, err := checks.ReadDefinition(selected.Path)
	if err != nil {
		return checks.Definition{}, err
	}
	return checks.NormalizeDefinition(def), nil
}

func (m *uiModel) toggleSort(key sortKey) {
	if m.sort.Key == key {
		m.sort.Desc = !m.sort.Desc
	} else {
		m.sort = sortState{Key: key, Desc: false}
	}
	m.cursor = 0
	m.rebuildFiltered()
	m.message = "sort: " + describeSort(m.sort)
}

func (m *uiModel) rebuildFiltered() {
	indexes := make([]int, 0, len(m.snapshot.Rows))
	for i, r := range m.snapshot.Rows {
		if matchesFilters(r, m.search, m.sourceFilter, m.statusFilter) {
			indexes = append(indexes, i)
		}
	}
	sortRows(indexes, m.snapshot.Rows, m.sort)
	m.filtered = indexes
	if m.cursor >= len(m.filtered) {
		m.cursor = max(0, len(m.filtered)-1)
	}
}

func sortRows(indexes []int, rows []row, state sortState) {
	sort.SliceStable(indexes, func(i, j int) bool {
		a := rows[indexes[i]]
		b := rows[indexes[j]]
		return compareRows(a, b, state)
	})
}

func (m uiModel) selectedRow() (row, bool) {
	if len(m.filtered) == 0 {
		return row{}, false
	}
	if m.cursor < 0 || m.cursor >= len(m.filtered) {
		return row{}, false
	}
	return m.snapshot.Rows[m.filtered[m.cursor]], true
}

func (m uiModel) bodyHeight() int {
	base := 12
	if m.showDetails {
		base += 10
	}
	return max(8, m.height-base)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (m uiModel) statusLine() string {
	switch m.mode {
	case modeSearch:
		return fmt.Sprintf("search: %s_", m.searchBuf)
	case modeConfirmStatus:
		if m.pendingStatus != nil {
			return fmt.Sprintf("confirm status: %s -> %s (Enter/Esc)", m.pendingStatus.row.ID, m.pendingStatus.status)
		}
	case modeDuplicateID:
		return fmt.Sprintf("duplicate id: %s_", m.duplicateID)
	case modeDuplicateName:
		return fmt.Sprintf("duplicate name: %s_", m.duplicateName)
	}
	return m.message
}

func suggestedDuplicateID(id string) string {
	id = strings.TrimSpace(strings.ToLower(id))
	if id == "" {
		return "new-check"
	}
	return id + "-copy"
}

func trimLastRune(s string) string {
	if s == "" {
		return s
	}
	runes := []rune(s)
	if len(runes) == 0 {
		return ""
	}
	return string(runes[:len(runes)-1])
}
