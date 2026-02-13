package checkstui

import (
	"fmt"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

type inputMode string

const (
	modeBrowse inputMode = "browse"
	modeSearch inputMode = "search"
)

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
		message:      "q quit | / search | s status | o source | 1..5 sort | h details | r refresh",
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
		if m.mode == modeSearch {
			return m.handleSearchMode(msg), nil
		}
		return m.handleBrowseMode(msg), nil
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
		if len(m.searchBuf) > 0 {
			m.searchBuf = m.searchBuf[:len(m.searchBuf)-1]
		}
	default:
		if msg.Type == tea.KeyRunes {
			m.searchBuf += string(msg.Runes)
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
	if m.mode == modeSearch {
		return fmt.Sprintf("search: %s_", m.searchBuf)
	}
	return m.message
}
