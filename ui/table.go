package ui

import (
	"fmt"
	"sort"
	"strings"

	"ss-stats-tui/classifier"
	"ss-stats-tui/model"

	"github.com/charmbracelet/lipgloss"
)

// SortDir is the sort direction.
type SortDir int

const (
	SortAsc SortDir = iota
	SortDesc
)

// TableColumn defines a column in the connection table.
type TableColumn struct {
	Key      string
	Title    string
	Width    int
	BaseWidth int
	Expand   bool
	Render   func(*model.Connection) string
	SortFunc func(a, b *model.Connection) bool
}

var defaultColumns = []TableColumn{
	{
		Key:   "signal",
		Title: "",
		Width: 2,
		Render: func(c *model.Connection) string {
			return RenderSignalBar(classifier.Classify(c))
		},
		SortFunc: nil,
	},
	{
		Key:   "state",
		Title: "State",
		Width: 12,
		Render: func(c *model.Connection) string {
			return lipgloss.NewStyle().Foreground(StateColor(c.State)).Render(c.State)
		},
		SortFunc: func(a, b *model.Connection) bool { return a.State < b.State },
	},
	{
		Key:   "local",
		Title: "Local",
		Width: 16,
		BaseWidth: 16,
		Expand: true,
		Render: func(c *model.Connection) string {
			return c.LocalAddr + ":" + c.LocalPort
		},
		SortFunc: func(a, b *model.Connection) bool {
			return a.LocalAddr+a.LocalPort < b.LocalAddr+b.LocalPort
		},
	},
	{
		Key:   "peer",
		Title: "Peer",
		Width: 16,
		BaseWidth: 16,
		Expand: true,
		Render: func(c *model.Connection) string {
			return c.PeerAddr + ":" + c.PeerPort
		},
		SortFunc: func(a, b *model.Connection) bool {
			return a.PeerAddr+a.PeerPort < b.PeerAddr+b.PeerPort
		},
	},
	{
		Key:   "process",
		Title: "Process",
		Width: 12,
		BaseWidth: 12,
		Expand: true,
		Render: func(c *model.Connection) string {
			if c.Process == nil {
				return "-"
			}
			return *c.Process
		},
		SortFunc: func(a, b *model.Connection) bool {
			aV := ""
			bV := ""
			if a.Process != nil {
				aV = *a.Process
			}
			if b.Process != nil {
				bV = *b.Process
			}
			return aV < bV
		},
	},
	{
		Key:   "rtt",
		Title: "RTT",
		Width: 7,
		Render: func(c *model.Connection) string {
			return fmtRTT(c.RTT)
		},
		SortFunc: func(a, b *model.Connection) bool {
			if a.RTT == nil && b.RTT == nil {
				return false
			}
			if a.RTT == nil {
				return true
			}
			if b.RTT == nil {
				return false
			}
			return *a.RTT < *b.RTT
		},
	},
	{
		Key:   "cwnd",
		Title: "CWnd",
		Width: 7,
		Render: func(c *model.Connection) string {
			return fmtNumRaw(c.CWnd)
		},
		SortFunc: func(a, b *model.Connection) bool {
			if a.CWnd == nil && b.CWnd == nil {
				return false
			}
			if a.CWnd == nil {
				return true
			}
			if b.CWnd == nil {
				return false
			}
			return *a.CWnd < *b.CWnd
		},
	},
	{
		Key:   "sq",
		Title: "SQ",
		Width: 5,
		Render: func(c *model.Connection) string {
			return fmtNumRaw(c.SendQ)
		},
		SortFunc: func(a, b *model.Connection) bool {
			if a.SendQ == nil && b.SendQ == nil {
				return false
			}
			if a.SendQ == nil {
				return true
			}
			if b.SendQ == nil {
				return false
			}
			return *a.SendQ < *b.SendQ
		},
	},
	{
		Key:   "rq",
		Title: "RQ",
		Width: 5,
		Render: func(c *model.Connection) string {
			return fmtNumRaw(c.RecvQ)
		},
		SortFunc: func(a, b *model.Connection) bool {
			if a.RecvQ == nil && b.RecvQ == nil {
				return false
			}
			if a.RecvQ == nil {
				return true
			}
			if b.RecvQ == nil {
				return false
			}
			return *a.RecvQ < *b.RecvQ
		},
	},
	{
		Key:   "tx",
		Title: "TX",
		Width: 8,
		Render: func(c *model.Connection) string {
			return fmtRate(c.DeltaBytesSent)
		},
		SortFunc: func(a, b *model.Connection) bool {
			if a.DeltaBytesSent == nil && b.DeltaBytesSent == nil {
				return false
			}
			if a.DeltaBytesSent == nil {
				return true
			}
			if b.DeltaBytesSent == nil {
				return false
			}
			return *a.DeltaBytesSent < *b.DeltaBytesSent
		},
	},
	{
		Key:   "rx",
		Title: "RX",
		Width: 8,
		Render: func(c *model.Connection) string {
			return fmtRate(c.DeltaBytesReceived)
		},
		SortFunc: func(a, b *model.Connection) bool {
			if a.DeltaBytesReceived == nil && b.DeltaBytesReceived == nil {
				return false
			}
			if a.DeltaBytesReceived == nil {
				return true
			}
			if b.DeltaBytesReceived == nil {
				return false
			}
			return *a.DeltaBytesReceived < *b.DeltaBytesReceived
		},
	},
	{
		Key:   "retrans",
		Title: "Retrans",
		Width: 6,
		Render: func(c *model.Connection) string {
			return fmtNumRaw(c.Retrans)
		},
		SortFunc: func(a, b *model.Connection) bool {
			if a.Retrans == nil && b.Retrans == nil {
				return false
			}
			if a.Retrans == nil {
				return true
			}
			if b.Retrans == nil {
				return false
			}
			return *a.Retrans < *b.Retrans
		},
	},
}

// sortCycle defines the order in which [h] cycles through sort modes.
var sortCycle = []struct {
	key string
	dir SortDir
}{
	{"state", SortAsc},
	{"state", SortDesc},
	{"local", SortAsc},
	{"local", SortDesc},
	{"peer", SortAsc},
	{"peer", SortDesc},
	{"process", SortAsc},
	{"process", SortDesc},
}

// TableModel holds the state for the connection table.
type TableModel struct {
	conns         []*model.Connection
	filter        *Filter
	sortKey       string
	sortDir       SortDir
	sortCycleIdx  int
	cursor        int
	page          int
	pageSize      int
	columns       []TableColumn
	width         int
	showDetail    bool
	cachedConns   []*model.Connection
}

func NewTableModel(filter *Filter, pageSize int) *TableModel {
	return &TableModel{
		filter:       filter,
		sortKey:      sortCycle[0].key,
		sortDir:      sortCycle[0].dir,
		sortCycleIdx: 0,
		pageSize:     pageSize,
		columns:      defaultColumns,
	}
}

// SetConnections updates the connection list.
func (t *TableModel) SetConnections(conns []*model.Connection) {
	t.conns = conns
	t.cachedConns = nil
}

// SetSize updates the table dimensions.
func (t *TableModel) SetSize(width, height int) {
	t.width = width
	t.pageSize = height
	if t.pageSize < 1 {
		t.pageSize = 1
	}

	// Reset expandable columns to base width
	for i := range t.columns {
		if t.columns[i].Expand {
			t.columns[i].Width = t.columns[i].BaseWidth
		}
	}

	// Distribute extra width to expandable columns
	totalBase := 0
	expandableCount := 0
	for _, col := range t.columns {
		if col.Expand {
			totalBase += col.BaseWidth
			expandableCount++
		} else {
			totalBase += col.Width
		}
	}

	if expandableCount > 0 && width > totalBase {
		extra := width - totalBase
		extraPerCol := extra / expandableCount
		remainder := extra % expandableCount
		for i := range t.columns {
			if t.columns[i].Expand {
				t.columns[i].Width = t.columns[i].BaseWidth + extraPerCol
				if remainder > 0 {
					t.columns[i].Width++
					remainder--
				}
			}
		}
	}
}

// GetSelected returns the currently selected connection.
func (t *TableModel) GetSelected() *model.Connection {
	filtered := t.getFiltered()
	idx := t.page*t.pageSize + t.cursor
	if idx < 0 || idx >= len(filtered) {
		return nil
	}
	return filtered[idx]
}

// GetCursor returns the absolute cursor position.
func (t *TableModel) GetCursor() int {
	return t.page*t.pageSize + t.cursor
}

// SetCursor sets the absolute cursor position.
func (t *TableModel) SetCursor(pos int) {
	filtered := t.getFiltered()
	if len(filtered) == 0 {
		t.page = 0
		t.cursor = 0
		return
	}
	if pos < 0 {
		pos = 0
	}
	if pos >= len(filtered) {
		pos = len(filtered) - 1
	}
	t.page = pos / t.pageSize
	t.cursor = pos % t.pageSize
}

// Next moves cursor down.
func (t *TableModel) Next() {
	filtered := t.getFiltered()
	if len(filtered) == 0 {
		return
	}
	// Check if we're at the very last item
	absPos := t.page*t.pageSize + t.cursor
	if absPos >= len(filtered)-1 {
		return // at the end
	}
	if t.cursor < t.pageSize-1 {
		t.cursor++
	} else {
		t.page++
		t.cursor = 0
	}
}

// Prev moves cursor up.
func (t *TableModel) Prev() {
	if t.cursor > 0 {
		t.cursor--
	} else if t.page > 0 {
		t.page--
		t.cursor = t.pageSize - 1
	}
}

// First moves to first item.
func (t *TableModel) First() {
	t.page = 0
	t.cursor = 0
}

// Last moves to last item.
func (t *TableModel) Last() {
	filtered := t.getFiltered()
	if len(filtered) == 0 {
		return
	}
	t.SetCursor(len(filtered) - 1)
}

// ToggleSort toggles sort on the given column.
func (t *TableModel) ToggleSort(key string) {
	if t.sortKey == key {
		t.sortDir = (t.sortDir + 1) % 2
	} else {
		t.sortKey = key
		t.sortDir = SortAsc
	}
	t.cachedConns = nil
	t.First()
}

// CycleSort cycles through the predefined sort order: state asc/desc, local asc/desc, peer asc/desc, process asc/desc.
func (t *TableModel) CycleSort() {
	t.sortCycleIdx = (t.sortCycleIdx + 1) % len(sortCycle)
	t.sortKey = sortCycle[t.sortCycleIdx].key
	t.sortDir = sortCycle[t.sortCycleIdx].dir
	t.cachedConns = nil
	t.First()
}

// InvalidateCache marks the cached results as stale.
func (t *TableModel) InvalidateCache() {
	t.cachedConns = nil
}

func (t *TableModel) getFiltered() []*model.Connection {
	if t.cachedConns != nil {
		return t.cachedConns
	}
	if t.conns == nil {
		return nil
	}
	var filtered []*model.Connection
	for _, c := range t.conns {
		if t.filter.Matches(c) {
			filtered = append(filtered, c)
		}
	}

	sort.SliceStable(filtered, func(i, j int) bool {
		for _, col := range t.columns {
			if col.Key == t.sortKey && col.SortFunc != nil {
				if t.sortDir == SortDesc {
					return !col.SortFunc(filtered[i], filtered[j])
				}
				return col.SortFunc(filtered[i], filtered[j])
			}
		}
		return false
	})

	t.cachedConns = filtered
	return filtered
}

func (t *TableModel) getVisible() []*model.Connection {
	filtered := t.getFiltered()
	start := t.page * t.pageSize
	end := start + t.pageSize
	if end > len(filtered) {
		end = len(filtered)
	}
	if start >= len(filtered) {
		return nil
	}
	return filtered[start:end]
}

// RenderBody renders the table body (header + separator + rows) without footer.
func (t *TableModel) RenderBody() string {
	visible := t.getVisible()
	if len(visible) == 0 {
		return "  No connections"
	}

	var b strings.Builder

	// Header
	var headerParts []string
	for _, col := range t.columns {
		style := lipgloss.NewStyle().Width(col.Width).Bold(true)
		if col.Key == t.sortKey {
			dir := "↑"
			if t.sortDir == SortDesc {
				dir = "↓"
			}
			headerParts = append(headerParts, style.Render(col.Title+dir))
		} else {
			headerParts = append(headerParts, style.Render(col.Title))
		}
	}
	b.WriteString(strings.Join(headerParts, "") + "\n")

	// Separator
	var sepParts []string
	for _, col := range t.columns {
		sepParts = append(sepParts, strings.Repeat("─", col.Width))
	}
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#555")).Render(strings.Join(sepParts, "")) + "\n")

	// Rows
	for i, c := range visible {
		var rowParts []string
		for _, col := range t.columns {
			val := col.Render(c)
			style := lipgloss.NewStyle().Width(col.Width).MaxWidth(col.Width)
			if i == t.cursor {
				style = style.Background(lipgloss.Color("#444")).Foreground(lipgloss.Color("#fff"))
			}
			rowParts = append(rowParts, style.Render(val))
		}
		b.WriteString(strings.Join(rowParts, "") + "\n")
	}

	return b.String()
}

// RenderFooter renders the table status bar.
func (t *TableModel) RenderFooter() string {
	filtered := t.getFiltered()
	total := len(filtered)
	pos := t.page*t.pageSize + t.cursor + 1
	dir := "↑"
	if t.sortDir == SortDesc {
		dir = "↓"
	}
	sortLabel := strings.ToLower(t.sortKey) + dir
	footer := fmt.Sprintf("  %d/%d  (page %d)  sort: %s  [h] cycle  [j/k] nav  [g/G] first/last  [Enter] detail  [/] filter  [?] help",
		pos, total, t.page+1, sortLabel)
	return lipgloss.NewStyle().Foreground(lipgloss.Color("#666")).Render(footer)
}

// GetFilteredCount returns the number of filtered connections.
func (t *TableModel) GetFilteredCount() int {
	return len(t.getFiltered())
}

// GetSignalsForSelected returns signals for the currently selected connection.
func (t *TableModel) GetSignalsForSelected() []model.Signal {
	c := t.GetSelected()
	if c == nil {
		return nil
	}
	return classifier.Classify(c)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
