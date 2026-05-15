package main

import (
	"fmt"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"ss-stats-tui/model"
	"ss-stats-tui/parser"
	"ss-stats-tui/poller"
	"ss-stats-tui/ui"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// tickMsg fires the next poll.
type tickMsg struct{}

// pollResultMsg carries the result of an async ss invocation.
type pollResultMsg struct {
	conns []*model.Connection
	err   error
}

func tickCmd(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg {
		return tickMsg{}
	})
}

func pollCmd() tea.Cmd {
	return func() tea.Msg {
		conns, err := parser.RunSS()
		return pollResultMsg{conns: conns, err: err}
	}
}

// ViewMode represents the active tab.
type ViewMode int

const (
	ViewLive ViewMode = iota
	ViewDetail
	ViewSocket
	ViewOverview
	ViewTop
	ViewPerf
	ViewEvents
	ViewFilter
	ViewHelp
)

// tabOrder is the cycle order for tab/shift-tab.
var tabOrder = []ViewMode{ViewLive, ViewDetail, ViewSocket, ViewOverview, ViewTop, ViewPerf, ViewEvents}

func nextTab(cur ViewMode, delta int) ViewMode {
	idx := 0
	for i, v := range tabOrder {
		if v == cur {
			idx = i
			break
		}
	}
	n := len(tabOrder)
	return tabOrder[((idx+delta)%n+n)%n]
}

// AppModel is the main bubbletea model.
type AppModel struct {
	width        int
	height       int
	buf          *poller.Buffer
	table        *ui.TableModel
	filter       *ui.Filter
	tab          ViewMode
	showHelp     bool
	lastError    error
	filterMode   bool
	filterBuf    string
	selectedKey  string
	quitting     bool
	statusMsg    string
	statusExpiry time.Time
}

func NewApp() *AppModel {
	buf := poller.NewBuffer()
	sharedFilter := &ui.Filter{HideListen: true}
	return &AppModel{
		buf:    buf,
		table:  ui.NewTableModel(sharedFilter, 20),
		filter: sharedFilter,
		tab:    ViewLive,
	}
}

func (m *AppModel) Init() tea.Cmd {
	return tea.Batch(
		tea.WindowSize(),
		pollCmd(),
	)
}

// contentHeight returns the height available for tab content.
func (m *AppModel) contentHeight() int {
	headerLines := 4
	if m.filter.IsActive() {
		headerLines = 5
	}
	footerLines := 1
	if m.tab == ViewLive {
		footerLines++
	}
	if m.showHelp {
		footerLines += 15
	}
	h := m.height - headerLines - footerLines
	if h < 1 {
		h = 1
	}
	return h
}

func (m *AppModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.table.SetSize(msg.Width, m.contentHeight())
		return m, nil

	case tea.KeyMsg:
		if m.filterMode {
			return m.handleFilterInput(msg)
		}

		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "?":
			m.showHelp = !m.showHelp
			return m, nil
		case "1":
			m.tab = ViewLive
		case "2":
			m.tab = ViewDetail
		case "3":
			m.tab = ViewSocket
		case "4":
			m.tab = ViewOverview
		case "5":
			m.tab = ViewTop
		case "6":
			m.tab = ViewPerf
		case "7":
			m.tab = ViewEvents
		case "tab":
			m.tab = nextTab(m.tab, 1)
		case "shift+tab":
			m.tab = nextTab(m.tab, -1)
		case "/":
			m.filterMode = true
			m.filterBuf = ""
			m.tab = ViewFilter
			return m, nil
		case "enter":
			if m.tab == ViewLive {
				if conn := m.table.GetSelected(); conn != nil {
					m.selectedKey = conn.ConnKey()
				}
				m.tab = ViewDetail
			}
		case "esc":
			if m.tab == ViewDetail || m.tab == ViewSocket {
				m.selectedKey = ""
				m.tab = ViewLive
			} else if m.tab == ViewHelp {
				m.tab = ViewLive
			} else if m.filter.IsActive() {
				m.filter.Reset()
				m.table.InvalidateCache()
			} else {
				m.showHelp = false
			}
		case "j", "down":
			m.table.Next()
		case "k", "up":
			m.table.Prev()
		case "g":
			m.table.First()
		case "G":
			m.table.Last()
		case "h":
			m.table.CycleSort()
		case "L":
			m.filter.HideListen = !m.filter.HideListen
			m.table.InvalidateCache()
		case "e":
			m.export("json")
		case "E":
			m.export("csv")
		}

	case tickMsg:
		return m, pollCmd()

	case pollResultMsg:
		if msg.err != nil {
			m.lastError = msg.err
		} else {
			m.lastError = nil
			m.buf.AddSnapshot(msg.conns)
			m.table.SetConnections(msg.conns)
			m.table.SetSize(m.width, m.contentHeight())
		}
		return m, tickCmd(poller.PollInterval)
	}

	return m, nil
}

func (m *AppModel) handleFilterInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.filterMode = false
		m.tab = ViewLive
		return m, nil
	case "enter":
		m.applyFilter()
		m.table.InvalidateCache()
		m.filterMode = false
		m.tab = ViewLive
		return m, nil
	case "backspace":
		if n := len(m.filterBuf); n > 0 {
			_, size := utf8.DecodeLastRuneInString(m.filterBuf)
			m.filterBuf = m.filterBuf[:n-size]
		}
	case "ctrl+w":
		words := strings.Fields(m.filterBuf)
		if len(words) > 0 {
			m.filterBuf = strings.Join(words[:len(words)-1], " ")
		}
	default:
		s := msg.String()
		if utf8.RuneCountInString(s) == 1 {
			m.filterBuf += s
		}
	}
	return m, nil
}

func (m *AppModel) applyFilter() {
	parts := strings.Fields(m.filterBuf)
	m.filter.Reset()

	for _, p := range parts {
		switch {
		case strings.HasPrefix(p, "local="):
			m.filter.LocalAddr = strings.TrimPrefix(p, "local=")
		case strings.HasPrefix(p, "peer="):
			m.filter.PeerAddr = strings.TrimPrefix(p, "peer=")
		case strings.HasPrefix(p, "lport="):
			m.filter.LocalPort = strings.TrimPrefix(p, "lport=")
		case strings.HasPrefix(p, "pport="):
			m.filter.PeerPort = strings.TrimPrefix(p, "pport=")
		case strings.HasPrefix(p, "state="):
			m.filter.State = strings.ToUpper(strings.TrimPrefix(p, "state="))
		case strings.HasPrefix(p, "proc="):
			m.filter.Process = strings.TrimPrefix(p, "proc=")
		case strings.HasPrefix(p, "signal="):
			m.filter.Signal = strings.TrimPrefix(p, "signal=")
		default:
			states := []string{"ESTAB", "LISTEN", "TIME-WAIT", "CLOSE-WAIT", "FIN-WAIT-1", "FIN-WAIT-2", "LAST-ACK", "SYN-SENT", "SYN-RECV"}
			isState := false
			for _, s := range states {
				if strings.ToUpper(p) == s {
					m.filter.State = s
					isState = true
					break
				}
			}
			if !isState {
				m.filter.LocalAddr = p
			}
		}
	}
}

func (m *AppModel) View() string {
	if m.quitting {
		return "\n  Goodbye!\n"
	}

	var b strings.Builder

	// Header (fixed)
	b.WriteString(ui.RenderHeader(m.buf, m.width) + "\n")

	// Tabs (fixed)
	b.WriteString(ui.RenderTabs(int(m.tab), m.width) + "\n")

	// Filter bar (fixed)
	if m.filter.IsActive() {
		filterText := fmt.Sprintf("  Filter: %s  [Esc clear]", m.renderFilterText())
		b.WriteString(lipgloss.NewStyle().
			Foreground(lipgloss.Color("#ffd43b")).
			Render(filterText) + "\n")
	}

	b.WriteString("\n")

	ch := m.contentHeight()

	// Content (clipped to available height)
	var content string
	var tableFooter string
	showTableFooter := false

	switch m.tab {
	case ViewLive:
		content = m.table.RenderBody()

		if sigs := m.table.GetSignalsForSelected(); len(sigs) > 0 {
			content += "\n" + ui.RenderSignals(sigs)
		}
		tableFooter = m.table.RenderFooter()
		showTableFooter = true

	case ViewDetail:
		conn := m.getConnectionByKey(m.selectedKey)
		content = ui.RenderDetail(conn, m.buf, m.width, ch)

	case ViewSocket:
		conn := m.getConnectionByKey(m.selectedKey)
		content = ui.RenderSocket(conn, m.buf, m.width, ch)

	case ViewOverview:
		content = ui.RenderOverview(m.buf, m.width, ch)

	case ViewTop:
		content = ui.RenderTop(m.buf, m.width, ch)

	case ViewPerf:
		content = ui.RenderPerf(m.buf, m.width, ch)

	case ViewEvents:
		content = ui.RenderEvents(m.buf, m.width, ch)

	case ViewFilter:
		content = "\n  Filter connections:\n\n"
		content += "  " + m.filterBuf + cursor() + "\n\n"
		content += lipgloss.NewStyle().Foreground(lipgloss.Color("#888")).Render(
			"  Syntax: local=<addr> peer=<addr> lport=<port> pport=<port>\n" +
				"          state=<state> proc=<name> signal=<label>\n" +
				"  Examples: state=ESTAB local=192.168 pport=443\n" +
				"            proc=nginx signal=RETRANS\n" +
				"  Enter to apply, Escape to cancel")
	}

	// Clip content to available height
	content = clipToHeight(content, ch)
	b.WriteString(content)

	// Table footer (fixed, outside clipped area)
	if showTableFooter {
		b.WriteString("\n" + tableFooter)
	}

	// Help
	if m.showHelp {
		b.WriteString("\n\n" + ui.RenderHelp())
	}

	// Footer (fixed)
	if !m.showHelp && m.tab != ViewFilter {
		b.WriteString(fmt.Sprintf("\n%s", m.renderFooter()))
	}

	// Wrap everything in a fixed-size frame to prevent terminal scroll
	return lipgloss.NewStyle().
		Height(m.height).
		Render(b.String())
}

// clipToHeight clips a string to at most maxLines lines.
func clipToHeight(s string, maxLines int) string {
	lines := strings.Split(s, "\n")
	if len(lines) <= maxLines {
		return s
	}
	return strings.Join(lines[:maxLines], "\n")
}

func (m *AppModel) getLatestConns() []*model.Connection {
	snap := m.buf.GetLatest()
	if snap == nil {
		return nil
	}
	return snap.Conns
}

func (m *AppModel) getConnectionByKey(key string) *model.Connection {
	snap := m.buf.GetLatest()
	if snap == nil {
		return nil
	}
	return snap.Lookup(key)
}

func (m *AppModel) renderFilterText() string {
	var parts []string
	if m.filter.LocalAddr != "" {
		parts = append(parts, "local="+m.filter.LocalAddr)
	}
	if m.filter.PeerAddr != "" {
		parts = append(parts, "peer="+m.filter.PeerAddr)
	}
	if m.filter.LocalPort != "" {
		parts = append(parts, "lport="+m.filter.LocalPort)
	}
	if m.filter.PeerPort != "" {
		parts = append(parts, "pport="+m.filter.PeerPort)
	}
	if m.filter.State != "" {
		parts = append(parts, "state="+m.filter.State)
	}
	if m.filter.Process != "" {
		parts = append(parts, "proc="+m.filter.Process)
	}
	if m.filter.Signal != "" {
		parts = append(parts, "signal="+m.filter.Signal)
	}
	return strings.Join(parts, " ")
}

func (m *AppModel) export(kind string) {
	ts := time.Now().Format("20060102-150405")
	name := fmt.Sprintf("ss-stats-%s.%s", ts, kind)
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}
	path := cwd + string(os.PathSeparator) + name

	var n int
	switch kind {
	case "json":
		n, err = m.buf.ExportJSON(path)
	case "csv":
		n, err = m.buf.ExportCSV(path)
	}
	if err != nil {
		m.statusMsg = "export failed: " + err.Error()
	} else {
		m.statusMsg = fmt.Sprintf("Exported %d %s → %s",
			n,
			map[string]string{"json": "snapshots", "csv": "rows"}[kind],
			path)
	}
	m.statusExpiry = time.Now().Add(5 * time.Second)
}

func (m *AppModel) renderFooter() string {
	if m.statusMsg != "" && time.Now().Before(m.statusExpiry) {
		return lipgloss.NewStyle().
			Foreground(lipgloss.Color("#000")).
			Background(lipgloss.Color("#51cf66")).
			Bold(true).
			Padding(0, 1).
			Render(m.statusMsg)
	}
	snap := m.buf.GetLatest()
	total := 0
	if snap != nil {
		total = len(snap.Conns)
	}
	filtered := m.table.GetFilteredCount()

	var parts []string
	parts = append(parts, fmt.Sprintf("%d conns", total))
	if m.filter.IsActive() {
		parts = append(parts, fmt.Sprintf("%d matched", filtered))
	}
	parts = append(parts, fmt.Sprintf("snapshots: %d", m.buf.Count()))
	parts = append(parts, "updated: "+ui.RenderTimeAgo(m.buf.LastUpdate()))

	return lipgloss.NewStyle().
		Foreground(lipgloss.Color("#666")).
		Render("  " + strings.Join(parts, "  |  "))
}

func cursor() string {
	return lipgloss.NewStyle().
		Background(lipgloss.Color("#5a56e7")).
		Render(" ")
}

func main() {
	app := NewApp()
	p := tea.NewProgram(app, tea.WithAltScreen())

	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
