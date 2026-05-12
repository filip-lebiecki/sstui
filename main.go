package main

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"sync"
	"time"

	"ss-stats-tui/model"
	"ss-stats-tui/parser"
	"ss-stats-tui/poller"
	"ss-stats-tui/ui"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// tickMsg is a custom tick message.
type tickMsg struct{}

// quitMsg signals the app to shut down the poller and exit.
type quitMsg struct{}

// tickCmd returns a command that sends a tickMsg after the given duration.
func tickCmd(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg {
		return tickMsg{}
	})
}

// ViewMode represents the active tab.
type ViewMode int

const (
	ViewLive ViewMode = iota
	ViewDetail
	ViewOverview
	ViewTop
	ViewFilter
	ViewHelp
)

// AppModel is the main bubbletea model.
type AppModel struct {
	width         int
	height        int
	buf           *poller.Buffer
	table         *ui.TableModel
	filter        *ui.Filter
	tab           ViewMode
	showHelp      bool
	lastError     error
	filterMode    bool
	filterBuf     string
	selectedKey   string
	done          chan struct{}
	doneOnce      sync.Once
	quitting      bool
}

func NewApp() *AppModel {
	buf := poller.NewBuffer()
	sharedFilter := &ui.Filter{}
	return &AppModel{
		buf:    buf,
		table:  ui.NewTableModel(sharedFilter, 20),
		filter: sharedFilter,
		tab:    ViewLive,
		done:   make(chan struct{}),
	}
}

func (m *AppModel) Init() tea.Cmd {
	return tea.Batch(
		tea.WindowSize(),
		tickCmd(time.Second),
	)
}

func (m *AppModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.table.SetSize(msg.Width, msg.Height-6)
		return m, nil

	case tea.KeyMsg:
		if m.filterMode {
			return m.handleFilterInput(msg)
		}

		switch msg.String() {
		case "q", "ctrl+c":
			return m, func() tea.Msg {
				m.doneOnce.Do(func() { close(m.done) })
				return quitMsg{}
			}
		case "?":
			m.showHelp = !m.showHelp
			return m, nil
		case "1":
			m.tab = ViewLive
		case "2":
			m.tab = ViewDetail
		case "3":
			m.tab = ViewOverview
		case "4":
			m.tab = ViewTop
		case "tab":
			m.tab = (m.tab + 1) % 4
		case "shift+tab":
			m.tab = (m.tab + 3) % 4
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
			if m.tab == ViewDetail {
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
		case "e":
			if m.filter.State == "ESTAB" {
				m.filter.State = ""
			} else {
				m.filter.State = "ESTAB"
			}
			m.table.InvalidateCache()
		}

	case quitMsg:
		m.quitting = true
		return m, tea.Quit

	case tickMsg:
		// Poll for new data
		conns, err := parser.RunSS()
		if err != nil {
			m.lastError = err
		} else {
			m.lastError = nil
			m.buf.AddSnapshot(conns)
			m.table.SetConnections(conns)
			m.table.SetSize(m.width, m.height-6)
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
		if len(m.filterBuf) > 0 {
			m.filterBuf = m.filterBuf[:len(m.filterBuf)-1]
		}
	case "ctrl+w":
		words := strings.Fields(m.filterBuf)
		if len(words) > 0 {
			m.filterBuf = strings.Join(words[:len(words)-1], " ")
		}
	default:
		if len(msg.String()) == 1 {
			m.filterBuf += msg.String()
		}
	}
	return m, nil
}

func (m *AppModel) applyFilter() {
	parts := strings.Fields(m.filterBuf)
	m.filter.Reset()

	for _, p := range parts {
		switch {
		case strings.HasPrefix(p, "src="):
			m.filter.SrcAddr = strings.TrimPrefix(p, "src=")
		case strings.HasPrefix(p, "dst="):
			m.filter.DstAddr = strings.TrimPrefix(p, "dst=")
		case strings.HasPrefix(p, "sport="):
			m.filter.SrcPort = strings.TrimPrefix(p, "sport=")
		case strings.HasPrefix(p, "dport="):
			m.filter.DstPort = strings.TrimPrefix(p, "dport=")
		case strings.HasPrefix(p, "state="):
			m.filter.State = strings.ToUpper(strings.TrimPrefix(p, "state="))
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
				m.filter.SrcAddr = p
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
	b.WriteString(ui.RenderHeader(m.buf, m.width, m.lastError != nil) + "\n")

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

	// Calculate available height for content
	headerLines := 4 // header + tabs + filter(maybe) + blank
	if m.filter.IsActive() {
		headerLines = 5
	}
	footerLines := 1 // main footer
	if m.tab == ViewLive {
		footerLines++ // table footer
	}
	if m.showHelp {
		footerLines += 15 // help panel
	}
	contentHeight := m.height - headerLines - footerLines
	if contentHeight < 1 {
		contentHeight = 1
	}

	// Content (clipped to available height)
	var content string
	var tableFooter string
	showTableFooter := false

	switch m.tab {
	case ViewLive:
		m.table.SetConnections(m.getLatestConns())
		m.table.SetSize(m.width, contentHeight)
		content = m.table.RenderBody()

		if sigs := m.table.GetSignalsForSelected(); len(sigs) > 0 {
			content += "\n" + ui.RenderSignals(sigs)
		}
		tableFooter = m.table.RenderFooter()
		showTableFooter = true

	case ViewDetail:
		conn := m.getConnectionByKey(m.selectedKey)
		content = ui.RenderDetail(conn, m.buf, m.width, contentHeight)

	case ViewOverview:
		content = ui.RenderOverview(m.buf, m.width, contentHeight)

	case ViewTop:
		content = ui.RenderTop(m.buf, m.width, contentHeight)

	case ViewFilter:
		content = "\n  Filter connections:\n\n"
		content += "  " + m.filterBuf + cursor() + "\n\n"
		content += lipgloss.NewStyle().Foreground(lipgloss.Color("#888")).Render(
			"  Syntax: src=<addr> dst=<addr> sport=<port> dport=<port> state=<state>\n" +
				"  Examples: state=ESTAB src=192.168 dport=443\n" +
				"  Enter to apply, Escape to cancel")
	}

	// Clip content to available height
	content = clipToHeight(content, contentHeight)
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
	for _, c := range m.getLatestConns() {
		if c.ConnKey() == key {
			return c
		}
	}
	return nil
}

func (m *AppModel) renderFilterText() string {
	var parts []string
	if m.filter.SrcAddr != "" {
		parts = append(parts, "src="+m.filter.SrcAddr)
	}
	if m.filter.DstAddr != "" {
		parts = append(parts, "dst="+m.filter.DstAddr)
	}
	if m.filter.SrcPort != "" {
		parts = append(parts, "sport="+m.filter.SrcPort)
	}
	if m.filter.DstPort != "" {
		parts = append(parts, "dport="+m.filter.DstPort)
	}
	if m.filter.State != "" {
		parts = append(parts, "state="+m.filter.State)
	}
	return strings.Join(parts, " ")
}

func (m *AppModel) renderFooter() string {
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
	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, syscall.SIGINT, syscall.SIGTERM)

	app := NewApp()
	p := tea.NewProgram(app, tea.WithAltScreen(), tea.WithoutCatchPanics())

	go func() {
		<-sigch
		app.doneOnce.Do(func() { close(app.done) })
		p.Quit()
	}()

	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
