package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"sstui/model"
	"sstui/parser"
	"sstui/poller"
	"sstui/ui"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// tickMsg fires the next poll.
type tickMsg struct{}

// pollResultMsg carries the result of an async ss invocation.
type pollResultMsg struct {
	conns []*model.Connection
	drops int             // record lines ss emitted that we couldn't parse
	sys   *poller.SysStat // host-wide /proc/net counters (nil if unreadable)
	err   error
}

func tickCmd(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg {
		return tickMsg{}
	})
}

func pollCmd() tea.Cmd {
	return func() tea.Msg {
		conns, drops, err := parser.RunSS()
		sys, _ := poller.ReadSysStat() // best-effort; nil on platforms without /proc/net
		return pollResultMsg{conns: conns, drops: drops, sys: sys, err: err}
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
	ViewSystem
	ViewFilter
)

// tabOrder is the cycle order for tab/shift-tab.
var tabOrder = []ViewMode{ViewLive, ViewDetail, ViewSocket, ViewOverview, ViewTop, ViewPerf, ViewEvents, ViewSystem}

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
	width         int
	height        int
	buf           *poller.Buffer
	table         *ui.TableModel
	filter        *ui.Filter
	tab           ViewMode
	showHelp      bool
	lastError     error
	lastDrops     int // unparsed ss records from the most recent poll
	filterMode    bool
	filterBuf     string
	filterCursor  int      // byte offset of the edit cursor within filterBuf
	filterPrevTab ViewMode // tab to restore when filter input is cancelled/applied
	selectedKey   string
	quitting      bool
	statusMsg     string
	statusExpiry  time.Time
	eventsScroll  int

	// Host-wide /proc/net counters: current read plus the previous one, so the
	// System tab can show per-poll deltas.
	sysCur  *poller.SysStat
	sysPrev *poller.SysStat

	// Pause / time-travel scrub. When paused, the Live table renders a frozen
	// snapshot `scrubOffset` polls back from newest instead of the live one.
	// Polling continues in the background; scrubOffset is bumped on each new
	// poll so the viewed moment stays pinned as history grows behind it.
	paused      bool
	scrubOffset int
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
		headerLines++
	}
	if m.paused {
		headerLines++ // scrub status bar
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
		case "8":
			m.tab = ViewSystem
		case "tab":
			m.tab = nextTab(m.tab, 1)
		case "shift+tab":
			m.tab = nextTab(m.tab, -1)
		case " ", "space":
			m.togglePause()
		case "[":
			m.scrub(1) // step back in time
		case "]":
			m.scrub(-1) // step forward in time
		case "{":
			m.scrub(10)
		case "}":
			m.scrub(-10)
		case "/":
			m.filterMode = true
			m.filterBuf = m.filter.Query()
			m.filterCursor = len(m.filterBuf)
			m.filterPrevTab = m.tab
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
			} else if m.filter.IsActive() {
				m.filter.Reset()
				m.table.InvalidateCache()
			} else {
				m.showHelp = false
			}
		case "j", "down":
			if m.tab == ViewEvents {
				m.eventsScroll++
				m.clampEventsScroll()
			} else {
				m.table.Next()
				m.syncSelectedKey()
			}
		case "k", "up":
			if m.tab == ViewEvents {
				m.eventsScroll--
				if m.eventsScroll < 0 {
					m.eventsScroll = 0
				}
			} else {
				m.table.Prev()
				m.syncSelectedKey()
			}
		case "pgdown":
			if m.tab == ViewEvents {
				m.eventsScroll += m.contentHeight() - 6
				m.clampEventsScroll()
			}
		case "pgup":
			if m.tab == ViewEvents {
				m.eventsScroll -= m.contentHeight() - 6
				if m.eventsScroll < 0 {
					m.eventsScroll = 0
				}
			}
		case "g":
			if m.tab == ViewEvents {
				m.eventsScroll = 0
			} else {
				m.table.First()
				m.syncSelectedKey()
			}
		case "G":
			if m.tab == ViewEvents {
				m.eventsScroll = ui.MaxEventsScroll(m.buf, m.contentHeight())
			} else {
				m.table.Last()
				m.syncSelectedKey()
			}
		case "h":
			m.table.CycleSort()
		case "L":
			m.filter.HideListen = !m.filter.HideListen
			m.table.InvalidateCache()
		case "r":
			on := ui.ToggleResolveDNS()
			if on {
				m.statusMsg = "reverse DNS: on"
			} else {
				m.statusMsg = "reverse DNS: off"
			}
			m.statusExpiry = time.Now().Add(3 * time.Second)
		case "e":
			if m.tab == ViewEvents {
				m.exportEvents("json")
			} else {
				m.export("json")
			}
		case "E":
			if m.tab == ViewEvents {
				m.exportEvents("csv")
			} else {
				m.export("csv")
			}
		}

	case tickMsg:
		return m, pollCmd()

	case pollResultMsg:
		m.lastError = msg.err
		m.lastDrops = msg.drops
		// Roll host counters forward only on a fresh read, so the System tab's
		// deltas always compare two real consecutive samples.
		if msg.sys != nil {
			m.sysPrev = m.sysCur
			m.sysCur = msg.sys
		}
		// Ingest on full success (even if zero sockets) or on a partial
		// failure that still returned data; skip only when both queries
		// failed (nil slice) so the last good snapshot is preserved.
		if msg.err == nil || len(msg.conns) > 0 {
			m.buf.AddSnapshot(msg.conns)
			if m.paused {
				// The new snapshot shifted "newest" by one; bump the offset so
				// the frozen view stays pinned to the same absolute moment as
				// history accumulates behind it.
				m.scrubOffset++
				m.clampScrub()
			}
			m.syncTable()
		}
		return m, tickCmd(poller.PollInterval)
	}

	return m, nil
}

func (m *AppModel) handleFilterInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.filterMode = false
		m.tab = m.restoreTab()
		return m, nil
	case "enter":
		m.applyFilter()
		m.table.InvalidateCache()
		m.filterMode = false
		m.tab = m.restoreTab()
		return m, nil
	case "left":
		if m.filterCursor > 0 {
			_, size := utf8.DecodeLastRuneInString(m.filterBuf[:m.filterCursor])
			m.filterCursor -= size
		}
	case "right":
		if m.filterCursor < len(m.filterBuf) {
			_, size := utf8.DecodeRuneInString(m.filterBuf[m.filterCursor:])
			m.filterCursor += size
		}
	case "home", "ctrl+a":
		m.filterCursor = 0
	case "end", "ctrl+e":
		m.filterCursor = len(m.filterBuf)
	case "backspace":
		if m.filterCursor > 0 {
			_, size := utf8.DecodeLastRuneInString(m.filterBuf[:m.filterCursor])
			m.filterBuf = m.filterBuf[:m.filterCursor-size] + m.filterBuf[m.filterCursor:]
			m.filterCursor -= size
		}
	case "delete":
		if m.filterCursor < len(m.filterBuf) {
			_, size := utf8.DecodeRuneInString(m.filterBuf[m.filterCursor:])
			m.filterBuf = m.filterBuf[:m.filterCursor] + m.filterBuf[m.filterCursor+size:]
		}
	case "ctrl+w":
		// Delete the word immediately before the cursor, leaving the rest intact.
		left := strings.TrimRight(m.filterBuf[:m.filterCursor], " ")
		if i := strings.LastIndex(left, " "); i >= 0 {
			left = left[:i+1]
		} else {
			left = ""
		}
		m.filterBuf = left + m.filterBuf[m.filterCursor:]
		m.filterCursor = len(left)
	default:
		s := msg.String()
		if utf8.RuneCountInString(s) == 1 {
			m.filterBuf = m.filterBuf[:m.filterCursor] + s + m.filterBuf[m.filterCursor:]
			m.filterCursor += len(s)
		}
	}
	return m, nil
}

func (m *AppModel) applyFilter() {
	m.filter.SetQuery(m.filterBuf)
}

// syncSelectedKey makes the Detail/Socket views follow table navigation: when
// either of those tabs is open, moving the table cursor (j/k/g/G) re-points the
// inspected connection at the new selection. On the Live tab it is a no-op —
// selectedKey is only consulted once the user presses Enter to drill in.
func (m *AppModel) syncSelectedKey() {
	if m.tab != ViewDetail && m.tab != ViewSocket {
		return
	}
	if conn := m.table.GetSelected(); conn != nil {
		m.selectedKey = conn.ConnKey()
	}
}

// restoreTab returns the tab to show after leaving filter input. It falls back
// to ViewLive if the stashed tab is unset or somehow still ViewFilter, so the
// user can never be stranded on the filter view with no input box.
func (m *AppModel) restoreTab() ViewMode {
	if m.filterPrevTab == ViewFilter {
		return ViewLive
	}
	return m.filterPrevTab
}

func (m *AppModel) View() string {
	if m.quitting {
		return "\n  Goodbye!\n"
	}

	var b strings.Builder

	// Header (fixed)
	b.WriteString(ui.RenderHeader(m.buf, m.filter, m.lastDrops, m.width) + "\n")

	// Tabs (fixed)
	b.WriteString(ui.RenderTabs(int(m.tab), m.width) + "\n")

	// Filter bar (fixed)
	if m.filter.IsActive() {
		filterText := fmt.Sprintf("  Filter: %s  [Esc clear]", m.renderFilterText())
		b.WriteString(lipgloss.NewStyle().
			Foreground(lipgloss.Color("#ffd43b")).
			Render(filterText) + "\n")
	}

	// Scrub status bar (fixed) — only while paused.
	if m.paused {
		b.WriteString(m.renderScrubBar() + "\n")
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
		content = ui.RenderEvents(m.buf, m.width, ch, m.eventsScroll)

	case ViewSystem:
		content = ui.RenderSystem(m.sysCur, m.sysPrev, m.width, ch)

	case ViewFilter:
		content = "\n  Filter connections:\n\n"
		content += "  " + renderFilterInput(m.filterBuf, m.filterCursor) + "\n\n"
		content += lipgloss.NewStyle().Foreground(lipgloss.Color("#888")).Render(
			"  Syntax: local=<addr> peer=<addr> sport=<port> dport=<port>\n" +
				"          state=<state> proc=<name> pid=<pid> signal=<label>\n" +
				"  Operators: and  or  not  ( )   (space = and)\n" +
				"  Examples: state=ESTAB local=192.168 dport=443\n" +
				"            (peer=10.0.0.1 or peer=10.1.0.1) and sport=1234\n" +
				"            proc=nginx not signal=RETRANS\n" +
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

// clipToHeight clips a string to at most maxLines lines, replacing the last
// visible line with a dim "↓ N more lines" indicator when content overflows
// so users know the bottom is hidden rather than missing.
func clipToHeight(s string, maxLines int) string {
	lines := strings.Split(s, "\n")
	if len(lines) <= maxLines {
		return s
	}
	if maxLines < 1 {
		return ""
	}
	hidden := len(lines) - maxLines + 1
	indicator := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#666")).
		Italic(true).
		Render(fmt.Sprintf("  ↓ %d more line(s)", hidden))
	return strings.Join(lines[:maxLines-1], "\n") + "\n" + indicator
}

func (m *AppModel) getConnectionByKey(key string) *model.Connection {
	// While scrubbing, resolve the key against the frozen snapshot so Detail/
	// Socket stay consistent with the (historical) row the user drilled into.
	if m.paused {
		if snap := m.viewSnapshot(); snap != nil {
			if c := snap.Lookup(key); c != nil {
				return c
			}
		}
	}
	// Otherwise search newest-first across the whole buffer rather than only the
	// latest snapshot, so Detail/Socket keep rendering a connection that has just
	// closed instead of blanking out the moment it drops off the table.
	return m.buf.LookupRecent(key)
}

// viewSnapshot returns the snapshot the Live table should render: the frozen
// scrub position when paused, otherwise the latest poll.
func (m *AppModel) viewSnapshot() *poller.Snapshot {
	if m.paused {
		if s := m.buf.SnapshotFromEnd(m.scrubOffset); s != nil {
			return s
		}
	}
	return m.buf.GetLatest()
}

// syncTable points the table at the currently-viewed snapshot (live or frozen)
// and re-applies the layout size. Called whenever that snapshot changes.
func (m *AppModel) syncTable() {
	if snap := m.viewSnapshot(); snap != nil {
		m.table.SetConnections(snap.Conns)
	}
	m.table.SetSize(m.width, m.contentHeight())
}

// clampScrub keeps the scrub offset within the available history.
func (m *AppModel) clampScrub() {
	max := m.buf.Count() - 1
	if max < 0 {
		max = 0
	}
	if m.scrubOffset > max {
		m.scrubOffset = max
	}
	if m.scrubOffset < 0 {
		m.scrubOffset = 0
	}
}

// togglePause enters or leaves scrub mode, starting at the newest snapshot.
func (m *AppModel) togglePause() {
	m.paused = !m.paused
	m.scrubOffset = 0
	m.syncTable()
}

// scrub moves the frozen view by delta polls (positive = further back in time)
// and refreshes the table. Auto-enters pause if the user starts scrubbing live.
func (m *AppModel) scrub(delta int) {
	if !m.paused {
		m.paused = true
		m.scrubOffset = 0
	}
	m.scrubOffset += delta
	m.clampScrub()
	m.syncTable()
}

func (m *AppModel) renderFilterText() string {
	return m.filter.Query()
}

// renderScrubBar renders the paused/time-travel status line: the frozen
// snapshot's wall-clock time, how far back it is, its position in the buffer,
// and the scrub keys.
func (m *AppModel) renderScrubBar() string {
	count := m.buf.Count()
	ts := "—"
	if snap := m.viewSnapshot(); snap != nil {
		ts = snap.Timestamp.Format("15:04:05")
	}
	ago := (time.Duration(m.scrubOffset) * poller.PollInterval).Truncate(time.Second)
	pos := count - m.scrubOffset // 1 = oldest, count = newest
	live := ""
	if m.scrubOffset == 0 {
		live = "  (newest)"
	}
	text := fmt.Sprintf("  ⏸ PAUSED  %s  -%s%s  ·  snapshot %d/%d  ·  [ ] step   { } ×10   space resume",
		ts, ago, live, pos, count)
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color("#000")).
		Background(lipgloss.Color("#ffd43b")).
		Bold(true).
		Render(text)
}

func (m *AppModel) clampEventsScroll() {
	max := ui.MaxEventsScroll(m.buf, m.contentHeight())
	if m.eventsScroll > max {
		m.eventsScroll = max
	}
	if m.eventsScroll < 0 {
		m.eventsScroll = 0
	}
}

func (m *AppModel) exportEvents(kind string) {
	events := ui.CollectEvents(m.buf)
	if len(events) == 0 {
		m.statusMsg = "no events to export"
		m.statusExpiry = time.Now().Add(5 * time.Second)
		return
	}

	ts := time.Now().Format("20060102-150405")
	name := fmt.Sprintf("ss-events-%s.%s", ts, kind)
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}
	path := filepath.Join(cwd, name)

	var n int
	switch kind {
	case "json":
		n, err = ui.ExportEventsJSON(events, path)
	case "csv":
		n, err = ui.ExportEventsCSV(events, path)
	default:
		m.statusMsg = "unknown export kind: " + kind
		m.statusExpiry = time.Now().Add(5 * time.Second)
		return
	}
	if err != nil {
		m.statusMsg = "events export failed: " + err.Error()
	} else {
		m.statusMsg = fmt.Sprintf("Exported %d events → %s", n, path)
	}
	m.statusExpiry = time.Now().Add(5 * time.Second)
}

func (m *AppModel) export(kind string) {
	ts := time.Now().Format("20060102-150405")
	name := fmt.Sprintf("ss-stats-%s.%s", ts, kind)
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}
	path := filepath.Join(cwd, name)

	var (
		n    int
		unit string
	)
	switch kind {
	case "json":
		n, err = m.buf.ExportJSON(path)
		unit = "snapshots"
	case "csv":
		n, err = m.buf.ExportCSV(path)
		unit = "rows"
	default:
		m.statusMsg = "unknown export kind: " + kind
		m.statusExpiry = time.Now().Add(5 * time.Second)
		return
	}
	if err != nil {
		m.statusMsg = "export failed: " + err.Error()
	} else {
		m.statusMsg = fmt.Sprintf("Exported %d %s → %s", n, unit, path)
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
	if m.lastError != nil {
		return lipgloss.NewStyle().
			Foreground(lipgloss.Color("#000")).
			Background(lipgloss.Color("#ff6b6b")).
			Bold(true).
			Padding(0, 1).
			Render("ss error: " + m.lastError.Error() + "  (data may be stale)")
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

// renderFilterInput renders the filter buffer with a block cursor at byte
// offset pos, highlighting the character under the cursor (or a trailing space
// when the cursor sits at the end of the text).
func renderFilterInput(buf string, pos int) string {
	style := lipgloss.NewStyle().Background(lipgloss.Color("#5a56e7"))
	if pos < 0 {
		pos = 0
	}
	if pos >= len(buf) {
		return buf + style.Render(" ")
	}
	_, size := utf8.DecodeRuneInString(buf[pos:])
	return buf[:pos] + style.Render(buf[pos:pos+size]) + buf[pos+size:]
}

// version is overridable at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	var (
		interval   = flag.Duration("interval", poller.PollInterval, "poll cadence (e.g. 1s, 500ms); minimum 100ms")
		filterExpr = flag.String("filter", "", "initial filter expression (same syntax as the `/` prompt)")
		showListen = flag.Bool("show-listen", false, "show LISTEN sockets at startup (hidden by default)")
		resolve    = flag.Bool("resolve", false, "resolve peer addresses to hostnames (reverse DNS) at startup")
		showVer    = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("sstui %s\n", version)
		return
	}

	if *interval < 100*time.Millisecond {
		fmt.Fprintf(os.Stderr, "interval too small (%s); minimum is 100ms\n", *interval)
		os.Exit(2)
	}
	poller.SetInterval(*interval)

	app := NewApp()
	if *showListen {
		app.filter.HideListen = false
	}
	if *resolve {
		ui.SetResolveDNS(true)
	}
	if *filterExpr != "" {
		app.filter.SetQuery(*filterExpr)
		app.table.InvalidateCache()
	}

	p := tea.NewProgram(app, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
