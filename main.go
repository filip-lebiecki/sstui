package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"sstui/findings"
	"sstui/model"
	"sstui/parser"
	"sstui/poller"
	"sstui/session"
	"sstui/ui"

	"github.com/aymanbagabas/go-osc52/v2"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// tickMsg fires the next poll.
type tickMsg struct{}

// pollResultMsg carries the result of an async ss invocation. recErr is
// set when recording the poll (--record) failed.
type pollResultMsg struct {
	poll   *session.Poll
	recErr error
}

func tickCmd(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg {
		return tickMsg{}
	})
}

// pollCmd polls in the background and, with rec set, records the poll
// there too, so encoding and compressing a large poll never stalls the UI.
// It records before the UI ingests the poll, which annotates the sockets.
func pollCmd(f parser.SSFilter, rec *session.Recorder) tea.Cmd {
	return func() tea.Msg {
		msg := pollResultMsg{poll: session.PollLive(f)}
		if rec != nil {
			msg.recErr = rec.Write(msg.poll)
		}
		return msg
	}
}

// ViewMode represents the active tab.
type ViewMode int

// The order matches the tab bar (ui.RenderTabs) and the 1–9 keys.
const (
	ViewFindings ViewMode = iota
	ViewLive
	ViewDetail
	ViewSocket
	ViewOverview
	ViewTop
	ViewPerf
	ViewEvents
	ViewSystem
	ViewFilter
)

// tabs lists the tab bar in order (also the 1–9 keys and tab/shift-tab
// cycle). It is the single source for both the views and their labels.
var tabs = []struct {
	mode ViewMode
	name string
}{
	{ViewFindings, "Findings"}, {ViewLive, "Live"}, {ViewDetail, "Detail"},
	{ViewSocket, "Socket"}, {ViewOverview, "Overview"}, {ViewTop, "Top"},
	{ViewPerf, "Perf"}, {ViewEvents, "Events"}, {ViewSystem, "System"},
}

var tabOrder, tabNames = func() ([]ViewMode, []string) {
	var modes []ViewMode
	var names []string
	for _, t := range tabs {
		modes = append(modes, t.mode)
		names = append(names, t.name)
	}
	return modes, names
}()

// tabIndex returns the tab-bar position of a view, or -1 (filter prompt).
func tabIndex(v ViewMode) int {
	for i, m := range tabOrder {
		if m == v {
			return i
		}
	}
	return -1
}

// helpBlockedKeys are ignored while the help panel covers the tab content.
var helpBlockedKeys = map[string]bool{
	"j": true, "k": true, "down": true, "up": true, "g": true, "G": true,
	"pgup": true, "pgdown": true, "enter": true, "h": true, "c": true,
	" ": true, "[": true, "]": true, "{": true, "}": true,
}

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
	filterMode    bool
	filterBuf     string
	filterCursor  int      // byte offset of the edit cursor within filterBuf
	filterPrevTab ViewMode // tab to restore when filter input is cancelled/applied
	selectedKey   string
	quitting      bool
	statusMsg     string
	statusExpiry  time.Time
	eventsScroll  int

	// sess owns the history buffer, host counters and findings analysis
	// (shared with the headless commands); buf is sess.Buf.
	sess *session.Session

	// rec, when set, records every poll to a file (--record).
	rec *session.Recorder
	// replay names the recording being replayed; "" when live. A replay
	// never polls: the whole recording is loaded up front.
	replay string

	// Pause / time-travel scrub. When paused, the Live table renders a frozen
	// snapshot `scrubOffset` polls back from newest instead of the live one.
	// Polling continues in the background; scrubOffset is bumped on each new
	// poll so the viewed moment stays pinned as history grows behind it.
	paused      bool
	scrubOffset int

	exporting bool // a background export is running

	// Findings selection, kept on the same finding across refreshes by ID.
	findingSel   int
	findingSelID string

	// ssFilter is passed to ss itself (--ss-filter): non-matching sockets
	// are never collected. Fixed for the session.
	ssFilter parser.SSFilter

	// tableSnap is the snapshot whose connections the table currently holds,
	// so syncTable can skip redundant reloads.
	tableSnap *poller.Snapshot
}

// NewApp returns the TUI over sess (nil for a fresh live session).
func NewApp(sess *session.Session) *AppModel {
	if sess == nil {
		sess = session.New("", false)
	}
	sharedFilter := &ui.Filter{HideListen: true}
	return &AppModel{
		sess:   sess,
		buf:    sess.Buf,
		table:  ui.NewTableModel(sharedFilter, 20),
		filter: sharedFilter,
		tab:    ViewFindings, // the triage home screen
	}
}

func (m *AppModel) Init() tea.Cmd {
	if m.replay != "" {
		return tea.WindowSize()
	}
	return tea.Batch(
		tea.WindowSize(),
		pollCmd(m.ssFilter, m.rec),
	)
}

// contentHeight returns the height available for the active tab's content.
func (m *AppModel) contentHeight() int {
	return m.contentHeightFor(m.tab)
}

// contentHeightFor returns the content height a given tab would get with the
// current header/footer chrome (filter bar, scrub bar, help overlay).
func (m *AppModel) contentHeightFor(tab ViewMode) int {
	headerLines := 4
	if m.filter.IsActive() {
		headerLines++
	}
	if m.paused {
		headerLines++ // scrub status bar
	}
	footerLines := 1
	if tab == ViewLive {
		footerLines++
	}
	h := m.height - headerLines - footerLines
	if h < 1 {
		h = 1
	}
	return h
}

func (m *AppModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	next, cmd := m.update(msg)
	// Layout chrome (help overlay, filter bar, scrub bar) can change on almost
	// any message, so re-fit the table after every update. It's sized for the
	// Live tab even when another tab is showing, because j/k on Detail/Socket
	// still navigate it and its page geometry must match what Live will draw.
	m.resizeTable()
	return next, cmd
}

// resizeTable fits the table's page size to the Live tab's content area.
func (m *AppModel) resizeTable() {
	m.table.SetSize(m.width, m.contentHeightFor(ViewLive))
}

func (m *AppModel) update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		if m.filterMode {
			return m.handleFilterInput(msg)
		}
		// The help panel hides the tab content, so keys that move or act on
		// what's underneath would change state the user can't see.
		if m.showHelp && helpBlockedKeys[msg.String()] {
			return m, nil
		}

		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "?":
			m.showHelp = !m.showHelp
			return m, nil
		case "1", "2", "3", "4", "5", "6", "7", "8", "9":
			m.tab = tabOrder[msg.String()[0]-'1']
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
			if m.tab == ViewFindings {
				m.openFinding()
			} else if m.tab == ViewLive {
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
			if m.tab == ViewFindings {
				m.selectFinding(m.findingSel + 1)
			} else if m.tab == ViewEvents {
				m.eventsScroll++
				m.clampEventsScroll()
			} else {
				m.table.Next()
				m.syncSelectedKey()
			}
		case "k", "up":
			if m.tab == ViewFindings {
				m.selectFinding(m.findingSel - 1)
			} else if m.tab == ViewEvents {
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
			if m.tab == ViewFindings {
				m.selectFinding(0)
			} else if m.tab == ViewEvents {
				m.eventsScroll = 0
			} else {
				m.table.First()
				m.syncSelectedKey()
			}
		case "G":
			if m.tab == ViewFindings {
				rep, _ := m.shownReport()
				m.selectFinding(len(rep.Findings) - 1)
			} else if m.tab == ViewEvents {
				m.eventsScroll = ui.MaxEventsScroll(m.buf, m.contentHeight())
			} else {
				m.table.Last()
				m.syncSelectedKey()
			}
		case "c":
			if m.tab == ViewFindings {
				m.copyFindingCommand()
			}
		case "h":
			m.table.CycleSort()
		case "L":
			m.filter.HideListen = !m.filter.HideListen
			m.table.InvalidateCache()
		case "r":
			on := ui.ToggleResolveDNS()
			if on {
				m.setStatus("reverse DNS: on", 3*time.Second)
			} else {
				m.setStatus("reverse DNS: off", 3*time.Second)
			}
		case "e":
			return m, m.startExport("json", m.tab == ViewEvents)
		case "E":
			return m, m.startExport("csv", m.tab == ViewEvents)
		}

	case tickMsg:
		return m, pollCmd(m.ssFilter, m.rec)

	case exportDoneMsg:
		m.exporting = false
		m.setStatus(msg.status, 5*time.Second)
		return m, nil

	case pollResultMsg:
		if msg.recErr != nil && m.rec != nil {
			m.rec.Close()
			m.rec = nil
			m.setStatus("recording stopped: "+msg.recErr.Error(), 10*time.Second)
		}
		if m.sess.Ingest(msg.poll) {
			if m.paused {
				// The new snapshot shifted "newest" by one; bump the offset so
				// the frozen view stays pinned to the same absolute moment as
				// history accumulates behind it.
				m.scrubOffset++
				m.clampScrub()
			}
			m.syncTable()
			m.reselectFinding()
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
		// KeyRunes covers both typed characters and bracketed paste (where
		// msg.String() is "[pasted text]", so it can't be used directly).
		var s string
		switch msg.Type {
		case tea.KeyRunes:
			s = sanitizeFilterInput(string(msg.Runes))
		case tea.KeySpace:
			s = " "
		}
		if s != "" {
			m.filterBuf = m.filterBuf[:m.filterCursor] + s + m.filterBuf[m.filterCursor:]
			m.filterCursor += len(s)
		}
	}
	return m, nil
}

// sanitizeFilterInput makes pasted text safe for the one-line filter: line
// breaks and tabs become spaces, other control characters are dropped.
func sanitizeFilterInput(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			return ' '
		case r < 0x20 || r == 0x7f:
			return -1
		}
		return r
	}, s)
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
	rep, repAt := m.shownReport()
	b.WriteString(ui.RenderHeader(m.buf, m.filter, m.sess.LastDrops, ui.FindingsPill(rep.Crit(), rep.Warn()), m.width) + "\n")

	// Tabs (fixed)
	b.WriteString(ui.RenderTabs(tabNames, tabIndex(m.tab), m.width) + "\n")

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
	case ViewFindings:
		content = ui.RenderFindings(rep, m.findingSel, m.width, ch, repAt, m.findingsStaleNote(), m.findingsAsOf())

	case ViewLive:
		content = m.table.RenderBody()

		if sigs := m.table.GetSignalsForSelected(); len(sigs) > 0 {
			content += "\n" + ui.RenderSignals(sigs)
		}
		tableFooter = m.table.RenderFooter()
		showTableFooter = true

	case ViewDetail:
		conn, hist := m.getConnectionByKey(m.selectedKey)
		content = ui.RenderDetail(conn, hist, m.buf, m.width, ch)

	case ViewSocket:
		conn, hist := m.getConnectionByKey(m.selectedKey)
		content = ui.RenderSocket(conn, hist, m.buf, m.width, ch)

	case ViewOverview:
		content = ui.RenderOverview(m.buf, m.width, ch)

	case ViewTop:
		content = ui.RenderTop(m.buf, m.width, ch)

	case ViewPerf:
		content = ui.RenderPerf(m.buf, m.width, ch)

	case ViewEvents:
		content = ui.RenderEvents(m.buf, m.width, ch, m.eventsScroll)

	case ViewSystem:
		content = ui.RenderSystem(m.sess.SysCur, m.sess.SysPrev, m.width, ch)

	case ViewFilter:
		content = "\n  Filter connections:\n\n"
		content += "  " + renderFilterInput(m.filterBuf, m.filterCursor) + "\n\n"
		content += lipgloss.NewStyle().Foreground(lipgloss.Color("#888")).Render(
			"  Syntax: local=<addr> peer=<addr> (peer==<addr> exact) sport=<port> dport=<port>\n" +
				"          state=<state> proc=<name> pid=<pid> signal=<label> proto=tcp|udp\n" +
				"  Operators: and  or  not  ( )   (space = and)\n" +
				"  Examples: state=ESTAB local=192.168 dport=443\n" +
				"            (peer=10.0.0.1 or peer=10.1.0.1) and sport=1234\n" +
				"            proc=nginx not signal=RETRANS\n" +
				"  Enter to apply, Escape to cancel")
	}

	// The help panel replaces the tab content (rather than being appended
	// below it) so it can never push the header off-screen on a short
	// terminal; it's clipped like any other tab.
	if m.showHelp && m.tab != ViewFilter {
		content = ui.RenderHelp()
		showTableFooter = false
	}

	// Clip content to available height
	content = clipToHeight(content, ch)
	b.WriteString(content)

	// Table footer (fixed, outside clipped area)
	if showTableFooter {
		b.WriteString("\n" + tableFooter)
	}

	// Footer (fixed)
	if m.tab != ViewFilter {
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

// getConnectionByKey resolves the inspected connection. historical is true
// when it comes from an older snapshot, which records only summary fields.
func (m *AppModel) getConnectionByKey(key string) (conn *model.Connection, historical bool) {
	// While scrubbing, resolve the key against the frozen snapshot so Detail/
	// Socket stay consistent with the (historical) row the user drilled into.
	if m.paused {
		if snap := m.viewSnapshot(); snap != nil {
			if c := snap.Lookup(key); c != nil {
				return c, !snap.Full()
			}
		}
	}
	// Otherwise search newest-first across the whole buffer rather than only the
	// latest snapshot, so Detail/Socket keep rendering a connection that has just
	// closed instead of blanking out the moment it drops off the table.
	c := m.buf.LookupRecent(key)
	return c, c != nil && m.buf.GetLatest().Lookup(key) != c
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
	m.resizeTable()
	snap := m.viewSnapshot()
	// While paused, polls keep arriving but usually leave the viewed snapshot
	// untouched; re-materializing a historical snapshot's connections each
	// time would allocate the whole table again for an identical view.
	if snap == nil || snap == m.tableSnap {
		return
	}
	m.tableSnap = snap
	m.table.SetConnections(snap.Connections())
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
	m.reselectFinding()
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
	m.reselectFinding()
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

// shownReport returns the findings for the moment on screen: the scrubbed
// snapshot's while paused, otherwise the newest poll's. at is the time to
// measure how long each finding has been active against.
func (m *AppModel) shownReport() (rep findings.Report, at time.Time) {
	if m.paused {
		if snap := m.viewSnapshot(); snap != nil {
			if rep, ok := m.sess.ReportFor(snap.Timestamp); ok {
				return rep, snap.Timestamp
			}
		}
	}
	if m.replay != "" {
		return m.sess.Report, m.sess.ReportAt
	}
	return m.sess.Report, time.Now()
}

// reselectFinding keeps the Findings selection on the same finding after
// the shown report changes (a new poll, or scrubbing), even if the ranking
// shifted.
func (m *AppModel) reselectFinding() {
	rep, _ := m.shownReport()
	sel := m.findingSel
	for i, f := range rep.Findings {
		if f.ID == m.findingSelID {
			sel = i
			break
		}
	}
	m.selectFinding(sel)
}

// findingsAsOf says which moment the Findings tab shows when it isn't the
// live present: a scrubbed snapshot, or the end of a replayed recording.
func (m *AppModel) findingsAsOf() string {
	switch {
	case m.paused:
		if snap := m.viewSnapshot(); snap != nil {
			return "as of " + snap.Timestamp.Format("15:04:05") + " (paused · [ ] step through time · space resumes)"
		}
	case m.replay != "" && !m.sess.ReportAt.IsZero():
		return "as of " + m.sess.ReportAt.Format("15:04:05") + ", the end of the recording · [ ] step back through it"
	}
	return ""
}

// findingsStaleNote explains when the Findings report is out of date because
// polling is failing (the report is only refreshed on a successful poll).
func (m *AppModel) findingsStaleNote() string {
	at := m.sess.ReportAt
	if m.replay != "" || m.sess.LastErr == nil || at.IsZero() || time.Since(at) < 2*poller.PollInterval {
		return ""
	}
	return fmt.Sprintf("analysis is from %s — polling is failing: %v", at.Format("15:04:05"), m.sess.LastErr)
}

// selectFinding moves the Findings selection, clamped to the list.
func (m *AppModel) selectFinding(i int) {
	rep, _ := m.shownReport()
	n := len(rep.Findings)
	m.findingSel = max(0, min(i, n-1))
	m.findingSelID = ""
	if n > 0 {
		m.findingSelID = rep.Findings[m.findingSel].ID
	}
}

func (m *AppModel) selectedFinding() *findings.Finding {
	rep, _ := m.shownReport()
	if m.findingSel < len(rep.Findings) {
		return &rep.Findings[m.findingSel]
	}
	return nil
}

// openFinding jumps from a finding to the Live tab filtered to exactly the
// sockets it's about.
func (m *AppModel) openFinding() {
	f := m.selectedFinding()
	if f == nil {
		return
	}
	if f.Filter == "" {
		m.setStatus("this finding is host-wide — it isn't tied to specific sockets", 4*time.Second)
		return
	}
	m.filter.SetQuery(f.Filter)
	if f.ShowListen {
		m.filter.HideListen = false
	}
	m.table.InvalidateCache()
	m.tab = ViewLive
	m.setStatus("showing sockets for: "+f.Title+"  (Esc clears the filter)", 5*time.Second)
}

// copyFindingCommand copies the selected finding's suggested command to the
// clipboard via OSC 52, which works over SSH and (with passthrough) in tmux.
func (m *AppModel) copyFindingCommand() {
	f := m.selectedFinding()
	if f == nil {
		return
	}
	cmd := f.Command()
	if cmd == "" {
		m.setStatus("no command to copy for this finding", 3*time.Second)
		return
	}
	seq := osc52.New(cmd)
	switch {
	case os.Getenv("TMUX") != "":
		seq = seq.Tmux()
	case strings.HasPrefix(os.Getenv("TERM"), "screen"):
		seq = seq.Screen()
	}
	// Write to the controlling terminal directly: bubbletea owns stdout for
	// frames, and stderr may be redirected to a file (which would just
	// collect an escape sequence while we claimed success). OSC 52 is
	// invisible, so it doesn't disturb the screen.
	tty, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0)
	if err != nil {
		m.setStatus("copy failed: no terminal to send the clipboard sequence to", 4*time.Second)
		return
	}
	defer tty.Close()
	if _, err := seq.WriteTo(tty); err != nil {
		m.setStatus("copy failed: "+err.Error(), 4*time.Second)
		return
	}
	m.setStatus("copied: "+cmd, 4*time.Second)
}

// exportDoneMsg reports the outcome of a background export.
type exportDoneMsg struct{ status string }

// startExport kicks off an export in the background and returns the command
// that runs it. Exporting the whole ring buffer can take seconds on a busy
// host, so it must not run on the Update goroutine (that froze the UI). The
// buffer's snapshots are immutable once published, so reading them from
// another goroutine is safe.
func (m *AppModel) startExport(kind string, events bool) tea.Cmd {
	if m.exporting {
		m.setStatus("export already in progress", 3*time.Second)
		return nil
	}
	m.exporting = true
	m.setStatus("exporting…", time.Hour) // replaced by exportDoneMsg
	buf := m.buf
	return func() tea.Msg {
		return exportDoneMsg{status: runExport(buf, kind, events)}
	}
}

// runExport writes the export file and returns the status line to show.
func runExport(buf *poller.Buffer, kind string, events bool) string {
	prefix, what := "ss-stats", ""
	if events {
		prefix = "ss-events"
	}
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}
	path := filepath.Join(cwd, fmt.Sprintf("%s-%s.%s", prefix, time.Now().Format("20060102-150405"), kind))

	var n int
	switch {
	case events:
		evs := ui.CollectEvents(buf)
		if len(evs) == 0 {
			return "no events to export"
		}
		what = "events"
		if kind == "json" {
			n, err = ui.ExportEventsJSON(evs, path)
		} else {
			n, err = ui.ExportEventsCSV(evs, path)
		}
	case kind == "json":
		n, err = buf.ExportJSON(path)
		what = "snapshots"
	default:
		n, err = buf.ExportCSV(path)
		what = "rows"
	}
	if err != nil {
		return "export failed: " + err.Error()
	}
	return fmt.Sprintf("Exported %d %s → %s", n, what, path)
}

func (m *AppModel) setStatus(msg string, d time.Duration) {
	m.statusMsg = msg
	m.statusExpiry = time.Now().Add(d)
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
	if m.sess.LastErr != nil && m.replay == "" {
		return lipgloss.NewStyle().
			Foreground(lipgloss.Color("#000")).
			Background(lipgloss.Color("#ff6b6b")).
			Bold(true).
			Padding(0, 1).
			Render("ss error: " + m.sess.LastErr.Error() + "  (data may be stale)")
	}
	snap := m.buf.GetLatest()
	total := 0
	if snap != nil {
		total = snap.Len()
	}
	filtered := m.table.GetFilteredCount()

	var parts []string
	parts = append(parts, fmt.Sprintf("%d conns", total))
	if m.filter.IsActive() {
		parts = append(parts, fmt.Sprintf("%d matched", filtered))
	}
	parts = append(parts, fmt.Sprintf("snapshots: %d", m.buf.Count()))
	if m.replay != "" {
		parts = append(parts, "replay: "+m.replay)
		if first := m.buf.SnapshotFromEnd(m.buf.Count() - 1); first != nil {
			parts = append(parts, first.Timestamp.Format("2006-01-02 15:04:05")+" – "+snap.Timestamp.Format("15:04:05"))
		}
	} else {
		parts = append(parts, "updated: "+ui.RenderTimeAgo(m.buf.LastUpdate()))
	}
	if m.rec != nil {
		parts = append(parts, "● recording")
	}
	if m.sess.SSFilter != "" {
		parts = append(parts, "ss filter: "+m.sess.SSFilter)
	}

	// Truncate with an ellipsis so a long --ss-filter visibly continues
	// (the renderer would otherwise clip it silently at the edge).
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color("#666")).
		Render(ansi.Truncate("  "+strings.Join(parts, "  |  "), max(m.width, 1), "…"))
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
	if len(os.Args) > 1 {
		if cmd, ok := subcommands[os.Args[1]]; ok {
			os.Exit(cmd(os.Args[2:]))
		}
	}
	os.Exit(runTUI(os.Args[1:]))
}

// tuiFlags are the display options shared by the live TUI and replay.
type tuiFlags struct {
	filterExpr *string
	showListen *bool
	resolve    *bool
}

func addTUIFlags(fs *flag.FlagSet) tuiFlags {
	return tuiFlags{
		filterExpr: fs.String("filter", "", "initial filter expression (same syntax as the `/` prompt)"),
		showListen: fs.Bool("show-listen", false, "show LISTEN sockets at startup (hidden by default)"),
		resolve:    fs.Bool("resolve", false, "resolve peer addresses to hostnames (reverse DNS) at startup"),
	}
}

// apply sets the display options on the app.
func (t tuiFlags) apply(app *AppModel) {
	if *t.showListen {
		app.filter.HideListen = false
	}
	if *t.resolve {
		ui.SetResolveDNS(true)
	}
	if *t.filterExpr != "" {
		app.filter.SetQuery(*t.filterExpr)
		app.table.InvalidateCache()
	}
}

// runTUI runs the interactive TUI on the live host.
func runTUI(args []string) int {
	fs := flag.NewFlagSet("sstui", flag.ContinueOnError)
	fs.Usage = func() { usage(fs) }
	live := addLiveFlags(fs)
	disp := addTUIFlags(fs)
	record := fs.String("record", "", "also record every poll to `FILE` (gzip if it ends in .gz) for replay or report later")
	showVer := fs.Bool("version", false, "print version and exit")
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseExit(err, 2)
	}
	if *showVer {
		fmt.Printf("sstui %s\n", version)
		return 0
	}
	if len(rest) > 0 {
		fmt.Fprintf(os.Stderr, "sstui: unexpected argument %q (commands: check, record, replay, report)\n", rest[0])
		return 2
	}
	ssf, err := live.setup()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	app := NewApp(session.New(ssf.String(), os.Geteuid() != 0))
	app.ssFilter = ssf
	disp.apply(app)
	if *record != "" {
		rec, err := session.Create(*record, session.NewHeader(version, ssf.String(), app.sess.Unprivileged))
		if err != nil {
			fmt.Fprintln(os.Stderr, "sstui:", err)
			return 1
		}
		app.rec = rec
		defer func() {
			if app.rec != nil {
				app.rec.Close()
				fmt.Fprintf(os.Stderr, "recorded to %s (replay with: sstui replay %s)\n", *record, *record)
			}
		}()
	}

	p := tea.NewProgram(app, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	return 0
}
