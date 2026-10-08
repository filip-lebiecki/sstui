package main

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"sstui/model"
	"sstui/poller"
	"sstui/session"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

// feed sends a message through Update and returns the model as *AppModel.
// newLiveApp returns an app showing the Live tab (the app itself starts on
// Findings).
func newLiveApp() *AppModel {
	m := NewApp(nil)
	m.tab = ViewLive
	return m
}

func feed(m *AppModel, msg tea.Msg) *AppModel {
	next, _ := m.Update(msg)
	return next.(*AppModel)
}

// polled wraps conns as a poll result taken now.
func polled(conns []*model.Connection) pollResultMsg {
	return pollResultMsg{poll: &session.Poll{Time: time.Now(), Conns: conns}}
}

func key(s string) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func snapWithAddr(addr string) []*model.Connection {
	return []*model.Connection{{
		Protocol: "tcp", State: "ESTAB",
		LocalAddr: addr, LocalPort: "1", PeerAddr: "9.9.9.9", PeerPort: "443",
	}}
}

// TestPauseScrub exercises the pause/time-travel flow end to end through the
// real Update/View, without a terminal: pause freezes the table, a new poll
// keeps the frozen moment pinned, scrubbing renders older history, and resume
// returns to live.
func TestPauseScrub(t *testing.T) {
	m := newLiveApp()
	m = feed(m, tea.WindowSizeMsg{Width: 140, Height: 40})

	// Three polls of history, each with a distinguishable local address.
	m = feed(m, polled(snapWithAddr("10.0.0.1")))
	m = feed(m, polled(snapWithAddr("10.0.0.2")))
	m = feed(m, polled(snapWithAddr("10.0.0.3"))) // newest

	// Live view shows the newest snapshot.
	if !strings.Contains(m.View(), "10.0.0.3") {
		t.Fatalf("live view should show newest snapshot 10.0.0.3")
	}

	// Pause: scrub bar appears, still at newest.
	m = feed(m, tea.KeyMsg{Type: tea.KeySpace})
	if !m.paused {
		t.Fatalf("space should pause")
	}
	if v := m.View(); !strings.Contains(v, "PAUSED") || !strings.Contains(v, "snapshot 3/3") {
		t.Fatalf("scrub bar missing or wrong position:\n%s", v)
	}

	// A new poll arrives while paused: the frozen moment stays pinned (we were
	// viewing the then-newest 10.0.0.3, which is now one back).
	m = feed(m, polled(snapWithAddr("10.0.0.4")))
	if m.scrubOffset != 1 {
		t.Fatalf("scrubOffset should pin to 1 after a poll while paused, got %d", m.scrubOffset)
	}
	if v := m.View(); !strings.Contains(v, "10.0.0.3") || strings.Contains(v, "10.0.0.4") {
		t.Fatalf("paused view should still show pinned 10.0.0.3, not the new 10.0.0.4:\n%s", v)
	}

	// Scrub back one: should reveal the older 10.0.0.2.
	m = feed(m, key("["))
	if v := m.View(); !strings.Contains(v, "10.0.0.2") {
		t.Fatalf("scrubbing back should show 10.0.0.2:\n%s", v)
	}

	// Scrub forward one: back to 10.0.0.3.
	m = feed(m, key("]"))
	if v := m.View(); !strings.Contains(v, "10.0.0.3") {
		t.Fatalf("scrubbing forward should show 10.0.0.3:\n%s", v)
	}

	// Resume: no scrub bar, live snapshot shown.
	m = feed(m, tea.KeyMsg{Type: tea.KeySpace})
	if m.paused {
		t.Fatalf("space should resume")
	}
	if v := m.View(); strings.Contains(v, "PAUSED") || !strings.Contains(v, "10.0.0.4") {
		t.Fatalf("resumed view should be live (10.0.0.4) with no scrub bar:\n%s", v)
	}
}

// TestHeaderFollowsPausedMoment: paused on an older snapshot, the header's
// counts and clock and the status bar's count are that moment's, as the
// tabs are, not the latest poll's.
func TestHeaderFollowsPausedMoment(t *testing.T) {
	m := newLiveApp()
	m = feed(m, tea.WindowSizeMsg{Width: 140, Height: 40})
	t0 := time.Date(2026, 10, 8, 14, 0, 0, 0, time.Local)
	for n := 1; n <= 3; n++ {
		var conns []*model.Connection
		for i := range n {
			conns = append(conns, snapWithAddr("10.0.0."+strconv.Itoa(i+1))...)
		}
		m = feed(m, pollResultMsg{poll: &session.Poll{Time: t0.Add(time.Duration(n) * 2 * time.Second), Conns: conns}})
	}
	header := func() string { return strings.SplitN(ansi.Strip(m.View()), "\n", 2)[0] }
	if h := header(); !strings.Contains(h, "TOTAL 3") || !strings.Contains(h, "14:00:06") {
		t.Fatalf("live header should show the latest poll: %q", h)
	}
	m = feed(m, key("["))
	m = feed(m, key("["))
	if h := header(); !strings.Contains(h, "TOTAL 1") || !strings.Contains(h, "14:00:02") {
		t.Errorf("paused on the first poll, the header should show it: %q", h)
	}
	if v := ansi.Strip(m.View()); !strings.Contains(v, "1 conns") {
		t.Errorf("paused on the first poll, the status bar should count its sockets:\n%s", v)
	}
}

// TestSystemTab verifies the 9 key opens the System tab and that host counters
// with a per-poll delta render (value + Δ/s).
func TestSystemTab(t *testing.T) {
	m := NewApp(nil)
	m = feed(m, tea.WindowSizeMsg{Width: 140, Height: 40})

	prev := &poller.SysStat{Timestamp: time.Now(), Counters: map[string]int64{
		"Tcp:RetransSegs": 100, "Tcp:OutSegs": 1000, "Tcp:CurrEstab": 5,
	}}
	cur := &poller.SysStat{Timestamp: time.Now(), Counters: map[string]int64{
		"Tcp:RetransSegs": 120, "Tcp:OutSegs": 3000, "Tcp:CurrEstab": 6,
	}}
	m = feed(m, pollResultMsg{poll: &session.Poll{Time: time.Now(), Conns: snapWithAddr("10.0.0.1"), Sys: prev}})
	m = feed(m, pollResultMsg{poll: &session.Poll{Time: time.Now(), Conns: snapWithAddr("10.0.0.1"), Sys: cur}})

	m = feed(m, key("9"))
	if m.tab != ViewSystem {
		t.Fatalf("key 9 should switch to System tab, got %v", m.tab)
	}
	v := m.View()
	if !strings.Contains(v, "Host Network Counters") {
		t.Fatalf("System tab should render the counters header:\n%s", v)
	}
	if !strings.Contains(v, "RetransSegs") || !strings.Contains(v, "/s") {
		t.Fatalf("System tab should show a counter with a per-second delta:\n%s", v)
	}
}

// TestScrubAutoPauses verifies that scrubbing from a live view enters pause.
func TestScrubAutoPauses(t *testing.T) {
	m := newLiveApp()
	m = feed(m, tea.WindowSizeMsg{Width: 140, Height: 40})
	m = feed(m, polled(snapWithAddr("10.0.0.1")))
	m = feed(m, polled(snapWithAddr("10.0.0.2")))

	m = feed(m, key("[")) // scrub back while live
	if !m.paused {
		t.Fatalf("scrubbing while live should auto-pause")
	}
	if m.scrubOffset != 1 {
		t.Fatalf("scrubOffset should be 1 after one step back, got %d", m.scrubOffset)
	}
}

func manyConns(n int, txFor func(i int) int) []*model.Connection {
	var conns []*model.Connection
	for i := 0; i < n; i++ {
		tx := txFor(i)
		conns = append(conns, &model.Connection{
			Protocol: "tcp", State: "ESTAB",
			LocalAddr: "10.0.0.1", LocalPort: strconv.Itoa(40000 + i),
			PeerAddr: "10.0.0.2", PeerPort: "443",
			DeltaBytesSent: &tx,
		})
	}
	return conns
}

// TestTableCursorStaysVisible is the regression for the cursor walking onto
// rows clipped off the bottom of the page: every selected row must be drawn.
func TestTableCursorStaysVisible(t *testing.T) {
	for _, filtered := range []bool{false, true} {
		m := newLiveApp()
		m = feed(m, tea.WindowSizeMsg{Width: 160, Height: 60})
		m = feed(m, polled(manyConns(200, func(int) int { return 0 })))
		if filtered { // the filter bar adds a header line
			m.filter.SetQuery("state=ESTAB")
			m.table.InvalidateCache()
		}
		help := filtered
		for i := 0; i < 120; i++ {
			sel := m.table.GetSelected()
			if sel == nil {
				t.Fatalf("filtered=%v: no selection after %d presses", help, i)
			}
			if !strings.Contains(m.View(), ":"+sel.LocalPort) {
				t.Fatalf("filtered=%v: selected row %s not visible after %d presses", help, sel.LocalPort, i)
			}
			m = feed(m, key("j"))
		}
	}
}

// TestTableSelectionFollowsConnection: when a poll re-sorts the rows, the
// highlight must stay on the same connection, not the same row index.
func TestTableSelectionFollowsConnection(t *testing.T) {
	m := newLiveApp()
	m = feed(m, tea.WindowSizeMsg{Width: 160, Height: 40})
	// Sort by TX descending.
	for i := 0; !strings.Contains(m.table.RenderFooter(), "sort: tx↓"); i++ {
		if i > 50 {
			t.Fatalf("never reached tx↓ sort; footer: %s", m.table.RenderFooter())
		}
		m = feed(m, key("h"))
	}
	m = feed(m, polled(manyConns(10, func(i int) int { return i * 100 })))
	m = feed(m, key("j"))
	m = feed(m, key("j"))
	want := m.table.GetSelected().LocalPort

	// Next poll reverses the TX ranking, so the row moves.
	m = feed(m, polled(manyConns(10, func(i int) int { return (10 - i) * 100 })))
	if got := m.table.GetSelected().LocalPort; got != want {
		t.Errorf("selection jumped from port %s to %s after re-sort", want, got)
	}
}

// TestFilterPaste: bracketed paste arrives as one KeyRunes message with the
// whole text; it must be inserted (newlines flattened), not ignored.
func TestFilterPaste(t *testing.T) {
	m := NewApp(nil)
	m = feed(m, tea.WindowSizeMsg{Width: 120, Height: 40})
	m = feed(m, key("/"))
	m = feed(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("peer=10.0.0.1\n"), Paste: true})
	m = feed(m, tea.KeyMsg{Type: tea.KeySpace})
	m = feed(m, key("x"))
	if m.filterBuf != "peer=10.0.0.1  x" {
		t.Errorf("filterBuf = %q, want %q", m.filterBuf, "peer=10.0.0.1  x")
	}
}

// TestFilterRejectsUnknownSignal: Enter on a query naming a removed signal
// keeps the prompt open with the reason and leaves the active filter alone;
// the next key clears the message.
func TestFilterRejectsUnknownSignal(t *testing.T) {
	m := NewApp(nil)
	m = feed(m, tea.WindowSizeMsg{Width: 120, Height: 40})
	if err := m.filter.SetQuery("state=ESTAB"); err != nil {
		t.Fatal(err)
	}
	m = feed(m, key("/"))
	m = feed(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(" signal=BBR_LOW"), Paste: true})
	m = feed(m, tea.KeyMsg{Type: tea.KeyEnter})
	if !m.filterMode || m.tab != ViewFilter {
		t.Fatalf("prompt should stay open after a rejected query")
	}
	if m.filter.Query() != "state=ESTAB" {
		t.Errorf("active filter = %q, want it unchanged", m.filter.Query())
	}
	if view := ansi.Strip(m.View()); !strings.Contains(view, "signal BBR_LOW was removed") {
		t.Errorf("prompt should explain the rejection:\n%s", view)
	}
	m = feed(m, tea.KeyMsg{Type: tea.KeyBackspace})
	if m.filterErr != "" {
		t.Errorf("editing should clear the error, got %q", m.filterErr)
	}
}

// TestHelpNeverOverflows: on a short terminal the help panel must not push
// the frame past the terminal height (which scrolls the header away).
func TestHelpNeverOverflows(t *testing.T) {
	m := NewApp(nil)
	m = feed(m, tea.WindowSizeMsg{Width: 120, Height: 20})
	m = feed(m, polled(snapWithAddr("10.0.0.1")))
	m = feed(m, key("?"))
	v := m.View()
	if n := strings.Count(v, "\n") + 1; n > 20 {
		t.Errorf("help view is %d lines on a 20-line terminal", n)
	}
	if !strings.Contains(v, "TOTAL") {
		t.Errorf("header should stay visible with help open")
	}
}

// TestExportRunsInBackground: pressing e returns a command instead of writing
// synchronously, shows progress, and reports the result when it completes.
func TestExportRunsInBackground(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	m := NewApp(nil)
	m = feed(m, tea.WindowSizeMsg{Width: 120, Height: 40})
	m = feed(m, polled(snapWithAddr("10.0.0.1")))

	next, cmd := m.Update(key("e"))
	m = next.(*AppModel)
	if cmd == nil || !m.exporting || m.statusMsg != "exporting…" {
		t.Fatalf("export should start in background (cmd=%v exporting=%v status=%q)", cmd != nil, m.exporting, m.statusMsg)
	}
	if _, again := m.Update(key("e")); again != nil {
		t.Errorf("a second export while one is running should be refused")
	}
	m = feed(m, cmd())
	if m.exporting || !strings.HasPrefix(m.statusMsg, "Exported 1 snapshots") {
		t.Errorf("after completion: exporting=%v status=%q", m.exporting, m.statusMsg)
	}
}

// TestFindingsHomeFlow: the app opens on Findings; a zero-window stall shows
// up there (and as a header pill), and Enter jumps to Live filtered to just
// the stalled socket.
func TestFindingsHomeFlow(t *testing.T) {
	m := NewApp(nil)
	if m.tab != ViewFindings {
		t.Fatalf("app should start on the Findings tab")
	}
	m = feed(m, tea.WindowSizeMsg{Width: 160, Height: 40})
	persist, dur := "persist", "2sec"
	stalled := &model.Connection{Protocol: "tcp", State: "ESTAB",
		LocalAddr: "10.0.0.1", LocalPort: "50001", PeerAddr: "10.0.0.5", PeerPort: "5432",
		TimerType: &persist, TimerDur: &dur}
	healthy := &model.Connection{Protocol: "tcp", State: "ESTAB",
		LocalAddr: "10.0.0.1", LocalPort: "50002", PeerAddr: "10.0.0.6", PeerPort: "443"}
	m = feed(m, polled([]*model.Connection{stalled, healthy}))

	v := m.View()
	if !strings.Contains(v, "peer not reading (zero window)") || !strings.Contains(v, "1 crit") {
		t.Fatalf("Findings should show the zero-window problem and a header pill:\n%s", v)
	}
	m = feed(m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.tab != ViewLive || m.table.GetFilteredCount() != 1 || m.table.GetSelected().LocalPort != "50001" {
		t.Errorf("Enter should open Live filtered to the stalled socket (tab=%v, rows=%d)", m.tab, m.table.GetFilteredCount())
	}
}

// TestHelpBlocksHiddenNavigation: with help covering the table, j must not
// move the (invisible) selection.
func TestHelpBlocksHiddenNavigation(t *testing.T) {
	m := newLiveApp()
	m = feed(m, tea.WindowSizeMsg{Width: 160, Height: 40})
	m = feed(m, polled(manyConns(10, func(int) int { return 0 })))
	before := m.table.GetSelected().LocalPort
	m = feed(m, key("?"))
	m = feed(m, key("j"))
	m = feed(m, key("?"))
	if got := m.table.GetSelected().LocalPort; got != before {
		t.Errorf("j under the help panel moved the selection %s → %s", before, got)
	}
}

// TestFindingsStaleWhenPollingFails: once polls start failing, the Findings
// tab says its analysis is old instead of silently showing it as current.
func TestFindingsStaleWhenPollingFails(t *testing.T) {
	m := NewApp(nil)
	m = feed(m, tea.WindowSizeMsg{Width: 160, Height: 40})
	m = feed(m, polled(snapWithAddr("10.0.0.1")))
	m.sess.ReportAt = time.Now().Add(-time.Minute) // pretend the last good poll was a while ago
	m = feed(m, pollResultMsg{poll: &session.Poll{Time: time.Now(), Err: errors.New("ss: exit status 1")}})
	if v := m.View(); !strings.Contains(v, "polling is failing") {
		t.Errorf("Findings should warn that its analysis is stale:\n%s", v)
	}
}
