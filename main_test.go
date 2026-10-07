package main

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"sstui/model"
	"sstui/poller"

	tea "github.com/charmbracelet/bubbletea"
)

// feed sends a message through Update and returns the model as *AppModel.
func feed(m *AppModel, msg tea.Msg) *AppModel {
	next, _ := m.Update(msg)
	return next.(*AppModel)
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
	m := NewApp()
	m = feed(m, tea.WindowSizeMsg{Width: 140, Height: 40})

	// Three polls of history, each with a distinguishable local address.
	m = feed(m, pollResultMsg{conns: snapWithAddr("10.0.0.1")})
	m = feed(m, pollResultMsg{conns: snapWithAddr("10.0.0.2")})
	m = feed(m, pollResultMsg{conns: snapWithAddr("10.0.0.3")}) // newest

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
	m = feed(m, pollResultMsg{conns: snapWithAddr("10.0.0.4")})
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

// TestSystemTab verifies the 8 key opens the System tab and that host counters
// with a per-poll delta render (value + Δ/s).
func TestSystemTab(t *testing.T) {
	m := NewApp()
	m = feed(m, tea.WindowSizeMsg{Width: 140, Height: 40})

	prev := &poller.SysStat{Timestamp: time.Now(), Counters: map[string]int64{
		"Tcp:RetransSegs": 100, "Tcp:OutSegs": 1000, "Tcp:CurrEstab": 5,
	}}
	cur := &poller.SysStat{Timestamp: time.Now(), Counters: map[string]int64{
		"Tcp:RetransSegs": 120, "Tcp:OutSegs": 3000, "Tcp:CurrEstab": 6,
	}}
	m = feed(m, pollResultMsg{conns: snapWithAddr("10.0.0.1"), sys: prev})
	m = feed(m, pollResultMsg{conns: snapWithAddr("10.0.0.1"), sys: cur})

	m = feed(m, key("8"))
	if m.tab != ViewSystem {
		t.Fatalf("key 8 should switch to System tab, got %v", m.tab)
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
	m := NewApp()
	m = feed(m, tea.WindowSizeMsg{Width: 140, Height: 40})
	m = feed(m, pollResultMsg{conns: snapWithAddr("10.0.0.1")})
	m = feed(m, pollResultMsg{conns: snapWithAddr("10.0.0.2")})

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
		m := NewApp()
		m = feed(m, tea.WindowSizeMsg{Width: 160, Height: 60})
		m = feed(m, pollResultMsg{conns: manyConns(200, func(int) int { return 0 })})
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
	m := NewApp()
	m = feed(m, tea.WindowSizeMsg{Width: 160, Height: 40})
	// Sort by TX descending.
	for i := 0; !strings.Contains(m.table.RenderFooter(), "sort: tx↓"); i++ {
		if i > 50 {
			t.Fatalf("never reached tx↓ sort; footer: %s", m.table.RenderFooter())
		}
		m = feed(m, key("h"))
	}
	m = feed(m, pollResultMsg{conns: manyConns(10, func(i int) int { return i * 100 })})
	m = feed(m, key("j"))
	m = feed(m, key("j"))
	want := m.table.GetSelected().LocalPort

	// Next poll reverses the TX ranking, so the row moves.
	m = feed(m, pollResultMsg{conns: manyConns(10, func(i int) int { return (10 - i) * 100 })})
	if got := m.table.GetSelected().LocalPort; got != want {
		t.Errorf("selection jumped from port %s to %s after re-sort", want, got)
	}
}

// TestFilterPaste: bracketed paste arrives as one KeyRunes message with the
// whole text; it must be inserted (newlines flattened), not ignored.
func TestFilterPaste(t *testing.T) {
	m := NewApp()
	m = feed(m, tea.WindowSizeMsg{Width: 120, Height: 40})
	m = feed(m, key("/"))
	m = feed(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("peer=10.0.0.1\n"), Paste: true})
	m = feed(m, tea.KeyMsg{Type: tea.KeySpace})
	m = feed(m, key("x"))
	if m.filterBuf != "peer=10.0.0.1  x" {
		t.Errorf("filterBuf = %q, want %q", m.filterBuf, "peer=10.0.0.1  x")
	}
}

// TestHelpNeverOverflows: on a short terminal the help panel must not push
// the frame past the terminal height (which scrolls the header away).
func TestHelpNeverOverflows(t *testing.T) {
	m := NewApp()
	m = feed(m, tea.WindowSizeMsg{Width: 120, Height: 20})
	m = feed(m, pollResultMsg{conns: snapWithAddr("10.0.0.1")})
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
	m := NewApp()
	m = feed(m, tea.WindowSizeMsg{Width: 120, Height: 40})
	m = feed(m, pollResultMsg{conns: snapWithAddr("10.0.0.1")})

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
