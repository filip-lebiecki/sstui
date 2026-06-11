package main

import (
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
