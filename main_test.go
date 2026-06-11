package main

import (
	"strings"
	"testing"

	"sstui/model"

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
