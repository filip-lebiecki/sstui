package ui

import (
	"strings"

	"sstui/model"
)

// Filter holds the current filter state.
type Filter struct {
	LocalAddr  string
	PeerAddr   string
	LocalPort  string
	PeerPort   string
	State      string
	Process    string // substring match against process name
	Signal     string // signal label or type (case-insensitive)
	HideListen bool
}

// Matches returns true if a connection matches the filter criteria.
func (f *Filter) Matches(c *model.Connection) bool {
	if f.HideListen && c.State == "LISTEN" {
		return false
	}
	if f.LocalAddr != "" && !strings.Contains(c.LocalAddr, f.LocalAddr) {
		return false
	}
	if f.PeerAddr != "" && !strings.Contains(c.PeerAddr, f.PeerAddr) {
		return false
	}
	if f.LocalPort != "" && c.LocalPort != f.LocalPort {
		return false
	}
	if f.PeerPort != "" && c.PeerPort != f.PeerPort {
		return false
	}
	if f.State != "" && c.State != f.State {
		return false
	}
	if f.Process != "" {
		if c.Process == nil {
			return false
		}
		if !strings.Contains(strings.ToLower(*c.Process), strings.ToLower(f.Process)) {
			return false
		}
	}
	if f.Signal != "" {
		want := strings.ToLower(f.Signal)
		found := false
		for _, s := range c.Signals {
			if strings.ToLower(string(s.Type)) == want || strings.ToLower(s.Type.Label()) == want {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// IsActive returns true if any filter is set.
func (f *Filter) IsActive() bool {
	return f.LocalAddr != "" || f.PeerAddr != "" || f.LocalPort != "" ||
		f.PeerPort != "" || f.State != "" || f.Process != "" || f.Signal != ""
}

// Reset clears all filters.
func (f *Filter) Reset() {
	f.LocalAddr = ""
	f.PeerAddr = ""
	f.LocalPort = ""
	f.PeerPort = ""
	f.State = ""
	f.Process = ""
	f.Signal = ""
}
