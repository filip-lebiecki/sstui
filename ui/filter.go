package ui

import (
	"strings"

	"ss-stats-tui/model"
)

// Filter holds the current filter state.
type Filter struct {
	SrcAddr string
	DstAddr string
	SrcPort string
	DstPort string
	State   string
}

// Matches returns true if a connection matches the filter criteria.
func (f *Filter) Matches(c *model.Connection) bool {
	if f.SrcAddr != "" && !strings.Contains(c.LocalAddr, f.SrcAddr) {
		return false
	}
	if f.DstAddr != "" && !strings.Contains(c.PeerAddr, f.DstAddr) {
		return false
	}
	if f.SrcPort != "" && c.LocalPort != f.SrcPort {
		return false
	}
	if f.DstPort != "" && c.PeerPort != f.DstPort {
		return false
	}
	if f.State != "" && c.State != f.State {
		return false
	}
	return true
}

// IsActive returns true if any filter is set.
func (f *Filter) IsActive() bool {
	return f.SrcAddr != "" || f.DstAddr != "" || f.SrcPort != "" || f.DstPort != "" || f.State != ""
}

// Reset clears all filters.
func (f *Filter) Reset() {
	f.SrcAddr = ""
	f.DstAddr = ""
	f.SrcPort = ""
	f.DstPort = ""
	f.State = ""
}
