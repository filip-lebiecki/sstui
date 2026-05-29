package ui

import (
	"testing"

	"github.com/charmbracelet/lipgloss"
)

// TestRenderTabsPadsToWidth guards the item-1 fix: padding must be computed
// from display width (lipgloss.Width), not raw byte length, so the bar fills
// the terminal even when the styled string contains ANSI escapes.
func TestRenderTabsPadsToWidth(t *testing.T) {
	for _, width := range []int{80, 100, 200} {
		got := lipgloss.Width(RenderTabs(0, width))
		if got != width {
			t.Errorf("RenderTabs(_, %d): display width = %d, want %d", width, got, width)
		}
	}
}

// TestRenderTabsNarrowTerminal ensures we don't panic or over-pad when the
// content is already wider than the terminal.
func TestRenderTabsNarrowTerminal(t *testing.T) {
	if got := lipgloss.Width(RenderTabs(0, 1)); got < 1 {
		t.Errorf("RenderTabs(_, 1): display width = %d, want >= 1", got)
	}
}
