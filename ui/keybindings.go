package ui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var (
	styleKey = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#5a56e7")).
			Bold(true).
			Width(12)

	styleDesc = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#ccc")).
			Width(30)
)

// RenderHelp renders the help/keyboard shortcuts panel.
func RenderHelp() string {
	bindings := []struct {
		key, desc string
	}{
		{"j / ↓", "Next connection"},
		{"k / ↑", "Previous connection"},
		{"g / G", "First / last connection"},
		{"Enter", "View connection detail"},
		{"Escape", "Go back / close filter"},
		{"1-7", "Switch tabs"},
		{"", "  1 Live  2 Detail  3 Socket  4 Overview"},
		{"", "  5 Top   6 Perf   7 Events"},
		{"Tab / S-Tab", "Next / prev tab"},
		{"Space", "Pause / resume (freeze the Live table)"},
		{"[ / ]", "Scrub back / forward one snapshot (pauses)"},
		{"{ / }", "Scrub back / forward ten snapshots"},
		{"h", "Cycle sort column / direction"},
		{"L", "Toggle hiding LISTEN sockets"},
		{"r", "Toggle reverse DNS (peer/local hostnames)"},
		{"/", "Open filter mode"},
		{"e", "Export ring buffer to JSON (events list on Events tab)"},
		{"E", "Export current snapshot to CSV (events list on Events tab)"},
		{"PgUp/PgDn", "Page scroll (Events tab)"},
		{"?", "Toggle this help"},
		{"q", "Quit"},
	}

	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(styleKey.Render("Key") + " " + styleDesc.Render("Action") + "\n")
	b.WriteString("  " + strings.Repeat("─", 44) + "\n")

	for _, kb := range bindings {
		b.WriteString(styleKey.Render(kb.key) + " " + styleDesc.Render(kb.desc) + "\n")
	}

	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#666")).
		Render("  Filter syntax: local=<addr> peer=<addr> sport=<port> dport=<port>\n" +
			"                 state=<state> proc=<name> pid=<pid> signal=<label>\n" +
			"  Operators: and  or  not  ( )   (space = and)\n" +
			"  In filter mode: type to edit, Enter to apply, Escape to cancel"))

	return b.String()
}
