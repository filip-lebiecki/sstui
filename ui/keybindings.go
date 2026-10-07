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
		{"Enter", "View connection detail (Findings: show affected sockets)"},
		{"c", "Copy a finding's suggested command (Findings)"},
		{"Escape", "Go back / close filter"},
		{"1-9", "Switch tabs"},
		{"", "  1 Findings  2 Live  3 Detail  4 Socket  5 Overview"},
		{"", "  6 Top  7 Perf  8 Events  9 System"},
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
			"                 state=<state> proc=<name> pid=<pid> signal=<label> proto=tcp|udp\n" +
			"  Operators: and  or  not  ( )   (space = and)\n" +
			"  In filter mode: type to edit, Enter to apply, Escape to cancel"))

	return b.String()
}
