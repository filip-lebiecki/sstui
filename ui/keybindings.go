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
		{"g", "First connection"},
		{"G", "Last connection"},
		{"Enter", "View connection detail"},
		{"Escape", "Go back / close filter"},
		{"1-4", "Switch tabs (Live/Detail/Overview/Top)"},
		{"Tab", "Next tab"},
		{"Shift+Tab", "Previous tab"},
		{"h", "Toggle sort on column"},
		{"/", "Open filter mode"},
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
		Render("  In filter mode: type to filter, Escape to close, Enter to apply"))

	return b.String()
}
