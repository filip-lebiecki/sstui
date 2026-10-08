package ui

import (
	"fmt"
	"strings"
	"time"

	"sstui/findings"

	"github.com/charmbracelet/lipgloss"
)

var (
	styleFindCrit  = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff6b6b")).Bold(true)
	styleFindWarn  = lipgloss.NewStyle().Foreground(lipgloss.Color("#ffa94d")).Bold(true)
	styleFindOK    = lipgloss.NewStyle().Foreground(lipgloss.Color("#51cf66")).Bold(true)
	styleFindTitle = lipgloss.NewStyle().Foreground(lipgloss.Color("#fff")).Bold(true)
	styleFindText  = lipgloss.NewStyle().Foreground(lipgloss.Color("#ccc"))
	styleFindDim   = lipgloss.NewStyle().Foreground(lipgloss.Color("#888"))
	styleFindCmd   = lipgloss.NewStyle().Foreground(lipgloss.Color("#74c0fc"))
	styleFindSel   = lipgloss.NewStyle().Background(lipgloss.Color("#444"))
)

// RenderFindings renders the Findings tab: a ranked list of host-level
// problems with the selected one expanded into what it means, the evidence,
// and what to do. sel is the selected index. The selected finding is kept in
// view by scrolling the list body; the summary line stays pinned.
//
// stale, when non-empty, warns that the report is out of date (polling is
// failing) and is shown under the summary. asOf, when non-empty, says which
// moment the report describes when it isn't the live present (paused, or a
// replay). now is the time finding ages are measured against.
func RenderFindings(rep findings.Report, sel, width, height int, now time.Time, stale, asOf string) string {
	head := renderFindingsSummary(rep) + "\n"
	// Notes are truncated with an ellipsis so a long filter visibly
	// continues instead of being clipped silently at the edge.
	if asOf != "" {
		head += styleFindTitle.Render(truncate("  ⏱ "+asOf, width)) + "\n"
		height--
	}
	if stale != "" {
		head += styleFindWarn.Render(truncate("  ⚠ "+stale, width)) + "\n"
		height--
	}
	if rep.SSFilter != "" {
		head += styleFindDim.Render(truncate("  scope: ss filter \""+rep.SSFilter+"\" — socket checks see only matching sockets; kernel counters stay host-wide", width)) + "\n"
		height--
	}

	if rep.HiddenProcs > 0 {
		head += styleFindDim.Render(truncate(fmt.Sprintf("  not root: process names hidden for %d %s owned by other users — run with sudo to see them",
			rep.HiddenProcs, pluralWord(rep.HiddenProcs, "socket")), width)) + "\n"
		height--
	}

	if len(rep.Findings) == 0 {
		return head + "\n" + renderNoFindings(rep, width)
	}
	sel = max(0, min(sel, len(rep.Findings)-1))

	textW := max(width-8, 30)
	var body []string
	selStart, selEnd := 0, 0
	for i, f := range rep.Findings {
		if i == sel {
			selStart = len(body)
		}
		body = append(body, findingTitleLine(f, i == sel, width, now))
		if i == sel {
			body = append(body, findingDetailLines(f, textW)...)
			selEnd = len(body)
			body = append(body, "")
		}
	}

	hint := styleFindDim.Render("  [j/k] select   [Enter] show affected sockets in Live   [c] copy command")
	avail := max(height-3, 1) // summary + blank + hint
	top := 0
	if selEnd > avail {
		top = min(selStart, selEnd-avail)
	}
	end := min(top+avail, len(body))
	return head + "\n" + strings.Join(body[top:end], "\n") + "\n" + hint
}

func renderFindingsSummary(rep findings.Report) string {
	var parts []string
	if c := rep.Crit(); c > 0 {
		parts = append(parts, styleFindCrit.Render(fmt.Sprintf("✖ %d critical", c)))
	}
	if w := rep.Warn(); w > 0 {
		parts = append(parts, styleFindWarn.Render(fmt.Sprintf("▲ %d %s", w, pluralWord(w, "warning"))))
	}
	if len(parts) == 0 {
		parts = append(parts, styleFindOK.Render("✓ healthy"))
	}
	stats := fmt.Sprintf("%d sockets (%d established)", rep.Sockets, rep.Estab)
	if rep.RetransPct >= 0 {
		stats += fmt.Sprintf(" · host retransmits %.2f%%", rep.RetransPct)
	}
	return styleSectionTitle.Render(" Findings") + "  " + strings.Join(parts, "  ") + "   " + styleFindDim.Render(stats)
}

func renderNoFindings(rep findings.Report, width int) string {
	var b strings.Builder
	b.WriteString("  " + styleFindOK.Render("✓ No problems detected") + "\n\n")
	b.WriteString(styleFindText.Width(max(width-4, 30)).PaddingLeft(2).Render(
		"Every poll checks for: peers that stopped reading (zero window), apps not draining "+
			"their sockets, full accept queues, failing handshakes, packet loss in both directions (per peer and host-wide), "+
			"reordering, path-MTU trouble, latency inflation, window- and buffer-limited throughput, "+
			"socket leaks (CLOSE-WAIT), TIME-WAIT churn, ephemeral-port exhaustion, SYN floods, "+
			"UDP buffer overflows and kernel memory pressure.") + "\n\n")
	b.WriteString(styleFindDim.Render("  Problems show up here as soon as they're detected. Tab 2 (Live) lists every socket."))
	return b.String()
}

func findingTitleLine(f findings.Finding, selected bool, width int, now time.Time) string {
	tag := styleFindWarn.Render("▲ WARN")
	if f.Severity >= 2 {
		tag = styleFindCrit.Render("✖ CRIT")
	}
	age := styleFindDim.Render(fmtAge(now.Sub(f.Since)))
	marker := "  "
	if selected {
		marker = styleFindTitle.Render("▶ ")
	}
	// Truncate the title so the age column stays on the line.
	titleW := max(width-lipgloss.Width(marker)-lipgloss.Width(tag)-lipgloss.Width(age)-4, 10)
	title := truncate(f.Title, titleW)
	line := marker + tag + "  " + styleFindTitle.Render(title)
	if pad := width - lipgloss.Width(line) - lipgloss.Width(age) - 1; pad > 0 {
		line += strings.Repeat(" ", pad)
	}
	line += age
	if selected {
		line = reapplyBackground(styleFindSel.Render(line), selectionBgSeq())
	}
	return line
}

// findingDetailLines expands the selected finding: meaning, evidence,
// actions (with commands), and the jump-to-sockets affordance.
func findingDetailLines(f findings.Finding, textW int) []string {
	// item wraps text at indent, prefixing the first line with bullet and
	// continuation lines with matching spaces (a hanging indent).
	item := func(indent int, bullet, text string, style lipgloss.Style) []string {
		bw := lipgloss.Width(bullet)
		lines := strings.Split(style.Width(max(textW-indent-bw, 10)).Render(text), "\n")
		for i := range lines {
			lead := strings.Repeat(" ", bw)
			if i == 0 {
				lead = bullet
			}
			lines[i] = strings.Repeat(" ", indent) + style.Render(lead) + lines[i]
		}
		return lines
	}

	var out []string
	out = append(out, item(6, "", f.Detail, styleFindDim.Italic(true))...)
	for _, e := range f.Evidence {
		out = append(out, item(6, "• ", e, styleFindText)...)
	}
	for _, a := range f.Actions {
		out = append(out, item(6, "→ ", a.Text, styleFindText)...)
		if a.Command != "" {
			out = append(out, item(8, "$ ", a.Command, styleFindCmd)...)
		}
	}
	if f.Filter != "" {
		n := "the affected sockets"
		if f.Count > 0 {
			n = fmt.Sprintf("%d affected %s", f.Count, pluralWord(f.Count, "socket"))
		}
		out = append(out, item(6, "⏎ ", "show "+n+" in Live  ("+f.Filter+")", styleFindDim)...)
	}
	return out
}

// fmtAge renders how long a finding has been active.
func fmtAge(d time.Duration) string {
	switch {
	case d < 5*time.Second:
		return "new"
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
}

func pluralWord(n int, w string) string {
	if n == 1 {
		return w
	}
	return w + "s"
}

// FindingsPill renders the header badge summarizing active findings, or ""
// when there are none — a nudge toward the Findings tab from any view.
func FindingsPill(crit, warn int) string {
	switch {
	case crit > 0:
		text := fmt.Sprintf("✖ %d crit", crit)
		if warn > 0 {
			text += fmt.Sprintf(" · %d warn", warn)
		}
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#000")).Background(lipgloss.Color("#ff6b6b")).
			Bold(true).Padding(0, 1).MarginRight(1).Render(text)
	case warn > 0:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#000")).Background(lipgloss.Color("#ffa94d")).
			Bold(true).Padding(0, 1).MarginRight(1).
			Render(fmt.Sprintf("▲ %d warn", warn))
	}
	return ""
}
