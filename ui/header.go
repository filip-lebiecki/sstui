package ui

import (
	"fmt"
	"strings"
	"time"

	"sstui/model"
	"sstui/poller"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

var (
	styleHeader = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#fff")).
			Background(lipgloss.Color("#5a56e7")).
			Padding(0, 1).
			Bold(true)

	styleStat = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#ccc")).
			Background(lipgloss.Color("#333")).
			Padding(0, 1).
			MarginRight(1)

	styleTabSelected = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#fff")).
				Background(lipgloss.Color("#5a56e7")).
				Padding(0, 2).
				Bold(true)

	styleTab = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#888")).
			Padding(0, 2)

	signalColors = map[model.SignalType]lipgloss.Color{
		model.SignalRetransInFlight:    lipgloss.Color("#ff6b6b"),
		model.SignalAppLimited:         lipgloss.Color("#51cf66"),
		model.SignalIdle:               lipgloss.Color("#868e96"),
		model.SignalZeroWindow:         lipgloss.Color("#ff6b6b"),
		model.SignalCongestionLoss:     lipgloss.Color("#ff6b6b"),
		model.SignalPMTUMismatch:       lipgloss.Color("#ffa94d"),
		model.SignalRTTSpike:           lipgloss.Color("#ffa94d"),
		model.SignalSendBufferPressure: lipgloss.Color("#ffd43b"),
		model.SignalRecvBufferPressure: lipgloss.Color("#ffd43b"),
		model.SignalHighRetransRate:    lipgloss.Color("#ff6b6b"),
		model.SignalCwndLimited:        lipgloss.Color("#868e96"),
		model.SignalListenQueueFull:    lipgloss.Color("#ff6b6b"),
		model.SignalRTOFiring:          lipgloss.Color("#ff6b6b"),
		model.SignalSynStall:           lipgloss.Color("#ffa94d"),
		model.SignalPeerNoAck:          lipgloss.Color("#ff6b6b"),
		model.SignalCWndCollapse:       lipgloss.Color("#ffa94d"),
		model.SignalDSACKSpurious:      lipgloss.Color("#ffd43b"),
		model.SignalReordering:         lipgloss.Color("#ffa94d"),
		model.SignalSocketDrops:        lipgloss.Color("#ff6b6b"),
		model.SignalRwndLimited:        lipgloss.Color("#ffd43b"),
		model.SignalSndbufLimited:      lipgloss.Color("#ffd43b"),
		model.SignalRcvbufLimited:      lipgloss.Color("#ffd43b"),
		model.SignalCloseWaitLeak:      lipgloss.Color("#ff6b6b"),
		model.SignalTimeWaitStorm:      lipgloss.Color("#ffa94d"),
		model.SignalInboundLoss:        lipgloss.Color("#ff6b6b"),
		model.SignalPathLoss:           lipgloss.Color("#ff6b6b"),
	}
)

// styleWarnStat is a high-visibility pill used for conditions that should catch
// the eye, e.g. unparsed ss records.
var styleWarnStat = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#000")).
	Background(lipgloss.Color("#ffa94d")).
	Padding(0, 1).
	MarginRight(1).
	Bold(true)

// RenderHeader renders the top status bar with stat pills. When filter is
// active, the aggregates count only connections matching it, so the totals
// line up with the rows shown in the table. drops is the number of ss records
// the parser couldn't read on the last poll; when non-zero it gets its own pill
// so a silent parse regression is visible rather than swallowed.
func RenderHeader(buf *poller.Buffer, filter *Filter, drops int, findingsPill string, width int) string {
	snap := buf.GetLatest()
	if snap == nil {
		return styleHeader.Render(" sstui | waiting for data...")
	}

	filtered := filter != nil && filter.IsActive()
	total := 0
	estab, listen := 0, 0
	var totalRTT, totalBytesSent, totalBytesRecv float64
	var rttCount int

	for _, c := range snap.Conns {
		if filtered && !filter.Matches(c) {
			continue
		}
		total++
		switch c.State {
		case "ESTAB":
			estab++
		case "LISTEN":
			listen++
		}
		if c.RTT != nil {
			totalRTT += *c.RTT
			rttCount++
		}
		if c.DeltaBytesSent != nil {
			totalBytesSent += float64(*c.DeltaBytesSent)
		}
		if c.DeltaBytesReceived != nil {
			totalBytesRecv += float64(*c.DeltaBytesReceived)
		}
	}

	avgRTT := "-"
	if rttCount > 0 {
		avgRTT = fmt.Sprintf("%.1fms", totalRTT/float64(rttCount))
	}

	txRate := fmtBytesPerSec(totalBytesSent)
	rxRate := fmtBytesPerSec(totalBytesRecv)

	ts := buf.LastUpdate().Format("15:04:05")

	totalLabel := "TOTAL"
	if filtered {
		totalLabel = "MATCH"
	}

	pills := []string{
		styleStat.Render(fmt.Sprintf("%s %d", totalLabel, total)),
		styleStat.Render(fmt.Sprintf("ESTAB %d", estab)),
		styleStat.Render(fmt.Sprintf("LISTEN %d", listen)),
		styleStat.Render(fmt.Sprintf("RTT %s", avgRTT)),
		styleStat.Render(fmt.Sprintf("TX %s", txRate)),
		styleStat.Render(fmt.Sprintf("RX %s", rxRate)),
		styleStat.Render(ts),
	}
	if findingsPill != "" {
		pills = append([]string{findingsPill}, pills...)
	}
	if drops > 0 {
		pills = append(pills, styleWarnStat.Render(fmt.Sprintf("⚠ %d unparsed", drops)))
	}

	pillsStr := strings.Join(pills, "")
	prefix := "sstui"

	content := prefix + " " + pillsStr
	if pad := width - lipgloss.Width(content); pad > 0 {
		content += strings.Repeat(" ", pad)
	}

	return lipgloss.NewStyle().
		Foreground(lipgloss.Color("#fff")).
		Background(lipgloss.Color("#5a56e7")).
		Padding(0, 0).
		Render(content)
}

// fmtBytesPerSec formats a per-poll byte delta as a rate. It uses the same
// decimal (1000-based) units as fmtRate so the header totals line up exactly
// with the sum of the per-row TX/RX rates in the table.
func fmtBytesPerSec(b float64) string {
	b /= poller.PollInterval.Seconds()
	switch {
	case b >= 1_000_000_000:
		return fmt.Sprintf("%.1fGB/s", b/1e9)
	case b >= 1_000_000:
		return fmt.Sprintf("%.1fMB/s", b/1e6)
	case b >= 1_000:
		return fmt.Sprintf("%.1fKB/s", b/1e3)
	default:
		return fmt.Sprintf("%.0fB/s", b)
	}
}

// RenderTabs renders the tab bar. It uses roomy padding when the terminal is
// wide enough, tighter padding when it isn't (9 tabs don't fit 80 columns
// with the roomy style), and truncates as a last resort so the bar never
// wraps onto a second line.
//
// tabs are the labels in order; current is the selected index (-1 for none).
func RenderTabs(tabs []string, current int, width int) string {
	render := func(pad int) string {
		var parts []string
		for i, t := range tabs {
			if i == current {
				parts = append(parts, styleTabSelected.Padding(0, pad).Render(t))
			} else {
				parts = append(parts, styleTab.Padding(0, pad).Render(t))
			}
		}
		return strings.Join(parts, "")
	}

	content := render(2)
	if lipgloss.Width(content) > width {
		content = render(1)
	}
	if lipgloss.Width(content) > width {
		content = ansi.Truncate(content, width, "")
	}
	if pad := width - lipgloss.Width(content); pad > 0 {
		content += strings.Repeat(" ", pad)
	}
	return content
}

// RenderSignals renders signal badges for a connection.
func RenderSignals(signals []model.Signal) string {
	if len(signals) == 0 {
		return ""
	}
	var parts []string
	for _, s := range signals {
		color := signalColors[s.Type]
		if color == "" || s.Severity == 0 {
			// Info-level signals are context, not alarms: grey whatever
			// their type's color (RETRANS is red when it's a warning).
			color = lipgloss.Color("#868e96")
		}
		bgColor := color
		style := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#000")).
			Background(bgColor).
			Padding(0, 1)
		parts = append(parts, style.Render(s.Type.Label()))
	}
	return strings.Join(parts, " ")
}

// Status dots for the signal column. A colored "●" rather than emoji: emoji
// width is ambiguous across terminals and tmux (1 vs 2 cells), which
// misaligned every column to its right.
var (
	dotOK   = colorize("●", lipgloss.Color("#51cf66"))
	dotWarn = colorize("●", lipgloss.Color("#ffd43b"))
	dotMany = colorize("●", lipgloss.Color("#ffa94d"))
	dotCrit = colorize("●", lipgloss.Color("#ff6b6b"))
)

// RenderSignalBar renders a compact signal indicator column.
func RenderSignalBar(signals []model.Signal) string {
	if len(signals) == 0 {
		return dotOK
	}
	var maxSev, warnCount int
	for _, s := range signals {
		if s.Severity > maxSev {
			maxSev = s.Severity
		}
		if s.Severity == 1 {
			warnCount++
		}
	}
	switch {
	case maxSev == 2:
		return dotCrit
	case warnCount >= 4:
		return dotMany
	case warnCount > 0:
		return dotWarn
	default:
		return dotOK
	}
}

// StateColor returns a color for a TCP state.
func StateColor(state string) lipgloss.Color {
	switch state {
	case "ESTAB":
		return lipgloss.Color("#51cf66")
	case "LISTEN":
		return lipgloss.Color("#74c0fc")
	case "TIME-WAIT":
		return lipgloss.Color("#868e96")
	case "CLOSE-WAIT":
		return lipgloss.Color("#ffa94d")
	case "FIN-WAIT-1", "FIN-WAIT-2":
		return lipgloss.Color("#ffd43b")
	case "LAST-ACK":
		return lipgloss.Color("#ff6b6b")
	case "SYN-SENT", "SYN-RECV":
		return lipgloss.Color("#da77f2")
	case "UDP_ACTIVE":
		return lipgloss.Color("#3bc9db")
	case "UDP_ESTAB":
		return lipgloss.Color("#22b8cf")
	case "UDP_IDLE":
		return lipgloss.Color("#868e96")
	case "UNCONN":
		return lipgloss.Color("#868e96")
	default:
		return lipgloss.Color("#868e96")
	}
}

// ProtoColor returns a color for the protocol tag.
func ProtoColor(proto string) lipgloss.Color {
	switch proto {
	case "tcp":
		return lipgloss.Color("#4dabf7")
	case "udp":
		return lipgloss.Color("#22b8cf")
	}
	return lipgloss.Color("#868e96")
}

// RenderTimeAgo renders a human-readable time ago string.
func RenderTimeAgo(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Second:
		return "just now"
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	default:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
}
