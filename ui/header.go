package ui

import (
	"fmt"
	"strings"
	"time"

	"ss-stats-tui/model"
	"ss-stats-tui/poller"

	"github.com/charmbracelet/lipgloss"
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

	styleStatLabel = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#888")).
			Inherit(styleStat)

	styleStatValue = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#fff")).
			Bold(true).
			Inherit(styleStat)

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
		model.SignalDeliveryDrop:       lipgloss.Color("#ffa94d"),
		model.SignalUnackedBuildup:     lipgloss.Color("#ffd43b"),
		model.SignalListenQueueFull:    lipgloss.Color("#ff6b6b"),
		model.SignalRTOFiring:          lipgloss.Color("#ff6b6b"),
		model.SignalSynStall:           lipgloss.Color("#ffa94d"),
		model.SignalOneWayStall:        lipgloss.Color("#ffd43b"),
		model.SignalCWndCollapse:       lipgloss.Color("#ffa94d"),
		model.SignalDSACKSpurious:      lipgloss.Color("#ffd43b"),
		model.SignalBBRUnderutil:       lipgloss.Color("#ffa94d"),
	}
)

// RenderHeader renders the top status bar with stat pills.
func RenderHeader(buf *poller.Buffer, width int) string {
	snap := buf.GetLatest()
	if snap == nil {
		return styleHeader.Render(fmt.Sprintf(" ss-stats | waiting for data... | %d cols", width))
	}

	total := len(snap.Conns)
	estab, listen := 0, 0
	var totalRTT, totalBytesSent, totalBytesRecv float64
	var rttCount int

	for _, c := range snap.Conns {
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

	pills := []string{
		styleStat.Render(fmt.Sprintf("TOTAL %d", total)),
		styleStat.Render(fmt.Sprintf("ESTAB %d", estab)),
		styleStat.Render(fmt.Sprintf("LISTEN %d", listen)),
		styleStat.Render(fmt.Sprintf("RTT %s", avgRTT)),
		styleStat.Render(fmt.Sprintf("TX %s", txRate)),
		styleStat.Render(fmt.Sprintf("RX %s", rxRate)),
		styleStat.Render(ts),
	}

	pillsStr := strings.Join(pills, "")
	prefix := "ss-stats"

	content := prefix + " " + pillsStr
	if len(content) < width {
		content += strings.Repeat(" ", width-len(content))
	}

	return lipgloss.NewStyle().
		Foreground(lipgloss.Color("#fff")).
		Background(lipgloss.Color("#5a56e7")).
		Padding(0, 0).
		Render(content)
}

func fmtBytesPerSec(b float64) string {
	b /= poller.PollInterval.Seconds()
	switch {
	case b >= 1_073_741_824:
		return fmt.Sprintf("%.1fGB/s", b/1073741824)
	case b >= 1_048_576:
		return fmt.Sprintf("%.1fMB/s", b/1048576)
	case b >= 1024:
		return fmt.Sprintf("%.1fKB/s", b/1024)
	default:
		return fmt.Sprintf("%.0fB/s", b)
	}
}

// RenderTabs renders the tab bar.
func RenderTabs(current int, width int) string {
	tabs := []string{"Live", "Detail", "Socket", "Overview", "Top", "Perf", "Events"}
	var parts []string

	for i, t := range tabs {
		if i == current {
			parts = append(parts, styleTabSelected.Render(t))
		} else {
			parts = append(parts, styleTab.Render(t))
		}
	}

	content := strings.Join(parts, "")
	if len(content) < width {
		content += strings.Repeat(" ", width-len(content))
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
		if color == "" {
			color = lipgloss.Color("#888")
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

// RenderSignalBar renders a compact signal indicator column.
func RenderSignalBar(signals []model.Signal) string {
	if len(signals) == 0 {
		return "🟢"
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
		return "🔴"
	case warnCount >= 4:
		return "🟠"
	case warnCount >= 2:
		return "🟡"
	case warnCount > 0:
		return "🟡"
	default:
		return "🟢"
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
		return lipgloss.Color("#5a56e7")
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
