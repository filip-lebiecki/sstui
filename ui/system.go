package ui

import (
	"fmt"
	"strings"

	"sstui/poller"

	"github.com/charmbracelet/lipgloss"
)

// RenderSystem renders host-wide networking counters from /proc/net with
// per-poll deltas (rendered as rates). cur is the latest read, prev the one
// before it (for deltas). This surfaces conditions that per-socket ss output
// can't: SYN floods that never become sockets, accept-queue overflows, and
// global retransmit / pruning / buffer-error rates.
func RenderSystem(cur, prev *poller.SysStat, width, height int) string {
	if cur == nil {
		return "\n  No system counters yet..."
	}

	var b strings.Builder
	b.WriteString(styleSectionTitle.Render(" Host Network Counters") + " " +
		styleTopDim.Render("(/proc/net/snmp + netstat — value, and Δ/s this poll)") + "\n\n")

	// row renders one counter: its current cumulative value and the per-poll
	// delta as a rate. alert marks counters where any non-zero delta is bad
	// (errors, drops, overflows) so they turn red the moment they move.
	row := func(label, key string, alert bool) {
		val, ok := cur.Get(key)
		if !ok {
			return
		}
		rateStr := styleTopDim.Render("·")
		valColor := lipgloss.Color("#ccc")
		if d, ok := cur.Delta(prev, key); ok && d > 0 {
			r := float64(d) / poller.PollInterval.Seconds()
			color := lipgloss.Color("#51cf66")
			if alert {
				color = lipgloss.Color("#ff6b6b")
				valColor = lipgloss.Color("#ff6b6b")
			}
			rateStr = lipgloss.NewStyle().Foreground(color).Render(fmt.Sprintf("+%.1f/s", r))
		}
		b.WriteString(fmt.Sprintf("  %s %s  %s\n",
			styleTopDim.Render(fmt.Sprintf("%-22s", label)),
			lipgloss.NewStyle().Foreground(valColor).Render(fmt.Sprintf("%14d", val)),
			rateStr))
	}

	section := func(title string, rows func()) {
		b.WriteString(styleSectionTitle.Render(" "+title) + "\n")
		rows()
		b.WriteString("\n")
	}

	section("TCP", func() {
		row("CurrEstab", "Tcp:CurrEstab", false)
		row("ActiveOpens", "Tcp:ActiveOpens", false)
		row("PassiveOpens", "Tcp:PassiveOpens", false)
		row("InSegs", "Tcp:InSegs", false)
		row("OutSegs", "Tcp:OutSegs", false)
		row("RetransSegs", "Tcp:RetransSegs", true)
		row("AttemptFails", "Tcp:AttemptFails", true)
		row("EstabResets", "Tcp:EstabResets", true)
		row("OutRsts", "Tcp:OutRsts", false)
		row("InErrs", "Tcp:InErrs", true)
	})

	section("Accept queue / SYN", func() {
		row("ListenOverflows", "TcpExt:ListenOverflows", true)
		row("ListenDrops", "TcpExt:ListenDrops", true)
		row("SyncookiesSent", "TcpExt:SyncookiesSent", true)
		row("SyncookiesRecv", "TcpExt:SyncookiesRecv", true)
		row("TCPReqQFullDrop", "TcpExt:TCPReqQFullDrop", true)
	})

	section("Loss / retransmit", func() {
		row("TCPSynRetrans", "TcpExt:TCPSynRetrans", false)
		row("TCPTimeouts", "TcpExt:TCPTimeouts", false)
		row("TCPLostRetransmit", "TcpExt:TCPLostRetransmit", true)
		row("TCPFastRetrans", "TcpExt:TCPFastRetrans", false)
		row("TCPSpuriousRTOs", "TcpExt:TCPSpuriousRTOs", false)
	})

	section("Buffer pressure / OFO", func() {
		row("PruneCalled", "TcpExt:PruneCalled", true)
		row("RcvPruned", "TcpExt:RcvPruned", true)
		row("OfoPruned", "TcpExt:OfoPruned", true)
		row("TCPOFOQueue", "TcpExt:TCPOFOQueue", false)
		row("TCPBacklogDrop", "TcpExt:TCPBacklogDrop", true)
	})

	section("UDP", func() {
		row("InDatagrams", "Udp:InDatagrams", false)
		row("OutDatagrams", "Udp:OutDatagrams", false)
		row("InErrors", "Udp:InErrors", true)
		row("RcvbufErrors", "Udp:RcvbufErrors", true)
		row("SndbufErrors", "Udp:SndbufErrors", true)
		row("NoPorts", "Udp:NoPorts", false)
	})

	return b.String()
}
