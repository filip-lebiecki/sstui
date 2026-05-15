package ui

import (
	"fmt"
	"sort"
	"strings"

	"ss-stats-tui/model"
	"ss-stats-tui/poller"

	"github.com/charmbracelet/lipgloss"
)

// RenderPerf renders the performance / anomaly view.
func RenderPerf(buf *poller.Buffer, width, height int) string {
	snap := buf.GetLatest()
	if snap == nil {
		return "\n  No data yet..."
	}

	var b strings.Builder

	b.WriteString(renderPerfSummary(buf, snap, width))
	b.WriteString("\n")
	b.WriteString(renderRTTInflation(snap))
	b.WriteString("\n")
	b.WriteString(renderSlowConns(snap))
	b.WriteString("\n")
	b.WriteString(renderRetransRate(snap))
	b.WriteString("\n")
	b.WriteString(renderRetransCum(snap))
	b.WriteString("\n")
	b.WriteString(renderQueuePressure(snap))
	b.WriteString("\n")
	b.WriteString(renderZeroWindow(snap))
	b.WriteString("\n")
	b.WriteString(renderSendBacklog(snap))

	return b.String()
}

// renderPerfSummary shows the current health: per-signal-type counts and a
// sparkline of total warn+crit signals across the recorded history.
func renderPerfSummary(buf *poller.Buffer, snap *poller.Snapshot, width int) string {
	var totalEstab, totalWarn, totalCrit int
	counts := make(map[model.SignalType]int)
	for _, c := range snap.Conns {
		if c.State == "ESTAB" {
			totalEstab++
		}
		for _, s := range c.Signals {
			counts[s.Type]++
			switch s.Severity {
			case 1:
				totalWarn++
			case 2:
				totalCrit++
			}
		}
	}

	var sb strings.Builder
	sb.WriteString(styleSectionTitle.Render(" Health Summary") + "\n")
	sb.WriteString(fmt.Sprintf("  %s %s    %s %s    %s %s\n",
		styleTopHdr.Render("ESTAB:"),
		lipgloss.NewStyle().Foreground(lipgloss.Color("#51cf66")).Bold(true).Render(fmt.Sprintf("%d", totalEstab)),
		styleTopHdr.Render("Warnings:"),
		lipgloss.NewStyle().Foreground(lipgloss.Color("#ffa94d")).Bold(true).Render(fmt.Sprintf("%d", totalWarn)),
		styleTopHdr.Render("Critical:"),
		lipgloss.NewStyle().Foreground(lipgloss.Color("#ff6b6b")).Bold(true).Render(fmt.Sprintf("%d", totalCrit))))

	// Per-signal-type counts (skip info-level: idle, app_limited).
	type sigCount struct {
		t model.SignalType
		n int
	}
	var sigs []sigCount
	for t, n := range counts {
		if t == model.SignalIdle || t == model.SignalAppLimited {
			continue
		}
		sigs = append(sigs, sigCount{t, n})
	}
	sort.Slice(sigs, func(i, j int) bool { return sigs[i].n > sigs[j].n })

	if len(sigs) > 0 {
		var parts []string
		for _, s := range sigs {
			color := signalColors[s.t]
			if color == "" {
				color = lipgloss.Color("#888")
			}
			parts = append(parts, lipgloss.NewStyle().
				Foreground(lipgloss.Color("#000")).
				Background(color).
				Padding(0, 1).
				Render(fmt.Sprintf("%s %d", s.t.Label(), s.n)))
		}
		sb.WriteString("  " + strings.Join(parts, " ") + "\n")
	}

	// History sparkline of warn+crit signal count.
	snapshots := buf.GetAll()
	if len(snapshots) > 1 {
		var vals []float64
		for _, sn := range snapshots {
			var n int
			for _, c := range sn.Conns {
				for _, s := range c.Signals {
					if s.Severity >= 1 {
						n++
					}
				}
			}
			vals = append(vals, float64(n))
		}
		chartW := min(width-30, 60)
		sb.WriteString(fmt.Sprintf("  %s %s\n",
			styleTopHdr.Render("Signals over time:"),
			renderSparkline(vals, chartW, lipgloss.Color("#ffa94d"))))
	}
	return sb.String()
}

// connLabel produces a short identifier: peer:port + process.
func connLabel(c *model.Connection) (peer, proc string) {
	peer = c.PeerAddr + ":" + c.PeerPort
	if peer == "*:*" || c.PeerAddr == "" {
		peer = c.LocalAddr + ":" + c.LocalPort + " (listen)"
	}
	proc = "-"
	if c.Process != nil {
		proc = *c.Process
	}
	return peer, proc
}

func perfTableHeader(cols ...string) string {
	var parts []string
	for _, c := range cols {
		parts = append(parts, styleTopHdr.Render(c))
	}
	return "  " + strings.Join(parts, " ") + "\n"
}

func protoTag(proto string) string {
	return lipgloss.NewStyle().Foreground(ProtoColor(proto)).
		Render(fmt.Sprintf("%-4s", strings.ToUpper(proto)))
}

func renderRTTInflation(snap *poller.Snapshot) string {
	type entry struct {
		conn   *model.Connection
		ratio  float64
		rtt    float64
		minrtt float64
	}
	var entries []entry
	for _, c := range snap.Conns {
		if c.RTT != nil && c.MinRTT != nil && *c.MinRTT > 0 {
			r := *c.RTT / *c.MinRTT
			if r > 1.5 {
				entries = append(entries, entry{c, r, *c.RTT, *c.MinRTT})
			}
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ratio > entries[j].ratio })
	if len(entries) > 12 {
		entries = entries[:12]
	}

	var sb strings.Builder
	sb.WriteString(styleSectionTitle.Render(" RTT Inflation (RTT/MinRTT)") + "\n")
	sb.WriteString(perfTableHeader(
		fmt.Sprintf("%-4s", "Proto"),
		fmt.Sprintf("%-30s", "Peer"),
		fmt.Sprintf("%-15s", "Process"),
		fmt.Sprintf("%-7s", "Ratio"),
		fmt.Sprintf("%-15s", ""),
		fmt.Sprintf("%-9s", "RTT"),
		"MinRTT"))
	for _, e := range entries {
		peer, proc := connLabel(e.conn)
		sb.WriteString(fmt.Sprintf("  %s %s %s %s %s %s %s\n",
			protoTag(e.conn.Protocol),
			styleTopAddr.Render(fmt.Sprintf("%-30s", truncate(peer, 30))),
			styleTopProc.Render(fmt.Sprintf("%-15s", truncate(proc, 15))),
			styleTopWarn.Render(fmt.Sprintf("%6.1fx", e.ratio)),
			fmtRatioBar((e.ratio-1)/14, 15),
			lipgloss.NewStyle().Foreground(colRTTHi).Render(fmt.Sprintf("%7.1fms", e.rtt)),
			styleTopDim.Render(fmt.Sprintf("%.1fms", e.minrtt))))
	}
	if len(entries) == 0 {
		sb.WriteString("  None detected\n")
	}
	return sb.String()
}

func renderSlowConns(snap *poller.Snapshot) string {
	type entry struct {
		conn *model.Connection
		rtt  float64
	}
	var entries []entry
	maxRTT := 0.0
	for _, c := range snap.Conns {
		if c.RTT != nil && *c.RTT > 50 {
			entries = append(entries, entry{c, *c.RTT})
			if *c.RTT > maxRTT {
				maxRTT = *c.RTT
			}
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].rtt > entries[j].rtt })
	if len(entries) > 12 {
		entries = entries[:12]
	}

	var sb strings.Builder
	sb.WriteString(styleSectionTitle.Render(" Slow Connections (RTT > 50ms)") + "\n")
	sb.WriteString(perfTableHeader(
		fmt.Sprintf("%-4s", "Proto"),
		fmt.Sprintf("%-30s", "Peer"),
		fmt.Sprintf("%-15s", "Process"),
		fmt.Sprintf("%-10s", "RTT"),
		""))
	for _, e := range entries {
		peer, proc := connLabel(e.conn)
		color := colRTTMid
		if e.rtt > 200 {
			color = colRTTHi
		}
		sb.WriteString(fmt.Sprintf("  %s %s %s %s %s\n",
			protoTag(e.conn.Protocol),
			styleTopAddr.Render(fmt.Sprintf("%-30s", truncate(peer, 30))),
			styleTopProc.Render(fmt.Sprintf("%-15s", truncate(proc, 15))),
			lipgloss.NewStyle().Foreground(color).Render(fmt.Sprintf("%8.1fms", e.rtt)),
			fmtPropBar(e.rtt, maxRTT, 15)))
	}
	if len(entries) == 0 {
		sb.WriteString("  None detected\n")
	}
	return sb.String()
}

func renderRetransRate(snap *poller.Snapshot) string {
	type entry struct {
		conn *model.Connection
		rate float64
	}
	var entries []entry
	for _, c := range snap.Conns {
		if c.DeltaBytesSent != nil && *c.DeltaBytesSent > 0 && c.DeltaBytesRetrans != nil {
			r := float64(*c.DeltaBytesRetrans) / float64(*c.DeltaBytesSent)
			if r > 0.02 {
				entries = append(entries, entry{c, r})
			}
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].rate > entries[j].rate })
	if len(entries) > 12 {
		entries = entries[:12]
	}

	var sb strings.Builder
	sb.WriteString(styleSectionTitle.Render(" Retransmit Rate (current poll)") + "\n")
	sb.WriteString(perfTableHeader(
		fmt.Sprintf("%-4s", "Proto"),
		fmt.Sprintf("%-30s", "Peer"),
		fmt.Sprintf("%-15s", "Process"),
		fmt.Sprintf("%-7s", "Rate"),
		""))
	for _, e := range entries {
		peer, proc := connLabel(e.conn)
		color := colRTTMid
		if e.rate > 0.2 {
			color = colRetrans
		} else if e.rate > 0.05 {
			color = colRTTHi
		}
		sb.WriteString(fmt.Sprintf("  %s %s %s %s %s\n",
			protoTag(e.conn.Protocol),
			styleTopAddr.Render(fmt.Sprintf("%-30s", truncate(peer, 30))),
			styleTopProc.Render(fmt.Sprintf("%-15s", truncate(proc, 15))),
			lipgloss.NewStyle().Foreground(color).Render(fmt.Sprintf("%5.1f%%", e.rate*100)),
			fmtRatioBar(e.rate/0.2, 15)))
	}
	if len(entries) == 0 {
		sb.WriteString("  None detected\n")
	}
	return sb.String()
}

func renderRetransCum(snap *poller.Snapshot) string {
	type entry struct {
		conn    *model.Connection
		retrans int
		lost    int
		bytes   int
	}
	var entries []entry
	for _, c := range snap.Conns {
		if c.Retrans != nil && *c.Retrans > 0 {
			lost := 0
			if c.Lost != nil {
				lost = *c.Lost
			}
			bytes := 0
			if c.BytesRetrans != nil {
				bytes = *c.BytesRetrans
			}
			entries = append(entries, entry{c, *c.Retrans, lost, bytes})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].retrans > entries[j].retrans })
	if len(entries) > 10 {
		entries = entries[:10]
	}

	var sb strings.Builder
	sb.WriteString(styleSectionTitle.Render(" Cumulative Retransmits") + "\n")
	sb.WriteString(perfTableHeader(
		fmt.Sprintf("%-4s", "Proto"),
		fmt.Sprintf("%-30s", "Peer"),
		fmt.Sprintf("%-15s", "Process"),
		fmt.Sprintf("%-8s", "Retrans"),
		fmt.Sprintf("%-6s", "Lost"),
		"Bytes"))
	for _, e := range entries {
		peer, proc := connLabel(e.conn)
		b := e.bytes
		sb.WriteString(fmt.Sprintf("  %s %s %s %s %s %s\n",
			protoTag(e.conn.Protocol),
			styleTopAddr.Render(fmt.Sprintf("%-30s", truncate(peer, 30))),
			styleTopProc.Render(fmt.Sprintf("%-15s", truncate(proc, 15))),
			styleTopWarn.Render(fmt.Sprintf("%8d", e.retrans)),
			styleTopWarn.Render(fmt.Sprintf("%6d", e.lost)),
			styleTopDim.Render(fmtBytes(&b))))
	}
	if len(entries) == 0 {
		sb.WriteString("  None detected\n")
	}
	return sb.String()
}

func renderQueuePressure(snap *poller.Snapshot) string {
	type entry struct {
		conn      *model.Connection
		sendQ     int
		recvQ     int
		sndbufLim int
		rcvbufLim int
	}
	var entries []entry
	for _, c := range snap.Conns {
		sq, rq := 0, 0
		if c.SendQ != nil {
			sq = *c.SendQ
		}
		if c.RecvQ != nil {
			rq = *c.RecvQ
		}
		if sq > 0 || rq > 0 {
			sndLim, rcvLim := 0, 0
			if c.SkmemTB != nil {
				sndLim = *c.SkmemTB
			}
			if c.SkmemRB != nil {
				rcvLim = *c.SkmemRB
			}
			entries = append(entries, entry{c, sq, rq, sndLim, rcvLim})
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].sendQ+entries[i].recvQ > entries[j].sendQ+entries[j].recvQ
	})
	if len(entries) > 12 {
		entries = entries[:12]
	}

	var sb strings.Builder
	sb.WriteString(styleSectionTitle.Render(" Queue Pressure") + "\n")
	sb.WriteString(perfTableHeader(
		fmt.Sprintf("%-4s", "Proto"),
		fmt.Sprintf("%-30s", "Peer"),
		fmt.Sprintf("%-15s", "Process"),
		fmt.Sprintf("%-10s", "SendQ"),
		fmt.Sprintf("%-10s", ""),
		fmt.Sprintf("%-10s", "RecvQ"),
		""))
	for _, e := range entries {
		peer, proc := connLabel(e.conn)
		sb.WriteString(fmt.Sprintf("  %s %s %s %s %s %s %s\n",
			protoTag(e.conn.Protocol),
			styleTopAddr.Render(fmt.Sprintf("%-30s", truncate(peer, 30))),
			styleTopProc.Render(fmt.Sprintf("%-15s", truncate(proc, 15))),
			styleTopCount.Render(fmt.Sprintf("%-10s", fmtBytes(&e.sendQ))),
			fmtPropBar(float64(e.sendQ), float64(e.sndbufLim), 10),
			styleTopCount.Render(fmt.Sprintf("%-10s", fmtBytes(&e.recvQ))),
			fmtPropBar(float64(e.recvQ), float64(e.rcvbufLim), 10)))
	}
	if len(entries) == 0 {
		sb.WriteString("  None detected\n")
	}
	return sb.String()
}

func renderZeroWindow(snap *poller.Snapshot) string {
	var entries []*model.Connection
	for _, c := range snap.Conns {
		if c.SndWnd != nil && *c.SndWnd == 0 && c.State == "ESTAB" {
			entries = append(entries, c)
		}
	}

	var sb strings.Builder
	sb.WriteString(styleSectionTitle.Render(" Zero Window (snd_wnd=0)") + "\n")
	if len(entries) == 0 {
		sb.WriteString("  None detected\n")
		return sb.String()
	}
	sb.WriteString(perfTableHeader(
		fmt.Sprintf("%-4s", "Proto"),
		fmt.Sprintf("%-40s", "Peer"),
		"Process"))
	for i, c := range entries {
		if i >= 15 {
			break
		}
		peer, proc := connLabel(c)
		sb.WriteString(fmt.Sprintf("  %s %s %s\n",
			protoTag(c.Protocol),
			styleTopWarn.Render(fmt.Sprintf("%-40s", truncate(peer, 40))),
			styleTopProc.Render(proc)))
	}
	return sb.String()
}

func renderSendBacklog(snap *poller.Snapshot) string {
	type entry struct {
		conn    *model.Connection
		unacked int
		cwnd    int
	}
	var entries []entry
	for _, c := range snap.Conns {
		if c.Unacked != nil && *c.Unacked > 0 {
			cwnd := 0
			if c.CWnd != nil {
				cwnd = *c.CWnd
			}
			entries = append(entries, entry{c, *c.Unacked, cwnd})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].unacked > entries[j].unacked })
	if len(entries) > 12 {
		entries = entries[:12]
	}

	var sb strings.Builder
	sb.WriteString(styleSectionTitle.Render(" Send Backlog (Unacked / CWnd)") + "\n")
	sb.WriteString(perfTableHeader(
		fmt.Sprintf("%-4s", "Proto"),
		fmt.Sprintf("%-30s", "Peer"),
		fmt.Sprintf("%-15s", "Process"),
		fmt.Sprintf("%-12s", "Unacked/CWnd"),
		""))
	for _, e := range entries {
		peer, proc := connLabel(e.conn)
		ratio := 0.0
		if e.cwnd > 0 {
			ratio = float64(e.unacked) / float64(e.cwnd)
		}
		sb.WriteString(fmt.Sprintf("  %s %s %s %s %s\n",
			protoTag(e.conn.Protocol),
			styleTopAddr.Render(fmt.Sprintf("%-30s", truncate(peer, 30))),
			styleTopProc.Render(fmt.Sprintf("%-15s", truncate(proc, 15))),
			styleTopCount.Render(fmt.Sprintf("%-12s", fmt.Sprintf("%d/%d", e.unacked, e.cwnd))),
			fmtRatioBar(ratio, 15)))
	}
	if len(entries) == 0 {
		sb.WriteString("  None detected\n")
	}
	return sb.String()
}
