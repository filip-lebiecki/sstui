package ui

import (
	"fmt"
	"math"
	"strings"

	"ss-stats-tui/model"
	"ss-stats-tui/poller"

	"github.com/charmbracelet/lipgloss"
)

var (
	styleDetailTitle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#5a56e7")).
				Bold(true).
				Padding(0, 1)

	styleDetailLabel = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#888")).
				PaddingLeft(1)

	styleDetailValue = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#fff")).
				Bold(true).
				PaddingLeft(1)

	styleSparkline = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#51cf66"))
)

// RenderDetail renders the detail view for a selected connection.
func RenderDetail(conn *model.Connection, buf *poller.Buffer, width, height int) string {
	if conn == nil {
		return "\n  No connection selected. Use Enter on a connection to view details."
	}

	signals := conn.Signals
	var b strings.Builder

	b.WriteString(styleDetailTitle.Render(" Connection Details") + "\n\n")

	var sections []string
	add := func(title string, body func() string) {
		sections = append(sections, renderDetailSection(title, body))
	}

	add("Identity", func() string {
		var sb strings.Builder
		sb.WriteString(fmtRow("Protocol", strings.ToUpper(conn.Protocol)))
		sb.WriteString(fmtRow("State", conn.State))
		sb.WriteString(fmtRow("Local", conn.LocalAddr+":"+conn.LocalPort))
		sb.WriteString(fmtRow("Peer", conn.PeerAddr+":"+conn.PeerPort))
		if conn.Process != nil {
			sb.WriteString(fmtRow("Process", *conn.Process))
		}
		if conn.PID != nil {
			sb.WriteString(fmtRow("PID", fmt.Sprintf("%d", *conn.PID)))
		}
		if conn.UID != nil {
			sb.WriteString(fmtRow("UID", fmt.Sprintf("%d", *conn.UID)))
		}
		if ka := keepaliveSeconds(conn); ka >= 0 {
			sb.WriteString(fmtRow("Keepalive", fmtKeepalive(conn)))
		} else if conn.TimerType != nil && conn.TimerDur != nil {
			sb.WriteString(fmtRow("Timer", fmt.Sprintf("%s (%s)", *conn.TimerType, *conn.TimerDur)))
		}
		return sb.String()
	})

	if len(signals) > 0 {
		add("Signals", func() string {
			return RenderSignals(signals) + "\n"
		})
	}

	add("Performance", func() string {
		var sb strings.Builder
		sb.WriteString(fmtRow("RTT", fmtRTT(conn.RTT)+"ms"))
		sb.WriteString(fmtRow("RTT Var", fmtFloat(conn.RTTVar, 1)+"ms"))
		sb.WriteString(fmtRow("Min RTT", fmtFloat(conn.MinRTT, 1)+"ms"))
		sb.WriteString(fmtRow("RTO", fmtFloat(conn.RTO, 1)+"ms"))
		sb.WriteString(fmtRow("ATO", fmtFloat(conn.ATO, 1)+"ms"))
		if conn.RTT != nil && conn.MinRTT != nil && *conn.MinRTT > 0 {
			ratio := *conn.RTT / *conn.MinRTT
			sb.WriteString(fmtRowBar("RTT/MinRTT",
				fmt.Sprintf("%.1fx", ratio),
				(ratio-1)/14))
		}
		return sb.String()
	})

	add("Congestion", func() string {
		var sb strings.Builder
		sb.WriteString(fmtRow("CWnd", fmtPackets(conn.CWnd)))
		sb.WriteString(fmtRow("ssthresh", fmtSSThresh(conn.SSThresh)))
		sb.WriteString(fmtRow("MSS", fmtNumRaw(conn.MSS)+" B"))
		sb.WriteString(fmtRow("PMTU", fmtNumRaw(conn.PMTU)+" B"))
		sb.WriteString(fmtRow("AdvMSS", fmtNumRaw(conn.AdvMSS)+" B"))
		sb.WriteString(fmtRow("RcvMSS", fmtNumRaw(conn.RcvMSS)+" B"))
		sb.WriteString(fmtRow("SndWnd", fmtBytes(conn.SndWnd)))
		sb.WriteString(fmtRow("RcvSpace", fmtBytes(conn.RcvSpace)))
		sb.WriteString(fmtRow("RcvSSThresh", fmtBytes(conn.RcvSSThresh)))
		{
			unacked := 0
			if conn.Unacked != nil {
				unacked = *conn.Unacked
			}
			cwnd := 0
			if conn.CWnd != nil {
				cwnd = *conn.CWnd
			}
			ratio := 0.0
			if cwnd > 0 {
				ratio = float64(unacked) / float64(cwnd)
			}
			sb.WriteString(fmtRowBar("Unacked/CWnd",
				fmt.Sprintf("%d/%d", unacked, cwnd), ratio))
		}
		if conn.CWnd != nil && conn.MSS != nil && *conn.MSS > 0 {
			bytes := *conn.CWnd * *conn.MSS
			if conn.SndWnd != nil && *conn.SndWnd > 0 {
				ratio := float64(bytes) / float64(*conn.SndWnd)
				sb.WriteString(fmtRowBar("CWnd / SndWnd",
					fmtBytes(&bytes)+" / "+fmtBytes(conn.SndWnd), ratio))
			} else {
				sb.WriteString(fmtRow("CWnd bytes", fmtBytes(&bytes)))
			}
		}
		if conn.WscaleSnd != nil && conn.WscaleRcv != nil {
			sb.WriteString(fmtRow("WScale", fmt.Sprintf("snd=%d rcv=%d", *conn.WscaleSnd, *conn.WscaleRcv)))
		}
		return sb.String()
	})

	add("Throughput", func() string {
		var sb strings.Builder
		sb.WriteString(fmtRow("Bytes Sent", fmtBytes(conn.BytesSent)))
		sb.WriteString(fmtRow("Bytes Recv", fmtBytes(conn.BytesReceived)))
		sb.WriteString(fmtRow("Bytes Acked", fmtBytes(conn.BytesAcked)))
		sb.WriteString(fmtRow("TX Rate", fmtRate(conn.DeltaBytesSent)))
		sb.WriteString(fmtRow("RX Rate", fmtRate(conn.DeltaBytesReceived)))
		sb.WriteString(fmtRow("Pacing Rate", fmtBPS(conn.PacingRate)))
		sb.WriteString(fmtRow("Delivery Rate", fmtBPS(conn.DeliveryRate)))
		sb.WriteString(fmtRow("Send (inst)", fmtBPS(conn.SendBPS)))
		sb.WriteString(fmtRow("Delivered", fmtPackets(conn.Delivered)))
		if conn.LastSnd != nil {
			sb.WriteString(fmtRow("Last Send", fmtMs(conn.LastSnd)))
		}
		if conn.LastRcv != nil {
			sb.WriteString(fmtRow("Last Recv", fmtMs(conn.LastRcv)))
		}
		if conn.LastAck != nil {
			sb.WriteString(fmtRow("Last Ack", fmtMs(conn.LastAck)))
		}
		return sb.String()
	})

	add("Retransmit", func() string {
		var sb strings.Builder
		sb.WriteString(fmtRow("Retrans (total)", fmtNumRaw(conn.Retrans)))
		sb.WriteString(fmtRow("Retrans (flight)", fmtNumRaw(conn.RetransNow)))
		sb.WriteString(fmtRow("Bytes Retrans", fmtBytes(conn.BytesRetrans)))
		sb.WriteString(fmtRow("Lost", fmtNumRaw(conn.Lost)))
		sb.WriteString(fmtRow("DSACK Dups", fmtNumRaw(conn.DSACKDups)))
		{
			rate := 0.0
			if conn.DeltaBytesSent != nil && *conn.DeltaBytesSent > 0 && conn.DeltaBytesRetrans != nil {
				rate = float64(*conn.DeltaBytesRetrans) / float64(*conn.DeltaBytesSent)
			}
			// Map 0% → empty, 20% → full (HI_RETRANS critical threshold).
			sb.WriteString(fmtRowBar("Retrans %",
				fmt.Sprintf("%.1f%%", rate*100), rate/0.2))
		}
		return sb.String()
	})

	add("Queues", func() string {
		var sb strings.Builder
		sb.WriteString(fmtRow("Send Q", fmtBytes(conn.SendQ)))
		sb.WriteString(fmtRow("Recv Q", fmtBytes(conn.RecvQ)))
		sb.WriteString(fmtRow("Segs Out", fmtNumRaw(conn.SegsOut)))
		sb.WriteString(fmtRow("Segs In", fmtNumRaw(conn.SegsIn)))
		sb.WriteString(fmtRow("Data Segs Out", fmtNumRaw(conn.DataSegsOut)))
		sb.WriteString(fmtRow("Data Segs In", fmtNumRaw(conn.DataSegsIn)))
		sb.WriteString(fmtRow("TX Δ", fmtSegRate(conn.DeltaSegsOut)))
		sb.WriteString(fmtRow("RX Δ", fmtSegRate(conn.DeltaSegsIn)))
		return sb.String()
	})

	add("Socket Memory", func() string {
		var sb strings.Builder
		{
			used, limit := 0, 0
			if conn.SkmemR != nil {
				used = *conn.SkmemR
			}
			if conn.SkmemRB != nil {
				limit = *conn.SkmemRB
			}
			ratio := 0.0
			if limit > 0 {
				ratio = float64(used) / float64(limit)
			}
			sb.WriteString(fmtRowBar("rcv buf",
				fmtBytes(&used)+" / "+fmtBytes(&limit), ratio))
		}
		{
			used, limit := 0, 0
			if conn.SkmemT != nil {
				used = *conn.SkmemT
			}
			if conn.SkmemTB != nil {
				limit = *conn.SkmemTB
			}
			ratio := 0.0
			if limit > 0 {
				ratio = float64(used) / float64(limit)
			}
			sb.WriteString(fmtRowBar("snd buf",
				fmtBytes(&used)+" / "+fmtBytes(&limit), ratio))
		}
		sb.WriteString(fmtRow("fwd alloc", fmtBytes(conn.SkmemF)))
		sb.WriteString(fmtRow("write alloc", fmtBytes(conn.SkmemW)))
		sb.WriteString(fmtRow("optmem", fmtBytes(conn.SkmemO)))
		return sb.String()
	})

	if conn.BBRBW != nil {
		add("BBR", func() string {
			var sb strings.Builder
			sb.WriteString(fmtRow("BW", fmtBPS(conn.BBRBW)))
			sb.WriteString(fmtRow("MRTT", fmtFloat(conn.BBRMRTT, 0)+"ms"))
			sb.WriteString(fmtRow("Pacing Gain", fmtFloat(conn.BBRPacingGain, 2)))
			sb.WriteString(fmtRow("CWnd Gain", fmtFloat(conn.BBRCWndGain, 2)))
			return sb.String()
		})
	}

	b.WriteString(layoutSections(sections, width))
	b.WriteString("\n")
	b.WriteString(renderSparklines(conn, buf, width))

	return b.String()
}

// layoutSections arranges detail sections into 1 or 2 columns based on width.
// In 2-column mode the right column is aligned by padding every left section
// to a uniform width — the widest line found among all left sections.
func layoutSections(sections []string, width int) string {
	const minTwoCol = 100
	const gap = "    "
	var b strings.Builder
	if width < minTwoCol {
		for _, s := range sections {
			b.WriteString(s)
			b.WriteString("\n")
		}
		return b.String()
	}
	// Find max visible width across all left-column sections.
	leftMax := 0
	for i := 0; i < len(sections); i += 2 {
		for _, line := range strings.Split(sections[i], "\n") {
			if w := lipgloss.Width(line); w > leftMax {
				leftMax = w
			}
		}
	}
	padLeft := lipgloss.NewStyle().Width(leftMax)
	for i := 0; i < len(sections); i += 2 {
		left := padLeft.Render(sections[i])
		if i+1 < len(sections) {
			b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, left, gap, sections[i+1]))
		} else {
			b.WriteString(sections[i])
		}
		b.WriteString("\n\n")
	}
	return b.String()
}

func renderDetailSection(title string, contentFn func() string) string {
	var b strings.Builder
	b.WriteString(styleDetailTitle.Render(" "+title) + "\n")
	b.WriteString(contentFn())
	return b.String()
}

func fmtRow(label, value string) string {
	return fmt.Sprintf("  %s %s\n",
		styleDetailLabel.Render(fmt.Sprintf("%-16s: ", label)),
		styleDetailValue.Render(value))
}

// fmtRowBar renders a label/value pair followed by a 10-cell ratio bar.
// The bar sits immediately after the value with a single-space gap.
func fmtRowBar(label, value string, ratio float64) string {
	return fmt.Sprintf("  %s %s %s\n",
		styleDetailLabel.Render(fmt.Sprintf("%-16s: ", label)),
		styleDetailValue.Render(value),
		fmtRatioBar(ratio, 10))
}

func renderSparklines(conn *model.Connection, buf *poller.Buffer, width int) string {
	snapshots := buf.GetAll()
	if len(snapshots) < 2 {
		return ""
	}

	key := conn.ConnKey()
	var rttVals, cwndVals, txVals, rxVals []float64
	var sqVals, rqVals, unackedVals, retransVals []float64

	pickF := func(p *float64) float64 {
		if p == nil {
			return 0
		}
		return *p
	}
	pickI := func(p *int) float64 {
		if p == nil {
			return 0
		}
		return float64(*p)
	}

	for _, snap := range snapshots {
		for _, c := range snap.Conns {
			if c.ConnKey() == key {
				rttVals = append(rttVals, pickF(c.RTT))
				cwndVals = append(cwndVals, pickI(c.CWnd))
				txVals = append(txVals, pickI(c.DeltaBytesSent))
				rxVals = append(rxVals, pickI(c.DeltaBytesReceived))
				sqVals = append(sqVals, pickI(c.SendQ))
				rqVals = append(rqVals, pickI(c.RecvQ))
				unackedVals = append(unackedVals, pickI(c.Unacked))
				retransVals = append(retransVals, pickI(c.Retrans))
				break
			}
		}
	}

	var b strings.Builder
	b.WriteString(styleDetailTitle.Render("  History (last "+fmt.Sprintf("%d polls", len(snapshots))+")") + "\n\n")

	chartWidth := min(width-20, 60)

	hasSignal := func(vals []float64) bool {
		for _, v := range vals {
			if v != 0 {
				return true
			}
		}
		return false
	}

	line := func(label string, vals []float64, color lipgloss.Color) {
		if len(vals) > 1 && hasSignal(vals) {
			b.WriteString("  " + label + renderSparkline(vals, chartWidth, color) + "\n")
		}
	}

	line("RTT:     ", rttVals, lipgloss.Color("#ffa94d"))
	line("CWnd:    ", cwndVals, lipgloss.Color("#74c0fc"))
	line("TX:      ", txVals, lipgloss.Color("#51cf66"))
	line("RX:      ", rxVals, lipgloss.Color("#da77f2"))
	line("SendQ:   ", sqVals, lipgloss.Color("#ffd43b"))
	line("RecvQ:   ", rqVals, lipgloss.Color("#ffd43b"))
	line("Unacked: ", unackedVals, lipgloss.Color("#3bc9db"))
	line("Retrans: ", retransVals, lipgloss.Color("#ff6b6b"))

	return b.String()
}

func renderSparkline(values []float64, width int, color lipgloss.Color) string {
	if len(values) == 0 {
		return ""
	}

	n := len(values)
	if n > width {
		step := float64(n) / float64(width)
		var sampled []float64
		for i := 0; i < width; i++ {
			idx := int(math.Floor(step*float64(i) + 0.5))
			if idx >= n {
				idx = n - 1
			}
			sampled = append(sampled, values[idx])
		}
		values = sampled
		n = len(values)
	}

	minV, maxV := values[0], values[0]
	for _, v := range values {
		if v < minV {
			minV = v
		}
		if v > maxV {
			maxV = v
		}
	}

	rangeV := maxV - minV
	if rangeV == 0 {
		rangeV = 1
	}

	levels := " .:-=+*#%@#"
	var b strings.Builder
	for _, v := range values {
		normalized := (v - minV) / rangeV
		idx := int(normalized * float64(len(levels)-1))
		if idx >= len(levels) {
			idx = len(levels) - 1
		}
		b.WriteString(string(levels[idx]))
	}

	return lipgloss.NewStyle().Foreground(color).Render(b.String())
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
