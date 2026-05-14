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

	// Identity
	b.WriteString(renderDetailSection("Identity", func() string {
		var sb strings.Builder
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
		return sb.String()
	}))

	b.WriteString("\n")

	// Signals
	if len(signals) > 0 {
		b.WriteString(renderDetailSection("Signals", func() string {
			return RenderSignals(signals)
		}))
		b.WriteString("\n")
	}

	// Performance
	b.WriteString(renderDetailSection("Performance", func() string {
		var sb strings.Builder
		sb.WriteString(fmtRow("RTT", fmtRTT(conn.RTT)+"ms"))
		sb.WriteString(fmtRow("RTT Var", fmtFloat(conn.RTTVar, 1)+"ms"))
		sb.WriteString(fmtRow("Min RTT", fmtFloat(conn.MinRTT, 1)+"ms"))
		sb.WriteString(fmtRow("RTO", fmtFloat(conn.RTO, 1)+"ms"))
		sb.WriteString(fmtRow("ATO", fmtFloat(conn.ATO, 1)+"ms"))
		if conn.RTT != nil && conn.MinRTT != nil && *conn.MinRTT > 0 {
			sb.WriteString(fmtRow("RTT/MinRTT", fmt.Sprintf("%.1fx", *conn.RTT / *conn.MinRTT)))
		}
		return sb.String()
	}))

	b.WriteString("\n")

	// Congestion
	b.WriteString(renderDetailSection("Congestion", func() string {
		var sb strings.Builder
		sb.WriteString(fmtRow("CWnd", fmtNumRaw(conn.CWnd)))
		sb.WriteString(fmtRow("ssthresh", fmtNumRaw(conn.SSThresh)))
		sb.WriteString(fmtRow("MSS", fmtNumRaw(conn.MSS)))
		sb.WriteString(fmtRow("SndWnd", fmtNumRaw(conn.SndWnd)))
		sb.WriteString(fmtRow("RcvSpace", fmtNumRaw(conn.RcvSpace)))
		sb.WriteString(fmtRow("Unacked", fmtNumRaw(conn.Unacked)))
		if conn.CWnd != nil && conn.MSS != nil && *conn.MSS > 0 {
			sb.WriteString(fmtRow("CWnd/MSS", fmt.Sprintf("%.1f", float64(*conn.CWnd)/float64(*conn.MSS))))
		}
		return sb.String()
	}))

	b.WriteString("\n")

	// Throughput
	b.WriteString(renderDetailSection("Throughput", func() string {
		var sb strings.Builder
		sb.WriteString(fmtRow("Bytes Sent", fmtBytes(conn.BytesSent)))
		sb.WriteString(fmtRow("Bytes Recv", fmtBytes(conn.BytesReceived)))
		sb.WriteString(fmtRow("Bytes Acked", fmtBytes(conn.BytesAcked)))
		sb.WriteString(fmtRow("TX Rate", fmtRate(conn.DeltaBytesSent)))
		sb.WriteString(fmtRow("RX Rate", fmtRate(conn.DeltaBytesReceived)))
		sb.WriteString(fmtRow("Pacing Rate", fmtBPS(conn.PacingRate)))
		sb.WriteString(fmtRow("Delivery Rate", fmtBPS(conn.DeliveryRate)))
		return sb.String()
	}))

	b.WriteString("\n")

	// Retransmit
	b.WriteString(renderDetailSection("Retransmit", func() string {
		var sb strings.Builder
		sb.WriteString(fmtRow("Retrans (total)", fmtNumRaw(conn.Retrans)))
		sb.WriteString(fmtRow("Retrans (flight)", fmtNumRaw(conn.RetransNow)))
		sb.WriteString(fmtRow("Bytes Retrans", fmtBytes(conn.BytesRetrans)))
		sb.WriteString(fmtRow("Lost", fmtNumRaw(conn.Lost)))
		sb.WriteString(fmtRow("DSACK Dups", fmtNumRaw(conn.DSACKDups)))
		if conn.DeltaBytesSent != nil && *conn.DeltaBytesSent > 0 && conn.DeltaBytesRetrans != nil {
			rate := float64(*conn.DeltaBytesRetrans) / float64(*conn.DeltaBytesSent)
			sb.WriteString(fmtRow("Retrans %", fmt.Sprintf("%.1f%%", rate*100)))
		}
		return sb.String()
	}))

	b.WriteString("\n")

	// Queues
	b.WriteString(renderDetailSection("Queues", func() string {
		var sb strings.Builder
		sb.WriteString(fmtRow("Send Q", fmtNumRaw(conn.SendQ)))
		sb.WriteString(fmtRow("Recv Q", fmtNumRaw(conn.RecvQ)))
		sb.WriteString(fmtRow("Segs Out", fmtNumRaw(conn.SegsOut)))
		sb.WriteString(fmtRow("Segs In", fmtNumRaw(conn.SegsIn)))
		sb.WriteString(fmtRow("TX Delta", fmtRate(conn.DeltaSegsOut)))
		sb.WriteString(fmtRow("RX Delta", fmtRate(conn.DeltaSegsIn)))
		return sb.String()
	}))

	b.WriteString("\n")

	// skmem
	b.WriteString(renderDetailSection("Socket Memory", func() string {
		var sb strings.Builder
		sb.WriteString(fmtRow("R", fmtNumRaw(conn.SkmemR)))
		sb.WriteString(fmtRow("RB", fmtNumRaw(conn.SkmemRB)))
		sb.WriteString(fmtRow("T", fmtNumRaw(conn.SkmemT)))
		sb.WriteString(fmtRow("TB", fmtNumRaw(conn.SkmemTB)))
		sb.WriteString(fmtRow("F", fmtNumRaw(conn.SkmemF)))
		sb.WriteString(fmtRow("W", fmtNumRaw(conn.SkmemW)))
		sb.WriteString(fmtRow("O", fmtNumRaw(conn.SkmemO)))
		return sb.String()
	}))

	b.WriteString("\n")

	// BBR
	if conn.BBRBW != nil {
		b.WriteString(renderDetailSection("BBR", func() string {
			var sb strings.Builder
			sb.WriteString(fmtRow("BW", fmtBPS(conn.BBRBW)))
			sb.WriteString(fmtRow("MRTT", fmtFloat(conn.BBRMRTT, 0)+"ms"))
			sb.WriteString(fmtRow("Pacing Gain", fmtFloat(conn.BBRPacingGain, 2)))
			sb.WriteString(fmtRow("CWnd Gain", fmtFloat(conn.BBRCWndGain, 2)))
			return sb.String()
		}))
		b.WriteString("\n")
	}

	// Sparklines from history
	b.WriteString(renderSparklines(conn, buf, width))

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

func renderSparklines(conn *model.Connection, buf *poller.Buffer, width int) string {
	snapshots := buf.GetAll()
	if len(snapshots) < 2 {
		return ""
	}

	key := conn.ConnKey()
	var rttVals, cwndVals, txVals, rxVals []float64

	for _, snap := range snapshots {
		for _, c := range snap.Conns {
			if c.ConnKey() == key {
				if c.RTT != nil {
					rttVals = append(rttVals, *c.RTT)
				} else {
					rttVals = append(rttVals, 0)
				}
				if c.CWnd != nil {
					cwndVals = append(cwndVals, float64(*c.CWnd))
				} else {
					cwndVals = append(cwndVals, 0)
				}
				if c.DeltaBytesSent != nil {
					txVals = append(txVals, float64(*c.DeltaBytesSent))
				} else {
					txVals = append(txVals, 0)
				}
				if c.DeltaBytesReceived != nil {
					rxVals = append(rxVals, float64(*c.DeltaBytesReceived))
				} else {
					rxVals = append(rxVals, 0)
				}
				break
			}
		}
	}

	var b strings.Builder
	b.WriteString(styleDetailTitle.Render("  History (last "+fmt.Sprintf("%d polls", len(snapshots))+")") + "\n\n")

	chartWidth := min(width-20, 60)

	if len(rttVals) > 1 {
		b.WriteString("  RTT:  " + renderSparkline(rttVals, chartWidth, lipgloss.Color("#ffa94d")) + "\n")
	}
	if len(cwndVals) > 1 {
		b.WriteString("  CWnd: " + renderSparkline(cwndVals, chartWidth, lipgloss.Color("#74c0fc")) + "\n")
	}
	if len(txVals) > 1 {
		b.WriteString("  TX:   " + renderSparkline(txVals, chartWidth, lipgloss.Color("#51cf66")) + "\n")
	}
	if len(rxVals) > 1 {
		b.WriteString("  RX:   " + renderSparkline(rxVals, chartWidth, lipgloss.Color("#da77f2")) + "\n")
	}

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
