package ui

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"sstui/model"
	"sstui/poller"

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
)

// RenderDetail renders the network-level detail view: identity, signals,
// performance, congestion, throughput, retransmits. Socket-side and historical
// data live in RenderSocket on a separate tab.
func RenderDetail(conn *model.Connection, buf *poller.Buffer, width, height int) string {
	if conn == nil {
		return "\n  No connection selected. Use Enter on a connection to view details."
	}

	var b strings.Builder

	b.WriteString(styleDetailTitle.Render(" Connection Detail") + "\n\n")

	var sections []string
	add := func(title string, body func() string) {
		sections = append(sections, renderDetailSection(title, body))
	}

	add("Identity", func() string {
		var sb strings.Builder
		sb.WriteString(fmtRowColor("Protocol", strings.ToUpper(conn.Protocol), ProtoColor(conn.Protocol)))
		sb.WriteString(fmtRowColor("State", conn.State, StateColor(conn.State)))
		sb.WriteString(fmtRowColor("Local", conn.LocalAddr+":"+conn.LocalPort, colAddr))
		sb.WriteString(fmtRowColor("Peer", conn.PeerAddr+":"+conn.PeerPort, colAddr))
		if conn.Process != nil {
			sb.WriteString(fmtRowColor("Process", *conn.Process, colProc))
		}
		if conn.PID != nil {
			sb.WriteString(fmtRowColor("PID", fmt.Sprintf("%d", *conn.PID), colPID))
		}
		if conn.UID != nil {
			sb.WriteString(fmtRowColor("UID", fmt.Sprintf("%d", *conn.UID), colPID))
		}
		if conn.Cgroup != nil {
			sb.WriteString(fmtRowColor("Cgroup", *conn.Cgroup, colDim))
		}
		if conn.CongAlgo != nil {
			algoColor := colPort
			if *conn.CongAlgo == "bbr" {
				algoColor = colTX
			}
			sb.WriteString(fmtRowColor("Cong Ctrl", *conn.CongAlgo, algoColor))
		}
		if ka := keepaliveSeconds(conn); ka >= 0 {
			sb.WriteString(fmtRowColor("Keepalive", fmtKeepalive(conn), colKA))
		} else if conn.TimerType != nil && conn.TimerDur != nil {
			sb.WriteString(fmtRowColor("Timer", fmt.Sprintf("%s (%s)", *conn.TimerType, *conn.TimerDur), colKA))
		}
		return sb.String()
	})

	add("Performance", func() string {
		var sb strings.Builder
		sb.WriteString(fmtRowColor("RTT", fmtRTT(conn.RTT)+"ms", rttColor(conn.RTT)))
		sb.WriteString(fmtRowColor("RTT Var", fmtFloat(conn.RTTVar, 1)+"ms", colDim))
		sb.WriteString(fmtRowColor("Min RTT", fmtFloat(conn.MinRTT, 1)+"ms", colDim))
		sb.WriteString(fmtRowColor("Rcv RTT", fmtFloat(conn.RcvRTT, 1)+"ms", colDim))
		sb.WriteString(fmtRowColor("RTO", fmtFloat(conn.RTO, 1)+"ms", rttColor(conn.RTO)))
		sb.WriteString(fmtRowColor("ATO", fmtFloat(conn.ATO, 1)+"ms", colDim))
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
		sb.WriteString(fmtRowColor("CWnd", fmtPackets(conn.CWnd), colPort))
		sb.WriteString(fmtRowColor("ssthresh", fmtSSThresh(conn.SSThresh), colDim))
		sb.WriteString(fmtRowColor("MSS", fmtNumRaw(conn.MSS)+" B", colDim))
		sb.WriteString(fmtRowColor("PMTU", fmtNumRaw(conn.PMTU)+" B", colDim))
		sb.WriteString(fmtRowColor("AdvMSS", fmtNumRaw(conn.AdvMSS)+" B", colDim))
		sb.WriteString(fmtRowColor("RcvMSS", fmtNumRaw(conn.RcvMSS)+" B", colDim))
		sb.WriteString(fmtRowColor("SndWnd", fmtBytes(conn.SndWnd), wndColor(conn.SndWnd)))
		sb.WriteString(fmtRowColor("RcvWnd", fmtBytes(conn.RcvWnd), wndColor(conn.RcvWnd)))
		sb.WriteString(fmtRowColor("RcvSpace", fmtBytes(conn.RcvSpace), colDim))
		sb.WriteString(fmtRowColor("RcvSSThresh", fmtBytes(conn.RcvSSThresh), colDim))
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
			sb.WriteString(fmtRowColor("WScale",
				fmt.Sprintf("snd=%d rcv=%d", *conn.WscaleSnd, *conn.WscaleRcv), colDim))
		}
		return sb.String()
	})

	add("Throughput", func() string {
		var sb strings.Builder
		sb.WriteString(fmtRowColor("Bytes Sent", fmtBytes(conn.BytesSent), dimIfZero(conn.BytesSent, colTX)))
		sb.WriteString(fmtRowColor("Bytes Recv", fmtBytes(conn.BytesReceived), dimIfZero(conn.BytesReceived, colRX)))
		sb.WriteString(fmtRowColor("Bytes Acked", fmtBytes(conn.BytesAcked), dimIfZero(conn.BytesAcked, colTX)))
		sb.WriteString(fmtRowColor("TX Rate", fmtRate(conn.DeltaBytesSent), dimIfZero(conn.DeltaBytesSent, colTX)))
		sb.WriteString(fmtRowColor("RX Rate", fmtRate(conn.DeltaBytesReceived), dimIfZero(conn.DeltaBytesReceived, colRX)))
		sb.WriteString(fmtRowColor("Pacing Rate", fmtBPS(conn.PacingRate), dimIfZero(conn.PacingRate, colPort)))
		sb.WriteString(fmtRowColor("Delivery Rate", fmtBPS(conn.DeliveryRate), dimIfZero(conn.DeliveryRate, colPort)))
		sb.WriteString(fmtRowColor("Send (inst)", fmtBPS(conn.SendBPS), dimIfZero(conn.SendBPS, colTX)))
		sb.WriteString(fmtRowColor("Delivered", fmtPackets(conn.Delivered), colDim))
		if conn.LastSnd != nil {
			sb.WriteString(fmtRowColor("Last Send", fmtMs(conn.LastSnd), colDim))
		}
		if conn.LastRcv != nil {
			sb.WriteString(fmtRowColor("Last Recv", fmtMs(conn.LastRcv), colDim))
		}
		if conn.LastAck != nil {
			sb.WriteString(fmtRowColor("Last Ack", fmtMs(conn.LastAck), colDim))
		}
		if conn.DeltaBusyMS != nil {
			pollMs := float64(poller.PollInterval / time.Millisecond)
			ratio := 0.0
			if pollMs > 0 {
				ratio = *conn.DeltaBusyMS / pollMs
			}
			sb.WriteString(fmtRowBar("Busy",
				fmt.Sprintf("%.0fms (%.0f%%)", *conn.DeltaBusyMS, ratio*100), ratio))
		}
		return sb.String()
	})

	add("Retransmit", func() string {
		var sb strings.Builder
		sb.WriteString(fmtRowColor("Retrans (total)", fmtNumRaw(conn.Retrans), dimIfZero(conn.Retrans, colRetrans)))
		sb.WriteString(fmtRowColor("Retrans (flight)", fmtNumRaw(conn.RetransNow), dimIfZero(conn.RetransNow, colRetrans)))
		sb.WriteString(fmtRowColor("Bytes Retrans", fmtBytes(conn.BytesRetrans), dimIfZero(conn.BytesRetrans, colRetrans)))
		sb.WriteString(fmtRowColor("Lost", fmtNumRaw(conn.Lost), dimIfZero(conn.Lost, colRetrans)))
		sb.WriteString(fmtRowColor("DSACK Dups", fmtNumRaw(conn.DSACKDups), dimIfZero(conn.DSACKDups, colQ)))
		sb.WriteString(fmtRowColor("Reordering", fmtNumRaw(conn.Reordering), colDim))
		sb.WriteString(fmtRowColor("Reord Seen", fmtNumRaw(conn.ReordSeen), dimIfZero(conn.ReordSeen, colQ)))
		sb.WriteString(fmtRowColor("Rcv OOO", fmtNumRaw(conn.RcvOOOPack), dimIfZero(conn.RcvOOOPack, colQ)))
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

	b.WriteString(layoutSections(sections, width))
	if len(conn.Signals) > 0 {
		b.WriteString("\n" + RenderSignals(conn.Signals) + "\n")
	}
	return b.String()
}

// RenderSocket renders the kernel/socket-side view of the selected connection:
// queue depths, socket memory, BBR state, and historical sparklines. Paired
// with RenderDetail on a sibling tab so the network-level data and the
// resource-level data each get the full viewport.
func RenderSocket(conn *model.Connection, buf *poller.Buffer, width, height int) string {
	if conn == nil {
		return "\n  No connection selected. Use Enter on a connection to view details."
	}

	var b strings.Builder
	b.WriteString(styleDetailTitle.Render(" Socket & History") + "\n")
	peer := conn.PeerAddr + ":" + conn.PeerPort
	if conn.Process != nil {
		peer += "  " + *conn.Process
	}
	b.WriteString("  " + lipgloss.NewStyle().Foreground(lipgloss.Color("#888")).Render(peer) + "\n\n")

	var sections []string
	add := func(title string, body func() string) {
		sections = append(sections, renderDetailSection(title, body))
	}

	add("Queues", func() string {
		var sb strings.Builder
		sb.WriteString(fmtRowColor("Send Q", fmtBytes(conn.SendQ), dimIfZero(conn.SendQ, colQ)))
		sb.WriteString(fmtRowColor("Recv Q", fmtBytes(conn.RecvQ), dimIfZero(conn.RecvQ, colQ)))
		sb.WriteString(fmtRowColor("Segs Out", fmtNumRaw(conn.SegsOut), colTX))
		sb.WriteString(fmtRowColor("Segs In", fmtNumRaw(conn.SegsIn), colRX))
		sb.WriteString(fmtRowColor("Data Segs Out", fmtNumRaw(conn.DataSegsOut), colTX))
		sb.WriteString(fmtRowColor("Data Segs In", fmtNumRaw(conn.DataSegsIn), colRX))
		sb.WriteString(fmtRowColor("TX Δ", fmtSegRate(conn.DeltaSegsOut), dimIfZero(conn.DeltaSegsOut, colTX)))
		sb.WriteString(fmtRowColor("RX Δ", fmtSegRate(conn.DeltaSegsIn), dimIfZero(conn.DeltaSegsIn, colRX)))
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
		sb.WriteString(fmtRowColor("fwd alloc", fmtBytes(conn.SkmemF), dimIfZero(conn.SkmemF, colAddr)))
		sb.WriteString(fmtRowColor("write alloc", fmtBytes(conn.SkmemW), dimIfZero(conn.SkmemW, colAddr)))
		sb.WriteString(fmtRowColor("optmem", fmtBytes(conn.SkmemO), dimIfZero(conn.SkmemO, colAddr)))
		sb.WriteString(fmtRowColor("backlog", fmtBytes(conn.SkmemBL), dimIfZero(conn.SkmemBL, colQ)))
		sb.WriteString(fmtRowColor("drops", fmtNumRaw(conn.SkmemD), dimIfZero(conn.SkmemD, colRetrans)))
		return sb.String()
	})

	if conn.BBRBW != nil {
		add("BBR", func() string {
			var sb strings.Builder
			sb.WriteString(fmtRowColor("BW", fmtBPS(conn.BBRBW), colTX))
			sb.WriteString(fmtRowColor("MRTT", fmtFloat(conn.BBRMRTT, 0)+"ms", colRTTHi))
			gainColor := func(p *float64) lipgloss.Color {
				if p == nil {
					return colDim
				}
				switch {
				case *p > 1.5:
					return colTX
				case *p < 0.85:
					return colRTTMid
				}
				return colPort
			}
			sb.WriteString(fmtRowColor("Pacing Gain", fmtFloat(conn.BBRPacingGain, 2), gainColor(conn.BBRPacingGain)))
			sb.WriteString(fmtRowColor("CWnd Gain", fmtFloat(conn.BBRCWndGain, 2), gainColor(conn.BBRCWndGain)))
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

// fmtRowColor is fmtRow with an explicit foreground color on the value.
// Use it to convey meaning at a glance (TX/RX direction, queue pressure,
// dimmed-when-zero) without losing the bold/aligned look of fmtRow.
func fmtRowColor(label, value string, color lipgloss.Color) string {
	val := lipgloss.NewStyle().
		Foreground(color).
		Bold(true).
		PaddingLeft(1).
		Render(value)
	return fmt.Sprintf("  %s %s\n",
		styleDetailLabel.Render(fmt.Sprintf("%-16s: ", label)),
		val)
}

// dimIfZero returns colDim when the int pointer is nil or 0, else accent.
// Used for both totals and per-poll deltas — in both cases nil and 0 mean
// "no activity worth highlighting".
func dimIfZero(v *int, accent lipgloss.Color) lipgloss.Color {
	if v == nil || *v == 0 {
		return colDim
	}
	return accent
}

// rttColor picks a color from the same three-tier scale used in the table:
// ≤50ms ok, ≤200ms mid, otherwise hi. Nil → dim.
func rttColor(p *float64) lipgloss.Color {
	if p == nil {
		return colDim
	}
	switch {
	case *p > 200:
		return colRTTHi
	case *p > 50:
		return colRTTMid
	}
	return colRTTOk
}

// wndColor highlights zero-window in red — a stuck peer receive window is a
// real fault, not a value to read past.
func wndColor(p *int) lipgloss.Color {
	if p == nil {
		return colDim
	}
	if *p == 0 {
		return colRetrans
	}
	return colPort
}

// fmtRowBar renders a label/value pair followed by a 10-cell ratio bar.
// The bar sits immediately after the value with a single-space gap.
func fmtRowBar(label, value string, ratio float64) string {
	return fmt.Sprintf("  %s %s %s\n",
		styleDetailLabel.Render(fmt.Sprintf("%-16s: ", label)),
		styleDetailValue.Render(value),
		fmtRatioBar(ratio, 10))
}

// Sparkline rendering walks the entire ring buffer (every snapshot, a Lookup
// per snapshot) for the inspected connection. The Detail/Socket views re-render
// on every bubbletea message, and j/k navigation can fire many in a row, so
// without caching each keystroke re-scans up to BufferSize snapshots. The buffer
// only changes once per poll and the output depends on (connection, width), so
// key the cache on all three: re-renders and held selections hit the cache; a
// new poll, a different connection, or a resize recomputes. Access is on the
// single Update/View goroutine, but a mutex keeps it safe regardless.
var (
	splCacheMu      sync.Mutex
	splCacheVersion time.Time
	splCacheKey     string
	splCacheWidth   int
	splCacheValid   bool
	splCacheResult  string
)

func renderSparklines(conn *model.Connection, buf *poller.Buffer, width int) string {
	key := conn.ConnKey()
	v := buf.LastUpdate()

	splCacheMu.Lock()
	defer splCacheMu.Unlock()
	if splCacheValid && splCacheKey == key && splCacheWidth == width && v.Equal(splCacheVersion) {
		return splCacheResult
	}

	result := computeSparklines(conn, buf, width)
	splCacheVersion = v
	splCacheKey = key
	splCacheWidth = width
	splCacheResult = result
	splCacheValid = true
	return result
}

func computeSparklines(conn *model.Connection, buf *poller.Buffer, width int) string {
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
		c := snap.Lookup(key)
		if c == nil {
			continue
		}
		rttVals = append(rttVals, pickF(c.RTT))
		cwndVals = append(cwndVals, pickI(c.CWnd))
		txVals = append(txVals, pickI(c.DeltaBytesSent))
		rxVals = append(rxVals, pickI(c.DeltaBytesReceived))
		sqVals = append(sqVals, pickI(c.SendQ))
		rqVals = append(rqVals, pickI(c.RecvQ))
		unackedVals = append(unackedVals, pickI(c.Unacked))
		retransVals = append(retransVals, pickI(c.Retrans))
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
			b.WriteString("  " + label + renderBarChart(vals, chartWidth, color) + "\n")
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
