package ui

import (
	"fmt"
	"sort"
	"strings"

	"ss-stats-tui/poller"
)

// RenderTop renders the top offenders view.
func RenderTop(buf *poller.Buffer, width, height int) string {
	snap := buf.GetLatest()
	if snap == nil {
		return "\n  No data yet..."
	}

	var b strings.Builder

	// RTT Inflation
	b.WriteString(renderSection("RTT Inflation (RTT/MinRTT ratio)", func() string {
		type rttEntry struct {
			key    string
			ratio  float64
			rtt    float64
			minrtt float64
		}
		var entries []rttEntry

		for _, c := range snap.Conns {
			if c.RTT != nil && c.MinRTT != nil && *c.MinRTT > 0 {
				ratio := *c.RTT / *c.MinRTT
				if ratio > 1.5 {
					entries = append(entries, rttEntry{
						key:    c.ConnKey(),
						ratio:  ratio,
						rtt:    *c.RTT,
						minrtt: *c.MinRTT,
					})
				}
			}
		}

		sort.Slice(entries, func(i, j int) bool { return entries[i].ratio > entries[j].ratio })

		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("  %-35s %10s %15s\n", "Connection", "Ratio", "RTT/MinRTT"))
		sb.WriteString("  " + strings.Repeat("─", 61) + "\n")
		for i, e := range entries {
			if i >= 15 {
				break
			}
			sb.WriteString(fmt.Sprintf("  %-35s %9.1fx %8.1f/%.1fms\n",
				truncate(e.key, 35), e.ratio, e.rtt, e.minrtt))
		}
		if len(entries) == 0 {
			sb.WriteString("  None detected\n")
		}
		return sb.String()
	}))

	b.WriteString("\n\n")

	// Retransmit Bursts
	b.WriteString(renderSection("Retransmit Bursts (cumulative)", func() string {
		type retransEntry struct {
			key     string
			retrans int
			lost    int
		}
		var entries []retransEntry

		for _, c := range snap.Conns {
			if c.Retrans != nil && *c.Retrans > 0 {
				lost := 0
				if c.Lost != nil {
					lost = *c.Lost
				}
				entries = append(entries, retransEntry{
					key:     c.ConnKey(),
					retrans: *c.Retrans,
					lost:    lost,
				})
			}
		}

		sort.Slice(entries, func(i, j int) bool { return entries[i].retrans > entries[j].retrans })

		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("  %-35s %10s %8s\n", "Connection", "Retrans", "Lost"))
		sb.WriteString("  " + strings.Repeat("─", 54) + "\n")
		for i, e := range entries {
			if i >= 15 {
				break
			}
			sb.WriteString(fmt.Sprintf("  %-35s %10d %8d\n",
				truncate(e.key, 35), e.retrans, e.lost))
		}
		if len(entries) == 0 {
			sb.WriteString("  None detected\n")
		}
		return sb.String()
	}))

	b.WriteString("\n\n")

	// Queue Pressure
	b.WriteString(renderSection("Queue Pressure", func() string {
		type queueEntry struct {
			key   string
			sendQ int
			recvQ int
		}
		var entries []queueEntry

		for _, c := range snap.Conns {
			sq := 0
			rq := 0
			if c.SendQ != nil {
				sq = *c.SendQ
			}
			if c.RecvQ != nil {
				rq = *c.RecvQ
			}
			if sq > 0 || rq > 0 {
				entries = append(entries, queueEntry{
					key:   c.ConnKey(),
					sendQ: sq,
					recvQ: rq,
				})
			}
		}

		sort.Slice(entries, func(i, j int) bool {
			return entries[i].sendQ+entries[i].recvQ > entries[j].sendQ+entries[j].recvQ
		})

		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("  %-35s %8s %8s\n", "Connection", "SendQ", "RecvQ"))
		sb.WriteString("  " + strings.Repeat("─", 52) + "\n")
		for i, e := range entries {
			if i >= 15 {
				break
			}
			sb.WriteString(fmt.Sprintf("  %-35s %8d %8d\n",
				truncate(e.key, 35), e.sendQ, e.recvQ))
		}
		if len(entries) == 0 {
			sb.WriteString("  None detected\n")
		}
		return sb.String()
	}))

	b.WriteString("\n\n")

	// Zero Window
	b.WriteString(renderSection("Zero Window (snd_wnd=0)", func() string {
		var entries []string
		for _, c := range snap.Conns {
			if c.SndWnd != nil && *c.SndWnd == 0 && c.State == "ESTAB" {
				entries = append(entries, c.ConnKey())
			}
		}

		if len(entries) == 0 {
			return "  None detected"
		}

		var sb strings.Builder
		for i, e := range entries {
			if i >= 20 {
				break
			}
			sb.WriteString(fmt.Sprintf("  %s\n", truncate(e, 50)))
		}
		return sb.String()
	}))

	b.WriteString("\n\n")

	// Send Backlog
	b.WriteString(renderSection("Send Backlog (high unacked)", func() string {
		type unackedEntry struct {
			key     string
			unacked int
		}
		var entries []unackedEntry

		for _, c := range snap.Conns {
			if c.Unacked != nil && *c.Unacked > 0 {
				entries = append(entries, unackedEntry{
					key:     c.ConnKey(),
					unacked: *c.Unacked,
				})
			}
		}

		sort.Slice(entries, func(i, j int) bool {
			return entries[i].unacked > entries[j].unacked
		})

		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("  %-35s %10s\n", "Connection", "Unacked"))
		sb.WriteString("  " + strings.Repeat("─", 46) + "\n")
		for i, e := range entries {
			if i >= 15 {
				break
			}
			sb.WriteString(fmt.Sprintf("  %-35s %10d\n",
				truncate(e.key, 35), e.unacked))
		}
		if len(entries) == 0 {
			sb.WriteString("  None detected\n")
		}
		return sb.String()
	}))

	b.WriteString("\n\n")

	// Top by bytes sent
	b.WriteString(renderSection("Top TX (total bytes sent)", func() string {
		type txEntry struct {
			key  string
			bits int
		}
		var entries []txEntry

		for _, c := range snap.Conns {
			if c.BytesSent != nil && *c.BytesSent > 0 {
				entries = append(entries, txEntry{
					key:  c.ConnKey(),
					bits: *c.BytesSent,
				})
			}
		}

		sort.Slice(entries, func(i, j int) bool {
			return entries[i].bits > entries[j].bits
		})

		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("  %-35s %12s\n", "Connection", "Bytes Sent"))
		sb.WriteString("  " + strings.Repeat("─", 48) + "\n")
		for i, e := range entries {
			if i >= 10 {
				break
			}
			sb.WriteString(fmt.Sprintf("  %-35s %12s\n",
				truncate(e.key, 35), fmtBytes(&e.bits)))
		}
		if len(entries) == 0 {
			sb.WriteString("  No data\n")
		}
		return sb.String()
	}))

	b.WriteString("\n\n")

	// Top by bytes received
	b.WriteString(renderSection("Top RX (total bytes received)", func() string {
		type rxEntry struct {
			key  string
			bits int
		}
		var entries []rxEntry

		for _, c := range snap.Conns {
			if c.BytesReceived != nil && *c.BytesReceived > 0 {
				entries = append(entries, rxEntry{
					key:  c.ConnKey(),
					bits: *c.BytesReceived,
				})
			}
		}

		sort.Slice(entries, func(i, j int) bool {
			return entries[i].bits > entries[j].bits
		})

		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("  %-35s %15s\n", "Connection", "Bytes Received"))
		sb.WriteString("  " + strings.Repeat("─", 51) + "\n")
		for i, e := range entries {
			if i >= 10 {
				break
			}
			sb.WriteString(fmt.Sprintf("  %-35s %15s\n",
				truncate(e.key, 35), fmtBytes(&e.bits)))
		}
		if len(entries) == 0 {
			sb.WriteString("  No data\n")
		}
		return sb.String()
	}))

	return b.String()
}
