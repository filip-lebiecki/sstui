package ui

import (
	"fmt"
	"sort"
	"strings"

	"ss-stats-tui/poller"
)

// RenderTop renders rankings: top processes, top ports, top TX/RX talkers.
func RenderTop(buf *poller.Buffer, width, height int) string {
	snap := buf.GetLatest()
	if snap == nil {
		return "\n  No data yet..."
	}

	var b strings.Builder

	// Top processes
	b.WriteString(renderSection("Top Processes", func() string {
		type procStats struct {
			name      string
			conns     int
			totalRTT  float64
			rttCount  int
			totalSent float64
			totalRecv float64
		}
		procs := make(map[string]*procStats)

		for _, c := range snap.Conns {
			name := "-"
			if c.Process != nil {
				name = *c.Process
			}
			ps, ok := procs[name]
			if !ok {
				ps = &procStats{name: name}
				procs[name] = ps
			}
			ps.conns++
			if c.RTT != nil {
				ps.totalRTT += *c.RTT
				ps.rttCount++
			}
			if c.DeltaBytesSent != nil {
				ps.totalSent += float64(*c.DeltaBytesSent)
			}
			if c.DeltaBytesReceived != nil {
				ps.totalRecv += float64(*c.DeltaBytesReceived)
			}
		}

		var psList []*procStats
		for _, ps := range procs {
			psList = append(psList, ps)
		}
		sort.Slice(psList, func(i, j int) bool { return psList[i].conns > psList[j].conns })

		if len(psList) > 20 {
			psList = psList[:20]
		}

		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("  %-15s %6s %8s %10s %10s\n", "Process", "Conns", "Avg RTT", "TX", "RX"))
		sb.WriteString("  " + strings.Repeat("─", 53) + "\n")
		for _, ps := range psList {
			avgRTT := "-"
			if ps.rttCount > 0 {
				avgRTT = fmt.Sprintf("%.1fms", ps.totalRTT/float64(ps.rttCount))
			}
			sb.WriteString(fmt.Sprintf("  %-15s %6d %8s %10s %10s\n",
				truncate(ps.name, 15),
				ps.conns,
				avgRTT,
				fmtBytesPerSec(ps.totalSent),
				fmtBytesPerSec(ps.totalRecv)))
		}
		return sb.String()
	}))

	b.WriteString("\n\n")

	// Top local ports
	b.WriteString(renderSection("Top Local Ports", func() string {
		type portStats struct {
			port  string
			conns int
		}
		ports := make(map[string]*portStats)
		for _, c := range snap.Conns {
			ps, ok := ports[c.LocalPort]
			if !ok {
				ps = &portStats{port: c.LocalPort}
				ports[c.LocalPort] = ps
			}
			ps.conns++
		}

		var psList []*portStats
		for _, ps := range ports {
			psList = append(psList, ps)
		}
		sort.Slice(psList, func(i, j int) bool { return psList[i].conns > psList[j].conns })

		if len(psList) > 15 {
			psList = psList[:15]
		}

		var sb strings.Builder
		for _, ps := range psList {
			sb.WriteString(fmt.Sprintf("  Port %-8s: %d connections\n", ps.port, ps.conns))
		}
		return sb.String()
	}))

	b.WriteString("\n\n")

	// Top TX (cumulative)
	b.WriteString(renderSection("Top TX (total bytes sent)", func() string {
		type txEntry struct {
			key   string
			bytes int
		}
		var entries []txEntry
		for _, c := range snap.Conns {
			if c.BytesSent != nil && *c.BytesSent > 0 {
				entries = append(entries, txEntry{key: c.ConnKey(), bytes: *c.BytesSent})
			}
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].bytes > entries[j].bytes })

		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("  %-40s %12s\n", "Connection", "Bytes Sent"))
		sb.WriteString("  " + strings.Repeat("─", 53) + "\n")
		for i, e := range entries {
			if i >= 10 {
				break
			}
			sb.WriteString(fmt.Sprintf("  %-40s %12s\n",
				truncate(e.key, 40), fmtBytes(&e.bytes)))
		}
		if len(entries) == 0 {
			sb.WriteString("  No data\n")
		}
		return sb.String()
	}))

	b.WriteString("\n\n")

	// Top RX (cumulative)
	b.WriteString(renderSection("Top RX (total bytes received)", func() string {
		type rxEntry struct {
			key   string
			bytes int
		}
		var entries []rxEntry
		for _, c := range snap.Conns {
			if c.BytesReceived != nil && *c.BytesReceived > 0 {
				entries = append(entries, rxEntry{key: c.ConnKey(), bytes: *c.BytesReceived})
			}
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].bytes > entries[j].bytes })

		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("  %-40s %15s\n", "Connection", "Bytes Received"))
		sb.WriteString("  " + strings.Repeat("─", 56) + "\n")
		for i, e := range entries {
			if i >= 10 {
				break
			}
			sb.WriteString(fmt.Sprintf("  %-40s %15s\n",
				truncate(e.key, 40), fmtBytes(&e.bytes)))
		}
		if len(entries) == 0 {
			sb.WriteString("  No data\n")
		}
		return sb.String()
	}))

	return b.String()
}
