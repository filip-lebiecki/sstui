package ui

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"ss-stats-tui/poller"

	"github.com/charmbracelet/lipgloss"
)

var (
	styleSectionTitle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#5a56e7")).
		Bold(true).
		Padding(0, 1)

	styleBar = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#5a56e7"))
)

// RenderOverview renders the overview view with timeseries and aggregate data.
func RenderOverview(buf *poller.Buffer, width, height int) string {
	snapshots := buf.GetAll()
	if len(snapshots) == 0 {
		return "\n  No data yet..."
	}

	var b strings.Builder

	// Connection count over time
	b.WriteString(renderSection("Connections Over Time", func() string {
		var counts []float64
		for _, snap := range snapshots {
			counts = append(counts, float64(len(snap.Conns)))
		}
		return renderSparkline(counts, min(width-30, 60), lipgloss.Color("#5a56e7")) +
			fmt.Sprintf("  (min: %.0f, max: %.0f)", getMin(counts), getMax(counts))
	}))

	b.WriteString("\n")

	// Average RTT over time
	b.WriteString(renderSection("Avg RTT Over Time", func() string {
		var rtts []float64
		for _, snap := range snapshots {
			var sum, cnt float64
			for _, c := range snap.Conns {
				if c.RTT != nil {
					sum += *c.RTT
					cnt++
				}
			}
			if cnt > 0 {
				rtts = append(rtts, sum/cnt)
			} else {
				rtts = append(rtts, 0)
			}
		}
		return renderSparkline(rtts, min(width-30, 60), lipgloss.Color("#ffa94d")) +
			fmt.Sprintf("  (min: %.1fms, max: %.1fms)", getMin(rtts), getMax(rtts))
	}))

	b.WriteString("\n")

	// TX/RX rate over time
	b.WriteString(renderSection("Throughput Over Time", func() string {
		var txVals, rxVals []float64
		for _, snap := range snapshots {
			var tx, rx float64
			for _, c := range snap.Conns {
				if c.DeltaBytesSent != nil {
					tx += float64(*c.DeltaBytesSent)
				}
				if c.DeltaBytesReceived != nil {
					rx += float64(*c.DeltaBytesReceived)
				}
			}
			txVals = append(txVals, tx)
			rxVals = append(rxVals, rx)
		}
		chartW := min((width-40)/2, 30)
		return "TX: " + renderSparkline(txVals, chartW, lipgloss.Color("#51cf66")) + "\n  "+
			"RX: " + renderSparkline(rxVals, chartW, lipgloss.Color("#da77f2"))
	}))

	b.WriteString("\n\n")

	// State distribution
	b.WriteString(renderSection("State Distribution", func() string {
		snap := buf.GetLatest()
		if snap == nil {
			return "-"
		}
		states := make(map[string]int)
		for _, c := range snap.Conns {
			states[c.State]++
		}

		type stateCount struct {
			state  string
			count  int
		}
		var sc []stateCount
		for s, c := range states {
			sc = append(sc, stateCount{s, c})
		}
		sort.Slice(sc, func(i, j int) bool { return sc[i].count > sc[j].count })

		total := len(snap.Conns)
		maxBar := min(width-40, 40)
		var sb strings.Builder
		for _, s := range sc {
			pct := float64(s.count) / float64(total) * 100
			barLen := int(math.Round(float64(s.count) / float64(total) * float64(maxBar)))
			if barLen < 1 && s.count > 0 {
				barLen = 1
			}
			bar := strings.Repeat("█", barLen)
			sb.WriteString(fmt.Sprintf("  %-10s %3d (%5.1f%%) %s\n",
				lipgloss.NewStyle().Foreground(StateColor(s.state)).Render(s.state),
				s.count, pct,
				styleBar.Render(bar)))
		}
		return sb.String()
	}))

	b.WriteString("\n\n")

	// Group by process
	b.WriteString(renderSection("Top Processes", func() string {
		snap := buf.GetLatest()
		if snap == nil {
			return "-"
		}

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

		header := fmt.Sprintf("  %-15s %6s %8s %10s %10s\n", "Process", "Conns", "Avg RTT", "TX", "RX")
		var sb strings.Builder
		sb.WriteString(header)
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

	// Group by local port
	b.WriteString(renderSection("Top Local Ports", func() string {
		snap := buf.GetLatest()
		if snap == nil {
			return "-"
		}

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

	return b.String()
}

func renderSection(title string, contentFn func() string) string {
	return styleSectionTitle.Render(" " + title) + "\n" + contentFn()
}

func getMin(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	m := vals[0]
	for _, v := range vals[1:] {
		if v < m {
			m = v
		}
	}
	return m
}

func getMax(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	m := vals[0]
	for _, v := range vals[1:] {
		if v > m {
			m = v
		}
	}
	return m
}
