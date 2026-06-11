package ui

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"sstui/poller"

	"github.com/charmbracelet/lipgloss"
)

var (
	styleSectionTitle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#5a56e7")).
				Bold(true).
				Padding(0, 1)

	styleBar = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#5a56e7"))

	styleBarDim = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#555555"))
)

// RenderOverview renders the overview view with timeseries and aggregate data.
func RenderOverview(buf *poller.Buffer, width, height int) string {
	snapshots := buf.GetAll()
	if len(snapshots) == 0 {
		return "\n  No data yet..."
	}

	var b strings.Builder

	// Connection count over time
	{
		var counts []float64
		for _, snap := range snapshots {
			counts = append(counts, float64(len(snap.Conns)))
		}
		stats := fmt.Sprintf("  (min: %.0f, max: %.0f)", getMin(counts), getMax(counts))
		b.WriteString(styleSectionTitle.Render(" Connections Over Time") + stats + "\n")
		b.WriteString("  " + renderBarChart(counts, min(width-32, 60), lipgloss.Color("#5a56e7")) + "\n")
	}

	b.WriteString("\n")

	// Average RTT over time
	{
		var rtts []float64
		var lastRTT float64 // carried forward across sample-less snapshots
		for _, snap := range snapshots {
			var sum, cnt float64
			for _, c := range snap.Conns {
				if c.RTT != nil {
					sum += *c.RTT
					cnt++
				}
			}
			if cnt > 0 {
				lastRTT = sum / cnt
			}
			// Carry the previous average forward when a snapshot has no RTT
			// samples (e.g. only UDP/LISTEN sockets) rather than injecting a 0,
			// which would drag the chart floor down and distort the curve.
			rtts = append(rtts, lastRTT)
		}
		stats := fmt.Sprintf("  (min: %.1fms, max: %.1fms)", getMin(rtts), getMax(rtts))
		b.WriteString(styleSectionTitle.Render(" Avg RTT Over Time") + stats + "\n")
		b.WriteString("  " + renderBarChart(rtts, min(width-32, 60), lipgloss.Color("#ffa94d")) + "\n")
	}

	b.WriteString("\n")

	// TX/RX rate over time
	{
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
		txStats := fmt.Sprintf("  (min: %s, max: %s)", fmtBytesPerSec(getMin(txVals)), fmtBytesPerSec(getMax(txVals)))
		rxStats := fmt.Sprintf("  (min: %s, max: %s)", fmtBytesPerSec(getMin(rxVals)), fmtBytesPerSec(getMax(rxVals)))
		b.WriteString(styleSectionTitle.Render(" Throughput Over Time") + "\n")
		b.WriteString("  TX:" + txStats + "\n")
		b.WriteString("  " + renderBarChart(txVals, chartW, lipgloss.Color("#51cf66")) + "\n")
		b.WriteString("  RX:" + rxStats + "\n")
		b.WriteString("  " + renderBarChart(rxVals, chartW, lipgloss.Color("#da77f2")) + "\n")
	}

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
			state string
			count int
		}
		var sc []stateCount
		for s, c := range states {
			sc = append(sc, stateCount{s, c})
		}
		sort.Slice(sc, func(i, j int) bool { return sc[i].count > sc[j].count })

		total := len(snap.Conns)
		maxBar := min(width-32, 40)
		var sb strings.Builder
		for _, s := range sc {
			pct := float64(s.count) / float64(total) * 100
			barLen := int(math.Round(float64(s.count) / float64(total) * float64(maxBar)))
			if barLen < 1 && s.count > 0 {
				barLen = 1
			}
			bar := styleBar.Render(strings.Repeat("█", barLen)) + styleBarDim.Render(strings.Repeat("░", maxBar-barLen))
			sb.WriteString(fmt.Sprintf("  %s %2d %6.1f%% %s\n",
				lipgloss.NewStyle().Foreground(StateColor(s.state)).Render(fmt.Sprintf("%-12s", s.state)),
				s.count, pct,
				bar))
		}
		return sb.String()
	}))

	return b.String()
}

func renderSection(title string, contentFn func() string) string {
	return styleSectionTitle.Render(" "+title) + "\n" + contentFn()
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

func renderBarChart(values []float64, width int, color lipgloss.Color) string {
	if len(values) == 0 || width <= 0 {
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

	levels := []rune("▁▂▃▄▅▆▇█")
	var b strings.Builder
	for _, v := range values {
		normalized := (v - minV) / rangeV
		idx := int(normalized * float64(len(levels)-1))
		b.WriteRune(levels[idx])
	}
	return lipgloss.NewStyle().Foreground(color).Render(b.String())
}
