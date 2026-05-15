package ui

import (
	"fmt"
	"strings"
	"time"

	"ss-stats-tui/model"
	"ss-stats-tui/poller"

	"github.com/charmbracelet/lipgloss"
)

// event represents a single signal-onset moment: the first poll in which a
// given signal type appeared on a connection after being absent (or after the
// connection first appeared).
type event struct {
	ts       time.Time
	conn     *model.Connection // pointer to the snapshot's connection at the time the signal fired
	sigType  model.SignalType
	severity int
	value    any
}

// RenderEvents walks the ring buffer and lists signal-onset events in reverse
// chronological order. Info-level signals (IDLE, APP_LIMITED) are skipped to
// keep the log focused on real anomalies.
func RenderEvents(buf *poller.Buffer, width, height int) string {
	snapshots := buf.GetAll()
	if len(snapshots) == 0 {
		return "\n  No data yet..."
	}

	// Track which signal types were active on each connection in the *previous*
	// snapshot it appeared in. A signal counts as a new event when it's in the
	// current snapshot's signal set but not in the prior one.
	prev := make(map[string]map[model.SignalType]bool)
	var events []event

	for _, snap := range snapshots {
		for _, c := range snap.Conns {
			key := c.ConnKey()
			before := prev[key]
			cur := make(map[model.SignalType]bool, len(c.Signals))
			for _, s := range c.Signals {
				cur[s.Type] = true
				if s.Severity == 0 {
					continue
				}
				if !before[s.Type] {
					events = append(events, event{
						ts:       snap.Timestamp,
						conn:     c,
						sigType:  s.Type,
						severity: s.Severity,
						value:    s.Value,
					})
				}
			}
			prev[key] = cur
		}
	}

	var b strings.Builder
	b.WriteString(styleSectionTitle.Render(" Signal Events") + " " +
		styleTopDim.Render(fmt.Sprintf("(%d total — newest first, scanning %d snapshots)",
			len(events), len(snapshots))) + "\n\n")

	if len(events) == 0 {
		b.WriteString("  No signal onsets recorded.\n")
		b.WriteString(styleTopDim.Render("  Events fire when a connection acquires a warn/crit signal it didn't have a poll ago.") + "\n")
		return b.String()
	}

	// Reverse-chronological — show newest first.
	rows := height - 4
	if rows < 1 {
		rows = 1
	}
	end := len(events)
	start := end - rows
	if start < 0 {
		start = 0
	}

	// Column header.
	b.WriteString(fmt.Sprintf("  %s %s %s %s %s %s\n",
		styleTopHdr.Render(fmt.Sprintf("%-8s", "Time")),
		styleTopHdr.Render(fmt.Sprintf("%-4s", "Sev")),
		styleTopHdr.Render(fmt.Sprintf("%-11s", "Signal")),
		styleTopHdr.Render(fmt.Sprintf("%-4s", "Proto")),
		styleTopHdr.Render(fmt.Sprintf("%-32s", "Peer")),
		styleTopHdr.Render("Process / detail")))

	for i := end - 1; i >= start; i-- {
		ev := events[i]
		peer, proc := connLabel(ev.conn)

		sevTag, sevColor := severityTag(ev.severity)
		sigColor := signalColors[ev.sigType]
		if sigColor == "" {
			sigColor = lipgloss.Color("#888")
		}

		detail := proc
		if ev.value != nil {
			detail = fmt.Sprintf("%-15s  %s", truncate(proc, 15), fmtEventValue(ev.value))
		}

		b.WriteString(fmt.Sprintf("  %s %s %s %s %s %s\n",
			styleTopDim.Render(ev.ts.Format("15:04:05")),
			lipgloss.NewStyle().Foreground(sevColor).Bold(true).Render(fmt.Sprintf("%-4s", sevTag)),
			lipgloss.NewStyle().Foreground(sigColor).Bold(true).Render(fmt.Sprintf("%-11s", ev.sigType.Label())),
			protoTag(ev.conn.Protocol),
			styleTopAddr.Render(fmt.Sprintf("%-32s", truncate(peer, 32))),
			styleTopProc.Render(detail)))
	}

	if start > 0 {
		b.WriteString(styleTopDim.Render(fmt.Sprintf("  … %d older events not shown\n", start)))
	}
	return b.String()
}

func severityTag(sev int) (string, lipgloss.Color) {
	switch sev {
	case 2:
		return "CRIT", lipgloss.Color("#ff6b6b")
	case 1:
		return "WARN", lipgloss.Color("#ffa94d")
	}
	return "INFO", lipgloss.Color("#868e96")
}

func fmtEventValue(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case float64:
		return fmt.Sprintf("%.2f", x)
	case int:
		return fmt.Sprintf("%d", x)
	}
	return fmt.Sprintf("%v", v)
}
