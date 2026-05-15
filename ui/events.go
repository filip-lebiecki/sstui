package ui

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"sstui/model"
	"sstui/poller"

	"github.com/charmbracelet/lipgloss"
)

// Event is a single signal-onset moment: the first poll in which a given
// signal type appeared on a connection after being absent (or after the
// connection first appeared in the ring buffer). Exported so the same list
// the Events tab renders can be written to JSON/CSV.
type Event struct {
	Timestamp time.Time
	Conn      *model.Connection // not serialized directly — we project relevant fields
	SigType   model.SignalType
	Severity  int
	Value     any
}

// CollectEvents walks the entire ring buffer and returns signal onsets in
// chronological order (oldest first). Info-level signals are filtered out.
// Drops keys absent from a snapshot so 4-tuple reuse doesn't suppress
// legitimate new signals on the reused tuple.
func CollectEvents(buf *poller.Buffer) []Event {
	snapshots := buf.GetAll()
	if len(snapshots) == 0 {
		return nil
	}

	prev := make(map[string]map[model.SignalType]bool)
	var events []Event

	for _, snap := range snapshots {
		seen := make(map[string]map[model.SignalType]bool, len(snap.Conns))
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
					events = append(events, Event{
						Timestamp: snap.Timestamp,
						Conn:      c,
						SigType:   s.Type,
						Severity:  s.Severity,
						Value:     s.Value,
					})
				}
			}
			seen[key] = cur
		}
		prev = seen
	}
	return events
}

// RenderEvents renders the Events tab. `scroll` is the number of events to
// skip from the *newest* end (0 = top, increases as the user scrolls toward
// older events). The renderer caps overflows internally — callers can pass
// any non-negative offset.
func RenderEvents(buf *poller.Buffer, width, height, scroll int) string {
	events := CollectEvents(buf)
	snapshotCount := buf.Count()

	var b strings.Builder
	b.WriteString(styleSectionTitle.Render(" Signal Events") + " " +
		styleTopDim.Render(fmt.Sprintf("(%d total — newest first, scanning %d snapshots)",
			len(events), snapshotCount)) + "\n\n")

	if len(events) == 0 {
		b.WriteString("  No signal onsets recorded.\n")
		b.WriteString(styleTopDim.Render("  Events fire when a connection acquires a warn/crit signal it didn't have a poll ago.") + "\n")
		return b.String()
	}

	// Visible window: rows for events after header/title/footer hint.
	rows := height - 5
	if rows < 1 {
		rows = 1
	}

	maxScroll := len(events) - rows
	if maxScroll < 0 {
		maxScroll = 0
	}
	if scroll > maxScroll {
		scroll = maxScroll
	}
	if scroll < 0 {
		scroll = 0
	}

	// Reverse-chronological: index 0 in display = events[len-1]. scroll skips
	// from the newest end backward in time.
	newestIdx := len(events) - 1 - scroll
	oldestIdx := newestIdx - rows + 1
	if oldestIdx < 0 {
		oldestIdx = 0
	}

	// Column header.
	b.WriteString(fmt.Sprintf("  %s %s %s %s %s %s\n",
		styleTopHdr.Render(fmt.Sprintf("%-8s", "Time")),
		styleTopHdr.Render(fmt.Sprintf("%-4s", "Sev")),
		styleTopHdr.Render(fmt.Sprintf("%-11s", "Signal")),
		styleTopHdr.Render(fmt.Sprintf("%-4s", "Proto")),
		styleTopHdr.Render(fmt.Sprintf("%-32s", "Peer")),
		styleTopHdr.Render("Process / detail")))

	for i := newestIdx; i >= oldestIdx; i-- {
		ev := events[i]
		peer, proc := connLabel(ev.Conn)

		sevTag, sevColor := severityTag(ev.Severity)
		sigColor := signalColors[ev.SigType]
		if sigColor == "" {
			sigColor = lipgloss.Color("#888")
		}

		detail := proc
		if ev.Value != nil {
			detail = fmt.Sprintf("%-15s  %s", truncate(proc, 15), fmtEventValue(ev.Value))
		}

		b.WriteString(fmt.Sprintf("  %s %s %s %s %s %s\n",
			styleTopDim.Render(ev.Timestamp.Format("15:04:05")),
			lipgloss.NewStyle().Foreground(sevColor).Bold(true).Render(fmt.Sprintf("%-4s", sevTag)),
			lipgloss.NewStyle().Foreground(sigColor).Bold(true).Render(fmt.Sprintf("%-11s", ev.SigType.Label())),
			protoTag(ev.Conn.Protocol),
			styleTopAddr.Render(fmt.Sprintf("%-32s", truncate(peer, 32))),
			styleTopProc.Render(detail)))
	}

	// Position hint at the bottom.
	hint := fmt.Sprintf("  showing %d-%d of %d  [j/k] scroll  [g/G] top/bottom  [e/E] export",
		len(events)-newestIdx, len(events)-oldestIdx, len(events))
	b.WriteString(styleTopDim.Render(hint))
	return b.String()
}

// MaxEventsScroll returns the largest valid scroll offset for the current
// buffer + viewport so callers can cap input keys without re-collecting
// events themselves.
func MaxEventsScroll(buf *poller.Buffer, height int) int {
	events := CollectEvents(buf)
	rows := height - 5
	if rows < 1 {
		rows = 1
	}
	m := len(events) - rows
	if m < 0 {
		return 0
	}
	return m
}

// severityTag returns a short tag and color for a warn/crit severity.
// Info-level signals are filtered before they reach this point, so only
// the two non-zero cases are reachable.
func severityTag(sev int) (string, lipgloss.Color) {
	if sev >= 2 {
		return "CRIT", lipgloss.Color("#ff6b6b")
	}
	return "WARN", lipgloss.Color("#ffa94d")
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

// ExportEventsJSON writes the events list to a JSON file. Returns the number
// of events written.
func ExportEventsJSON(events []Event, path string) (int, error) {
	type exported struct {
		Timestamp time.Time        `json:"timestamp"`
		Signal    model.SignalType `json:"signal"`
		Label     string           `json:"label"`
		Severity  int              `json:"severity"`
		Value     any              `json:"value,omitempty"`
		Proto     string           `json:"proto"`
		LocalAddr string           `json:"local_addr"`
		LocalPort string           `json:"local_port"`
		PeerAddr  string           `json:"peer_addr"`
		PeerPort  string           `json:"peer_port"`
		Process   string           `json:"process,omitempty"`
		PID       *int             `json:"pid,omitempty"`
	}

	out := make([]exported, 0, len(events))
	for _, e := range events {
		proc := ""
		if e.Conn.Process != nil {
			proc = *e.Conn.Process
		}
		out = append(out, exported{
			Timestamp: e.Timestamp,
			Signal:    e.SigType,
			Label:     e.SigType.Label(),
			Severity:  e.Severity,
			Value:     e.Value,
			Proto:     e.Conn.Protocol,
			LocalAddr: e.Conn.LocalAddr,
			LocalPort: e.Conn.LocalPort,
			PeerAddr:  e.Conn.PeerAddr,
			PeerPort:  e.Conn.PeerPort,
			Process:   proc,
			PID:       e.Conn.PID,
		})
	}

	f, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return 0, err
	}
	return len(out), nil
}

// ExportEventsCSV writes the events list as a flat CSV.
func ExportEventsCSV(events []Event, path string) (int, error) {
	f, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	header := []string{
		"timestamp", "signal", "label", "severity", "value",
		"proto", "local_addr", "local_port", "peer_addr", "peer_port",
		"process", "pid",
	}
	if err := w.Write(header); err != nil {
		return 0, err
	}

	for _, e := range events {
		proc := ""
		if e.Conn.Process != nil {
			proc = *e.Conn.Process
		}
		pid := ""
		if e.Conn.PID != nil {
			pid = strconv.Itoa(*e.Conn.PID)
		}
		val := ""
		if e.Value != nil {
			val = fmtEventValue(e.Value)
		}
		row := []string{
			e.Timestamp.UTC().Format(time.RFC3339Nano),
			string(e.SigType), e.SigType.Label(),
			strconv.Itoa(e.Severity), val,
			e.Conn.Protocol,
			e.Conn.LocalAddr, e.Conn.LocalPort,
			e.Conn.PeerAddr, e.Conn.PeerPort,
			proc, pid,
		}
		if err := w.Write(row); err != nil {
			return 0, err
		}
	}
	return len(events), w.Error()
}
