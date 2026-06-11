package ui

import (
	"sstui/model"

	"github.com/charmbracelet/lipgloss"
)

// Diagnosis is a one-line, plain-English verdict for a connection, synthesized
// from its active signals. Headline is the verdict; Hint is an optional next
// step. Severity drives the color (0 healthy, 1 warn, 2 crit).
type Diagnosis struct {
	Headline string
	Hint     string
	Severity int
}

// diagnose turns a connection's signals into a single triage verdict. It picks
// the most actionable signal rather than listing all of them: the badges
// already enumerate what fired, so the diagnosis answers "what does this mean
// and what do I do". Rules are ordered by how decisive/actionable they are, not
// strictly by severity, so a clear root cause (e.g. zero window) wins over a
// downstream symptom (e.g. unacked buildup) even at equal severity.
func diagnose(c *model.Connection) Diagnosis {
	if c == nil {
		return Diagnosis{}
	}

	has := func(t model.SignalType) (model.Signal, bool) {
		for _, s := range c.Signals {
			if s.Type == t {
				return s, true
			}
		}
		return model.Signal{}, false
	}

	// Ordered rules: first match wins. Each names a root cause and a next step.
	rules := []struct {
		sig      model.SignalType
		headline string
		hint     string
	}{
		{model.SignalSocketDrops, "Kernel dropping data at this socket",
			"buffer overran — the receiving end isn't reading fast enough"},
		{model.SignalListenQueueFull, "Accept queue full — new connections are being dropped",
			"the listening app isn't accept()ing fast enough; raise backlog / somaxconn"},
		{model.SignalSynStall, "Handshake stalled (SYN retransmitting)",
			"peer unreachable — check DNS, firewall, or routing"},
		{model.SignalZeroWindow, "Stalled: peer's receive window is zero",
			"the remote application has stopped reading from its socket"},
		{model.SignalRwndLimited, "Throughput limited by the receiver's window",
			"the peer can't advertise window fast enough — it's the bottleneck, not you"},
		{model.SignalSndbufLimited, "Throughput limited by the local send buffer",
			"raise SO_SNDBUF or the app isn't writing fast enough"},
		{model.SignalRTOFiring, "Retransmission timeout firing repeatedly",
			"heavy loss or an unresponsive peer — the RTO is backing off"},
		{model.SignalCongestionLoss, "Congestion loss — segments are being dropped on the path",
			"the path is saturated or lossy"},
		{model.SignalHighRetransRate, "High retransmit rate this poll",
			"a meaningful fraction of sent bytes are being resent"},
		{model.SignalReordering, "Packet reordering on the path",
			"often a multipath / LACP / queue issue, not congestion"},
		{model.SignalRecvBufferPressure, "Receive buffer filling up",
			"the local application isn't reading fast enough"},
		{model.SignalSendBufferPressure, "Send buffer backing up",
			"data is queued faster than the path can drain it"},
		{model.SignalOneWayStall, "Traffic flowing one direction only",
			"possible half-closed peer or a stuck application read/write"},
		{model.SignalRTTSpike, "Latency spike — RTT well above this connection's minimum",
			"transient congestion or a route change"},
		{model.SignalCWndCollapse, "Congestion window collapsed",
			"a loss event just cut the sending rate sharply"},
	}

	for _, r := range rules {
		if s, ok := has(r.sig); ok {
			return Diagnosis{Headline: r.headline, Hint: r.hint, Severity: s.Severity}
		}
	}

	// No actionable fault. Distinguish "healthy and moving data" from "idle".
	if _, idle := has(model.SignalIdle); idle {
		return Diagnosis{Headline: "Idle — connection open, no bytes moving", Severity: 0}
	}
	// Surface the worst remaining (info-level) signal generically, else healthy.
	if worst := worstSeverity(c.Signals); worst > 0 {
		return Diagnosis{Headline: "Degraded — see signals below", Severity: worst}
	}
	return Diagnosis{Headline: "Healthy — no anomalies detected", Severity: 0}
}

func worstSeverity(sigs []model.Signal) int {
	w := 0
	for _, s := range sigs {
		if s.Severity > w {
			w = s.Severity
		}
	}
	return w
}

// RenderDiagnosis renders the diagnosis banner shown at the top of the Detail
// view: a colored verdict line plus an optional dim hint.
func RenderDiagnosis(c *model.Connection) string {
	d := diagnose(c)

	var color lipgloss.Color
	var glyph string
	switch d.Severity {
	case 2:
		color, glyph = lipgloss.Color("#ff6b6b"), "✖"
	case 1:
		color, glyph = lipgloss.Color("#ffa94d"), "▲"
	default:
		color, glyph = lipgloss.Color("#51cf66"), "✓"
	}

	line := lipgloss.NewStyle().Foreground(color).Bold(true).
		Render("  " + glyph + " " + d.Headline)
	if d.Hint != "" {
		line += "\n" + lipgloss.NewStyle().Foreground(lipgloss.Color("#888")).
			Render("    → "+d.Hint)
	}
	return line
}
