package ui

import (
	"sstui/classifier"
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
		{model.SignalCloseWaitLeak, "File-descriptor leak: process stuck on many CLOSE-WAIT sockets",
			"the app received the peer's FIN but isn't calling close()"},
		{model.SignalTimeWaitStorm, "TIME-WAIT storm toward this peer",
			"many short-lived connections — risks exhausting ephemeral ports; consider connection reuse"},
		{model.SignalSocketDrops, "Kernel dropping data at this socket",
			"buffer overran — the receiving end isn't reading fast enough"},
		{model.SignalListenQueueFull, "Accept queue full — new connections are being dropped",
			"the listening app isn't accept()ing fast enough; raise backlog / somaxconn"},
		{model.SignalSynStall, "Handshake stalled (SYN retransmitting)",
			"peer unreachable — check DNS, firewall, or routing"},
		{model.SignalZeroWindow, "Stalled: peer's receive window is zero",
			"the remote application has stopped reading from its socket"},
		{model.SignalRwndLimited, "Throughput limited by the receiver's window",
			"the receiver's buffer is too small for the path, or the app there reads slowly — the bottleneck is at that end, not the network"},
		{model.SignalSndbufLimited, "Throughput limited by the local send buffer",
			"the app has more to send, but the socket's buffer is too small for the path: an app-set SO_SNDBUF or a low tcp_wmem max"},
		{model.SignalRTOFiring, "Retransmission timeout firing repeatedly",
			"heavy loss or an unresponsive peer — the RTO is backing off"},
		{model.SignalPeerNoAck, "Peer stopped acknowledging data",
			"data has been outstanding a full poll with no ACK — peer hung, or the path/a middlebox is black-holing packets"},
		{model.SignalPathLoss, "Steady packet loss on the path",
			"data is retransmitted poll after poll without a queue building up — a lossy link or device, or a bottleneck with a very small buffer"},
		{model.SignalCongestionLoss, "Congestion loss — segments are being dropped on the path",
			"the path is saturated or lossy"},
		{model.SignalHighRetransRate, "High retransmit rate this poll",
			"a meaningful fraction of sent bytes are being resent"},
		{model.SignalInboundLoss, "Inbound packet loss — data from the peer arrives with gaps",
			"segments are lost (or reordered) between the peer and this host; check this host's RX drops, then the path from the peer"},
		{model.SignalReordering, "Packet reordering on the path",
			"the sender detected out-of-order delivery — often ECMP/LACP or multi-queue hashing, not congestion"},
		{model.SignalRecvBufferPressure, "Receive buffer filling up",
			"the local application isn't reading fast enough"},
		{model.SignalSendBufferPressure, "Send buffer backing up",
			"data is queued faster than the path can drain it"},
		{model.SignalRTTSpike, "Latency spike — RTT well above this connection's minimum",
			"transient congestion or a route change"},
		{model.SignalCWndCollapse, "Congestion window collapsed",
			"loss or ECN congestion marks just cut the sending rate sharply"},
	}

	lossDrops := classifier.DropsExplainedByInboundLoss(c)
	for _, r := range rules {
		if (r.sig == model.SignalRTOFiring || r.sig == model.SignalPeerNoAck) && classifier.HungAfterHandshake(c) {
			if s, ok := has(r.sig); ok && s.Severity > 0 {
				return Diagnosis{Headline: "Hung right after the handshake — likely a path MTU black hole",
					Hint:     "nothing acknowledged since the handshake while full-sized segments time out: a smaller MTU on the path, with ICMP \"fragmentation needed\" filtered",
					Severity: s.Severity}
			}
		}
		if r.sig == model.SignalSocketDrops && c.State == "LISTEN" {
			if s, ok := has(r.sig); ok {
				// A listener's drops aren't unread data: refused handshakes
				// or stray handshake segments. Only the host counters tell
				// which, so the Findings tab, not this view, decides.
				if q, full := has(model.SignalListenQueueFull); full {
					s.Severity = max(s.Severity, q.Severity)
					return Diagnosis{Headline: "Accept queue full — new connections are being dropped",
						Hint:     "the listening app isn't accept()ing fast enough; raise backlog / somaxconn",
						Severity: s.Severity}
				}
				return Diagnosis{Headline: "Listener discarded incoming packets",
					Hint:     "refused connection attempts (accept or SYN queue overflow) or stray handshake segments; the Findings tab says which",
					Severity: s.Severity}
			}
		}
		// Info-level signals are context (a full TCP send buffer, one poll's
		// retransmits), not a verdict; they're listed below the banner.
		if s, ok := has(r.sig); ok && s.Severity > 0 {
			if r.sig == model.SignalInboundLoss && lossDrops {
				return Diagnosis{Headline: r.headline,
					Hint:     "segments are lost (or reordered) between the peer and this host, and the kernel is also discarding out-of-order data — check this host's RX drops, then the path from the peer",
					Severity: s.Severity}
			}
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
