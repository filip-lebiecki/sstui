package ui

import (
	"strings"
	"testing"

	"sstui/model"
)

func withSignals(sigs ...model.Signal) *model.Connection {
	return &model.Connection{Protocol: "tcp", State: "ESTAB", Signals: sigs}
}

func TestDiagnose(t *testing.T) {
	tests := []struct {
		name     string
		conn     *model.Connection
		wantSev  int
		wantSubs string // substring expected in the headline
	}{
		{"nil", nil, 0, ""},
		{"healthy", withSignals(), 0, "Healthy"},
		{"idle", withSignals(model.Signal{Type: model.SignalIdle, Severity: 0}), 0, "Idle"},
		{"zero window", withSignals(model.Signal{Type: model.SignalZeroWindow, Severity: 2}), 2, "receive window is zero"},
		{"socket drops wins", withSignals(
			model.Signal{Type: model.SignalRTTSpike, Severity: 1},
			model.Signal{Type: model.SignalSocketDrops, Severity: 2},
		), 2, "dropping data"},
		{"rwnd limited", withSignals(model.Signal{Type: model.SignalRwndLimited, Severity: 1}), 1, "receiver's window"},
		{"a listener's drops aren't unread data", func() *model.Connection {
			c := withSignals(model.Signal{Type: model.SignalSocketDrops, Severity: 2})
			c.State = "LISTEN"
			return c
		}(), 2, "Listener discarded incoming packets"},
		{"a full queue explains a listener's drops, at the worse severity", func() *model.Connection {
			c := withSignals(model.Signal{Type: model.SignalSocketDrops, Severity: 1}, model.Signal{Type: model.SignalListenQueueFull, Severity: 2})
			c.State = "LISTEN"
			return c
		}(), 2, "Accept queue full"},
		{"info-level context isn't a verdict", withSignals(
			model.Signal{Type: model.SignalSendBufferPressure, Severity: 0},
			model.Signal{Type: model.SignalHighRetransRate, Severity: 0},
		), 0, "Healthy"},
	}
	for _, tt := range tests {
		d := diagnose(tt.conn)
		if d.Severity != tt.wantSev {
			t.Errorf("%s: severity = %d, want %d", tt.name, d.Severity, tt.wantSev)
		}
		if tt.wantSubs != "" && !strings.Contains(d.Headline, tt.wantSubs) {
			t.Errorf("%s: headline %q should contain %q", tt.name, d.Headline, tt.wantSubs)
		}
	}
}

// TestDiagnosePrefersRootCause checks that a decisive root cause (zero window)
// is chosen over a downstream symptom (RTT spike) at equal-ish severity.
func TestDiagnosePrefersRootCause(t *testing.T) {
	c := withSignals(
		model.Signal{Type: model.SignalRTTSpike, Severity: 1},
		model.Signal{Type: model.SignalZeroWindow, Severity: 2},
	)
	if d := diagnose(c); !strings.Contains(d.Headline, "receive window is zero") {
		t.Errorf("expected zero-window root cause, got %q", d.Headline)
	}
}

// Drops during inbound loss with an empty queue are not a slow reader.
// (The classifier makes those drops info.)
func TestDiagnoseLossDrops(t *testing.T) {
	c := withSignals(
		model.Signal{Type: model.SignalSocketDrops, Severity: 0},
		model.Signal{Type: model.SignalInboundLoss, Severity: 1},
	)
	ooo := 30
	c.DeltaRcvOOOPack = &ooo
	d := diagnose(c)
	if !strings.Contains(d.Headline, "Inbound packet loss") || !strings.Contains(d.Hint, "discarding out-of-order data") {
		t.Errorf("want the inbound-loss verdict naming the discards, got %+v", d)
	}
}

// A connection hung after its handshake reads as a black hole, as in Findings.
func TestDiagnosePMTUBlackHole(t *testing.T) {
	c := withSignals(model.Signal{Type: model.SignalRTOFiring, Severity: 2})
	one, unacked, mss := 1, 11, 1448
	c.State, c.Delivered, c.Unacked, c.MSS = "ESTAB", &one, &unacked, &mss
	if d := diagnose(c); !strings.Contains(d.Headline, "path MTU black hole") || d.Severity != 2 {
		t.Errorf("want the black-hole verdict, got %+v", d)
	}
}

// Drops at a socket holding no receive memory are TCP's host-wide limit.
func TestDiagnoseMemoryRefusedDrops(t *testing.T) {
	c := withSignals(model.Signal{Type: model.SignalSocketDrops, Severity: 2})
	r, rb, ssthresh, mss := 0, 726839, 5792, 1448
	c.SkmemR, c.SkmemRB, c.RcvSSThresh, c.AdvMSS = &r, &rb, &ssthresh, &mss
	if d := diagnose(c); !strings.Contains(d.Headline, "TCP is short of memory host-wide") || d.Severity != 2 {
		t.Errorf("want the memory verdict, got %+v", d)
	}
}
