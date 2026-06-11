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
// is chosen over a downstream symptom (unacked buildup) at equal-ish severity.
func TestDiagnosePrefersRootCause(t *testing.T) {
	c := withSignals(
		model.Signal{Type: model.SignalUnackedBuildup, Severity: 1},
		model.Signal{Type: model.SignalZeroWindow, Severity: 2},
	)
	if d := diagnose(c); !strings.Contains(d.Headline, "receive window is zero") {
		t.Errorf("expected zero-window root cause, got %q", d.Headline)
	}
}
