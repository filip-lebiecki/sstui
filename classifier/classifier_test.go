package classifier

import (
	"testing"

	"sstui/model"
)

func ip(i int) *int { return &i }

func TestQueueSeverity(t *testing.T) {
	tests := []struct {
		name   string
		q      int
		bufCap *int
		want   int
	}{
		// Capacity-relative: judged as a fraction of the buffer.
		{"relative below warn", 1000, ip(100_000), 0},
		{"relative warn", 60_000, ip(100_000), 1},
		{"relative crit", 90_000, ip(100_000), 2},
		// Small absolute queue against a large buffer is not pressure.
		{"tiny vs large buffer", 200, ip(200_000), 0},
		// Absolute fallback when buffer size is unknown.
		{"absolute below warn", 8 * 1024, nil, 0},
		{"absolute warn", 20 * 1024, nil, 1},
		{"absolute crit", 70 * 1024, nil, 2},
		// The old 100-byte CRIT threshold must no longer fire.
		{"old noise floor stays quiet", 100, nil, 0},
	}
	for _, tt := range tests {
		if got := queueSeverity(tt.q, tt.bufCap); got != tt.want {
			t.Errorf("%s: queueSeverity(%d, %v) = %d, want %d", tt.name, tt.q, tt.bufCap, got, tt.want)
		}
	}
}

func TestQueuePressurePersistence(t *testing.T) {
	bufCap := ip(100_000)
	full := ip(90_000) // crit-level depth
	low := ip(100)     // not pressure

	// First poll (no prev) never fires, even at crit depth.
	if got := queuePressure(full, nil, bufCap); got != 0 {
		t.Errorf("first poll should not fire, got %d", got)
	}
	// Pressure on this poll but not the previous one: still suppressed.
	if got := queuePressure(full, low, bufCap); got != 0 {
		t.Errorf("single-poll spike should not fire, got %d", got)
	}
	// Sustained across both polls: fires at the current poll's severity.
	if got := queuePressure(full, full, bufCap); got != 2 {
		t.Errorf("sustained pressure should fire crit, got %d", got)
	}
}

// TestClassifyQueueNoiseSuppressed is the regression for the false-positive
// flood: a small, steady send queue on an ESTAB socket must produce no signal.
func TestClassifyQueueNoiseSuppressed(t *testing.T) {
	c := &model.Connection{
		Protocol: "tcp", State: "ESTAB",
		SendQ: ip(512), PrevSendQ: ip(512), SkmemTB: ip(200_000),
	}
	for _, s := range Classify(c) {
		if s.Type == model.SignalSendBufferPressure {
			t.Fatalf("a 512-byte send queue should not raise SEND_Q")
		}
	}
}

func sigByType(sigs []model.Signal, t model.SignalType) (model.Signal, bool) {
	for _, s := range sigs {
		if s.Type == t {
			return s, true
		}
	}
	return model.Signal{}, false
}

func TestClassifySocketDrops(t *testing.T) {
	// No new drops this poll: no signal.
	none := &model.Connection{Protocol: "udp", State: "UDP_ESTAB", DeltaSkmemD: ip(0)}
	if _, ok := sigByType(Classify(none), model.SignalSocketDrops); ok {
		t.Errorf("zero drop delta should not raise DROPS")
	}

	// A few drops: warn.
	warn := &model.Connection{Protocol: "udp", State: "UDP_ESTAB", DeltaSkmemD: ip(3)}
	if s, ok := sigByType(Classify(warn), model.SignalSocketDrops); !ok || s.Severity != 1 {
		t.Errorf("3 drops should warn, got %+v (present=%v)", s, ok)
	}

	// A burst: crit. Works on TCP too.
	crit := &model.Connection{Protocol: "tcp", State: "ESTAB", DeltaSkmemD: ip(50)}
	if s, ok := sigByType(Classify(crit), model.SignalSocketDrops); !ok || s.Severity != 2 {
		t.Errorf("50 drops should be crit, got %+v (present=%v)", s, ok)
	}
}
