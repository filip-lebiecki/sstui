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

func fl(f float64) *float64 { return &f }

func TestLimitedSeverity(t *testing.T) {
	old := PollIntervalMS
	PollIntervalMS = 2000
	defer func() { PollIntervalMS = old }()

	tests := []struct {
		name string
		ms   *float64
		want int
	}{
		{"nil", nil, 0},
		{"zero", fl(0), 0},
		{"below warn (10%)", fl(200), 0},
		{"warn (40%)", fl(800), 1},
		{"crit (90%)", fl(1800), 2},
	}
	for _, tt := range tests {
		if got, _ := limitedSeverity(tt.ms); got != tt.want {
			t.Errorf("%s: limitedSeverity = %d, want %d", tt.name, got, tt.want)
		}
	}
}

func TestClassifyBottleneckRequiresSending(t *testing.T) {
	old := PollIntervalMS
	PollIntervalMS = 2000
	defer func() { PollIntervalMS = old }()

	// Heavily rwnd-limited but not sending: no signal (the limit is moot).
	idle := &model.Connection{Protocol: "tcp", State: "ESTAB", DeltaRwndLimitedMS: fl(1900)}
	if _, ok := sigByType(Classify(idle), model.SignalRwndLimited); ok {
		t.Errorf("rwnd-limited but idle should not fire RWND_LIM")
	}

	// Sending and rwnd-limited: fires.
	busy := &model.Connection{Protocol: "tcp", State: "ESTAB",
		DeltaBytesSent: ip(1), DeltaRwndLimitedMS: fl(1900)}
	if s, ok := sigByType(Classify(busy), model.SignalRwndLimited); !ok || s.Severity != 2 {
		t.Errorf("sending + rwnd-limited should fire crit, got %+v (present=%v)", s, ok)
	}
}

func hasSig(c *model.Connection, typ model.SignalType) bool {
	_, ok := sigByType(c.Signals, typ)
	return ok
}

func TestClassifyAggregateCloseWaitLeak(t *testing.T) {
	var conns []*model.Connection
	// 25 CLOSE-WAIT sockets on PID 100 (over the warn threshold of 20).
	for i := 0; i < 25; i++ {
		conns = append(conns, &model.Connection{Protocol: "tcp", State: "CLOSE-WAIT", PID: ip(100)})
	}
	// A healthy ESTAB on a different PID, and a lone CLOSE-WAIT on PID 200.
	conns = append(conns, &model.Connection{Protocol: "tcp", State: "ESTAB", PID: ip(200)})
	conns = append(conns, &model.Connection{Protocol: "tcp", State: "CLOSE-WAIT", PID: ip(200)})

	ClassifyAggregate(conns)

	for i := 0; i < 25; i++ {
		if !hasSig(conns[i], model.SignalCloseWaitLeak) {
			t.Fatalf("conn %d should carry CW_LEAK", i)
		}
	}
	if hasSig(conns[26], model.SignalCloseWaitLeak) {
		t.Errorf("a single CLOSE-WAIT on PID 200 should not be a leak")
	}
	if hasSig(conns[25], model.SignalCloseWaitLeak) {
		t.Errorf("the ESTAB socket should not carry CW_LEAK")
	}
}

func TestClassifyAggregateCloseWaitNeedsPID(t *testing.T) {
	var conns []*model.Connection
	for i := 0; i < 30; i++ {
		conns = append(conns, &model.Connection{Protocol: "tcp", State: "CLOSE-WAIT"}) // no PID
	}
	ClassifyAggregate(conns)
	for _, c := range conns {
		if hasSig(c, model.SignalCloseWaitLeak) {
			t.Fatalf("CLOSE-WAIT with unknown PID cannot be attributed to a leak")
		}
	}
}

func TestClassifyAggregateTimeWaitStorm(t *testing.T) {
	var conns []*model.Connection
	// 250 TIME-WAIT toward one peer endpoint (over warn 200), plus a few toward
	// another peer that should stay quiet.
	for i := 0; i < 250; i++ {
		conns = append(conns, &model.Connection{Protocol: "tcp", State: "TIME-WAIT",
			PeerAddr: "10.0.0.1", PeerPort: "443"})
	}
	for i := 0; i < 5; i++ {
		conns = append(conns, &model.Connection{Protocol: "tcp", State: "TIME-WAIT",
			PeerAddr: "10.0.0.2", PeerPort: "443"})
	}
	ClassifyAggregate(conns)

	if !hasSig(conns[0], model.SignalTimeWaitStorm) {
		t.Errorf("250 TIME-WAIT to one peer should raise TW_STORM")
	}
	if hasSig(conns[250], model.SignalTimeWaitStorm) {
		t.Errorf("5 TIME-WAIT to another peer should not raise TW_STORM")
	}
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
