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

// TestClassifyZeroWindowPersistTimer is the regression for ZERO_WIN never
// firing: ss omits snd_wnd when it is 0, so a stalled sender shows no snd_wnd
// at all — only the persist (zero-window probe) timer.
func TestClassifyZeroWindowPersistTimer(t *testing.T) {
	persist, dur := "persist", "2.456sec"
	c := &model.Connection{Protocol: "tcp", State: "ESTAB",
		TimerType: &persist, TimerDur: &dur, SndWnd: nil, DeltaBytesSent: ip(0)}
	if s, ok := sigByType(Classify(c), model.SignalZeroWindow); !ok || s.Severity != 2 {
		t.Errorf("persist timer should raise crit ZERO_WIN, got %+v (present=%v)", s, ok)
	}

	// Persist timer armed for a tiny but non-zero window: ss prints snd_wnd,
	// and the reported value wins.
	tiny := &model.Connection{Protocol: "tcp", State: "ESTAB", TimerType: &persist, SndWnd: ip(900)}
	if _, ok := sigByType(Classify(tiny), model.SignalZeroWindow); ok {
		t.Errorf("reported snd_wnd:900 should not raise ZERO_WIN even with persist timer")
	}

	keepalive := "keepalive"
	healthy := &model.Connection{Protocol: "tcp", State: "ESTAB",
		TimerType: &keepalive, SndWnd: ip(65536)}
	if _, ok := sigByType(Classify(healthy), model.SignalZeroWindow); ok {
		t.Errorf("open window with keepalive timer should not raise ZERO_WIN")
	}
}

// TestClassifyRTTSpikeFloor: a large RTT/MinRTT ratio on a sub-millisecond
// path (loopback, LAN) is jitter, not a spike; the same ratio with a real
// absolute excess is.
func TestClassifyRTTSpikeFloor(t *testing.T) {
	loopback := &model.Connection{Protocol: "tcp", State: "ESTAB", RTT: fl(0.402), MinRTT: fl(0.049)}
	if _, ok := sigByType(Classify(loopback), model.SignalRTTSpike); ok {
		t.Errorf("0.402ms vs 0.049ms min (8x, <1ms excess) should not raise RTT_SPIKE")
	}
	wan := &model.Connection{Protocol: "tcp", State: "ESTAB", RTT: fl(120), MinRTT: fl(10)}
	if s, ok := sigByType(Classify(wan), model.SignalRTTSpike); !ok || s.Severity != 1 {
		t.Errorf("120ms vs 10ms min should warn RTT_SPIKE, got %+v (present=%v)", s, ok)
	}
}

// TestClassifyPeerNoAck: NO_ACK needs data outstanding on two consecutive
// polls with nothing ACKed in between — not just unacked > 0 once.
func TestClassifyPeerNoAck(t *testing.T) {
	stuck := &model.Connection{Protocol: "tcp", State: "ESTAB",
		Unacked: ip(5), PrevUnacked: ip(5), DeltaBytesAcked: ip(0), LastAck: ip(12000)}
	if s, ok := sigByType(Classify(stuck), model.SignalPeerNoAck); !ok || s.Severity != 2 {
		t.Errorf("12s without an ACK while data is outstanding should be crit NO_ACK, got %+v (present=%v)", s, ok)
	}

	// Idle connection that just sent: outstanding now, but not last poll.
	justSent := &model.Connection{Protocol: "tcp", State: "ESTAB",
		Unacked: ip(1), PrevUnacked: ip(0), DeltaBytesAcked: ip(0), LastAck: ip(60000)}
	// Bulk upload: outstanding on both polls but the peer is ACKing.
	bulk := &model.Connection{Protocol: "tcp", State: "ESTAB",
		Unacked: ip(40), PrevUnacked: ip(40), DeltaBytesAcked: ip(5_000_000), LastAck: ip(2)}
	// Short --interval on a slow path: two polls inside one round trip.
	slowRTT := &model.Connection{Protocol: "tcp", State: "ESTAB", RTO: fl(350),
		Unacked: ip(3), PrevUnacked: ip(3), DeltaBytesAcked: ip(0), LastAck: ip(150)}
	for name, c := range map[string]*model.Connection{"just sent": justSent, "bulk upload": bulk, "within one RTT": slowRTT} {
		if _, ok := sigByType(Classify(c), model.SignalPeerNoAck); ok {
			t.Errorf("%s should not raise NO_ACK", name)
		}
	}
}

// TestClassifyReorderingUsesReordSeen: receiver-side out-of-order packets
// (rcv_ooopack) also follow plain loss, so only sender-detected reordering
// counts.
func TestClassifyReorderingUsesReordSeen(t *testing.T) {
	lossOnly := &model.Connection{Protocol: "tcp", State: "ESTAB", DeltaRcvOOOPack: ip(30)}
	if _, ok := sigByType(Classify(lossOnly), model.SignalReordering); ok {
		t.Errorf("rcv_ooopack growth alone should not raise REORDER")
	}
	reord := &model.Connection{Protocol: "tcp", State: "ESTAB", DeltaReordSeen: ip(3)}
	if s, ok := sigByType(Classify(reord), model.SignalReordering); !ok || s.Severity != 1 {
		t.Errorf("reord_seen growth should warn REORDER, got %+v (present=%v)", s, ok)
	}
}

// TestClassifyCWndCollapse: a sharp cwnd cut fires only with loss or ECN
// marks in the same poll; a cut without them (restart after idle, cwnd
// validation) and BBR's ProbeRTT drop to 4 packets (cwnd_gain 1) are by
// design. Without bytes_retrans (old kernel) there's no evidence, so no signal.
func TestClassifyCWndCollapse(t *testing.T) {
	collapse := func(prev, cur int) *model.Connection {
		return &model.Connection{Protocol: "tcp", State: "ESTAB", PrevCWnd: ip(prev), CWnd: ip(cur),
			DeltaBytesRetrans: ip(0), DeltaDeliveredCE: ip(0)}
	}
	cases := []struct {
		name    string
		c       *model.Connection
		wantSev int // 0 = no signal
		wantVal string
	}{
		{"idle restart, no loss", collapse(241, 100), 0, ""},
		{"loss: bytes retransmitted", func() *model.Connection { c := collapse(100, 40); c.DeltaBytesRetrans = ip(7240); return c }(), 1, "100→40 after loss"},
		{"loss: packets marked lost", func() *model.Connection { c := collapse(100, 20); c.Lost = ip(3); return c }(), 2, "100→20 after loss"},
		{"ECN marks", func() *model.Connection { c := collapse(100, 40); c.DeltaDeliveredCE = ip(12); return c }(), 1, "100→40 after ECN marks"},
		{"old kernel, no evidence", &model.Connection{Protocol: "tcp", State: "ESTAB", PrevCWnd: ip(100), CWnd: ip(40)}, 0, ""},
		{"BBR ProbeRTT on a lossy path", func() *model.Connection {
			c := collapse(698, 4)
			c.BBRCWndGain, c.DeltaBytesRetrans = fl(1), ip(1448)
			return c
		}(), 0, ""},
		{"BBR PROBE_BW loss", func() *model.Connection {
			c := collapse(698, 4)
			c.BBRCWndGain, c.DeltaBytesRetrans = fl(2), ip(1448)
			return c
		}(), 2, "698→4 after loss"},
	}
	for _, tc := range cases {
		s, ok := sigByType(Classify(tc.c), model.SignalCWndCollapse)
		switch {
		case tc.wantSev == 0 && ok:
			t.Errorf("%s: want no CWND_DROP, got %+v", tc.name, s)
		case tc.wantSev > 0 && (!ok || s.Severity != tc.wantSev || s.Value != tc.wantVal):
			t.Errorf("%s: want CWND_DROP sev %d %q, got %+v (present=%v)", tc.name, tc.wantSev, tc.wantVal, s, ok)
		}
	}
}

// TestClassifyCwndLimitedIsInfo: a full congestion window is healthy bulk
// transfer, so CWND_LIM is informational.
func TestClassifyCwndLimitedIsInfo(t *testing.T) {
	c := &model.Connection{Protocol: "tcp", State: "ESTAB", Unacked: ip(38), CWnd: ip(40)}
	if s, ok := sigByType(Classify(c), model.SignalCwndLimited); !ok || s.Severity != 0 {
		t.Errorf("want info-level CWND_LIM, got %+v (present=%v)", s, ok)
	}
}

// TestClassifyInboundLoss: segments arriving after a gap as a share of data
// received, with a minimum of traffic before judging.
func TestClassifyInboundLoss(t *testing.T) {
	cases := []struct {
		name    string
		ooo, in int
		want    int // severity, 0 = no signal
	}{
		{"clean", 0, 1000, 0},
		{"below warn", 10, 1000, 0},
		{"warn", 30, 1000, 1},
		{"crit", 150, 1000, 2},
		{"too little data to judge", 20, 50, 0},
	}
	for _, tc := range cases {
		c := &model.Connection{Protocol: "tcp", State: "ESTAB", DeltaRcvOOOPack: ip(tc.ooo), DeltaDataSegsIn: ip(tc.in)}
		s, ok := sigByType(Classify(c), model.SignalInboundLoss)
		if got := map[bool]int{true: s.Severity}[ok]; got != tc.want {
			t.Errorf("%s: severity %d, want %d (%+v)", tc.name, got, tc.want, s)
		}
	}
}

func TestDropsExplainedByInboundLoss(t *testing.T) {
	drops := model.Signal{Type: model.SignalSocketDrops, Severity: 1}
	rx := model.Signal{Type: model.SignalInboundLoss, Severity: 1}
	rcvq := model.Signal{Type: model.SignalRecvBufferPressure, Severity: 1}
	for name, tc := range map[string]struct {
		sigs []model.Signal
		want bool
	}{
		"drops under inbound loss, empty queue": {[]model.Signal{drops, rx}, true},
		"drops with a full receive queue":       {[]model.Signal{drops, rx, rcvq}, false},
		"drops without loss":                    {[]model.Signal{drops}, false},
		"loss without drops":                    {[]model.Signal{rx}, false},
	} {
		if got := DropsExplainedByInboundLoss(tc.sigs); got != tc.want {
			t.Errorf("%s: got %v, want %v", name, got, tc.want)
		}
	}
}
