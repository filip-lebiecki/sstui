package classifier

import (
	"testing"
	"time"

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
func sp(s string) *string   { return &s }

func TestLimitedSeverity(t *testing.T) {
	old := PollIntervalMS
	PollIntervalMS = 2000
	defer func() { PollIntervalMS = old }()

	tests := []struct {
		name     string
		ms, prev *float64
		want     int
	}{
		{"nil", nil, fl(1800), 0},
		{"zero", fl(0), fl(1800), 0},
		{"below warn (10%)", fl(200), fl(1800), 0},
		{"warn (40%)", fl(800), fl(1800), 1},
		{"crit (90%)", fl(1800), fl(1800), 2},
		{"crit after a warn poll", fl(1800), fl(800), 2},
		{"one poll alone", fl(1800), fl(200), 0},
		{"no previous poll", fl(1800), nil, 0},
	}
	for _, tt := range tests {
		if got, _ := limitedSeverity(tt.ms, tt.prev); got != tt.want {
			t.Errorf("%s: limitedSeverity = %d, want %d", tt.name, got, tt.want)
		}
	}
}

func TestClassifyBottleneckRequiresSending(t *testing.T) {
	old := PollIntervalMS
	PollIntervalMS = 2000
	defer func() { PollIntervalMS = old }()

	// Heavily rwnd-limited but not sending: no signal (the limit is moot).
	idle := &model.Connection{Protocol: "tcp", State: "ESTAB", DeltaRwndLimitedMS: fl(1900), PrevDeltaRwndLimitedMS: fl(1900)}
	if _, ok := sigByType(Classify(idle), model.SignalRwndLimited); ok {
		t.Errorf("rwnd-limited but idle should not fire RWND_LIM")
	}

	// Sending and rwnd-limited: fires.
	busy := &model.Connection{Protocol: "tcp", State: "ESTAB",
		DeltaBytesSent: ip(1), DeltaRwndLimitedMS: fl(1900), PrevDeltaRwndLimitedMS: fl(1900)}
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

// TestReordering: steady reord_seen growth over the window is reordering;
// the stray event or two loss recovery and request bursts produce isn't, and
// neither is out-of-order arrival at the receiver (rcv_ooopack), which plain
// loss causes too. reord(n, steady, events) builds n complete 2 s slots of
// 1.448 MB (1000 segments) each, the first `steady` of them with `events`
// reordering events.
func TestReordering(t *testing.T) {
	t0 := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	reord := func(n, steady, events int) *model.Connection {
		c := &model.Connection{Protocol: "tcp", State: "ESTAB", MSS: ip(1448), DeltaRcvOOOPack: ip(30)}
		for i := range n {
			s := model.SendSlot{Start: t0.Add(time.Duration(2*i) * time.Second), End: t0.Add(time.Duration(2*i+2) * time.Second), Sent: 1_448_000}
			if i < steady {
				s.Reord = events
			}
			c.SendSlots = append(c.SendSlots, s)
		}
		return c
	}
	for _, tt := range []struct {
		name    string
		c       *model.Connection
		wantSev int
	}{
		{"steady reordering", reord(6, 6, 9), 1},
		{"heavy reordering", reord(6, 6, 80), 2},
		{"in half the slots", reord(6, 3, 9), 1},
		{"stray events in two slots", reord(6, 2, 2), 0},
		{"steady but below 0.1% of segments", func() *model.Connection {
			c := reord(6, 6, 1)
			for i := range c.SendSlots {
				c.SendSlots[i].Sent *= 10 // 1 event per 10,000 segments
			}
			return c
		}(), 0},
		{"too little history", reord(3, 3, 9), 0},
		{"no MSS to count segments", func() *model.Connection { c := reord(6, 6, 9); c.MSS = nil; return c }(), 0},
		{"receiver-side out-of-order only", &model.Connection{Protocol: "tcp", State: "ESTAB", DeltaRcvOOOPack: ip(30)}, 0},
		{"under steady path loss the counter proves nothing", func() *model.Connection {
			c := reord(6, 6, 9)
			c.MinRTT = fl(40)
			for i := range c.SendSlots {
				c.SendSlots[i].Retrans = 30_000 // ~2% retransmitted, steady, no queue: PATH_LOSS
				c.SendSlots[i].QueueMS = []float64{1}
			}
			if _, ok := sigByType(Classify(c), model.SignalPathLoss); !ok {
				t.Fatal("setup: this case needs PATH_LOSS to fire")
			}
			return c
		}(), 0},
	} {
		s, ok := sigByType(Classify(tt.c), model.SignalReordering)
		switch {
		case tt.wantSev == 0 && ok:
			t.Errorf("%s: want no REORDER, got %+v", tt.name, s)
		case tt.wantSev > 0 && (!ok || s.Severity != tt.wantSev):
			t.Errorf("%s: want REORDER sev %d, got %+v (present=%v)", tt.name, tt.wantSev, s, ok)
		}
	}
}

// TestClassifyCWndCollapse: a cwnd cut deeper than one halving (rounded
// down, as Reno rounds) shows, as info-level context, only with loss or ECN
// marks in the same poll;
// a cut without them (restart after idle, cwnd validation) and BBR's
// ProbeRTT drop to 4 packets (cwnd_gain 1) are by design. Without
// bytes_retrans (old kernel) only packets marked lost count.
func TestClassifyCWndCollapse(t *testing.T) {
	collapse := func(prev, cur int) *model.Connection {
		return &model.Connection{Protocol: "tcp", State: "ESTAB", PrevCWnd: ip(prev), CWnd: ip(cur),
			DeltaBytesRetrans: ip(0), DeltaDeliveredCE: ip(0)}
	}
	cases := []struct {
		name    string
		c       *model.Connection
		fires   bool
		wantVal string
	}{
		{"idle restart, no loss", collapse(241, 100), false, ""},
		{"loss: bytes retransmitted", func() *model.Connection { c := collapse(100, 40); c.DeltaBytesRetrans = ip(7240); return c }(), true, "100→40 after loss"},
		{"loss: packets marked lost", func() *model.Connection { c := collapse(100, 20); c.Lost = ip(3); return c }(), true, "100→20 after loss"},
		{"ECN marks", func() *model.Connection { c := collapse(100, 40); c.DeltaDeliveredCE = ip(12); return c }(), true, "100→40 after ECN marks"},
		{"Reno halving of an odd cwnd", func() *model.Connection { c := collapse(41, 20); c.DeltaBytesRetrans = ip(1448); return c }(), false, ""},
		{"exact halving", func() *model.Connection { c := collapse(40, 20); c.DeltaBytesRetrans = ip(1448); return c }(), false, ""},
		{"deeper than one halving", func() *model.Connection { c := collapse(41, 19); c.DeltaBytesRetrans = ip(1448); return c }(), true, "41→19 after loss"},
		{"two Reno halvings", func() *model.Connection { c := collapse(41, 10); c.DeltaBytesRetrans = ip(1448); return c }(), true, "41→10 after loss"},
		{"deeper than two halvings", func() *model.Connection { c := collapse(41, 9); c.DeltaBytesRetrans = ip(1448); return c }(), true, "41→9 after loss"},
		{"old kernel, no evidence", &model.Connection{Protocol: "tcp", State: "ESTAB", PrevCWnd: ip(100), CWnd: ip(40)}, false, ""},
		{"old kernel, packets marked lost", &model.Connection{Protocol: "tcp", State: "ESTAB", PrevCWnd: ip(100), CWnd: ip(40), Lost: ip(3)}, true, "100→40 after loss"},
		{"BBR ProbeRTT on a lossy path", func() *model.Connection {
			c := collapse(698, 4)
			c.BBRCWndGain, c.DeltaBytesRetrans = fl(1), ip(1448)
			return c
		}(), false, ""},
		{"BBR PROBE_BW loss", func() *model.Connection {
			c := collapse(698, 4)
			c.BBRCWndGain, c.DeltaBytesRetrans = fl(2), ip(1448)
			return c
		}(), true, "698→4 after loss"},
	}
	for _, tc := range cases {
		s, ok := sigByType(Classify(tc.c), model.SignalCWndCollapse)
		switch {
		case !tc.fires && ok:
			t.Errorf("%s: want no CWND_DROP, got %+v", tc.name, s)
		case tc.fires && (!ok || s.Severity != 0 || s.Value != tc.wantVal):
			t.Errorf("%s: want info CWND_DROP %q, got %+v (present=%v)", tc.name, tc.wantVal, s, ok)
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

// TestClassifyInboundLoss: segments arriving after a gap in most receive
// slots, with no queue on the way in, is inbound loss; gaps with a queue
// (congestion), bursty gaps, or no timestamps to measure the queue aren't.
// gappy(n, withGaps, oooPerSlot, queueMS) builds n complete 2 s slots of
// 1000 segments, the first withGaps of them with oooPerSlot out of order.
func TestClassifyInboundLoss(t *testing.T) {
	t0 := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	gappy := func(n, withGaps, ooo int, queueMS float64) *model.Connection {
		c := &model.Connection{Protocol: "tcp", State: "ESTAB", MinRTT: fl(40), Timestamps: true}
		for i := range n {
			s := model.RecvSlot{Start: t0.Add(time.Duration(2*i) * time.Second), End: t0.Add(time.Duration(2*i+2) * time.Second),
				Segs: 1000, QueueMS: []float64{queueMS, queueMS}}
			if i < withGaps {
				s.OOO = ooo
			}
			c.RecvSlots = append(c.RecvSlots, s)
		}
		return c
	}
	noTS := gappy(6, 6, 60, 1)
	noTS.Timestamps = false
	for i := range noTS.RecvSlots {
		noTS.RecvSlots[i].QueueMS = nil // the poller records no queue without timestamps
	}
	cases := []struct {
		name string
		c    *model.Connection
		want int // severity, 0 = no signal
	}{
		{"steady gaps, no queue", gappy(6, 6, 60, 1), 1},
		{"heavy", gappy(6, 6, 150, 1), 2},
		{"half the slots is still steady", gappy(6, 3, 120, 1), 1},
		{"below warn", gappy(6, 6, 10, 1), 0},
		{"bursty: 2 of 6 slots", gappy(6, 2, 300, 1), 0},
		{"a queue: congestion", gappy(6, 6, 60, 30), 0},
		{"a queue in a third of the polls: congestion", func() *model.Connection {
			c := gappy(6, 6, 60, 1)
			for i := range 4 {
				c.RecvSlots[i].QueueMS = []float64{1, 30} // 4 of 12 polls
			}
			return c
		}(), 0},
		{"a queue in a sixth of the polls: no queue", func() *model.Connection {
			c := gappy(6, 6, 60, 1)
			for i := range 2 {
				c.RecvSlots[i].QueueMS = []float64{1, 30} // 2 of 12 polls
			}
			return c
		}(), 1},
		{"no timestamps, no verdict", noTS, 0},
		{"too little history", gappy(3, 3, 60, 1), 0},
	}
	for _, tc := range cases {
		s, ok := sigByType(Classify(tc.c), model.SignalInboundLoss)
		if got := map[bool]int{true: s.Severity}[ok]; got != tc.want {
			t.Errorf("%s: severity %d, want %d (%+v)", tc.name, got, tc.want, s)
		}
	}
}

// TestDropsExplainedByInboundLoss: drops in a poll where segments arrived
// after a gap, with an empty receive queue, are loss-recovery discards,
// whether or not RX_LOSS (a verdict over seconds) has fired yet.
func TestDropsExplainedByInboundLoss(t *testing.T) {
	drops := model.Signal{Type: model.SignalSocketDrops, Severity: 1}
	rcvq := model.Signal{Type: model.SignalRecvBufferPressure, Severity: 1}
	for name, tc := range map[string]struct {
		sigs []model.Signal
		ooo  *int
		want bool
	}{
		"drops with gaps, empty queue":     {[]model.Signal{drops}, ip(30), true},
		"drops with gaps, full queue":      {[]model.Signal{drops, rcvq}, ip(30), false},
		"drops without gaps":               {[]model.Signal{drops}, ip(0), false},
		"drops, gaps unknown (old kernel)": {[]model.Signal{drops}, nil, false},
		"gaps without drops":               {nil, ip(30), false},
	} {
		c := &model.Connection{Signals: tc.sigs, DeltaRcvOOOPack: tc.ooo}
		if got := DropsExplainedByInboundLoss(c); got != tc.want {
			t.Errorf("%s: got %v, want %v", name, got, tc.want)
		}
	}
}

// TestPathLoss: steady loss with no queue building is path loss; bursty loss,
// loss with a full queue, too little loss or too little history isn't. BBR
// skips the queue test. lossy(n, retransmitting, queueMS) builds n complete
// 2 s slots of 1 MB each whose polls saw a queue of queueMS, the first
// `retransmitting` of them losing 0.2%.
func TestPathLoss(t *testing.T) {
	t0 := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	lossy := func(n, retransmitting int, queueMS float64) *model.Connection {
		c := &model.Connection{Protocol: "tcp", State: "ESTAB", MinRTT: fl(40)}
		for i := range n {
			s := model.SendSlot{Start: t0.Add(time.Duration(2*i) * time.Second), End: t0.Add(time.Duration(2*i+2) * time.Second),
				Sent: 1_000_000, QueueMS: []float64{queueMS, queueMS}}
			if i < retransmitting {
				s.Retrans = 2_000
			}
			c.SendSlots = append(c.SendSlots, s)
		}
		return c
	}
	bbr := func(c *model.Connection) *model.Connection { c.CongAlgo = sp("bbr"); return c }
	heavy := func(c *model.Connection) *model.Connection {
		for i := range c.SendSlots {
			if c.SendSlots[i].Retrans > 0 {
				c.SendSlots[i].Retrans = 30_000
			}
		}
		return c
	}
	partial := func(c *model.Connection) *model.Connection {
		last := c.SendSlots[len(c.SendSlots)-1].End
		c.SendSlots = append(c.SendSlots, model.SendSlot{Start: last, End: last.Add(time.Second), Sent: 1_000_000})
		return c
	}
	for _, tt := range []struct {
		name    string
		c       *model.Connection
		wantSev int
	}{
		{"steady, no queue", lossy(6, 4, 1), 1},
		{"steady, 3% retransmitted", heavy(lossy(6, 6, 1)), 2},
		{"half the slots is still steady", lossy(6, 3, 1), 1},
		{"bursty: 2 of 6 slots", lossy(6, 2, 1), 0},
		{"full queue: congestion", lossy(6, 6, 30), 0},
		{"queue under 10% of min RTT is no queue", lossy(6, 6, 3.9), 1},
		{"BBR's standing queue isn't congestion", bbr(lossy(6, 6, 30)), 1},
		{"too little loss", func() *model.Connection {
			c := lossy(6, 6, 1)
			for i := range c.SendSlots {
				c.SendSlots[i].Retrans = 400 // 0.04%
			}
			return c
		}(), 0},
		{"too little history", lossy(3, 3, 1), 0},
		{"a filling slot doesn't count", partial(lossy(3, 3, 1)), 0},
		{"no slots (idle or old kernel)", &model.Connection{Protocol: "tcp", State: "ESTAB"}, 0},
	} {
		s, ok := sigByType(Classify(tt.c), model.SignalPathLoss)
		switch {
		case tt.wantSev == 0 && ok:
			t.Errorf("%s: want no PATH_LOSS, got %+v", tt.name, s)
		case tt.wantSev > 0 && (!ok || s.Severity != tt.wantSev):
			t.Errorf("%s: want PATH_LOSS sev %d, got %+v (present=%v)", tt.name, tt.wantSev, s, ok)
		}
	}
}

// TestSynStall: a lost SYN or SYN-ACK costs one retry and the handshake goes
// through, so one retry is quiet; two (~3 s without an answer) warn and
// three (~7 s) are critical.
func TestSynStall(t *testing.T) {
	for _, tt := range []struct{ retries, wantSev int }{{0, 0}, {1, 0}, {2, 1}, {3, 2}, {6, 2}} {
		c := &model.Connection{Protocol: "tcp", State: "SYN-SENT", TimerRetrans: ip(tt.retries)}
		s, ok := sigByType(Classify(c), model.SignalSynStall)
		if (tt.wantSev == 0 && ok) || (tt.wantSev > 0 && (!ok || s.Severity != tt.wantSev)) {
			t.Errorf("%d retries: want SYN_STALL sev %d, got %+v (present=%v)", tt.retries, tt.wantSev, s, ok)
		}
	}
}

// TestRecvQueuePressure: a TCP receive buffer holds about half of rb in data,
// so a TCP Recv-Q is judged against that (a full one reaches crit), while a
// UDP Recv-Q is judged against rb. Both must persist across two polls.
func TestRecvQueuePressure(t *testing.T) {
	for _, tt := range []struct {
		name      string
		proto     string
		cur, prev int
		wantSev   int
	}{
		{"tcp reader keeping up", "tcp", 0, 0, 0},
		{"tcp 30% of rb", "tcp", 39_000, 39_000, 1},
		{"tcp full (60% of rb)", "tcp", 78_000, 78_000, 2},
		{"tcp one poll only", "tcp", 78_000, 0, 0},
		{"udp 30% of rb", "udp", 39_000, 39_000, 0},
		{"udp 60% of rb", "udp", 78_000, 78_000, 1},
	} {
		c := &model.Connection{Protocol: tt.proto, State: "ESTAB", RecvQ: ip(tt.cur), PrevRecvQ: ip(tt.prev), SkmemRB: ip(131_072)}
		if tt.proto == "udp" {
			c.State = "UDP_ESTAB"
		}
		s, ok := sigByType(Classify(c), model.SignalRecvBufferPressure)
		if got := map[bool]int{true: s.Severity}[ok]; got != tt.wantSev {
			t.Errorf("%s: RCV_Q severity %d, want %d", tt.name, got, tt.wantSev)
		}
	}
}
