package classifier

import (
	"fmt"
	"strconv"

	"sstui/model"
)

// Aggregate-signal thresholds. These count sockets across the whole snapshot
// rather than inspecting one connection, so they live in ClassifyAggregate.
const (
	closeWaitWarn = 20  // CLOSE-WAIT sockets held by one process
	closeWaitCrit = 50  //   — likely an fd leak (app not calling close())
	timeWaitWarn  = 200 // TIME-WAIT sockets toward one peer endpoint
	timeWaitCrit  = 2000
)

// ClassifyAggregate adds signals that depend on counts across the whole
// snapshot, not a single connection. It runs once per poll after per-connection
// Classify and appends to each affected connection's Signals:
//
//   - CLOSE_WAIT leak: a process sitting on many CLOSE-WAIT sockets has received
//     the peer's FIN but isn't calling close() — a classic file-descriptor leak.
//   - TIME-WAIT storm: many TIME-WAIT sockets toward one peer endpoint risk
//     exhausting the local ephemeral port range for that 4-tuple.
func ClassifyAggregate(conns []*model.Connection) {
	closeWaitByPID := make(map[int][]*model.Connection)
	timeWaitByPeer := make(map[string]int)

	for _, c := range conns {
		switch c.State {
		case "CLOSE-WAIT":
			if c.PID != nil { // a leak is attributable only to a known process
				closeWaitByPID[*c.PID] = append(closeWaitByPID[*c.PID], c)
			}
		case "TIME-WAIT":
			timeWaitByPeer[c.PeerAddr+":"+c.PeerPort]++
		}
	}

	for _, group := range closeWaitByPID {
		if sev := tierSeverity(len(group), closeWaitWarn, closeWaitCrit); sev > 0 {
			for _, c := range group {
				c.Signals = append(c.Signals, model.Signal{
					Type: model.SignalCloseWaitLeak, Severity: sev,
					Value: strconv.Itoa(len(group)) + " CLOSE-WAIT",
				})
			}
		}
	}

	for _, c := range conns {
		if c.State != "TIME-WAIT" {
			continue
		}
		n := timeWaitByPeer[c.PeerAddr+":"+c.PeerPort]
		if sev := tierSeverity(n, timeWaitWarn, timeWaitCrit); sev > 0 {
			c.Signals = append(c.Signals, model.Signal{
				Type: model.SignalTimeWaitStorm, Severity: sev,
				Value: strconv.Itoa(n) + " to peer",
			})
		}
	}
}

// DropsExplainedByInboundLoss reports whether a socket's kernel drops (DROPS)
// are most likely out-of-order data discarded during inbound loss recovery
// rather than a slow reader: the drops coincide with RX_LOSS and the receive
// queue is not under sustained pressure (no RCV_Q). Under inbound loss the
// out-of-order queue holds everything behind each gap; when that exceeds the
// socket's receive memory the kernel drops segments even though the
// application has read everything. Blaming the app there points the
// operator at the wrong end. Call it on a fully classified signal list.
func DropsExplainedByInboundLoss(sigs []model.Signal) bool {
	var drops, rxLoss, rcvQ bool
	for _, s := range sigs {
		switch s.Type {
		case model.SignalSocketDrops:
			drops = true
		case model.SignalInboundLoss:
			rxLoss = true
		case model.SignalRecvBufferPressure:
			rcvQ = true
		}
	}
	return drops && rxLoss && !rcvQ
}

// Inbound-loss thresholds: share of received data segments that arrived out
// of order in one poll, and the minimum data segments for a verdict.
const (
	inboundLossWarn    = 0.02
	inboundLossCrit    = 0.10
	inboundLossMinSegs = 100
)

// tierSeverityF is tierSeverity for ratios.
func tierSeverityF(v, warn, crit float64) int {
	switch {
	case v >= crit:
		return 2
	case v >= warn:
		return 1
	}
	return 0
}

// tierSeverity returns 2 at/above crit, 1 at/above warn, else 0.
func tierSeverity(n, warn, crit int) int {
	switch {
	case n >= crit:
		return 2
	case n >= warn:
		return 1
	}
	return 0
}

// PollIntervalMS is the poll cadence in milliseconds. It's used to judge what
// fraction of an interval a connection spent blocked on the receive window or
// send buffer. The poller sets it at startup (a package var rather than an
// import so classifier doesn't depend on poller); it defaults to the 2s cadence.
var PollIntervalMS float64 = 2000

// Queue-pressure thresholds. When the socket buffer size is known (from skmem)
// the queue is judged as a fraction of capacity; otherwise these absolute byte
// floors apply. A few hundred bytes in flight during a normal transfer is not
// pressure, so the floors sit at kilobyte scale to keep the signal meaningful.
const (
	queueWarnRatio = 0.5
	queueCritRatio = 0.8
	queueWarnBytes = 16 * 1024
	queueCritBytes = 64 * 1024
)

// queueSeverity rates a single queue depth against its buffer capacity (or the
// absolute fallback when capacity is unknown). 0 means "not under pressure".
func queueSeverity(q int, bufCap *int) int {
	if bufCap != nil && *bufCap > 0 {
		ratio := float64(q) / float64(*bufCap)
		switch {
		case ratio >= queueCritRatio:
			return 2
		case ratio >= queueWarnRatio:
			return 1
		}
		return 0
	}
	switch {
	case q >= queueCritBytes:
		return 2
	case q >= queueWarnBytes:
		return 1
	}
	return 0
}

// queuePressure returns the severity for a socket queue, but only when it has
// been under pressure on *both* this poll and the previous one. Requiring
// persistence (and stashed prev value) means a momentary queue during a normal
// burst doesn't fire — only sustained backpressure does. Returns 0 to suppress
// the signal (including on a connection's first poll, when prev is nil).
func queuePressure(cur, prev, bufCap *int) int {
	if cur == nil || prev == nil {
		return 0
	}
	curSev := queueSeverity(*cur, bufCap)
	if curSev == 0 || queueSeverity(*prev, bufCap) == 0 {
		return 0
	}
	return curSev
}

// limitedSeverity rates a per-poll "blocked" duration (ms) as a fraction of the
// poll interval: warn at ≥25%, crit at ≥75%. Returns (0, frac) below the warn
// threshold so the caller can suppress. Sub-quarter-interval blocking is normal
// jitter and not worth a signal.
func limitedSeverity(deltaMS *float64) (int, float64) {
	if deltaMS == nil || *deltaMS <= 0 || PollIntervalMS <= 0 {
		return 0, 0
	}
	frac := *deltaMS / PollIntervalMS
	switch {
	case frac >= 0.75:
		return 2, frac
	case frac >= 0.25:
		return 1, frac
	}
	return 0, frac
}

// IsZeroWindow reports whether the peer is advertising a zero receive window.
// ss omits snd_wnd entirely when it is 0, so the absent field can't be told
// apart from an old kernel that doesn't report it. A reported snd_wnd wins;
// otherwise the persist timer is the indicator — the kernel arms it to send
// zero-window probes. (It can also be armed for a tiny non-zero window, but
// then ss prints that window and the first branch answers.)
func IsZeroWindow(c *model.Connection) bool {
	if c.SndWnd != nil {
		return *c.SndWnd == 0
	}
	return c.TimerType != nil && *c.TimerType == "persist"
}

// RTTInflationMinExcessMS is the minimum absolute gap between smoothed RTT and
// min RTT before an RTT/MinRTT ratio counts as inflation. On loopback and LAN
// paths min RTT is tens of microseconds, so delayed ACKs and scheduling jitter
// alone produce large ratios (0.4ms / 0.05ms = 8x) that mean nothing.
const RTTInflationMinExcessMS = 10.0

// RTTInflation returns rtt/minrtt when both are known and the excess over min
// RTT is large enough to matter (see RTTInflationMinExcessMS). ok is false
// when the ratio can't be computed or the excess is below the floor.
func RTTInflation(c *model.Connection) (ratio float64, ok bool) {
	if c.RTT == nil || c.MinRTT == nil || *c.MinRTT <= 0 {
		return 0, false
	}
	if *c.RTT-*c.MinRTT < RTTInflationMinExcessMS {
		return 0, false
	}
	return *c.RTT / *c.MinRTT, true
}

// sendingState reports whether a socket in this state can have data of its
// own in flight awaiting ACK.
func sendingState(state string) bool {
	switch state {
	case "ESTAB", "CLOSE-WAIT", "FIN-WAIT-1", "LAST-ACK", "CLOSING":
		return true
	}
	return false
}

// noAckFloorMS is how long a connection with data in flight may go without
// an ACK before NO_ACK fires: the larger of its RTO and one second.
func noAckFloorMS(c *model.Connection) float64 {
	floor := 1000.0
	if c.RTO != nil && *c.RTO > floor {
		floor = *c.RTO
	}
	return floor
}

// fmtSecs renders milliseconds as whole seconds ("12s"), or ms below 1s.
func fmtSecs(ms int) string {
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	return fmt.Sprintf("%ds", ms/1000)
}

// Classify analyzes a connection and returns detected signals.
func Classify(c *model.Connection) []model.Signal {
	var signals []model.Signal

	// Socket-buffer drops (skmem 'd') are the kernel telling us it discarded
	// data at this socket because the buffer was full — the receiver couldn't
	// keep up. Applies to both TCP and UDP; a per-poll increase is a hard data
	// loss event, not a soft warning, so even one drop is worth surfacing.
	if c.DeltaSkmemD != nil && *c.DeltaSkmemD > 0 {
		sev := 1
		if *c.DeltaSkmemD > 10 {
			sev = 2
		}
		signals = append(signals, model.Signal{Type: model.SignalSocketDrops, Severity: sev, Value: *c.DeltaSkmemD})
	}

	if c.Protocol == "udp" {
		if sev := queuePressure(c.RecvQ, c.PrevRecvQ, c.SkmemRB); sev > 0 {
			signals = append(signals, model.Signal{Type: model.SignalRecvBufferPressure, Severity: sev, Value: *c.RecvQ})
		}
		if sev := queuePressure(c.SendQ, c.PrevSendQ, c.SkmemTB); sev > 0 {
			signals = append(signals, model.Signal{Type: model.SignalSendBufferPressure, Severity: sev, Value: *c.SendQ})
		}
		if c.State == "UDP_IDLE" {
			signals = append(signals, model.Signal{Type: model.SignalIdle, Severity: 0})
		}
		return signals
	}

	if c.State == "LISTEN" {
		// For LISTEN sockets ss reports Recv-Q as the current accept-queue
		// depth and Send-Q as its maximum (somaxconn-capped backlog). A full
		// or nearly-full accept queue means new SYNs are getting dropped,
		// which is a distinct failure from generic buffer pressure.
		rq, sq := 0, 0
		if c.RecvQ != nil {
			rq = *c.RecvQ
		}
		if c.SendQ != nil {
			sq = *c.SendQ
		}
		if sq > 0 && rq > 0 {
			ratio := float64(rq) / float64(sq)
			if ratio > 0.8 {
				sev := 1
				if ratio >= 1.0 {
					sev = 2
				}
				signals = append(signals, model.Signal{Type: model.SignalListenQueueFull, Severity: sev,
					Value: fmt.Sprintf("%d/%d", rq, sq)})
			}
		} else if rq > 0 {
			// Backlog limit unknown — fall back to absolute threshold.
			sev := 1
			if rq > 100 {
				sev = 2
			}
			signals = append(signals, model.Signal{Type: model.SignalListenQueueFull, Severity: sev, Value: rq})
		}
		return signals
	}

	// SYN-SENT with the retransmission timer running and at least one retry
	// means the handshake is stalled — DNS/firewall/route problem.
	if c.State == "SYN-SENT" && c.TimerRetrans != nil && *c.TimerRetrans > 0 {
		sev := 1
		if *c.TimerRetrans >= 3 {
			sev = 2
		}
		signals = append(signals, model.Signal{Type: model.SignalSynStall, Severity: sev, Value: *c.TimerRetrans})
	}

	if v := c.RetransNow; v != nil && *v > 3 {
		sev := 1
		if *v > 10 {
			sev = 2
		}
		signals = append(signals, model.Signal{Type: model.SignalRetransInFlight, Severity: sev, Value: *v})
	}

	// app_limited is a state, not a fault — surface as info only.
	if c.AppLimited == 1 {
		signals = append(signals, model.Signal{Type: model.SignalAppLimited, Severity: 0})
	}

	// IDLE: ESTAB with no bytes moving this poll. Only fire when we actually
	// have deltas to compare against — on the very first snapshot of a new
	// connection both deltas are nil and we can't yet tell idle from active.
	// A socket with data stuck in its send queue isn't idle — it's stalled
	// (e.g. zero window), so don't label it as if nothing were wrong.
	sendQueued := c.SendQ != nil && *c.SendQ > 0
	if c.State == "ESTAB" && !sendQueued && c.DeltaBytesSent != nil && c.DeltaBytesReceived != nil {
		if *c.DeltaBytesSent == 0 && *c.DeltaBytesReceived == 0 {
			signals = append(signals, model.Signal{Type: model.SignalIdle, Severity: 0})
		}
	}

	if c.State == "ESTAB" && IsZeroWindow(c) {
		var v any
		if c.TimerDur != nil {
			v = "next zero-window probe in " + *c.TimerDur
		}
		signals = append(signals, model.Signal{Type: model.SignalZeroWindow, Severity: 2, Value: v})
	}

	if v := c.Lost; v != nil && *v > 2 {
		sev := 1
		if *v > 10 {
			sev = 2
		}
		signals = append(signals, model.Signal{Type: model.SignalCongestionLoss, Severity: sev, Value: *v})
	}

	// Real PMTU problem: path MTU below our advertised MSS.
	if c.PMTU != nil && c.AdvMSS != nil && *c.PMTU > 0 && *c.AdvMSS > 0 {
		// PMTU includes IP+TCP headers (~40-60B). Compare with margin.
		if *c.PMTU < *c.AdvMSS+40 {
			signals = append(signals, model.Signal{Type: model.SignalPMTUMismatch, Severity: 1,
				Value: fmt.Sprintf("pmtu=%d advmss=%d", *c.PMTU, *c.AdvMSS)})
		}
	}

	if ratio, ok := RTTInflation(c); ok {
		if ratio > 5 {
			sev := 1
			if ratio > 15 {
				sev = 2
			}
			signals = append(signals, model.Signal{Type: model.SignalRTTSpike, Severity: sev, Value: ratio})
		}
	}

	if sev := queuePressure(c.SendQ, c.PrevSendQ, c.SkmemTB); sev > 0 {
		signals = append(signals, model.Signal{Type: model.SignalSendBufferPressure, Severity: sev, Value: *c.SendQ})
	}

	if sev := queuePressure(c.RecvQ, c.PrevRecvQ, c.SkmemRB); sev > 0 {
		signals = append(signals, model.Signal{Type: model.SignalRecvBufferPressure, Severity: sev, Value: *c.RecvQ})
	}

	if c.DeltaBytesRetrans != nil && c.DeltaBytesSent != nil && *c.DeltaBytesSent > 0 {
		rate := float64(*c.DeltaBytesRetrans) / float64(*c.DeltaBytesSent)
		if rate > 0.05 {
			sev := 1
			if rate > 0.2 {
				sev = 2
			}
			signals = append(signals, model.Signal{Type: model.SignalHighRetransRate, Severity: sev, Value: rate})
		}
	}

	// Only flag delivery drop when the app is actually trying to send.
	if c.AppLimited == 0 && c.DeltaBytesSent != nil && *c.DeltaBytesSent > 0 &&
		c.DeliveryRate != nil && c.PacingRate != nil && *c.PacingRate > 0 {
		ratio := float64(*c.DeliveryRate) / float64(*c.PacingRate)
		if ratio < 0.5 {
			signals = append(signals, model.Signal{Type: model.SignalDeliveryDrop, Severity: 1, Value: ratio})
		}
	}

	// Bottleneck attribution: how much of this poll the sender spent blocked on
	// the peer's receive window (rwnd_limited) vs. its own send buffer
	// (sndbuf_limited). Only meaningful while actively sending — a limit on an
	// idle connection is moot. A high fraction tells you *where* the throughput
	// ceiling is: RWND_LIM = the receiver isn't reading/advertising window fast
	// enough; SNDBUF_LIM = the local send buffer (SO_SNDBUF / app) is the cap.
	if c.DeltaBytesSent != nil && *c.DeltaBytesSent > 0 {
		if sev, frac := limitedSeverity(c.DeltaRwndLimitedMS); sev > 0 {
			signals = append(signals, model.Signal{Type: model.SignalRwndLimited, Severity: sev,
				Value: fmt.Sprintf("%.0f%% of poll", frac*100)})
		}
		if sev, frac := limitedSeverity(c.DeltaSndbufLimitedMS); sev > 0 {
			signals = append(signals, model.Signal{Type: model.SignalSndbufLimited, Severity: sev,
				Value: fmt.Sprintf("%.0f%% of poll", frac*100)})
		}
	}

	// Cwnd-limited: most of the congestion window is in flight. That's what a
	// healthy bulk transfer looks like (the sender is using all the window it
	// has), so it's informational context, not a warning.
	if c.Unacked != nil && c.CWnd != nil && *c.CWnd > 0 && *c.Unacked > 10 &&
		float64(*c.Unacked) > 0.8*float64(*c.CWnd) {
		signals = append(signals, model.Signal{Type: model.SignalCwndLimited, Severity: 0, Value: *c.Unacked})
	}

	// RTO firing: retransmission timer active and we've already retransmitted
	// at least twice — RTO is doubling. This catches escalating loss episodes
	// that the RETRANS-in-flight signal can miss when only one segment is
	// outstanding but it keeps timing out.
	if c.State == "ESTAB" && c.TimerType != nil && *c.TimerType == "on" &&
		c.TimerRetrans != nil && *c.TimerRetrans >= 2 {
		sev := 1
		if *c.TimerRetrans >= 4 {
			sev = 2
		}
		signals = append(signals, model.Signal{Type: model.SignalRTOFiring, Severity: sev, Value: *c.TimerRetrans})
	}

	// Peer not acknowledging: data was outstanding at the previous poll, is
	// still outstanding, and not one byte was ACKed in between. A live peer
	// ACKs within an RTT, so a whole silent poll interval means it's hung or
	// the path is black-holing. Requiring outstanding data on both polls
	// avoids flagging the instant after an idle connection sends (when
	// unacked > 0 for one RTT) and one-way bulk transfers (which are ACKed).
	// Zero-window stalls don't trip it: probes are sent outside the window,
	// so unacked is 0 while persisting.
	//
	// The ACK silence must also outlast the retransmission timeout (and 1s):
	// with a short --interval, two polls can land inside one round trip of a
	// slow path, where waiting for an ACK is perfectly normal.
	if sendingState(c.State) && c.Unacked != nil && *c.Unacked > 0 &&
		c.PrevUnacked != nil && *c.PrevUnacked > 0 &&
		c.DeltaBytesAcked != nil && *c.DeltaBytesAcked == 0 &&
		c.LastAck != nil && float64(*c.LastAck) >= noAckFloorMS(c) {
		sev := 1
		if *c.LastAck >= 10000 {
			sev = 2
		}
		signals = append(signals, model.Signal{Type: model.SignalPeerNoAck, Severity: sev,
			Value: fmt.Sprintf("%d unacked, no ACK for %s", *c.Unacked, fmtSecs(*c.LastAck))})
	}

	// CWnd collapse: congestion window dropped sharply between polls. Only
	// meaningful when the prior window was non-trivial; tiny windows
	// fluctuate naturally during slow start.
	if c.PrevCWnd != nil && c.CWnd != nil && *c.PrevCWnd >= 20 {
		ratio := float64(*c.CWnd) / float64(*c.PrevCWnd)
		if ratio < 0.5 {
			sev := 1
			if ratio < 0.25 {
				sev = 2
			}
			signals = append(signals, model.Signal{Type: model.SignalCWndCollapse, Severity: sev,
				Value: fmt.Sprintf("%d→%d", *c.PrevCWnd, *c.CWnd)})
		}
	}

	// DSACK growth: peer reported duplicate ACKs since last poll. Means our
	// RTO was too aggressive and we retransmitted unnecessarily.
	if c.DeltaDSACKDups != nil && *c.DeltaDSACKDups > 0 {
		sev := 1
		if *c.DeltaDSACKDups > 5 {
			sev = 2
		}
		signals = append(signals, model.Signal{Type: model.SignalDSACKSpurious, Severity: sev, Value: *c.DeltaDSACKDups})
	}

	// Inbound loss: data segments from the peer arriving after a gap
	// (rcv_ooopack) as a share of data segments received this poll. On the
	// receiving host this is the only visible trace of loss on the
	// peer → here path — the retransmit counters belong to the sender. One
	// lost segment makes everything behind it arrive out of order until the
	// retransmission fills the hole (≈ a window's worth), so the ratio
	// overstates the loss rate and the thresholds sit well above typical
	// loss percentages. A minimum of data received keeps a stray packet on a
	// quiet connection from tripping it. Reordering on the path also counts.
	if c.DeltaRcvOOOPack != nil && c.DeltaDataSegsIn != nil && *c.DeltaDataSegsIn >= inboundLossMinSegs {
		ratio := float64(*c.DeltaRcvOOOPack) / float64(*c.DeltaDataSegsIn)
		if sev := tierSeverityF(ratio, inboundLossWarn, inboundLossCrit); sev > 0 {
			signals = append(signals, model.Signal{Type: model.SignalInboundLoss, Severity: sev,
				Value: fmt.Sprintf("%.1f%% of %d segments arrived after a gap", ratio*100, *c.DeltaDataSegsIn)})
		}
	}

	// Reordering: the sender detected reordering this poll (reord_seen —
	// e.g. a SACK for a segment above a hole that is later filled without a
	// retransmit). rcv_ooopack is deliberately not used: the receiver queues
	// out-of-order packets after any loss too, so it can't tell reordering
	// from loss — and the fix differs (ECMP/LACP hashing vs. congestion).
	if c.DeltaReordSeen != nil && *c.DeltaReordSeen > 0 {
		sev := 1
		if *c.DeltaReordSeen > 50 {
			sev = 2
		}
		signals = append(signals, model.Signal{Type: model.SignalReordering, Severity: sev, Value: *c.DeltaReordSeen})
	}

	// BBR delivering less than half its bandwidth estimate while actively
	// trying to send (and not app-limited). Surfaces BBR-specific
	// under-utilization that the generic DEL_DROP signal may miss when
	// pacing_rate is calibrated to the actual delivery rate.
	if c.BBRBW != nil && *c.BBRBW > 0 && c.DeliveryRate != nil &&
		c.AppLimited == 0 && c.DeltaBytesSent != nil && *c.DeltaBytesSent > 0 {
		ratio := float64(*c.DeliveryRate) / float64(*c.BBRBW)
		if ratio < 0.5 {
			signals = append(signals, model.Signal{Type: model.SignalBBRUnderutil, Severity: 1, Value: ratio})
		}
	}

	return signals
}
