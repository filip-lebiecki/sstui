package classifier

import (
	"fmt"
	"slices"
	"strconv"
	"time"

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
// rather than a slow reader: segments arrived after a gap in the same poll
// and the receive queue is not under sustained pressure (no RCV_Q). Under
// inbound loss the out-of-order queue holds everything behind each gap; when
// that exceeds the socket's receive memory the kernel drops segments even
// though the application has read everything. Blaming the app there points
// the operator at the wrong end. This poll's gaps, not the RX_LOSS verdict:
// RX_LOSS needs seconds of steady gaps with no queue, while the discards
// happen with any gap, congestion included. Classify makes such DROPS info
// (they're loss's consequence, not a fault of their own); call it on a fully
// classified connection.
func DropsExplainedByInboundLoss(c *model.Connection) bool {
	if c.DeltaRcvOOOPack == nil || *c.DeltaRcvOOOPack == 0 {
		return false
	}
	var drops, rcvQ bool
	for _, s := range c.Signals {
		switch s.Type {
		case model.SignalSocketDrops:
			drops = true
		case model.SignalRecvBufferPressure:
			rcvQ = true
		}
	}
	return drops && !rcvQ
}

// MemoryRefusedDrops reports drops (DROPS, not the loss-recovery kind) at a
// TCP socket holding almost none of its receive buffer (under a quarter):
// with that much room in its own buffer, the kernel can only have refused
// the memory host-wide (tcp_mem). In the lab such sockets held 0 bytes of
// 128-700 KB buffers, their windows clamped to 6 KB, dropping every poll; a
// slow reader drops with its buffer full.
func MemoryRefusedDrops(c *model.Connection) bool {
	if c.Protocol != "tcp" || c.State == "LISTEN" || c.SkmemR == nil || c.SkmemRB == nil || *c.SkmemRB <= 0 {
		return false
	}
	for _, s := range c.Signals {
		if s.Type == model.SignalSocketDrops {
			return s.Severity > 0 && *c.SkmemR*4 < *c.SkmemRB
		}
	}
	return false
}

// HungAfterHandshake reports whether a connection completed its handshake but
// has had nothing acknowledged since (delivered counts the SYN), while its
// data waits for an ACK with segments larger than every IPv4 path must carry
// (576-byte datagrams, a 536-byte MSS): with a stall signal (RTO, NO_ACK),
// the signature of a path MTU black hole. A black hole that starts after
// data got through (a route change into a tunnel) can't be told from loss.
func HungAfterHandshake(c *model.Connection) bool {
	return c.State == "ESTAB" && c.Delivered != nil && *c.Delivered <= 1 &&
		c.Unacked != nil && *c.Unacked > 0 && c.MSS != nil && *c.MSS > 536
}

// Inbound-loss thresholds: share of received data segments that arrived
// after a gap. One lost segment makes everything behind it arrive out of
// order until the retransmission fills the hole, so the share overstates the
// loss rate: in the scenario lab 0.1% loss gave about 6%, 1% about 10% and 3%
// about 17%.
const (
	inboundLossWarn = 0.02
	inboundLossCrit = 0.10
)

// inboundLoss judges a connection's recent receiving (c.RecvSlots) for loss
// on the path from the peer, the receiving side's view of what pathLoss
// judges on the sender: segments arriving after a gap (rcv_ooopack) in at
// least half of the slots, at least inboundLossWarn of the segments
// received, and no queue on the way in: rcv_rtt within max(4 ms, 10% of min
// RTT) of the minimum in at least three quarters of the receiving polls. A
// flow filling a bottleneck loses packets too, and they arrive with gaps just
// the same, but its data waits in the bottleneck's queue, which rcv_rtt (an
// RTT sample the receiver takes with timestamps) includes. Without
// timestamps there's no verdict.
//
// Three quarters, where pathLoss takes the median: bursty responses on
// several connections build a queue only when they overlap, so in the lab a
// healthy request/response client sometimes saw one in barely half its
// polls, while a lossy path never did. rcv_rtt can afford the stricter
// test: unlike the sender's RTT it isn't inflated by delayed ACKs, since the
// timestamp echoed is the time the ACK was sent.
//
// The minimum is the lower of the connection's own and its path's
// (PathMinRTT, other connections to the same peer): a pure receiver measures
// min RTT only on its handshake, so a connection opened through an already
// full queue starts from an inflated baseline and took that queue for none
// (in the lab, 76 ms against its siblings' 41 ms). If every connection to the
// peer opened through the queue, the baseline stays inflated; hosts with
// different paths behind one address (NAT) can only lower it, which hides
// loss rather than inventing it.
//
// Reordering on the path also leaves gaps. A sender that doesn't back off
// on loss (BBR) keeps a standing queue even on a lossy path, so its loss
// goes unreported here; the sender's PATH_LOSS still sees it.
func inboundLoss(c *model.Connection) (sev int, value string) {
	slots := completeSlots(c.RecvSlots, func(s model.RecvSlot) time.Duration { return s.End.Sub(s.Start) })
	if slots == nil || c.MinRTT == nil {
		return 0, ""
	}
	base := *c.MinRTT
	if c.PathMinRTT != nil {
		base = min(base, *c.PathMinRTT)
	}
	var segs, ooo, gappy int
	var queue []float64
	for _, s := range slots {
		segs += s.Segs
		ooo += s.OOO
		if s.OOO > 0 {
			gappy++
		}
		for _, rtt := range s.RTTMS {
			queue = append(queue, rtt-base)
		}
	}
	if segs == 0 || len(queue) == 0 {
		return 0, ""
	}
	ratio := float64(ooo) / float64(segs)
	if gappy*2 < len(slots) || ratio < inboundLossWarn {
		return 0, ""
	}
	slices.Sort(queue)
	if queue[len(queue)*3/4] >= max(4, 0.1*base) {
		return 0, "" // the data waits in a queue: congestion
	}
	span := slots[len(slots)-1].End.Sub(slots[0].Start).Round(time.Second)
	return tierSeverityF(ratio, inboundLossWarn, inboundLossCrit),
		fmt.Sprintf("%.1f%% of %d segments arrived after a gap over %s, in %d of %d slots", ratio*100, segs, span, gappy, len(slots))
}

// Path-loss thresholds, set from the scenario lab (lab/): healthy congestion
// retransmits about 0.02-0.07% on fast links and in a minority of slots,
// while 0.1% path loss already caps a cubic flow at a fraction of the link.
const (
	pathLossWarn = 0.0005 // share of bytes retransmitted
	pathLossCrit = 0.01
)

// pathLoss judges a connection's recent sending (c.SendSlots, kept by the
// poller over the last several seconds) for loss on the path rather than the
// loss TCP causes itself while filling a link. It fires when all three hold:
//
//   - steady: at least half of the slots retransmitted. Slow-start overshoot
//     and request bursts lose in a slot or two, then nothing.
//   - enough: at least pathLossWarn of the bytes sent were retransmitted
//     (crit at pathLossCrit).
//   - no queue: while sending, RTT typically (the median over all its polls)
//     sat within max(4 ms, 10% of min RTT) of its minimum. Congestion loss
//     happens because the flow filled the bottleneck queue, so its RTT climbs
//     while it sends; a lossy link throttles the flow before it can build a
//     queue. All sending polls count, not just those that retransmitted: a
//     request burst loses packets right after an idle gap, while the smoothed
//     RTT still reflects the quiet. The median, not the peak: with only a
//     segment or two in flight, a delayed ACK alone adds tens of ms to an RTT
//     sample. BBR is exempt: it keeps a standing queue and doesn't back off
//     on loss.
//
// A bottleneck whose buffer is only a few milliseconds deep drops before the
// queue shows, so several flows saturating one also look like path loss; the
// finding names both causes.
func pathLoss(c *model.Connection) (sev int, value string) {
	slots := completeSendSlots(c)
	if slots == nil {
		return 0, ""
	}
	var sent, retr, lossy int
	var queue []float64
	for _, s := range slots {
		sent += s.Sent
		retr += s.Retrans
		if s.Retrans > 0 {
			lossy++
		}
		queue = append(queue, s.QueueMS...)
	}
	rate := float64(retr) / float64(sent)
	if lossy*2 < len(slots) || rate < pathLossWarn {
		return 0, ""
	}
	bbr := c.CongAlgo != nil && *c.CongAlgo == "bbr"
	if !bbr {
		if c.MinRTT == nil || len(queue) == 0 {
			return 0, ""
		}
		slices.Sort(queue)
		if queue[len(queue)/2] >= max(4, 0.1**c.MinRTT) {
			return 0, "" // the flow builds a queue: congestion
		}
	}
	return tierSeverityF(rate, pathLossWarn, pathLossCrit),
		fmt.Sprintf("%.2f%% retransmitted over %s, in %d of %d slots", rate*100, slotSpan(slots), lossy, len(slots))
}

// slotMinCount is the least complete slots PATH_LOSS, REORDER and RX_LOSS
// judge: about 8 s of sending (receiving) at 2 s slots.
const slotMinCount = 4

// completeSlots returns slots without the one still filling (span shorter
// than model.SendSlotMin), or nil when fewer than slotMinCount are complete:
// too little traffic to judge.
func completeSlots[S any](slots []S, span func(S) time.Duration) []S {
	if n := len(slots); n > 0 && span(slots[n-1]) < model.SendSlotMin {
		slots = slots[:n-1]
	}
	if len(slots) < slotMinCount {
		return nil
	}
	return slots
}

func completeSendSlots(c *model.Connection) []model.SendSlot {
	return completeSlots(c.SendSlots, func(s model.SendSlot) time.Duration { return s.End.Sub(s.Start) })
}

func slotSpan(slots []model.SendSlot) time.Duration {
	return slots[len(slots)-1].End.Sub(slots[0].Start).Round(time.Second)
}

// Reordering thresholds: reordering events as a share of data segments sent.
// Set from the scenario lab: 0.1% of packets reordered on a 100 Mbit/s path
// gives about 0.9% (each reordered packet can count more than once), while
// the stray events request bursts produce stay far below 0.1% over a window,
// and in a few percent of polls. Loss recovery can pass it; the ratio to
// retransmits (reorderPerRetrans) tells that apart.
const (
	reorderWarn = 0.001
	reorderCrit = 0.05
	// reorderPerRetrans is the least reordering events per retransmitted
	// segment over the window. Loss recovery ticks reord_seen steadily too
	// (at 0.1% loss in up to 4 of 5 slots, up to 0.28% of segments), but
	// at most 5.5 events per retransmit in the lab, while real reordering
	// gave 21 or more (mostly 70+), retransmitting only now and then.
	reorderPerRetrans = 10
)

// reordering judges a connection's recent sending for packet reordering on
// the way to the peer, from reord_seen: the sender saw a segment acknowledged
// out of order without a retransmit. It fires when reordering is steady (in
// at least half of the slots), at least reorderWarn of the segments sent, and
// far more common than retransmits (reorderPerRetrans). The counter also
// ticks without any reordering: now and then on request bursts, which a
// per-poll rule reported as reordering, and steadily during loss recovery,
// which only the retransmits tell apart. Real reordering, from ECMP or LACP
// hashing or multi-queue NICs, shows up in nearly every poll.
//
// rcv_ooopack is deliberately not used: the receiver queues out-of-order
// packets after any loss too, so it can't tell reordering from loss, and the
// fix differs (path hashing vs. congestion).
func reordering(c *model.Connection) (sev int, value string) {
	slots := completeSendSlots(c)
	if slots == nil || c.MSS == nil || *c.MSS <= 0 {
		return 0, ""
	}
	var sent, retrans, events, steady int
	for _, s := range slots {
		sent += s.Sent
		retrans += s.Retrans
		events += s.Reord
		if s.Reord > 0 {
			steady++
		}
	}
	rate := float64(events) / (float64(sent) / float64(*c.MSS))
	retransSegs := float64(retrans) / float64(*c.MSS)
	if steady*2 < len(slots) || rate < reorderWarn || float64(events) < reorderPerRetrans*retransSegs {
		return 0, ""
	}
	return tierSeverityF(rate, reorderWarn, reorderCrit),
		fmt.Sprintf("%.2f%% of segments over %s, in %d of %d slots", rate*100, slotSpan(slots), steady, len(slots))
}

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

// tcpRecvPayload is how much data a TCP receive buffer of rb bytes holds:
// rb is a memory budget that also pays each packet's overhead, and TCP sizes
// its window to fit, historically half of it (tcp_adv_win_scale), these days
// what the kernel measures (in the lab, a slow reader's full buffer held
// 0.4-0.63 of rb in data). Judged against rb itself, a full TCP receive
// queue barely reached the warning level. A reader that keeps up leaves
// Recv-Q at 0, so the lower bar doesn't catch healthy traffic.
func tcpRecvPayload(rb *int) *int {
	if rb == nil {
		return nil
	}
	half := *rb / 2
	return &half
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
// jitter and not worth a signal. The previous poll (prevMS) must have been
// limited too: a new connection on a long path is briefly rwnd-limited while
// the receiver's buffer autotuning catches up with slow start (in the lab, a
// quarter of the first busy poll at 100 ms RTT), which isn't a fault.
func limitedSeverity(deltaMS, prevMS *float64) (int, float64) {
	sev, frac := limitedLevel(deltaMS)
	if sev == 0 {
		return 0, frac
	}
	if prev, _ := limitedLevel(prevMS); prev == 0 {
		return 0, frac
	}
	return sev, frac
}

func limitedLevel(deltaMS *float64) (int, float64) {
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

// sendBufferCaps reports whether a sender's own send buffer holds back its
// flight, which the kernel's sndbuf_limited time misses: with a small
// SO_SNDBUF each ACK frees space the app refills at once, so the kernel
// counts that as busy sending (8-32% "sndbuf limited" in the lab, with the
// connection at a seventh of the path's rate) and flags it app-limited. The
// structure tells instead, on this poll and the previous one: the buffer is
// full (Send-Q at 40% of tb or more; like the receive side, the rest pays
// per-packet overhead), everything queued is already in flight (nothing
// waits unsent), and neither the congestion window (under 80% used) nor the
// peer's window holds the flight back. A cwnd-limited bulk sender keeps
// data waiting unsent; an app with little to send never fills the buffer.
func sendBufferCaps(c *model.Connection) bool {
	if c.SendQ == nil || c.PrevSendQ == nil || c.SkmemTB == nil || *c.SkmemTB <= 0 ||
		c.Unacked == nil || c.MSS == nil || c.CWnd == nil || *c.CWnd <= 0 {
		return false
	}
	full := func(q int) bool { return float64(q) >= 0.4*float64(*c.SkmemTB) }
	flight := *c.Unacked * *c.MSS
	rwndRoom := c.SndWnd == nil || flight+2**c.MSS < *c.SndWnd
	return full(*c.SendQ) && full(*c.PrevSendQ) && *c.SendQ <= flight+2**c.MSS &&
		float64(*c.Unacked) <= 0.8*float64(*c.CWnd) && rwndRoom
}

// receiveWindowFill reports whether this socket's receive window is what
// holds the peer back, seen from the receiving end, and how full the window
// runs: on this poll and the previous one the data arriving per round trip
// (bytes received over the poll × rcv_rtt) fills at least 80% of the
// advertised window, while the application keeps up (Recv-Q below a quarter
// of the buffer, so it's not a slow reader, which RCV_Q reports). A receiver
// whose window has room to spare gets a fraction of it per round trip: in
// the lab healthy receivers peaked at 0.42, a buffer capped at 128 KB on a
// 500 KB path ran at 0.95-1.03. Two polls, because a new connection's window
// runs full for a moment while autotuning catches up with slow start.
// rcv_rtt is a real RTT sample only with timestamps.
func receiveWindowFill(c *model.Connection) (float64, bool) {
	if !c.Timestamps || c.RcvRTT == nil || *c.RcvRTT <= 0 || c.RcvWnd == nil || *c.RcvWnd <= 0 ||
		c.SkmemRB == nil || c.RecvQ == nil || PollIntervalMS <= 0 ||
		c.DeltaBytesReceived == nil || c.PrevDeltaBytesReceived == nil {
		return 0, false
	}
	if float64(*c.RecvQ) >= 0.25*float64(*c.SkmemRB) {
		return 0, false // a backlog: the reader, not the buffer
	}
	fill := func(bytes int) float64 {
		return float64(bytes) / PollIntervalMS * *c.RcvRTT / float64(*c.RcvWnd)
	}
	cur, prev := fill(*c.DeltaBytesReceived), fill(*c.PrevDeltaBytesReceived)
	const minBytes = 10_000 // a few segments, so a trickle never counts
	if *c.DeltaBytesReceived < minBytes || *c.PrevDeltaBytesReceived < minBytes || cur < 0.8 || prev < 0.8 {
		return 0, false
	}
	return cur, true
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

// bbrProbeRTT reports whether a BBR connection is in its ProbeRTT phase, the
// only phase that runs with a cwnd gain of 1 (STARTUP and DRAIN use 2.89,
// PROBE_BW uses 2).
func bbrProbeRTT(c *model.Connection) bool {
	return c.BBRCWndGain != nil && *c.BBRCWndGain < 1.5
}

// cwndCutCause names the congestion event in this poll that explains a cwnd
// reduction: "loss" (retransmissions or packets marked lost) or "ECN marks"
// (ACKs echoing congestion marks). It returns "" when the poll shows neither:
// the kernel then shrank a window the connection wasn't using, either on
// restart after idle (tcp_slow_start_after_idle) or while app-limited (cwnd
// validation), which says nothing about the path. Without bytes_retrans
// (kernels before 4.19) only packets marked lost count: no evidence, no claim.
//
// Only this poll is checked. Once an event's reduction settles it is at
// most half (cubic 0.7x, Reno 0.5x rounded down, DCTCP 0.5x-1x; BBR restores
// its previous cwnd when recovery ends). A settled drop past CWND_DROP's
// threshold (below the rounded-down half) therefore needs a further event
// in the later poll. Deeper transient cuts (an RTO's reset to 1, BBR
// holding cwnd to packets in flight during recovery, PRR under heavy loss)
// start with a retransmission, which the first poll to see the lower cwnd
// also counts.
func cwndCutCause(c *model.Connection) string {
	switch {
	case c.DeltaBytesRetrans != nil && *c.DeltaBytesRetrans > 0, c.Lost != nil && *c.Lost > 0:
		return "loss"
	case c.DeltaDeliveredCE != nil && *c.DeltaDeliveredCE > 0:
		return "ECN marks"
	}
	return ""
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

	// SYN-SENT still retrying means the handshake is stalled: DNS, firewall
	// or routing. One retry isn't enough: on a path that loses a packet now
	// and then, a lost SYN or SYN-ACK costs one retry (after 1 s) and the
	// connection goes through. A second retry means ~3 s without an answer;
	// a third, ~7 s (SYN backoff doubles from 1 s).
	if c.State == "SYN-SENT" && c.TimerRetrans != nil && *c.TimerRetrans >= 2 {
		sev := 1
		if *c.TimerRetrans >= 3 {
			sev = 2
		}
		signals = append(signals, model.Signal{Type: model.SignalSynStall, Severity: sev, Value: *c.TimerRetrans})
	}

	// RETRANS, LOSS, HI_RETRANS, CWND_DROP and (for TCP) SEND_Q describe one
	// poll and are info-level context: a few segments lost and resent, a
	// window cut, a full send buffer are all normal while TCP fills a link
	// (the scenario lab's healthy controls raise every one of them). Loss
	// that matters is PATH_LOSS, judged over seconds, and a sender held back
	// shows as ZERO_WIN, RWND_LIM, SNDBUF_LIM or NO_ACK.
	if v := c.RetransNow; v != nil && *v > 3 {
		signals = append(signals, model.Signal{Type: model.SignalRetransInFlight, Severity: 0, Value: *v})
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

	if v := c.Lost; v != nil && *v > 2 { // info: see RETRANS above
		signals = append(signals, model.Signal{Type: model.SignalCongestionLoss, Severity: 0, Value: *v})
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

	// A TCP send queue filling up is an application writing faster than the
	// path drains: info (see RETRANS above). A UDP one, kept at warn above,
	// means this host can't put packets out as fast as the app sends.
	if queuePressure(c.SendQ, c.PrevSendQ, c.SkmemTB) > 0 {
		signals = append(signals, model.Signal{Type: model.SignalSendBufferPressure, Severity: 0, Value: *c.SendQ})
	}

	if sev := queuePressure(c.RecvQ, c.PrevRecvQ, tcpRecvPayload(c.SkmemRB)); sev > 0 {
		signals = append(signals, model.Signal{Type: model.SignalRecvBufferPressure, Severity: sev, Value: *c.RecvQ})
	}

	lossSev, lossV := pathLoss(c)
	if lossSev > 0 {
		signals = append(signals, model.Signal{Type: model.SignalPathLoss, Severity: lossSev, Value: lossV})
	}

	if c.DeltaBytesRetrans != nil && c.DeltaBytesSent != nil && *c.DeltaBytesSent > 0 {
		if rate := float64(*c.DeltaBytesRetrans) / float64(*c.DeltaBytesSent); rate > 0.05 { // info: see RETRANS
			signals = append(signals, model.Signal{Type: model.SignalHighRetransRate, Severity: 0, Value: rate})
		}
	}

	// Bottleneck attribution: how much of this poll the sender spent blocked on
	// the peer's receive window (rwnd_limited) vs. its own send buffer
	// (sndbuf_limited). Only meaningful while actively sending — a limit on an
	// idle connection is moot. A high fraction tells you *where* the throughput
	// ceiling is: RWND_LIM = the receiver isn't reading/advertising window fast
	// enough; SNDBUF_LIM = the local send buffer (SO_SNDBUF / app) is the cap.
	if c.DeltaBytesSent != nil && *c.DeltaBytesSent > 0 {
		if sev, frac := limitedSeverity(c.DeltaRwndLimitedMS, c.PrevDeltaRwndLimitedMS); sev > 0 {
			signals = append(signals, model.Signal{Type: model.SignalRwndLimited, Severity: sev,
				Value: fmt.Sprintf("%.0f%% of poll", frac*100)})
		}
		if sev, frac := limitedSeverity(c.DeltaSndbufLimitedMS, c.PrevDeltaSndbufLimitedMS); sev > 0 {
			signals = append(signals, model.Signal{Type: model.SignalSndbufLimited, Severity: sev,
				Value: fmt.Sprintf("%.0f%% of poll", frac*100)})
		} else if sendBufferCaps(c) {
			signals = append(signals, model.Signal{Type: model.SignalSndbufLimited, Severity: 1,
				Value: fmt.Sprintf("buffer full, all %d KB in flight", *c.SendQ/1024)})
		}
	}
	if fill, ok := receiveWindowFill(c); ok {
		signals = append(signals, model.Signal{Type: model.SignalRcvbufLimited, Severity: 1,
			// ≥100% is measurement noise (nominal poll interval, one
			// window snapshot): the window can't be overfilled.
			Value: fmt.Sprintf("≈%.0f%% of the %d KB window arrives every round trip", min(fill, 1)*100, *c.RcvWnd/1024)})
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

	// CWnd collapse: congestion window dropped sharply between polls, with
	// loss or ECN marks in the same poll to explain it (see cwndCutCause).
	// Only meaningful when the prior window was non-trivial; tiny windows
	// fluctuate naturally during slow start. BBR's ProbeRTT phase is skipped:
	// every ~10s it deliberately cuts cwnd to 4 packets for ~200ms to re-measure
	// min RTT, so on a lossy path a poll landing there would look like a collapse.
	//
	// "Sharply" means deeper than one halving: below half the previous window,
	// rounded down the way Reno rounds its halving, so a single 41→20 cut
	// never fires. Info-level context (see RETRANS above): slow start
	// overshooting a link cuts the window like this on healthy traffic.
	if c.PrevCWnd != nil && c.CWnd != nil && *c.PrevCWnd >= 20 && !bbrProbeRTT(c) {
		if cause := cwndCutCause(c); cause != "" && *c.CWnd < *c.PrevCWnd/2 {
			signals = append(signals, model.Signal{Type: model.SignalCWndCollapse, Severity: 0,
				Value: fmt.Sprintf("%d→%d after %s", *c.PrevCWnd, *c.CWnd, cause)})
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

	// Inbound loss: on the receiving host, segments arriving after a gap are
	// the only trace of loss on the peer → here path; the retransmit
	// counters belong to the sender. Judged over seconds, like PATH_LOSS.
	if sev, v := inboundLoss(c); sev > 0 {
		signals = append(signals, model.Signal{Type: model.SignalInboundLoss, Severity: sev, Value: v})
	}

	if DropsExplainedByInboundLoss(&model.Connection{Signals: signals, DeltaRcvOOOPack: c.DeltaRcvOOOPack}) {
		for i := range signals {
			if signals[i].Type == model.SignalSocketDrops {
				signals[i].Severity = 0
				signals[i].Value = fmt.Sprintf("%v out-of-order (loss recovery)", signals[i].Value)
			}
		}
	}

	if sev, v := reordering(c); sev > 0 {
		signals = append(signals, model.Signal{Type: model.SignalReordering, Severity: sev, Value: v})
	}

	return signals
}
