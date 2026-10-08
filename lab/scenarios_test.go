//go:build lab

package lab

import (
	"testing"
	"time"
)

// wan is a plausible wide-area path, applied to both directions: 20 ms each
// way (40 ms RTT) and a 100 Mbit/s bottleneck buffering about one
// bandwidth-delay product (350 packets, ~40 ms). An oversized buffer would
// add bufferbloat to every scenario and blur what it's testing.
var wan = link{Delay: "20ms", Rate: "100mbit", Buffer: 350}

// slow is a 10 Mbit/s link with a one-BDP buffer (35 packets), where a few
// flows already lose packets steadily just by sharing it.
var slow = link{Delay: "20ms", Rate: "10mbit", Buffer: 35}

// long is a 100 ms RTT path at 100 Mbit/s with a one-BDP buffer.
var long = link{Delay: "50ms", Rate: "100mbit", Buffer: 850}

// Loss is judged over about 12 s of sending (poller.SlotWindow), so loss
// scenarios record longer than that.
const lossRecord = 16 * time.Second

const port = ":5001"

// ---- healthy controls: sstui must stay quiet ------------------------------

// TestHealthyBulk: one connection sending as fast as the path allows. A
// loss-based sender fills the bottleneck queue and loses a packet now and
// then; that's how it finds the link rate, not a fault.
func TestHealthyBulk(t *testing.T) {
	l := newLab(t)
	l.path(wan, wan)
	l.start(l.b, "sink", addrB+port)
	l.start(l.a, "send", addrB+port)
	l.recordAndCheck(l.a, lossRecord).expectClean(t)
}

// TestHealthyBulkBBR: BBR's startup overshoots the path and loses a burst
// of packets once; after that it runs without loss.
func TestHealthyBulkBBR(t *testing.T) {
	l := newLab(t)
	l.path(wan, wan)
	l.start(l.b, "sink", addrB+port)
	l.start(l.a, "send", addrB+port, "1", "bbr")
	l.recordAndCheck(l.a, lossRecord).expectClean(t)
}

// TestHealthySlowLinkCongestion: four flows sharing a 10 Mbit/s link. Their
// windows are small, so each loses well over 0.5% of its packets, every few
// seconds, as it probes for bandwidth; the losses come with a full queue.
func TestHealthySlowLinkCongestion(t *testing.T) {
	l := newLab(t)
	l.path(slow, slow)
	l.start(l.b, "sink", addrB+port)
	l.start(l.a, "send", addrB+port, "4")
	l.recordAndCheck(l.a, lossRecord).expectClean(t)
}

// TestHealthyLongPath: four flows on a 100 ms path, where each sawtooth
// takes seconds and slow start overshoots hard.
func TestHealthyLongPath(t *testing.T) {
	l := newLab(t)
	l.path(long, long)
	l.start(l.b, "sink", addrB+port)
	l.start(l.a, "send", addrB+port, "4")
	l.recordAndCheck(l.a, lossRecord).expectClean(t)
}

// Not a control: several flows saturating a link whose buffer is only a few
// milliseconds deep. They drop before any queueing delay shows, which from
// the endpoint looks exactly like a lossy link, so PATH_LOSS can warn there;
// the loss finding names both causes (see classifier.pathLoss).

// TestHealthyRequestResponse: eight persistent connections fetching 1 MB
// responses with idle gaps, like an API or a cache. Bursts, idle restarts and
// a shared bottleneck are all normal here.
func TestHealthyRequestResponse(t *testing.T) {
	l := newLab(t)
	l.path(wan, wan)
	l.start(l.b, "reqserver", addrB+port, "1000000")
	l.start(l.a, "reqclient", addrB+port, "1000000", "8")
	l.recordAndCheck(l.b, lossRecord).expectClean(t)
}

// ---- failures: sstui must name them ---------------------------------------

// TestPacketLoss: 1% random loss on the data path. For a loss-based sender
// on a 40 ms path that caps throughput at a few Mbit/s, a twentieth of the
// link.
func TestPacketLoss(t *testing.T) {
	l := newLab(t)
	l.path(wan.with("loss 1%"), wan)
	l.start(l.b, "sink", addrB+port)
	l.start(l.a, "send", addrB+port)
	r := l.recordAndCheck(l.a, lossRecord)
	r.expect(t, "loss", "warning")
	r.expectNone(t, "reorder") // loss recovery ticks reord_seen; it isn't reordering
}

// TestLightPacketLoss: 0.1% loss. Still enough to hold a cubic flow on a
// 40 ms path to a fraction of a 100 Mbit/s link.
func TestLightPacketLoss(t *testing.T) {
	l := newLab(t)
	l.path(wan.with("loss 0.1%"), wan)
	l.start(l.b, "sink", addrB+port)
	l.start(l.a, "send", addrB+port)
	r := l.recordAndCheck(l.a, lossRecord)
	r.expect(t, "loss", "warning")
	r.expectNone(t, "reorder") // loss recovery ticks reord_seen; it isn't reordering
}

// TestHeavyPacketLoss: 3% loss is critical.
func TestHeavyPacketLoss(t *testing.T) {
	l := newLab(t)
	l.path(wan.with("loss 3%"), wan)
	l.start(l.b, "sink", addrB+port)
	l.start(l.a, "send", addrB+port)
	r := l.recordAndCheck(l.a, lossRecord)
	r.expect(t, "loss", "critical")
	r.expectNone(t, "reorder") // loss recovery ticks reord_seen; it isn't reordering
}

// TestPacketLossBBR: BBR keeps its throughput under 1% loss, but the path is
// still dropping packets and the operator should know.
func TestPacketLossBBR(t *testing.T) {
	l := newLab(t)
	l.path(wan.with("loss 1%"), wan)
	l.start(l.b, "sink", addrB+port)
	l.start(l.a, "send", addrB+port, "1", "bbr")
	r := l.recordAndCheck(l.a, lossRecord)
	r.expect(t, "loss", "warning")
	r.expectNone(t, "reorder") // loss recovery ticks reord_seen; it isn't reordering
}

// TestPacketLossRequestResponse: 1% loss on the response path of a bursty
// request/response service, recorded on the server.
func TestPacketLossRequestResponse(t *testing.T) {
	l := newLab(t)
	l.path(wan, wan.with("loss 1%"))
	l.start(l.b, "reqserver", addrB+port, "1000000")
	l.start(l.a, "reqclient", addrB+port, "1000000", "8")
	r := l.recordAndCheck(l.b, lossRecord)
	r.expect(t, "loss", "warning")
	r.expectNone(t, "reorder") // loss recovery ticks reord_seen; it isn't reordering
}

// TestReordering: 0.5% of packets overtake a few others on the way to the
// peer, as with ECMP or LACP hashing. Linux copes, but it's worth knowing,
// and it must not read as packet loss.
func TestReordering(t *testing.T) {
	l := newLab(t)
	l.path(wan, wan)
	l.reorder(l.a, "0.5%")
	l.start(l.b, "sink", addrB+port)
	l.start(l.a, "send", addrB+port)
	r := l.recordAndCheck(l.a, lossRecord)
	r.expect(t, "reorder", "warning")
	r.expectNone(t, "loss")
}

// TestHeavyReordering: 10% of packets reordered is critical.
func TestHeavyReordering(t *testing.T) {
	l := newLab(t)
	l.path(wan, wan)
	l.reorder(l.a, "10%")
	l.start(l.b, "sink", addrB+port)
	l.start(l.a, "send", addrB+port)
	r := l.recordAndCheck(l.a, lossRecord)
	r.expect(t, "reorder", "critical")
	r.expectNone(t, "loss")
}

// TestReorderingRequestResponse: reordering on the response path of a bursty
// request/response service, recorded on the server.
func TestReorderingRequestResponse(t *testing.T) {
	l := newLab(t)
	l.path(wan, wan)
	l.reorder(l.b, "2%")
	l.start(l.b, "reqserver", addrB+port, "1000000")
	l.start(l.a, "reqclient", addrB+port, "1000000", "8")
	r := l.recordAndCheck(l.b, lossRecord)
	r.expect(t, "reorder", "warning")
	r.expectNone(t, "loss")
}

// TestSynStall: the path drops everything the client sends, so its
// handshakes never complete and the SYNs back off (1 s, 3 s, 7 s, ...).
func TestSynStall(t *testing.T) {
	l := newLab(t)
	l.path(wan.with("loss 100%"), wan)
	l.start(l.b, "sink", addrB+port)
	l.start(l.a, "hold", addrB+port, "5")
	l.recordAndCheck(l.a, 9*time.Second).expect(t, "syn_stall", "critical")
}

// TestZeroWindow: the receiving application stops reading. Its buffer fills,
// it advertises a zero window, and the sender's data piles up in Send-Q.
func TestZeroWindow(t *testing.T) {
	l := newLab(t)
	l.path(wan, wan)
	l.start(l.b, "stall", addrB+port)
	l.start(l.a, "send", addrB+port)
	l.recordAndCheck(l.a, 6*time.Second).expect(t, "zero_window", "critical")
}

// TestAcceptQueueFull: a server that stops calling accept() with a backlog
// of 8, and clients still connecting. The queue fills and the kernel drops
// new handshakes.
func TestAcceptQueueFull(t *testing.T) {
	l := newLab(t)
	l.path(wan, wan)
	l.start(l.b, "backlog", addrB+port, "8")
	l.start(l.a, "hold", addrB+port, "30")
	r := l.recordAndCheck(l.b, 5*time.Second)
	r.expect(t, "listen_queue", "critical")
	r.expectNone(t, "recv_backlog") // the listener's drops are refused connections, not unread data
}

// TestAcceptQueueBursts: bursts of 40 connections against a backlog of 4,
// accepted one every 10 ms. Each burst overflows the queue, which has
// drained again by the time sstui polls, so only the listener's drop
// counter tells; it should still name that listener.
func TestAcceptQueueBursts(t *testing.T) {
	l := newLab(t)
	l.path(wan, wan)
	l.start(l.b, "slowaccept", addrB+port, "4", "10")
	l.start(l.a, "burst", addrB+port, "40", "1500")
	r := l.recordAndCheck(l.b, 8*time.Second)
	r.expect(t, "listen_queue", "critical")
	r.expectNone(t, "recv_backlog")
	r.expectNone(t, "listen_overflow_host") // folded into the listener's finding
}

// TestCloseWaitLeak: clients hang up, but the server never closes its side;
// 60 sockets sit in CLOSE-WAIT, each holding a file descriptor.
func TestCloseWaitLeak(t *testing.T) {
	l := newLab(t)
	l.path(wan, wan)
	l.start(l.b, "noclose", addrB+port)
	l.start(l.a, "hangup", addrB+port, "60")
	l.recordAndCheck(l.b, 4*time.Second).expect(t, "close_wait", "critical")
}
