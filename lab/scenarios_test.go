//go:build lab

package lab

import (
	"testing"
	"time"
)

// wan is a plausible wide-area path, applied to both directions: 20 ms each
// way (40 ms RTT) and a 100 Mbit/s bottleneck with a sane queue of 500
// packets (about 60 ms at that rate). An oversized queue would add bufferbloat
// to every scenario and blur what it's testing.
const wan = "delay 20ms rate 100mbit limit 500"

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
	l.recordAndCheck(l.a, 10*time.Second).expectClean(t)
}

// TestHealthyRequestResponse: eight persistent connections fetching 1 MB
// responses with idle gaps, like an API or a cache. Bursts, idle restarts and
// a shared bottleneck are all normal here.
func TestHealthyRequestResponse(t *testing.T) {
	l := newLab(t)
	l.path(wan, wan)
	l.start(l.b, "reqserver", addrB+port, "1000000")
	l.start(l.a, "reqclient", addrB+port, "1000000", "8")
	l.recordAndCheck(l.b, 10*time.Second).expectClean(t)
}

// ---- failures: sstui must name them ---------------------------------------

// TestPacketLoss: 1% random loss on the data path. For a loss-based sender
// on a 40 ms path that caps throughput at a few Mbit/s, a twentieth of the
// link.
func TestPacketLoss(t *testing.T) {
	l := newLab(t)
	l.path(wan+" loss 1%", wan)
	l.start(l.b, "sink", addrB+port)
	l.start(l.a, "send", addrB+port)
	l.recordAndCheck(l.a, 6*time.Second).expect(t, "loss", "warning")
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
	l.recordAndCheck(l.b, 5*time.Second).expect(t, "listen_queue", "critical")
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
