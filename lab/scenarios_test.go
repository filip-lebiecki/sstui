//go:build lab

package lab

import (
	"os"
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

// healthy runs a healthy control twice: at the lab's 500 ms interval for d,
// and at sstui's default 2 s, which is what users run, for at least 24 s so
// loss is judged over full windows. Polls that far apart catch more in each
// one and stretch the timing of every slot; false alarms hide there.
func healthy(t *testing.T, d time.Duration, setup func(l *lab)) {
	for _, run := range []struct {
		interval string
		d        time.Duration
	}{{"500ms", d}, {"2s", max(d, 24*time.Second)}} {
		t.Run(run.interval, func(t *testing.T) {
			l := newLab(t)
			l.interval = run.interval
			setup(l)
			client, server := l.recordBoth(run.d)
			client.expectClean(t)
			server.expectClean(t)
		})
	}
}

// TestHealthyBulk: one connection sending as fast as the path allows. A
// loss-based sender fills the bottleneck queue and loses a packet now and
// then; that's how it finds the link rate, not a fault.
func TestHealthyBulk(t *testing.T) {
	healthy(t, lossRecord, func(l *lab) {
		l.path(wan, wan)
		l.start(l.b, "sink", addrB+port)
		l.start(l.a, "send", addrB+port)
	})
}

// TestHealthyBulkBBR: BBR's startup overshoots the path and loses a burst
// of packets once; after that it runs without loss.
func TestHealthyBulkBBR(t *testing.T) {
	healthy(t, lossRecord, func(l *lab) {
		l.path(wan, wan)
		l.start(l.b, "sink", addrB+port)
		l.start(l.a, "send", addrB+port, "1", "bbr")
	})
}

// TestHealthySlowLinkCongestion: four flows sharing a 10 Mbit/s link. Their
// windows are small, so each loses well over 0.5% of its packets, every few
// seconds, as it probes for bandwidth; the losses come with a full queue.
func TestHealthySlowLinkCongestion(t *testing.T) {
	healthy(t, lossRecord, func(l *lab) {
		l.path(slow, slow)
		l.start(l.b, "sink", addrB+port)
		l.start(l.a, "send", addrB+port, "4")
	})
}

// TestHealthyMixed: bulk and bursty request/response sharing the link. The
// bulk senders keep the queue full while the responses burst into it.
func TestHealthyMixed(t *testing.T) {
	healthy(t, 32*time.Second, func(l *lab) {
		l.path(wan, wan)
		l.start(l.b, "sink", addrB+port)
		l.start(l.a, "send", addrB+port, "2")
		l.start(l.b, "reqserver", addrB+":443", "1000000")
		l.start(l.a, "reqclient", addrB+":443", "1000000", "8")
	})
}

// TestHealthyLongPath: four flows on a 100 ms path, where each sawtooth
// takes seconds and slow start overshoots hard.
func TestHealthyLongPath(t *testing.T) {
	healthy(t, lossRecord, func(l *lab) {
		l.path(long, long)
		l.start(l.b, "sink", addrB+port)
		l.start(l.a, "send", addrB+port, "4")
	})
}

// Not a control: several flows saturating a link whose buffer is only a few
// milliseconds deep. They drop before any queueing delay shows, which from
// the endpoint looks exactly like a lossy link, so PATH_LOSS can warn there;
// the loss finding names both causes (see classifier.pathLoss).

// TestHealthyRequestResponse: eight persistent connections fetching 1 MB
// responses with idle gaps, like an API or a cache. Bursts, idle restarts and
// a shared bottleneck are all normal here.
func TestHealthyRequestResponse(t *testing.T) {
	healthy(t, lossRecord, func(l *lab) {
		l.path(wan, wan)
		l.start(l.b, "reqserver", addrB+port, "1000000")
		l.start(l.a, "reqclient", addrB+port, "1000000", "8")
	})
}

// ---- failures: sstui must name them ---------------------------------------

// TestPacketLoss: 1% random loss on the data path. For a loss-based sender
// on a 40 ms path that caps throughput at a few Mbit/s, a twentieth of the
// link. The sender sees its retransmits; the receiver only the gaps in what
// arrives, and must name the loss too.
func TestPacketLoss(t *testing.T) {
	l := newLab(t)
	l.path(wan.with("loss 1%"), wan)
	l.start(l.b, "sink", addrB+port)
	l.start(l.a, "send", addrB+port)
	r, rx := l.recordBoth(lossRecord)
	r.expect(t, "loss", "warning")
	r.expectNone(t, "reorder")
	rx.expect(t, "rx_loss", "warning")
}

// TestLightPacketLoss: 0.1% loss. Still enough to hold a cubic flow on a
// 40 ms path to a fraction of a 100 Mbit/s link.
func TestLightPacketLoss(t *testing.T) {
	l := newLab(t)
	l.path(wan.with("loss 0.1%"), wan)
	l.start(l.b, "sink", addrB+port)
	l.start(l.a, "send", addrB+port)
	r, rx := l.recordBoth(lossRecord)
	r.expect(t, "loss", "warning")
	r.expectNone(t, "reorder")
	rx.expect(t, "rx_loss", "warning")
}

// TestPacketLossDefaultInterval: 1% loss watched at sstui's default 2 s
// interval rather than the lab's 500 ms. Loss is judged in slots of 2 s;
// polls 2 s apart, give or take a few ms, must each complete one, or the
// window holds too few slots for a verdict every other poll and the finding
// comes and goes. Over 32 s (17 polls) the verdict holds from about the
// sixth poll on.
func TestPacketLossDefaultInterval(t *testing.T) {
	l := newLab(t)
	l.path(wan.with("loss 1%"), wan)
	l.interval = "2s"
	l.start(l.b, "sink", addrB+port)
	l.start(l.a, "send", addrB+port)
	r, rx := l.recordBoth(32 * time.Second)
	r.expectSteady(t, "loss", 10)
	rx.expectSteady(t, "rx_loss", 10)
}

// TestHeavyPacketLoss: 3% loss is critical.
func TestHeavyPacketLoss(t *testing.T) {
	l := newLab(t)
	l.path(wan.with("loss 3%"), wan)
	l.start(l.b, "sink", addrB+port)
	l.start(l.a, "send", addrB+port)
	r, rx := l.recordBoth(lossRecord)
	r.expect(t, "loss", "critical")
	r.expectNone(t, "reorder")
	rx.expect(t, "rx_loss", "warning")
}

// TestPacketLossBBR: BBR keeps its throughput under 1% loss, but the path is
// still dropping packets and the operator should know. Only the sender can
// tell: BBR keeps a standing queue, which the receiver can't tell from
// congestion (see classifier.inboundLoss).
func TestPacketLossBBR(t *testing.T) {
	l := newLab(t)
	l.path(wan.with("loss 1%"), wan)
	l.start(l.b, "sink", addrB+port)
	l.start(l.a, "send", addrB+port, "1", "bbr")
	r := l.recordAndCheck(l.a, lossRecord)
	r.expect(t, "loss", "warning")
	r.expectNone(t, "reorder")
}

// TestPacketLossRequestResponse: 1% loss on the response path of a bursty
// request/response service, recorded on the server.
func TestPacketLossRequestResponse(t *testing.T) {
	l := newLab(t)
	l.path(wan, wan.with("loss 1%"))
	l.start(l.b, "reqserver", addrB+port, "1000000")
	l.start(l.a, "reqclient", addrB+port, "1000000", "8")
	rx, r := l.recordBoth(lossRecord)
	r.expect(t, "loss", "warning")
	r.expectNone(t, "reorder")
	rx.expect(t, "rx_loss", "warning")
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

// TestLightReordering: 0.03% of packets reordered, a few a second: TCP
// barely notices, but the path is reordering, and a busier flow through it
// would see more. Reported once slow start's losses leave the window: until
// then the reordering is too rare next to them (reorderPerRetrans).
func TestLightReordering(t *testing.T) {
	l := newLab(t)
	l.path(wan, wan)
	l.reorder(l.a, "0.03%")
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

// TestPortExhaustion: a client opening a new connection per request, with no
// reuse, toward one server. Every closed connection holds its port in
// TIME-WAIT for 60 s, so a 1000-port range runs dry within seconds and
// connect() starts failing.
func TestPortExhaustion(t *testing.T) {
	l := newLab(t)
	l.path(wan, wan)
	l.sysctl(l.a, "net.ipv4.ip_local_port_range=40000 40999")
	l.start(l.b, "sink", addrB+port)
	l.start(l.a, "churn", addrB+port, "50")
	r := l.recordAndCheck(l.a, 6*time.Second)
	r.expect(t, "ephemeral_ports", "critical")
	r.expect(t, "time_wait", "warning")
}

// TestPathMTU: a link in the middle of the path (a tunnel, say) carries 1400
// bytes, not 1500. The router says so with ICMP and the sender's path MTU
// discovery adapts; worth knowing, but nothing is broken.
func TestPathMTU(t *testing.T) {
	l := newLab(t)
	l.path(wan, wan)
	l.narrowLink(1400)
	l.start(l.b, "sink", addrB+port)
	l.start(l.a, "send", addrB+port)
	r := l.recordAndCheck(l.a, 6*time.Second)
	r.expect(t, "pmtu", "warning")
	r.expectNone(t, "loss")
}

// TestPMTUBlackHole: the same narrow link, but a firewall drops the ICMP that
// would report it. The handshake's small packets get through, every
// full-sized data segment vanishes, and the connection hangs.
func TestPMTUBlackHole(t *testing.T) {
	l := newLab(t)
	l.path(wan, wan)
	l.narrowLink(1400)
	l.dropICMP(l.a)
	l.start(l.b, "sink", addrB+port)
	l.start(l.a, "send", addrB+port)
	r := l.recordAndCheck(l.a, 10*time.Second)
	r.expect(t, "pmtu_blackhole", "critical")
	r.expectNone(t, "loss")
}

// TestSlowReader: the receiving application reads only 500 KB/s of a
// 100 Mbit/s path. Its receive queue stays full and TCP flow control holds
// the sender to the reader's pace: the receiver names its slow reader, the
// sender sees the window holding it back.
func TestSlowReader(t *testing.T) {
	l := newLab(t)
	l.path(wan, wan)
	l.start(l.b, "slowsink", addrB+port, "500")
	l.start(l.a, "send", addrB+port)
	client, server := l.recordBoth(8 * time.Second)
	server.expect(t, "recv_backlog", "critical") // a full TCP receive queue
	client.expect(t, "rwnd", "warning")
}

// TestSmallReceiveBuffer: the receiver reads everything at once, but its
// receive buffer is capped at 128 KB (tcp_rmem), too small for a 100 Mbit/s,
// 40 ms path (a bandwidth-delay product of 500 KB): the window holds the
// sender to a few MB/s while the link sits mostly idle. The sender sees the
// window holding it back; the receiver, its whole window arriving every
// round trip while it keeps up.
func TestSmallReceiveBuffer(t *testing.T) {
	l := newLab(t)
	l.path(wan, wan)
	l.sysctl(l.b, "net.ipv4.tcp_rmem=4096 131072 131072")
	l.start(l.b, "sink", addrB+port)
	l.start(l.a, "send", addrB+port)
	client, server := l.recordBoth(8 * time.Second)
	client.expect(t, "rwnd", "warning")
	server.expect(t, "rcvbuf", "warning")
	server.expectNone(t, "recv_backlog") // the reader keeps up
}

// TestSmallSendBuffer: the sending application sets SO_SNDBUF to 64 KB,
// which also turns off the kernel's send-buffer autotuning. The buffer holds
// less than the path's 500 KB bandwidth-delay product, so the sender stalls
// on its own buffer.
func TestSmallSendBuffer(t *testing.T) {
	l := newLab(t)
	l.path(wan, wan)
	l.start(l.b, "sink", addrB+port)
	l.start(l.a, "sndbuf", addrB+port, "65536")
	l.recordAndCheck(l.a, 8*time.Second).expect(t, "sndbuf", "warning")
}

// TestBufferbloat: a 10 Mbit/s bottleneck buffering 1000 packets, over a
// second of queue. A loss-based sender fills it before it loses anything, so
// every packet, this flow's and anyone else's, waits behind the queue.
func TestBufferbloat(t *testing.T) {
	l := newLab(t)
	l.path(link{Delay: "20ms", Rate: "10mbit", Buffer: 1000}, wan)
	l.start(l.b, "sink", addrB+port)
	l.start(l.a, "send", addrB+port)
	r := l.recordAndCheck(l.a, lossRecord)
	r.expect(t, "rtt", "critical")
	r.expectNone(t, "loss") // the losses come with a full queue: congestion
}

// TestSynFlood: 100 clients whose handshakes never complete (their side
// drops every SYN-ACK), against a listener with a backlog of 16 that
// accepts promptly. Half-open connections fill its SYN queue, and the
// kernel answers the rest with syncookies.
func TestSynFlood(t *testing.T) {
	l := newLab(t)
	l.path(wan, wan)
	l.dropSynAcks(l.a)
	l.start(l.b, "slowaccept", addrB+port, "16", "1")
	l.start(l.a, "hold", addrB+port, "100")
	l.recordAndCheck(l.b, 6*time.Second).expect(t, "syn_backlog", "warning")
}

// TestUDPReceiveDrops: a UDP receiver that processes 500 KB/s while 2 MB/s
// arrives. UDP has no flow control: once its receive buffer is full, the
// kernel drops what the application hasn't read.
func TestUDPReceiveDrops(t *testing.T) {
	l := newLab(t)
	l.path(wan, wan)
	l.start(l.b, "udpsink", addrB+port, "500")
	l.start(l.a, "udpsend", addrB+port, "2000")
	l.recordAndCheck(l.b, 6*time.Second).expect(t, "recv_backlog", "critical")
}

// TestLossOnLocalLink: this host's own link loses 1% of what it sends, so
// every peer sees loss at once. Six servers (addresses) rather than one make
// the common factor this host, not one peer's path.
func TestLossOnLocalLink(t *testing.T) {
	l := newLab(t)
	l.path(wan, wan)
	l.lossyNIC(l.a, "1%")
	l.start(l.b, "sink", port)
	for _, addr := range l.moreAddrs(l.b, 6) {
		l.start(l.a, "send", addr+port)
	}
	r := l.recordAndCheck(l.a, lossRecord)
	r.expect(t, "loss_local", "warning")
	r.expectNone(t, "loss") // not six separate per-peer findings
}

// TestInboundLossOnLocalLink: this host's incoming link loses 1% of what
// arrives (as a NIC dropping on receive would), so data from every sender
// arrives with gaps. Six clients (addresses) rather than one make the common
// factor this host's receive path, not one sender's path.
func TestInboundLossOnLocalLink(t *testing.T) {
	l := newLab(t)
	l.path(wan.with("loss 1%"), wan) // the router's link into b
	l.start(l.b, "sink", addrB+port)
	for _, src := range l.moreAddrs(l.a, 6) {
		l.start(l.a, "sendfrom", src, addrB+port)
	}
	r := l.recordAndCheck(l.b, lossRecord)
	r.expect(t, "rx_loss_local", "warning")
	r.expectNone(t, "rx_loss") // not six separate per-peer findings
}

// TestPMTUBlackHoleLocal: this host's link MTU is misconfigured (1500 here,
// 1400 at the other end), so its full-sized packets vanish toward every
// peer. Connections to six servers (addresses) hang right after their
// handshakes, which points at this host's MTU rather than one path.
func TestPMTUBlackHoleLocal(t *testing.T) {
	l := newLab(t)
	l.path(wan, wan)
	l.mismatchedMTU(1400)
	l.start(l.b, "sink", port)
	for _, addr := range l.moreAddrs(l.b, 6) {
		l.start(l.a, "send", addr+port)
	}
	r := l.recordAndCheck(l.a, 10*time.Second)
	r.expect(t, "pmtu_blackhole_local", "critical")
	r.expectNone(t, "pmtu_blackhole") // not six separate per-peer findings
}

// TestShortConnectionLoss: this host's link loses 3% of what it sends while
// it uploads 200 KB at a time over fresh connections, eight at once. Each
// connection lasts well under a second, too short for any one of them to
// show steady loss, but the host as a whole keeps retransmitting. (The
// churn also leaves hundreds of sockets in TIME-WAIT, which is reported too,
// rightly.)
func TestShortConnectionLoss(t *testing.T) {
	l := newLab(t)
	l.path(wan, wan)
	l.lossyNIC(l.a, "3%")
	l.start(l.b, "sink", addrB+port)
	l.start(l.a, "upload", addrB+port, "200000", "8")
	l.recordAndCheck(l.a, lossRecord).expect(t, "retrans_host", "warning")
}

// TestUDPReceiveDropsFiltered: the UDP overload of TestUDPReceiveDrops,
// recorded with an ss filter that leaves the dropping socket out (sstui
// watching only SSH). The host's UDP counters still see the drops.
func TestUDPReceiveDropsFiltered(t *testing.T) {
	l := newLab(t)
	l.path(wan, wan)
	l.ssFilter = "sport = :22"
	l.start(l.b, "udpsink", addrB+port, "500")
	l.start(l.a, "udpsend", addrB+port, "2000")
	r := l.recordAndCheck(l.b, 6*time.Second)
	r.expect(t, "udp_rcvbuf_host", "critical")
	r.expectNone(t, "recv_backlog") // the socket is out of view
}

// TestAcceptQueueBurstsFiltered: the accept-queue bursts of
// TestAcceptQueueBursts, recorded with an ss filter that leaves the
// listener out. The host's ListenOverflows / ListenDrops still see them.
func TestAcceptQueueBurstsFiltered(t *testing.T) {
	l := newLab(t)
	l.path(wan, wan)
	l.ssFilter = "sport = :22"
	l.start(l.b, "slowaccept", addrB+port, "4", "10")
	l.start(l.a, "burst", addrB+port, "40", "1500")
	l.recordAndCheck(l.b, 8*time.Second).expect(t, "listen_overflow_host", "critical")
}

// TestHealthyLateJoiner: four flows keep a 10 Mbit/s link and its queue
// full; a fifth connects 3 s later, so its handshake, the receiver's only
// RTT sample before data flows, already waits in that queue. Healthy
// congestion all the same: the receiver must not take it for path loss.
func TestHealthyLateJoiner(t *testing.T) {
	healthy(t, lossRecord, func(l *lab) {
		l.path(slow, slow)
		l.start(l.b, "sink", addrB+port)
		l.start(l.a, "send", addrB+port, "4")
		time.Sleep(3 * time.Second)
		l.start(l.a, "send", addrB+port)
	})
}

// TestPMTUBlackHoleMidConnection: a bulk upload and a chatty connection of
// small messages run to one server; 3 s in, the path changes to one that
// carries only 1400 bytes with ICMP filtered (a route change into a tunnel).
// The upload, which got data through before, hangs; the small messages
// keep getting through.
func TestPMTUBlackHoleMidConnection(t *testing.T) {
	l := newLab(t)
	l.path(wan, wan)
	l.start(l.b, "sink", addrB+port)
	l.start(l.b, "reqserver", addrB+":5002", "200")
	l.start(l.a, "send", addrB+port)
	l.start(l.a, "reqclient", addrB+":5002", "200", "1")
	time.Sleep(3 * time.Second)
	l.narrowLink(1400)
	l.dropICMP(l.a)
	r := l.recordAndCheck(l.a, 10*time.Second)
	r.expectTitle(t, "loss", "stall while others to it get through")
}

// TestReceiveMemoryPressure: TCP's host-wide memory limit (tcp_mem) is far
// below what eight connections into slow readers hold in their receive
// queues. Their data keeps arriving at queues already over the limit, so the
// kernel collapses and prunes them. Host-wide: run only on a disposable
// machine (SSTUI_LAB_HOSTWIDE=1).
func TestReceiveMemoryPressure(t *testing.T) {
	hostWide(t)
	l := newLab(t)
	l.path(wan, wan)
	l.start(l.b, "slowsink", addrB+port, "200")
	l.start(l.a, "send", addrB+port, "8")
	time.Sleep(3 * time.Second) // let the receive queues fill
	l.squeezeTCPMem("32 48 64")
	// The server's namespace sees the pruning and its sockets' drops; tcp_mem
	// exists only in the machine's own, which sees TCP's memory against it.
	wb, wh := l.startRecord(l.b, 8*time.Second), l.startRecord("", 8*time.Second)
	server, host := l.check(wb(), "server"), l.check(wh(), "host")
	server.expect(t, "rcv_mem_pressure", "critical")
	server.expectNone(t, "recv_backlog") // the drops are the memory limit's, not the readers'
	host.expect(t, "rcv_mem_pressure", "critical")
}

// TestReceiveQueuePruned: a receiver shrinks its buffer while the window it
// advertised is still in flight, so one socket's queue outgrows its own
// buffer and the kernel collapses it and drops data. Pruning, but TCP isn't
// short of memory host-wide: that mustn't be blamed on tcp_mem.
func TestReceiveQueuePruned(t *testing.T) {
	l := newLab(t)
	l.path(wan, wan)
	l.start(l.b, "shrinksink", addrB+port)
	l.start(l.a, "send", addrB+port)
	server := l.recordAndCheck(l.b, 8*time.Second)
	server.expect(t, "rcv_prune", "warning")
	server.expectNone(t, "rcv_mem_pressure")
}

// TestDemo records the README's demo (docs/demo): one server, web-1, whose
// services run healthy for a while, then three things go wrong at once. A
// worker falls behind its feed, an auth service stops accepting, and an
// uploader's path to one peer starts losing 1% of its packets. It runs
// only with SSTUI_LAB_DEMO set to where the recording goes.
func TestDemo(t *testing.T) {
	out := os.Getenv("SSTUI_LAB_DEMO")
	if out == "" {
		t.Skip("records the README demo; set SSTUI_LAB_DEMO to the recording's path")
	}
	l := newLab(t)
	l.path(wan, wan)
	l.hostname, l.interval = "web-1", "2s"
	peers := l.moreAddrs(l.a, 2)
	l.start(l.a, "sink", peers[1]+port)
	l.startAs(l.b, "api", "reqserver", addrB+":443", "20000")
	l.start(l.a, "reqclient", addrB+":443", "20000", "8")
	l.startAs(l.b, "worker", "slowsink", addrB+":7000", "300")
	l.startAs(l.b, "auth", "backlog", addrB+":8443", "16")

	wait := l.startRecord(l.b, 60*time.Second)
	time.Sleep(16 * time.Second)
	l.start(l.a, "send", addrB+":7000") // more work than the worker can take
	l.start(l.a, "hold", addrB+":8443", "40")
	l.lossTo(l.a, peers[1], 100)
	l.startAs(l.b, "uploader", "send", peers[1]+port)
	path := wait()

	r := l.check(path, "server")
	r.expect(t, "recv_backlog", "critical")
	r.expect(t, "listen_queue", "critical")
	r.expect(t, "loss", "warning")
	// Nothing else, so the healthy opening and the api stay quiet. The
	// burst of 40 connections at a backlog of 16 may overflow the SYN
	// queue for a poll before the accept queue is seen full.
	for _, f := range r.Findings {
		switch kind(f.ID) {
		case "recv_backlog", "listen_queue", "loss", "syn_backlog", "listen_overflow_host":
		default:
			t.Errorf("demo: unexpected %s finding: %s", f.ID, f.Title)
		}
	}
	l.copyOut(path, out)
}

// TestHealthyIdleKeepalive: idle connections with TCP keepalive on (Go's
// default, a probe every 15 s). The server's kernel discards each probe by
// design (an old sequence number, answered with an ACK) and counts it in
// the socket's drop counter, so idle connections with empty buffers show
// drops. No data was lost: sstui must stay quiet.
func TestHealthyIdleKeepalive(t *testing.T) {
	healthy(t, 10*time.Second, func(l *lab) {
		l.path(wan, wan)
		l.start(l.b, "noclose", addrB+port)
		l.start(l.a, "hold", addrB+port, "20")
		time.Sleep(10 * time.Second) // the recording spans the first probes, at 15 s
	})
}
