package ui

import (
	"strings"
	"testing"

	"sstui/model"
	"sstui/poller"

	"github.com/charmbracelet/x/ansi"
)

// TestDetailInboundOOORatio: the Inbound section reports out-of-order
// arrivals against data segments received, per poll and lifetime.
func TestDetailInboundOOORatio(t *testing.T) {
	i := func(v int) *int { return &v }
	c := &model.Connection{Protocol: "tcp", State: "ESTAB",
		LocalAddr: "10.0.0.1", LocalPort: "443", PeerAddr: "10.0.0.2", PeerPort: "51000",
		CWnd:       i(10),
		RcvOOOPack: i(30), DataSegsIn: i(1000), DeltaRcvOOOPack: i(5), DeltaDataSegsIn: i(100)}
	out := ansi.Strip(RenderDetail(c, false, poller.NewBuffer(), 140, 60))
	for _, want := range []string{"Inbound (receiver side)", "5.00% poll · 3.00% life", "loss (or reordering) on the peer → here path"} {
		if !strings.Contains(out, want) {
			t.Errorf("detail missing %q:\n%s", want, out)
		}
	}
}

// TestDetailDeliveredCE: the ECN row appears only once the peer has echoed
// congestion marks.
func TestDetailDeliveredCE(t *testing.T) {
	i := func(v int) *int { return &v }
	c := &model.Connection{Protocol: "tcp", State: "ESTAB",
		LocalAddr: "10.0.0.1", LocalPort: "443", PeerAddr: "10.0.0.2", PeerPort: "51000",
		CWnd: i(10), Delivered: i(500), DeliveredCE: i(0)}
	if out := ansi.Strip(RenderDetail(c, false, poller.NewBuffer(), 140, 60)); strings.Contains(out, "Delivered CE") {
		t.Errorf("Delivered CE row should be hidden while 0")
	}
	c.DeliveredCE = i(12)
	if out := ansi.Strip(RenderDetail(c, false, poller.NewBuffer(), 140, 60)); !strings.Contains(out, "Delivered CE") {
		t.Errorf("Delivered CE row missing once non-zero:\n%s", out)
	}
}

func TestDetailInboundHiddenForUDP(t *testing.T) {
	c := &model.Connection{Protocol: "udp", State: "UDP_ESTAB", LocalAddr: "10.0.0.1", LocalPort: "53", PeerAddr: "10.0.0.2", PeerPort: "5353"}
	if out := ansi.Strip(RenderDetail(c, false, poller.NewBuffer(), 140, 60)); strings.Contains(out, "Inbound") {
		t.Errorf("UDP sockets have no TCP inbound counters; section should be hidden")
	}
}

func TestOOORatio(t *testing.T) {
	i := func(v int) *int { return &v }
	if r, ok := oooRatio(i(3), i(300)); !ok || r != 0.01 {
		t.Errorf("3/300 = %v, %v; want 0.01", r, ok)
	}
	if _, ok := oooRatio(i(3), i(0)); ok {
		t.Errorf("no data segments received: ratio is undefined")
	}
	if _, ok := oooRatio(nil, i(10)); ok {
		t.Errorf("unknown OOO count: ratio is undefined")
	}
}

// TestSocketSendBufferQueued: a TCP send buffer's fill is what's queued in
// it (skmem w), checked against tb; t is only what the device holds, near 0
// with a full buffer (the demo's uploader: t 0, w 1.5 MB of a 1.6 MB tb).
// UDP's queue is t.
func TestSocketSendBufferQueued(t *testing.T) {
	i := func(v int) *int { return &v }
	tcp := &model.Connection{Protocol: "tcp", State: "ESTAB", SkmemT: i(0), SkmemW: i(1_536_000), SkmemTB: i(1_638_400)}
	if out := ansi.Strip(RenderSocket(tcp, false, poller.NewBuffer(), 140, 40)); !strings.Contains(out, "snd buf         :   1.5M / 1.6M") {
		t.Errorf("TCP send buffer should show w / tb:\n%s", out)
	}
	udp := &model.Connection{Protocol: "udp", State: "UNCONN", SkmemT: i(4096), SkmemW: i(0), SkmemTB: i(212_992)}
	if out := ansi.Strip(RenderSocket(udp, false, poller.NewBuffer(), 140, 40)); !strings.Contains(out, "snd buf         :   4.0K / 208.0K") {
		t.Errorf("UDP send buffer should show t / tb:\n%s", out)
	}
}
