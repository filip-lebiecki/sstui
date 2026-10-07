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
