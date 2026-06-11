package ui

import (
	"strings"
	"testing"

	"sstui/model"
	"sstui/poller"
)

// TestOverviewRTTSkipsLeadingNoData guards the avg-RTT fix: snapshots before
// the first RTT sample must not seed the series with a spurious 0.0ms, which
// would otherwise show up as the chart's min.
func TestOverviewRTTSkipsLeadingNoData(t *testing.T) {
	buf := poller.NewBuffer()
	// First poll: only a UDP socket, no RTT.
	buf.AddSnapshot([]*model.Connection{{
		Protocol: "udp", State: "UDP_IDLE",
		LocalAddr: "0.0.0.0", LocalPort: "53", PeerAddr: "*", PeerPort: "*",
	}})
	// Second poll: a TCP socket with a real RTT.
	rtt := 12.5
	buf.AddSnapshot([]*model.Connection{{
		Protocol: "tcp", State: "ESTAB",
		LocalAddr: "10.0.0.1", LocalPort: "1", PeerAddr: "9.9.9.9", PeerPort: "443",
		RTT: &rtt,
	}})

	out := RenderOverview(buf, 120, 40)
	if strings.Contains(out, "min: 0.0ms") {
		t.Errorf("avg-RTT chart should not report a 0.0ms min from leading no-data snapshots:\n%s", out)
	}
	if !strings.Contains(out, "min: 12.5ms") {
		t.Errorf("avg-RTT min should be the first real sample (12.5ms):\n%s", out)
	}
}
