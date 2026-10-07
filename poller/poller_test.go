package poller

import (
	"testing"
	"time"
	"unsafe"

	"sstui/classifier"
	"sstui/model"
)

// TestSetInterval verifies the poll cadence override also updates the
// classifier's notion of the interval, and that a non-positive value is ignored.
func TestSetInterval(t *testing.T) {
	origInterval := PollInterval
	origMS := classifier.PollIntervalMS
	defer func() {
		PollInterval = origInterval
		classifier.PollIntervalMS = origMS
	}()

	SetInterval(500 * time.Millisecond)
	if PollInterval != 500*time.Millisecond {
		t.Errorf("PollInterval = %s, want 500ms", PollInterval)
	}
	if classifier.PollIntervalMS != 500 {
		t.Errorf("classifier.PollIntervalMS = %v, want 500", classifier.PollIntervalMS)
	}

	SetInterval(-1) // ignored
	if PollInterval != 500*time.Millisecond {
		t.Errorf("non-positive interval should be ignored, got %s", PollInterval)
	}
}

// TestBufferCompactsDemotedSnapshots verifies item 6: once a snapshot is no
// longer the latest, its connections are slimmed to the history-relevant
// fields (freeing the rest), while the latest snapshot stays full and Lookup
// still resolves.
func TestBufferCompactsDemotedSnapshots(t *testing.T) {
	buf := NewBuffer()
	inode := "999"
	mk := func() []*model.Connection {
		bsent := 12345 // fresh heavy field per snapshot
		rtt := 7.5
		return []*model.Connection{{
			Protocol: "tcp", State: "ESTAB",
			LocalAddr: "1.1.1.1", LocalPort: "1",
			PeerAddr: "2.2.2.2", PeerPort: "2",
			Inode:     &inode,
			BytesSent: &bsent, // heavy: dropped from history
			RTT:       &rtt,   // kept: read by sparklines/overview
		}}
	}

	buf.AddSnapshot(mk()) // snapshot 0 — latest, full
	buf.AddSnapshot(mk()) // snapshot 1 — latest; snapshot 0 demoted -> compacted

	all := buf.GetAll()
	if len(all) != 2 {
		t.Fatalf("got %d snapshots, want 2", len(all))
	}
	demoted, latest := all[0], all[1]

	if demoted.Full() {
		t.Errorf("demoted snapshot should have dropped its full-detail Conns")
	}
	dc := demoted.Connections()[0]
	if dc.BytesSent != nil {
		t.Errorf("demoted snapshot should have dropped BytesSent")
	}
	if v := dc.RTT; v == nil || *v != 7.5 {
		t.Errorf("demoted snapshot should keep RTT, got %v", v)
	}
	if dc.Inode == nil || *dc.Inode != "999" || dc.ConnKey() != latest.Conns[0].ConnKey() {
		t.Errorf("materialized connection should keep its identity, got key %q", dc.ConnKey())
	}
	if demoted.Lookup(dc.ConnKey()) == nil || demoted.LookupSample(dc.ConnKey()) == nil {
		t.Errorf("Lookup must still resolve after demotion")
	}
	if latest.Conns[0].BytesSent == nil {
		t.Errorf("latest snapshot must remain full (BytesSent present)")
	}
}

// TestLookupRecent verifies that a key still resolves after the connection
// drops out of the latest snapshot (so closed connections stay inspectable),
// and that the most recent occurrence wins when the key appears more than once.
func TestLookupRecent(t *testing.T) {
	buf := NewBuffer()
	inode := "42"
	mk := func(rtt float64) []*model.Connection {
		r := rtt
		return []*model.Connection{{
			Protocol: "tcp", State: "ESTAB",
			LocalAddr: "1.1.1.1", LocalPort: "1",
			PeerAddr: "2.2.2.2", PeerPort: "2",
			Inode: &inode, RTT: &r,
		}}
	}
	buf.AddSnapshot(mk(1.0)) // connection present
	buf.AddSnapshot(mk(2.0)) // present again, newer RTT
	k := buf.GetLatest().Conns[0].ConnKey()

	// Most recent occurrence wins.
	if c := buf.LookupRecent(k); c == nil || c.RTT == nil || *c.RTT != 2.0 {
		t.Fatalf("LookupRecent should return newest occurrence (RTT 2.0), got %v", c)
	}

	// Connection disappears from the latest snapshot but stays in history.
	buf.AddSnapshot(nil)
	if buf.GetLatest().Lookup(k) != nil {
		t.Fatalf("precondition: key should be absent from latest snapshot")
	}
	if c := buf.LookupRecent(k); c == nil {
		t.Errorf("LookupRecent should still find a closed connection in history")
	}

	if buf.LookupRecent("nonexistent|key") != nil {
		t.Errorf("LookupRecent should return nil for an unknown key")
	}
}

// TestSnapshotFromEnd verifies the scrub accessor maps offsets to the right
// snapshot newest-first and rejects out-of-range offsets.
func TestSnapshotFromEnd(t *testing.T) {
	buf := NewBuffer()
	mk := func(addr string) []*model.Connection {
		return []*model.Connection{{
			Protocol: "tcp", State: "ESTAB",
			LocalAddr: addr, LocalPort: "1", PeerAddr: "2.2.2.2", PeerPort: "2",
		}}
	}
	buf.AddSnapshot(mk("1.1.1.1")) // oldest
	buf.AddSnapshot(mk("2.2.2.2"))
	buf.AddSnapshot(mk("3.3.3.3")) // newest

	if s := buf.SnapshotFromEnd(0); s == nil || s.Connections()[0].LocalAddr != "3.3.3.3" {
		t.Errorf("offset 0 should be newest (3.3.3.3), got %v", s)
	}
	if s := buf.SnapshotFromEnd(2); s == nil || s.Connections()[0].LocalAddr != "1.1.1.1" {
		t.Errorf("offset 2 should be oldest (1.1.1.1), got %v", s)
	}
	if s := buf.SnapshotFromEnd(3); s != nil {
		t.Errorf("offset past the buffer should be nil, got %v", s)
	}
	if s := buf.SnapshotFromEnd(-1); s != nil {
		t.Errorf("negative offset should be nil, got %v", s)
	}
}

// TestFirstLossBurstProducesDelta: a clean connection's previous sample has
// bytes_retrans zero-filled by the parser, so its first loss burst yields a
// delta (and therefore can raise HI_RETRANS) instead of being skipped.
func TestFirstLossBurstProducesDelta(t *testing.T) {
	i := func(v int) *int { return &v }
	ino := "7"
	mk := func(sent, retrans int) []*model.Connection {
		return []*model.Connection{{Protocol: "tcp", State: "ESTAB", Inode: &ino,
			LocalAddr: "1.1.1.1", LocalPort: "1", PeerAddr: "2.2.2.2", PeerPort: "2",
			CWnd: i(10), BytesSent: i(sent), BytesRetrans: i(retrans), BytesReceived: i(0)}}
	}
	buf := NewBuffer()
	buf.AddSnapshot(mk(1000, 0))
	buf.AddSnapshot(mk(11000, 4000))
	c := buf.GetLatest().Conns[0]
	if c.DeltaBytesRetrans == nil || *c.DeltaBytesRetrans != 4000 {
		t.Fatalf("DeltaBytesRetrans = %v, want 4000", c.DeltaBytesRetrans)
	}
	found := false
	for _, s := range c.Signals {
		found = found || s.Type == model.SignalHighRetransRate
	}
	if !found {
		t.Errorf("40%% retransmit rate on first loss burst should raise HI_RETRANS")
	}
}

// TestECNCutRaisesCWndDrop: delivered_ce growth becomes a per-poll delta, and
// a cwnd cut it explains raises CWND_DROP with no retransmits at all.
func TestECNCutRaisesCWndDrop(t *testing.T) {
	i := func(v int) *int { return &v }
	ino := "7"
	mk := func(cwnd, ce int) []*model.Connection {
		return []*model.Connection{{Protocol: "tcp", State: "ESTAB", Inode: &ino,
			LocalAddr: "1.1.1.1", LocalPort: "1", PeerAddr: "2.2.2.2", PeerPort: "2",
			CWnd: i(cwnd), BytesSent: i(1000), BytesRetrans: i(0), Delivered: i(500), DeliveredCE: i(ce)}}
	}
	buf := NewBuffer()
	buf.AddSnapshot(mk(100, 3))
	buf.AddSnapshot(mk(40, 15))
	c := buf.GetLatest().Conns[0]
	if c.DeltaDeliveredCE == nil || *c.DeltaDeliveredCE != 12 {
		t.Fatalf("DeltaDeliveredCE = %v, want 12", c.DeltaDeliveredCE)
	}
	var got any
	for _, s := range c.Signals {
		if s.Type == model.SignalCWndCollapse {
			got = s.Value
		}
	}
	if got != "100→40 after ECN marks" {
		t.Errorf("CWND_DROP value = %v, want \"100→40 after ECN marks\"", got)
	}
}

// TestSampleRoundTrip: every field the history views read must survive
// newSample -> Conn. Adding a history field means extending newSample, Conn
// and this test together.
func TestSampleRoundTrip(t *testing.T) {
	i := func(v int) *int { return &v }
	str := func(v string) *string { return &v }
	rtt := 12.5
	sig := []model.Signal{{Type: model.SignalRTTSpike, Severity: 1, Value: 6.2}}
	c := &model.Connection{
		Protocol: "tcp", State: "ESTAB",
		LocalAddr: "10.0.0.1", LocalPort: "443", PeerAddr: "10.0.0.2", PeerPort: "51000",
		Inode: str("99"), Process: str("nginx"), PID: i(42),
		TimerType: str("keepalive"), TimerDur: str("1min49sec"),
		RTT: &rtt, RecvQ: i(1), SendQ: i(2), CWnd: i(30), Unacked: i(4), Retrans: i(5),
		DeltaBytesSent: i(1000), DeltaBytesReceived: i(2000),
		Signals: sig,
	}
	ts := time.Unix(1700000000, 0)
	got := func() *model.Connection { s := newSample(c, c.Signals); return s.Conn(ts) }()

	ptrs := func(c *model.Connection) []any {
		d := func(p *int) any {
			if p == nil {
				return nil
			}
			return *p
		}
		ds := func(p *string) any {
			if p == nil {
				return nil
			}
			return *p
		}
		df := func(p *float64) any {
			if p == nil {
				return nil
			}
			return *p
		}
		return []any{c.Protocol, c.State, c.LocalAddr, c.LocalPort, c.PeerAddr, c.PeerPort,
			ds(c.Inode), ds(c.Process), d(c.PID), ds(c.TimerType), df(c.RTT),
			d(c.RecvQ), d(c.SendQ), d(c.CWnd), d(c.Unacked), d(c.Retrans),
			d(c.DeltaBytesSent), d(c.DeltaBytesReceived), c.ConnKey(), len(c.Signals)}
	}
	want, have := ptrs(c), ptrs(got)
	for k := range want {
		if want[k] != have[k] {
			t.Errorf("field #%d: want %v, got %v", k, want[k], have[k])
		}
	}
	if ms, _ := model.ParseSSDuration(*got.TimerDur); ms != 109000 {
		t.Errorf("timer duration round-trip: got %q (%vms), want 109000ms", *got.TimerDur, ms)
	}
	if !got.Timestamp.Equal(ts) {
		t.Errorf("timestamp = %v, want %v", got.Timestamp, ts)
	}
}

// TestSampleSizeBudget guards the ring buffer's memory footprint: history
// holds ~1500 samples per socket, so every byte here is multiplied.
func TestSampleSizeBudget(t *testing.T) {
	if sz := unsafe.Sizeof(Sample{}); sz > 104 {
		t.Errorf("Sample is %d bytes; budget is 104 — keep history fields compact", sz)
	}
}
