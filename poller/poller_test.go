package poller

import (
	"testing"

	"sstui/model"
)

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

	if demoted.Conns[0].BytesSent != nil {
		t.Errorf("demoted snapshot should have dropped BytesSent")
	}
	if v := demoted.Conns[0].RTT; v == nil || *v != 7.5 {
		t.Errorf("demoted snapshot should keep RTT, got %v", v)
	}
	if demoted.Lookup(demoted.Conns[0].ConnKey()) == nil {
		t.Errorf("Lookup must still resolve after compaction")
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
