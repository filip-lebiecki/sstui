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
