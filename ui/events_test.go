package ui

import (
	"testing"

	"sstui/model"
	"sstui/poller"
)

// TestCollectEventsCachedReuses verifies item 5: between polls the cached
// events slice is reused (same backing array) rather than recomputed, and a
// new snapshot invalidates the cache.
func TestCollectEventsCachedReuses(t *testing.T) {
	evCacheValid = false // isolate from any package-global state

	buf := poller.NewBuffer()
	inode := "777"
	mk := func(retrans *int) []*model.Connection {
		return []*model.Connection{{
			Protocol: "tcp", State: "ESTAB",
			LocalAddr: "1.1.1.1", LocalPort: "1",
			PeerAddr: "2.2.2.2", PeerPort: "2",
			Inode: &inode, RetransNow: retrans,
		}}
	}

	buf.AddSnapshot(mk(nil)) // no signal yet
	r := 5
	buf.AddSnapshot(mk(&r)) // RETRANS warn onset

	ev1 := collectEventsCached(buf)
	if len(ev1) == 0 {
		t.Fatalf("expected at least one signal onset, got 0")
	}

	ev2 := collectEventsCached(buf)
	if len(ev2) != len(ev1) || &ev1[0] != &ev2[0] {
		t.Errorf("expected cached slice to be reused without recompute")
	}

	// A new snapshot must invalidate the cache.
	buf.AddSnapshot(mk(&r))
	ev3 := collectEventsCached(buf)
	if len(ev3) != 0 && &ev3[0] == &ev1[0] {
		t.Errorf("expected cache to be recomputed after a new snapshot")
	}
}
