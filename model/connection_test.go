package model

import "testing"

func ptr(s string) *string { return &s }

func TestConnKeyDisambiguatesReusePort(t *testing.T) {
	// Two SO_REUSEPORT listeners: identical 4-tuple, distinct inodes.
	a := &Connection{Protocol: "tcp", LocalAddr: "0.0.0.0", LocalPort: "443",
		PeerAddr: "0.0.0.0", PeerPort: "*", Inode: ptr("1001")}
	b := &Connection{Protocol: "tcp", LocalAddr: "0.0.0.0", LocalPort: "443",
		PeerAddr: "0.0.0.0", PeerPort: "*", Inode: ptr("1002")}
	if a.ConnKey() == b.ConnKey() {
		t.Errorf("expected distinct keys for distinct inodes, both = %q", a.ConnKey())
	}
}

func TestConnKeyStableForSameSocket(t *testing.T) {
	// Same socket seen in two polls keeps the same inode → same key.
	a := &Connection{Protocol: "tcp", LocalAddr: "10.0.0.1", LocalPort: "22",
		PeerAddr: "10.0.0.2", PeerPort: "5555", Inode: ptr("42")}
	b := &Connection{Protocol: "tcp", LocalAddr: "10.0.0.1", LocalPort: "22",
		PeerAddr: "10.0.0.2", PeerPort: "5555", Inode: ptr("42")}
	if a.ConnKey() != b.ConnKey() {
		t.Errorf("expected stable key, got %q vs %q", a.ConnKey(), b.ConnKey())
	}
}

func TestConnKeyFallsBackWithoutInode(t *testing.T) {
	// Unprivileged ss (nil inode) and the "0" sentinel both fall back to the
	// bare 4-tuple, so the key matches a tuple-only connection.
	base := &Connection{Protocol: "tcp", LocalAddr: "1.2.3.4", LocalPort: "80",
		PeerAddr: "5.6.7.8", PeerPort: "9000"}
	nilInode := *base
	zeroInode := *base
	zeroInode.Inode = ptr("0")
	if nilInode.ConnKey() != base.ConnKey() {
		t.Errorf("nil inode key %q != tuple key %q", nilInode.ConnKey(), base.ConnKey())
	}
	if zeroInode.ConnKey() != base.ConnKey() {
		t.Errorf("inode-0 key %q != tuple key %q", zeroInode.ConnKey(), base.ConnKey())
	}
}
