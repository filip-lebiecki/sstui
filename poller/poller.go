package poller

import (
	"sync"
	"time"

	"ss-stats-tui/classifier"
	"ss-stats-tui/model"
)

const (
	BufferSize   = 1500 // 50 minutes at 2s intervals
	PollInterval = 2 * time.Second
)

// Snapshot is a point-in-time capture of all connections.
type Snapshot struct {
	Timestamp time.Time
	Conns     []*model.Connection
	byKey     map[string]*model.Connection
}

// Lookup returns the connection in this snapshot with the given key, or nil.
func (s *Snapshot) Lookup(key string) *model.Connection {
	if s == nil {
		return nil
	}
	return s.byKey[key]
}

// Buffer holds a ring buffer of snapshots.
type Buffer struct {
	mu         sync.RWMutex
	snapshots  []*Snapshot
	head       int
	count      int
	prevMap    map[string]*model.Connection
	lastUpdate time.Time
}

func NewBuffer() *Buffer {
	return &Buffer{
		snapshots: make([]*Snapshot, BufferSize),
		prevMap:   make(map[string]*model.Connection),
	}
}

// AddSnapshot stores a new snapshot and computes deltas.
func (b *Buffer) AddSnapshot(conns []*model.Connection) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Build a set of current keys for cleanup
	currentKeys := make(map[string]bool, len(conns))

	// Compute deltas from previous snapshot, then classify once per poll.
	for _, c := range conns {
		key := c.ConnKey()
		currentKeys[key] = true
		prev := b.prevMap[key]
		if prev != nil && sameConnection(c, prev) {
			b.computeDeltas(c, prev)
		}
		c.Signals = classifier.Classify(c)
		b.prevMap[key] = c
	}

	// Remove stale entries for connections that no longer exist
	for k := range b.prevMap {
		if !currentKeys[k] {
			delete(b.prevMap, k)
		}
	}

	byKey := make(map[string]*model.Connection, len(conns))
	for _, c := range conns {
		byKey[c.ConnKey()] = c
	}
	snap := &Snapshot{
		Timestamp: time.Now(),
		Conns:     conns,
		byKey:     byKey,
	}

	b.snapshots[b.head] = snap
	b.head = (b.head + 1) % BufferSize
	if b.count < BufferSize {
		b.count++
	}
	b.lastUpdate = time.Now()
}

// sameConnection returns false when the previous (key, inode) appears to belong
// to a different socket — e.g. a TIME-WAIT was reaped and the 4-tuple was
// reused. Falls back to true when inodes aren't reported (unprivileged ss),
// since in that case the negative-delta check is the only safety net.
func sameConnection(cur, prev *model.Connection) bool {
	if cur.Inode != nil && prev.Inode != nil {
		return *cur.Inode == *prev.Inode
	}
	return true
}

func (b *Buffer) computeDeltas(cur, prev *model.Connection) {
	type deltaPair struct {
		curVal  *int
		prevVal *int
		out     **int
	}

	pairs := []*deltaPair{
		{curVal: cur.BytesSent, prevVal: prev.BytesSent, out: &cur.DeltaBytesSent},
		{curVal: cur.BytesReceived, prevVal: prev.BytesReceived, out: &cur.DeltaBytesReceived},
		{curVal: cur.SegsOut, prevVal: prev.SegsOut, out: &cur.DeltaSegsOut},
		{curVal: cur.SegsIn, prevVal: prev.SegsIn, out: &cur.DeltaSegsIn},
		{curVal: cur.BytesRetrans, prevVal: prev.BytesRetrans, out: &cur.DeltaBytesRetrans},
		{curVal: cur.DSACKDups, prevVal: prev.DSACKDups, out: &cur.DeltaDSACKDups},
	}

	for _, p := range pairs {
		if p.curVal != nil && p.prevVal != nil {
			delta := *p.curVal - *p.prevVal
			if delta >= 0 {
				*p.out = &delta
			} else {
				*p.out = nil
			}
		} else {
			*p.out = nil
		}
	}

	// Stash prev CWnd so the classifier can detect collapses (cwnd may
	// shrink, unlike monotonic counters above).
	if prev.CWnd != nil {
		v := *prev.CWnd
		cur.PrevCWnd = &v
	}
}

// GetLatest returns the most recent snapshot.
func (b *Buffer) GetLatest() *Snapshot {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.count == 0 {
		return nil
	}
	idx := (b.head - 1 + BufferSize) % BufferSize
	return b.snapshots[idx]
}

// GetAll returns all snapshots in chronological order.
func (b *Buffer) GetAll() []*Snapshot {
	b.mu.RLock()
	defer b.mu.RUnlock()
	result := make([]*Snapshot, 0, b.count)
	for i := 0; i < b.count; i++ {
		idx := (b.head - b.count + i + BufferSize) % BufferSize
		result = append(result, b.snapshots[idx])
	}
	return result
}

// Count returns the number of stored snapshots.
func (b *Buffer) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.count
}

// LastUpdate returns the time of the last successful poll.
func (b *Buffer) LastUpdate() time.Time {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.lastUpdate
}
