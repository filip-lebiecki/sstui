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
	// stateCounts is precomputed at snapshot creation so render-time code
	// doesn't have to walk Conns for every snapshot it visits.
	stateCounts map[string]int
}

// Lookup returns the connection in this snapshot with the given key, or nil.
func (s *Snapshot) Lookup(key string) *model.Connection {
	if s == nil {
		return nil
	}
	return s.byKey[key]
}

// StateCount returns the number of connections in this snapshot with the
// given state. Cheap O(1) lookup; the index is built when the snapshot is
// added to the buffer.
func (s *Snapshot) StateCount(state string) int {
	if s == nil {
		return 0
	}
	return s.stateCounts[state]
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

// AddSnapshot stores a new snapshot and computes deltas. Delta computation
// and classification run outside the write lock so concurrent readers
// (GetLatest, GetAll) aren't blocked while we walk every connection. We
// only take the lock briefly when reading prev pointers and again to
// publish the new snapshot.
func (b *Buffer) AddSnapshot(conns []*model.Connection) {
	// Phase 1: snapshot the prev pointers we need under a read lock. The
	// Connection structs they point to are immutable after publication, so
	// reading their fields outside the lock is safe.
	b.mu.RLock()
	prevs := make(map[string]*model.Connection, len(conns))
	for _, c := range conns {
		if p, ok := b.prevMap[c.ConnKey()]; ok {
			prevs[c.ConnKey()] = p
		}
	}
	b.mu.RUnlock()

	// Phase 2: compute deltas and classify with no lock held. The new conns
	// are only visible to this goroutine until we publish in phase 3.
	for _, c := range conns {
		if prev, ok := prevs[c.ConnKey()]; ok && sameConnection(c, prev) {
			computeDeltas(c, prev)
		}
		c.Signals = classifier.Classify(c)
	}

	// Phase 3: build indexes and publish under the write lock.
	byKey := make(map[string]*model.Connection, len(conns))
	stateCounts := make(map[string]int)
	currentKeys := make(map[string]bool, len(conns))
	for _, c := range conns {
		key := c.ConnKey()
		currentKeys[key] = true
		byKey[key] = c
		stateCounts[c.State]++
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	for _, c := range conns {
		b.prevMap[c.ConnKey()] = c
	}
	for k := range b.prevMap {
		if !currentKeys[k] {
			delete(b.prevMap, k)
		}
	}

	snap := &Snapshot{
		Timestamp:   time.Now(),
		Conns:       conns,
		byKey:       byKey,
		stateCounts: stateCounts,
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

func computeDeltas(cur, prev *model.Connection) {
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

	// busy: is cumulative ms of TCP work since socket creation; the per-poll
	// delta is what tells us how busy the kernel was on this socket recently.
	if cur.BusyMS != nil && prev.BusyMS != nil {
		d := *cur.BusyMS - *prev.BusyMS
		if d >= 0 {
			cur.DeltaBusyMS = &d
		}
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
