package poller

import (
	"sync"
	"time"

	"sstui/classifier"
	"sstui/model"
)

const BufferSize = 1500 // ~50 minutes at the default 2s interval

// PollInterval is the cadence between ss invocations. It's a var (not a const)
// so it can be overridden at startup via --interval; use SetInterval to change
// it so the classifier's cadence stays in sync. Display code derives rates from
// it, so a change is reflected consistently everywhere.
var PollInterval = 2 * time.Second

// Keep the classifier's notion of the poll cadence in sync with ours, so its
// fraction-of-interval signals (rwnd/sndbuf limited) are scaled correctly. Done
// here rather than via an import in the classifier to avoid an import cycle.
func init() {
	syncClassifierInterval()
}

func syncClassifierInterval() {
	classifier.PollIntervalMS = float64(PollInterval / time.Millisecond)
}

// SetInterval overrides the poll cadence and keeps dependent state in sync.
// A non-positive duration is ignored.
func SetInterval(d time.Duration) {
	if d <= 0 {
		return
	}
	PollInterval = d
	syncClassifierInterval()
}

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

// compact returns a slimmed copy of the snapshot, keeping only the fields that
// historical views actually read (overview/perf aggregates, the per-signal
// sparklines, the detail sparklines, and the events list). Each ~60-field
// Connection — most of whose fields are heap-allocated pointers — is replaced
// with a lean copy, which lets the GC reclaim the rest once the original
// snapshot is no longer referenced.
//
// It returns a *new* Snapshot rather than mutating the receiver: published
// snapshots must stay immutable so the lockless readers (Snapshot.Lookup, and
// the unlocked field reads in AddSnapshot's delta phase) never race. The
// caller swaps the ring slot pointer under the buffer write lock. stateCounts
// is immutable post-publication, so it is shared rather than copied.
//
// The current latest snapshot is never compacted, so the full-detail
// Socket/Detail views still have everything they need; only snapshots that
// have aged out of "latest" are slimmed.
func (s *Snapshot) compact() *Snapshot {
	conns := make([]*model.Connection, 0, len(s.Conns))
	byKey := make(map[string]*model.Connection, len(s.Conns))
	for _, c := range s.Conns {
		if c == nil {
			continue
		}
		slim := &model.Connection{
			Timestamp: c.Timestamp,
			Protocol:  c.Protocol,
			State:     c.State,
			LocalAddr: c.LocalAddr,
			LocalPort: c.LocalPort,
			PeerAddr:  c.PeerAddr,
			PeerPort:  c.PeerPort,
			Process:   c.Process,
			PID:       c.PID,
			Inode:     c.Inode, // kept: ConnKey/Lookup depend on it
			// Fields read by historical charts/lists and the pause/scrub view
			// of the Live table (which renders the same columns from history):
			RecvQ:              c.RecvQ,
			SendQ:              c.SendQ,
			RTT:                c.RTT,
			CWnd:               c.CWnd,
			Unacked:            c.Unacked,
			Retrans:            c.Retrans,
			TimerType:          c.TimerType, // kept: KA column in scrub view
			TimerDur:           c.TimerDur,  // kept: KA column in scrub view
			DeltaBytesSent:     c.DeltaBytesSent,
			DeltaBytesReceived: c.DeltaBytesReceived,
			Signals:            c.Signals,
		}
		conns = append(conns, slim)
		byKey[slim.ConnKey()] = slim
	}
	return &Snapshot{
		Timestamp:   s.Timestamp,
		Conns:       conns,
		byKey:       byKey,
		stateCounts: s.stateCounts,
	}
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
	// Signals that depend on counts across the whole snapshot (fd leaks,
	// TIME-WAIT storms) run after the per-connection pass and append to the
	// affected connections.
	classifier.ClassifyAggregate(conns)

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
	// Slim the snapshot being demoted from "latest" before publishing the new
	// one, so at most a single full-detail snapshot is retained at a time.
	// Replace the slot with a fresh compacted snapshot (rather than mutating
	// in place) so any reader still holding the old pointer keeps seeing an
	// immutable, fully-formed snapshot.
	if demotedIdx := (b.head - 1 + BufferSize) % BufferSize; b.snapshots[demotedIdx] != nil {
		b.snapshots[demotedIdx] = b.snapshots[demotedIdx].compact()
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
		{curVal: cur.RcvOOOPack, prevVal: prev.RcvOOOPack, out: &cur.DeltaRcvOOOPack},
		{curVal: cur.SkmemD, prevVal: prev.SkmemD, out: &cur.DeltaSkmemD},
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

	// Stash prev send/recv queue depths so the classifier can require queue
	// pressure to persist across two polls before firing (these are levels,
	// not monotonic counters, so a plain delta isn't meaningful).
	if prev.SendQ != nil {
		v := *prev.SendQ
		cur.PrevSendQ = &v
	}
	if prev.RecvQ != nil {
		v := *prev.RecvQ
		cur.PrevRecvQ = &v
	}

	// busy: is cumulative ms of TCP work since socket creation; the per-poll
	// delta is what tells us how busy the kernel was on this socket recently.
	if cur.BusyMS != nil && prev.BusyMS != nil {
		d := *cur.BusyMS - *prev.BusyMS
		if d >= 0 {
			cur.DeltaBusyMS = &d
		}
	}

	// rwnd_limited / sndbuf_limited are likewise cumulative ms; their per-poll
	// deltas tell us how long the sender was blocked on the peer's receive
	// window vs. its own send buffer during the last interval — i.e. where the
	// throughput bottleneck currently is.
	cur.DeltaRwndLimitedMS = deltaFloat(cur.RwndLimitedMS, prev.RwndLimitedMS)
	cur.DeltaSndbufLimitedMS = deltaFloat(cur.SndbufLimitedMS, prev.SndbufLimitedMS)
}

// deltaFloat returns cur-prev when both are present and the result is
// non-negative (cumulative counters never decrease except on reuse), else nil.
func deltaFloat(cur, prev *float64) *float64 {
	if cur == nil || prev == nil {
		return nil
	}
	d := *cur - *prev
	if d < 0 {
		return nil
	}
	return &d
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

// LookupRecent returns the most recent connection with the given key, searching
// the ring buffer newest-first. When the key is in the latest snapshot this is
// the live connection; once it closes and drops out, the caller still gets the
// last captured state (so Detail/Socket views keep showing a just-closed socket
// instead of going blank) until it ages out of the buffer. Returns nil if the
// key was never seen.
func (b *Buffer) LookupRecent(key string) *model.Connection {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for i := 0; i < b.count; i++ {
		idx := ((b.head-1-i)%BufferSize + BufferSize) % BufferSize
		if snap := b.snapshots[idx]; snap != nil {
			if c := snap.Lookup(key); c != nil {
				return c
			}
		}
	}
	return nil
}

// SnapshotFromEnd returns the snapshot `offset` positions back from the newest
// (0 = newest, 1 = one poll ago, …). Returns nil when offset is out of range.
// Used by the pause/scrub view to render an arbitrary point in history.
func (b *Buffer) SnapshotFromEnd(offset int) *Snapshot {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if offset < 0 || offset >= b.count {
		return nil
	}
	idx := ((b.head-1-offset)%BufferSize + BufferSize) % BufferSize
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
