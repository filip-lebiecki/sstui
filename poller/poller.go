package poller

import (
	"slices"
	"strings"
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

// SlotWindow is how far back PATH_LOSS, REORDER and RX_LOSS look: 12 s, or
// four polls when polling is slower than every 3 s, so it always spans
// several slots.
func SlotWindow() time.Duration {
	return max(12*time.Second, 4*PollInterval)
}

// slotMinBytes is the least a poll must send (or receive) to count toward a
// send (receive) slot, a few segments, so keepalives and trickles don't
// dilute the picture.
const slotMinBytes = 10_000

// advanceSendSlots returns cur's send slots: prev's, plus this poll when cur
// was sending, minus slots that started more than SlotWindow ago. Slots are
// at least model.SendSlotMin long, so the signal judges the same spans whether
// polling every 500 ms or every 2 s. prev's slice is never modified: it
// belongs to the previous snapshot.
func advanceSendSlots(cur, prev *model.Connection) []model.SendSlot {
	if cur.DeltaBytesSent == nil || cur.DeltaBytesRetrans == nil {
		return nil // the kernel doesn't report the counters
	}
	slots := slices.Clone(prev.SendSlots)
	if *cur.DeltaBytesSent >= slotMinBytes {
		if n := len(slots); n == 0 || slots[n-1].End.Sub(slots[n-1].Start) >= model.SendSlotMin {
			slots = append(slots, model.SendSlot{Start: prev.Timestamp})
		}
		s := &slots[len(slots)-1]
		s.End = cur.Timestamp
		s.Sent += *cur.DeltaBytesSent
		s.Retrans += *cur.DeltaBytesRetrans
		if cur.DeltaReordSeen != nil {
			s.Reord += *cur.DeltaReordSeen
		}
		if cur.RTT != nil && cur.MinRTT != nil {
			// Clip so the slot copied from prev gets its own array instead
			// of appending into prev's spare capacity.
			s.QueueMS = append(slices.Clip(s.QueueMS), *cur.RTT-*cur.MinRTT)
		}
	}
	cut := cur.Timestamp.Add(-SlotWindow())
	for len(slots) > 0 && slots[0].Start.Before(cut) {
		slots = slots[1:]
	}
	return slots
}

// advanceRecvSlots is advanceSendSlots for receiving: cur's receive slots,
// with this poll added when cur received at least slotMinBytes.
func advanceRecvSlots(cur, prev *model.Connection) []model.RecvSlot {
	if cur.DeltaBytesReceived == nil || cur.DeltaDataSegsIn == nil || cur.DeltaRcvOOOPack == nil {
		return nil // the kernel doesn't report the counters
	}
	slots := slices.Clone(prev.RecvSlots)
	if *cur.DeltaBytesReceived >= slotMinBytes {
		if n := len(slots); n == 0 || slots[n-1].End.Sub(slots[n-1].Start) >= model.SendSlotMin {
			slots = append(slots, model.RecvSlot{Start: prev.Timestamp})
		}
		s := &slots[len(slots)-1]
		s.End = cur.Timestamp
		s.Segs += *cur.DeltaDataSegsIn
		s.OOO += *cur.DeltaRcvOOOPack
		// With timestamps, rcv_rtt is an RTT sample taken by the receiver
		// (from our ACK to the data echoing it), so it includes the queue
		// our incoming data waits in. Without them it's a minimum, no use.
		if cur.Timestamps && cur.RcvRTT != nil && cur.MinRTT != nil {
			s.QueueMS = append(slices.Clip(s.QueueMS), *cur.RcvRTT-*cur.MinRTT)
		}
	}
	cut := cur.Timestamp.Add(-SlotWindow())
	for len(slots) > 0 && slots[0].Start.Before(cut) {
		slots = slots[1:]
	}
	return slots
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
//
// Every snapshot carries compact Samples (sorted by key) for the historical
// views. Only the newest snapshot also keeps the full-detail Conns, for the
// Live/Detail/Socket/Top/Perf views; when a snapshot is demoted from "latest"
// its Conns are dropped and only the Samples remain.
type Snapshot struct {
	Timestamp time.Time
	// Conns are the full-detail connections, sorted by key. Nil once the
	// snapshot is no longer the latest — use Connections() or Samples() to
	// read any snapshot regardless of age.
	Conns   []*model.Connection
	samples []Sample // sorted by key; samples[i] describes Conns[i] while full
	// stateCounts is precomputed at snapshot creation so render-time code
	// doesn't have to walk the connections for every snapshot it visits.
	stateCounts map[string]int
}

// Len returns the number of connections in the snapshot.
func (s *Snapshot) Len() int {
	if s == nil {
		return 0
	}
	return len(s.samples)
}

// Samples returns the compact per-connection records, sorted by key. The
// slice is shared and must not be modified.
func (s *Snapshot) Samples() []Sample {
	if s == nil {
		return nil
	}
	return s.samples
}

// Full reports whether the snapshot still holds full-detail connections.
func (s *Snapshot) Full() bool { return s != nil && s.Conns != nil }

// find returns the index of key in samples, or -1. Binary search over the
// key-sorted samples, so history needs no per-snapshot index map.
func (s *Snapshot) find(key string) int {
	i, ok := slices.BinarySearchFunc(s.samples, key, func(sm Sample, k string) int {
		return strings.Compare(sm.key.Value(), k)
	})
	if !ok {
		return -1
	}
	return i
}

// LookupSample returns the sample with the given key, or nil.
func (s *Snapshot) LookupSample(key string) *Sample {
	if s == nil {
		return nil
	}
	if i := s.find(key); i >= 0 {
		return &s.samples[i]
	}
	return nil
}

// Lookup returns the connection in this snapshot with the given key, or nil.
// For a demoted snapshot the connection is materialized from its sample, so
// only the history fields are populated.
func (s *Snapshot) Lookup(key string) *model.Connection {
	if s == nil {
		return nil
	}
	i := s.find(key)
	if i < 0 {
		return nil
	}
	if s.Conns != nil {
		return s.Conns[i]
	}
	return s.samples[i].Conn(s.Timestamp)
}

// Connections returns the snapshot's connections: the full-detail ones while
// it is the latest, otherwise slim connections materialized from the samples
// (which allocates — meant for rendering one snapshot, not for scanning all
// of history).
func (s *Snapshot) Connections() []*model.Connection {
	if s == nil {
		return nil
	}
	if s.Conns != nil {
		return s.Conns
	}
	conns := make([]*model.Connection, len(s.samples))
	for i := range s.samples {
		conns[i] = s.samples[i].Conn(s.Timestamp)
	}
	return conns
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

// demote returns a copy of the snapshot without the full-detail connections.
// It returns a new Snapshot rather than mutating the receiver: published
// snapshots stay immutable so readers holding the old pointer never race. The
// samples and state counts are immutable too, so they're shared.
func (s *Snapshot) demote() *Snapshot {
	return &Snapshot{
		Timestamp:   s.Timestamp,
		samples:     s.samples,
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
	signals    signalInterner // only touched by AddSnapshot
}

func NewBuffer() *Buffer {
	return &Buffer{
		snapshots: make([]*Snapshot, BufferSize),
		prevMap:   make(map[string]*model.Connection),
	}
}

// AddSnapshot stores a new snapshot taken now and computes deltas.
func (b *Buffer) AddSnapshot(conns []*model.Connection) { b.AddSnapshotAt(conns, time.Now()) }

// AddSnapshotAt stores a new snapshot taken at ts (a recording's poll time
// when replaying) and computes deltas. Delta computation
// and classification run outside the write lock so concurrent readers
// (GetLatest, GetAll) aren't blocked while we walk every connection. We
// only take the lock briefly when reading prev pointers and again to
// publish the new snapshot.
func (b *Buffer) AddSnapshotAt(conns []*model.Connection, ts time.Time) {
	// Compute each connection's key once; ConnKey() then returns the cache.
	// The conns are still private to this goroutine, so writing is safe.
	for _, c := range conns {
		c.SetKey(c.ConnKey())
	}

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

	// Phase 3: build the compact history records and publish under the write
	// lock. Conns are sorted by key so samples[i] matches Conns[i] and both
	// can be binary-searched.
	slices.SortFunc(conns, func(x, y *model.Connection) int {
		return strings.Compare(x.ConnKey(), y.ConnKey())
	})
	samples := make([]Sample, len(conns))
	stateCounts := make(map[string]int)
	for i, c := range conns {
		c.Signals = b.signals.intern(c.Signals)
		samples[i] = newSample(c, c.Signals)
		// Key by the interned state: c.State is a substring of the raw ss
		// line and would pin it for as long as this snapshot lives.
		stateCounts[samples[i].State()]++
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	clear(b.prevMap)
	for _, c := range conns {
		b.prevMap[c.ConnKey()] = c
	}

	snap := &Snapshot{
		Timestamp:   ts,
		Conns:       conns,
		samples:     samples,
		stateCounts: stateCounts,
	}
	// Demote the outgoing latest snapshot before publishing the new one, so at
	// most a single full-detail snapshot is retained at a time. The slot gets
	// a fresh demoted snapshot (rather than being mutated in place) so any
	// reader still holding the old pointer keeps an immutable, whole snapshot.
	if demotedIdx := (b.head - 1 + BufferSize) % BufferSize; b.snapshots[demotedIdx] != nil {
		b.snapshots[demotedIdx] = b.snapshots[demotedIdx].demote()
	}
	b.snapshots[b.head] = snap
	b.head = (b.head + 1) % BufferSize
	if b.count < BufferSize {
		b.count++
	}
	b.lastUpdate = ts
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
		{curVal: cur.DataSegsIn, prevVal: prev.DataSegsIn, out: &cur.DeltaDataSegsIn},
		{curVal: cur.ReordSeen, prevVal: prev.ReordSeen, out: &cur.DeltaReordSeen},
		{curVal: cur.BytesAcked, prevVal: prev.BytesAcked, out: &cur.DeltaBytesAcked},
		{curVal: cur.DeliveredCE, prevVal: prev.DeliveredCE, out: &cur.DeltaDeliveredCE},
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
	if prev.Unacked != nil {
		v := *prev.Unacked
		cur.PrevUnacked = &v
	}
	cur.SendSlots = advanceSendSlots(cur, prev)
	cur.RecvSlots = advanceRecvSlots(cur, prev)

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
	cur.PrevDeltaRwndLimitedMS = prev.DeltaRwndLimitedMS
	cur.PrevDeltaSndbufLimitedMS = prev.DeltaSndbufLimitedMS
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
