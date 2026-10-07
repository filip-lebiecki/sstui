package poller

import (
	"math"
	"time"
	"unique"

	"sstui/model"
)

// Sample is the compact, history-side record of one connection in one
// snapshot: just the fields the historical views read (Overview/Perf
// aggregates, sparklines, events, the scrubbed Live table), stored as values
// rather than ~90 heap pointers.
//
// A full model.Connection is 808 bytes before counting its pointees, and its
// strings are substrings of the ~1 KB ss output line, so keeping them in the
// ring buffer pinned every line for ~50 minutes. A Sample is ~100 bytes:
// identity strings are interned through package unique (8-byte handles,
// shared across snapshots and reclaimed by the GC once no sample refers to
// them), and numbers are stored inline with a presence bitmask.
type Sample struct {
	key   unique.Handle[string] // ConnKey(); also the sort/lookup key
	ident unique.Handle[sampleIdent]
	state unique.Handle[string]
	timer unique.Handle[sampleTimer] // valid when has&hasTimer

	signals []model.Signal

	deltaSent, deltaRecv              int64
	rtt                               float32
	recvQ, sendQ, cwnd, unacked, retr int32
	has                               uint16
}

// sampleIdent is the per-socket identity that rarely changes between polls,
// interned as one handle so a sample pays 8 bytes for all of it.
type sampleIdent struct {
	Protocol, LocalAddr, LocalPort, PeerAddr, PeerPort string
	Inode, Process                                     string
	PID                                                int
	HasInode, HasProcess, HasPID                       bool
}

type sampleTimer struct{ Type, Dur string }

const (
	hasRTT uint16 = 1 << iota
	hasRecvQ
	hasSendQ
	hasCWnd
	hasUnacked
	hasRetrans
	hasDeltaSent
	hasDeltaRecv
	hasTimer
)

// clamp32 saturates v into int32 range; queue depths and windows never get
// near it in practice, but a wrap would render as a negative number.
func clamp32(v int) int32 {
	switch {
	case v > math.MaxInt32:
		return math.MaxInt32
	case v < math.MinInt32:
		return math.MinInt32
	}
	return int32(v)
}

// newSample captures the history-relevant fields of c. signals should already
// be interned/right-sized by the caller (see signalInterner).
func newSample(c *model.Connection, signals []model.Signal) Sample {
	id := sampleIdent{
		Protocol: c.Protocol, LocalAddr: c.LocalAddr, LocalPort: c.LocalPort,
		PeerAddr: c.PeerAddr, PeerPort: c.PeerPort,
	}
	if c.Inode != nil {
		id.Inode, id.HasInode = *c.Inode, true
	}
	if c.Process != nil {
		id.Process, id.HasProcess = *c.Process, true
	}
	if c.PID != nil {
		id.PID, id.HasPID = *c.PID, true
	}

	s := Sample{
		key:     unique.Make(c.ConnKey()),
		ident:   unique.Make(id),
		state:   unique.Make(c.State),
		signals: signals,
	}
	if c.TimerType != nil && c.TimerDur != nil {
		s.timer = unique.Make(sampleTimer{*c.TimerType, *c.TimerDur})
		s.has |= hasTimer
	}
	if c.RTT != nil {
		s.rtt, s.has = float32(*c.RTT), s.has|hasRTT
	}
	setI32 := func(p *int, dst *int32, bit uint16) {
		if p != nil {
			*dst, s.has = clamp32(*p), s.has|bit
		}
	}
	setI32(c.RecvQ, &s.recvQ, hasRecvQ)
	setI32(c.SendQ, &s.sendQ, hasSendQ)
	setI32(c.CWnd, &s.cwnd, hasCWnd)
	setI32(c.Unacked, &s.unacked, hasUnacked)
	setI32(c.Retrans, &s.retr, hasRetrans)
	if c.DeltaBytesSent != nil {
		s.deltaSent, s.has = int64(*c.DeltaBytesSent), s.has|hasDeltaSent
	}
	if c.DeltaBytesReceived != nil {
		s.deltaRecv, s.has = int64(*c.DeltaBytesReceived), s.has|hasDeltaRecv
	}
	return s
}

// Key returns the connection key (same as model.Connection.ConnKey).
func (s *Sample) Key() string { return s.key.Value() }

// State returns the connection state.
func (s *Sample) State() string { return s.state.Value() }

// Signals returns the signals active on this connection at this snapshot.
// The slice is shared; callers must not modify it.
func (s *Sample) Signals() []model.Signal { return s.signals }

// RTT returns the smoothed RTT in ms.
func (s *Sample) RTT() (float64, bool) { return float64(s.rtt), s.has&hasRTT != 0 }

// DeltaBytesSent returns bytes sent during the poll ending at this snapshot.
func (s *Sample) DeltaBytesSent() (int64, bool) { return s.deltaSent, s.has&hasDeltaSent != 0 }

// DeltaBytesReceived returns bytes received during the poll ending here.
func (s *Sample) DeltaBytesReceived() (int64, bool) { return s.deltaRecv, s.has&hasDeltaRecv != 0 }

// CWnd, SendQ, RecvQ, Unacked and Retrans return the level at this snapshot.
func (s *Sample) CWnd() (int, bool)    { return int(s.cwnd), s.has&hasCWnd != 0 }
func (s *Sample) SendQ() (int, bool)   { return int(s.sendQ), s.has&hasSendQ != 0 }
func (s *Sample) RecvQ() (int, bool)   { return int(s.recvQ), s.has&hasRecvQ != 0 }
func (s *Sample) Unacked() (int, bool) { return int(s.unacked), s.has&hasUnacked != 0 }
func (s *Sample) Retrans() (int, bool) { return int(s.retr), s.has&hasRetrans != 0 }

// Conn materializes a slim model.Connection from the sample, for views that
// render history through the regular connection type (the scrubbed Live
// table, Detail of a closed or historical connection, events, export). Only
// the history-relevant fields are populated; everything else is nil. Each
// call allocates, so aggregate views should read the Sample accessors instead.
func (s *Sample) Conn(ts time.Time) *model.Connection {
	id := s.ident.Value()
	c := &model.Connection{
		Timestamp: ts,
		Protocol:  id.Protocol,
		State:     s.state.Value(),
		LocalAddr: id.LocalAddr, LocalPort: id.LocalPort,
		PeerAddr: id.PeerAddr, PeerPort: id.PeerPort,
		Signals: s.signals,
	}
	c.SetKey(s.key.Value())
	if id.HasInode {
		c.Inode = &id.Inode
	}
	if id.HasProcess {
		c.Process = &id.Process
	}
	if id.HasPID {
		c.PID = &id.PID
	}
	if s.has&hasTimer != 0 {
		t := s.timer.Value()
		c.TimerType, c.TimerDur = &t.Type, &t.Dur
	}
	if v, ok := s.RTT(); ok {
		c.RTT = &v
	}
	intPtr := func(v int, ok bool) *int {
		if !ok {
			return nil
		}
		return &v
	}
	c.RecvQ = intPtr(s.RecvQ())
	c.SendQ = intPtr(s.SendQ())
	c.CWnd = intPtr(s.CWnd())
	c.Unacked = intPtr(s.Unacked())
	c.Retrans = intPtr(s.Retrans())
	if v, ok := s.DeltaBytesSent(); ok {
		n := int(v)
		c.DeltaBytesSent = &n
	}
	if v, ok := s.DeltaBytesReceived(); ok {
		n := int(v)
		c.DeltaBytesReceived = &n
	}
	return c
}

// signalSetKey identifies a small signal set whose members carry no Value.
// Those sets (IDLE, APP_LIM+IDLE, …) are by far the most common and identical
// across thousands of samples, so they're shared instead of copied.
type signalSetKey struct {
	n     int8
	types [4]model.SignalType
	sevs  [4]int8
}

// signalInterner right-sizes signal slices for long-term storage and shares
// the common value-less sets. Used only from AddSnapshot (single goroutine).
type signalInterner struct {
	sets map[signalSetKey][]model.Signal
}

func (si *signalInterner) intern(sigs []model.Signal) []model.Signal {
	if len(sigs) == 0 {
		return nil
	}
	if len(sigs) <= 4 {
		k := signalSetKey{n: int8(len(sigs))}
		shareable := true
		for i, sg := range sigs {
			if sg.Value != nil {
				shareable = false
				break
			}
			k.types[i], k.sevs[i] = sg.Type, int8(sg.Severity)
		}
		if shareable {
			if si.sets == nil {
				si.sets = make(map[signalSetKey][]model.Signal)
			}
			if shared, ok := si.sets[k]; ok {
				return shared
			}
			cp := append([]model.Signal(nil), sigs...)
			si.sets[k] = cp
			return cp
		}
	}
	// Copy to an exact-capacity slice so append growth slack isn't retained.
	return append(make([]model.Signal, 0, len(sigs)), sigs...)
}
