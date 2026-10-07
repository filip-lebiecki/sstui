// Package session is the analysis pipeline shared by the TUI and the
// headless commands (check, record, replay, report): it ingests polls into
// the history buffer, rolls the host counters forward, runs the findings
// analysis on each poll, and dates every finding.
//
// A poll comes either from the live host (PollLive) or from a recording
// (Reader), so the same analysis runs on a server and, later, on a laptop.
package session

import (
	"time"

	"sstui/findings"
	"sstui/model"
	"sstui/parser"
	"sstui/poller"
)

// Poll is one observation of the host: what ss returned plus the host
// counters and kernel settings the analysis reads.
type Poll struct {
	Time   time.Time
	Conns  []*model.Connection
	Drops  int             // record lines ss emitted that couldn't be parsed
	Sys    *poller.SysStat // nil when /proc/net was unreadable
	Sysctl poller.Sysctls  // nil when unchanged (recordings) or unreadable
	Err    error
}

// PollLive runs ss with the filter and reads the host counters and kernel
// settings.
func PollLive(f parser.SSFilter) *Poll {
	conns, drops, err := parser.RunSS(f)
	sys, _ := poller.ReadSysStat() // best-effort; nil on platforms without /proc/net
	return &Poll{Time: time.Now(), Conns: conns, Drops: drops, Sys: sys, Sysctl: poller.ReadSysctls(), Err: err}
}

// Session holds the history and analysis state for one live run or one
// recording.
type Session struct {
	Buf *poller.Buffer
	// Host counters: the latest read plus the one before it, so deltas
	// always compare two real consecutive samples.
	SysCur, SysPrev *poller.SysStat
	Sysctl          poller.Sysctls
	// sysHist holds recent host counters, oldest first, back to the first
	// sample at least poller.LossWindow old (the windowed retransmit rate).
	sysHist []timedSys

	SSFilter     string // ss filter in effect ("" for none)
	Unprivileged bool   // not running as root: other users' processes are hidden

	LastErr   error // error from the most recent poll
	LastDrops int   // unparsed ss records in the most recent poll

	// Report is the analysis of the newest snapshot; ReportAt is that
	// snapshot's poll time.
	Report   findings.Report
	ReportAt time.Time

	tracker findings.Tracker
	// history holds the report for each snapshot in the buffer, oldest
	// first, so a view of an older snapshot can show what was wrong then.
	history []timedReport
}

type timedSys struct {
	at  time.Time
	sys *poller.SysStat
}

// sysWindow returns the host counters from about poller.LossWindow ago, or nil
// while the history is shorter than that.
func (s *Session) sysWindow(now time.Time) *poller.SysStat {
	if len(s.sysHist) == 0 || now.Sub(s.sysHist[0].at) < poller.LossWindow() {
		return nil
	}
	return s.sysHist[0].sys
}

type timedReport struct {
	at  time.Time
	rep findings.Report
}

// New starts an empty session.
func New(ssFilter string, unprivileged bool) *Session {
	return &Session{Buf: poller.NewBuffer(), SSFilter: ssFilter, Unprivileged: unprivileged}
}

// Ingest adds a poll: it stores the snapshot, analyses it and dates the
// findings at the poll's time. It reports false when the poll produced no
// snapshot (ss failed outright), leaving the last good one in place. Ingest
// takes ownership of p.Conns, which it annotates (deltas, signals) and sorts.
func (s *Session) Ingest(p *Poll) bool {
	s.LastErr, s.LastDrops = p.Err, p.Drops
	if p.Sys != nil {
		s.SysPrev, s.SysCur = s.SysCur, p.Sys
		s.sysHist = append(s.sysHist, timedSys{p.Time, p.Sys})
		for len(s.sysHist) > 1 && p.Time.Sub(s.sysHist[1].at) >= poller.LossWindow() {
			s.sysHist = s.sysHist[1:]
		}
	}
	if p.Sysctl != nil {
		s.Sysctl = p.Sysctl
	}
	// Ingest on full success (even if zero sockets) or on a partial failure
	// that still returned data; skip only when nothing came back.
	if p.Err != nil && len(p.Conns) == 0 {
		return false
	}
	s.Buf.AddSnapshotAt(p.Conns, p.Time)

	rep := findings.Analyze(findings.Input{
		Conns:        s.Buf.GetLatest().Conns,
		Sys:          s.SysCur,
		SysPrev:      s.SysPrev,
		SysWindow:    s.sysWindow(p.Time),
		Sysctl:       s.Sysctl,
		Interval:     poller.PollInterval,
		SSFilter:     s.SSFilter,
		Unprivileged: s.Unprivileged,
	})
	s.tracker.Update(rep.Findings, p.Time)
	s.Report, s.ReportAt = rep, p.Time

	s.history = append(s.history, timedReport{p.Time, rep})
	if len(s.history) > poller.BufferSize {
		s.history = append(s.history[:0], s.history[1:]...)
	}
	return true
}

// ReportFor returns the analysis of the snapshot taken at ts, if it is
// still in the history.
func (s *Session) ReportFor(ts time.Time) (findings.Report, bool) {
	// Newest first: views almost always ask about recent snapshots.
	for i := len(s.history) - 1; i >= 0; i-- {
		if h := s.history[i]; h.at.Equal(ts) {
			return h.rep, true
		} else if h.at.Before(ts) {
			break
		}
	}
	return findings.Report{}, false
}
