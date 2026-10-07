package session

import (
	"cmp"
	"slices"
	"time"

	"sstui/findings"
	"sstui/poller"
)

// Timeline summarises the findings across a watch or a recording: when each
// one was first and last seen, how often, and whether it was still active
// at the end. check and report are built on it.
type Timeline struct {
	Start, End time.Time
	Analyses   int // polls analysed
	// FirstSys and LastSys are the earliest and latest host counter reads,
	// for totals over the whole window.
	FirstSys, LastSys *poller.SysStat
	Last              findings.Report // analysis of the final poll

	byID map[string]*Occurrence
	all  []*Occurrence // first-seen order
}

// Occurrence is one finding's history over the window.
type Occurrence struct {
	Finding     findings.Finding // most recent version (evidence, counts)
	First, Last time.Time
	Polls       int // analyses it appeared in
	Worst       int // highest severity seen
	Active      bool
}

// Add records one poll's analysis. sys is that poll's host counter read
// (nil if none).
func (t *Timeline) Add(rep findings.Report, at time.Time, sys *poller.SysStat) {
	if t.Analyses == 0 {
		t.Start = at
	}
	t.End = at
	t.Analyses++
	t.Last = rep
	if sys != nil {
		if t.FirstSys == nil {
			t.FirstSys = sys
		}
		t.LastSys = sys
	}
	if t.byID == nil {
		t.byID = make(map[string]*Occurrence)
	}
	for _, o := range t.all {
		o.Active = false
	}
	for _, f := range rep.Findings {
		o := t.byID[f.ID]
		if o == nil {
			o = &Occurrence{First: at}
			t.byID[f.ID] = o
			t.all = append(t.all, o)
		}
		o.Finding, o.Last, o.Active = f, at, true
		o.Polls++
		o.Worst = max(o.Worst, f.Severity)
	}
}

// Ranked returns every finding seen, most important first: still active
// before resolved, then by worst severity, then by how long it lasted.
func (t *Timeline) Ranked() []*Occurrence {
	out := slices.Clone(t.all)
	slices.SortStableFunc(out, func(x, y *Occurrence) int {
		if x.Active != y.Active {
			if x.Active {
				return -1
			}
			return 1
		}
		if c := cmp.Compare(y.Worst, x.Worst); c != 0 {
			return c
		}
		return cmp.Compare(y.Polls, x.Polls)
	})
	return out
}

// Worst returns the highest severity seen during the window (0 when
// nothing was found).
func (t *Timeline) Worst() int {
	w := 0
	for _, o := range t.all {
		w = max(w, o.Worst)
	}
	return w
}

// Count returns how many distinct findings reached the given worst severity.
func (t *Timeline) Count(sev int) int {
	n := 0
	for _, o := range t.all {
		if o.Worst == sev {
			n++
		}
	}
	return n
}
