// Package findings turns per-socket signals and host counters into a short,
// ranked list of host-level problems — each with the evidence behind it and
// concrete next steps tailored to this host's kernel settings. It answers
// "what's wrong on this box and what do I do about it" in one screen, where
// the per-socket views answer "what is this one connection doing".
//
// Analysis is pure (Input in, Report out) and runs once per poll; Tracker
// adds "active since" across polls.
package findings

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"sstui/model"
	"sstui/poller"
)

// Action is one recommended next step: what to do and why, plus an optional
// shell command to run.
type Action struct {
	Text    string
	Command string
}

// Finding is one host-level problem, usually aggregating many sockets that
// share a cause (same peer, same process, same listener).
type Finding struct {
	ID       string // stable across polls: rule + group key
	Severity int    // 1 warn, 2 crit
	Title    string
	Detail   string // what it means, in one sentence
	Evidence []string
	Actions  []Action
	// Filter is a Live-tab filter expression selecting the affected sockets
	// ("" when the finding isn't about specific sockets). ShowListen asks the
	// Live tab to stop hiding LISTEN sockets, which the filter targets.
	Filter     string
	ShowListen bool
	Count      int       // affected sockets
	Since      time.Time // first seen; set by Tracker
}

// Command returns the first runnable command among the actions, or "".
func (f *Finding) Command() string {
	for _, a := range f.Actions {
		if a.Command != "" {
			return a.Command
		}
	}
	return ""
}

// Input is everything one analysis pass looks at.
type Input struct {
	Conns        []*model.Connection // latest full-detail snapshot
	Sys, SysPrev *poller.SysStat     // host counters, current and previous poll
	Sysctl       poller.Sysctls
	Interval     time.Duration // poll interval, to turn counter deltas into rates
	// SSFilter is the ss filter expression in effect ("" for none). When
	// set, Conns is only the matching subset, so socket-count checks
	// (ephemeral ports, TIME-WAIT storms, CLOSE-WAIT leaks) see a partial
	// picture; the report carries it so the UI can say so.
	SSFilter string
	// Unprivileged is set when sstui isn't running as root: ss then only
	// reports process names for the current user's sockets.
	Unprivileged bool
}

// Report is the result of one analysis pass.
type Report struct {
	Findings []Finding
	Sockets  int
	Estab    int
	// RetransPct is the host-wide TCP retransmit rate over the last poll
	// (RetransSegs / OutSegs), or -1 when unknown.
	RetransPct float64
	// SSFilter echoes Input.SSFilter: when non-empty, socket-based findings
	// cover only sockets matching it (host counters stay host-wide).
	SSFilter string
	// HiddenProcs counts sockets whose owning process ss couldn't name
	// because sstui isn't root (0 when running as root).
	HiddenProcs int
}

// Crit and Warn count findings by severity.
func (r *Report) Crit() int { return r.count(2) }
func (r *Report) Warn() int { return r.count(1) }

func (r *Report) count(sev int) int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity == sev {
			n++
		}
	}
	return n
}

// Analyze runs every rule over the input and returns findings ranked most
// severe first, then by how many sockets they affect. Remaining ties keep
// rule order, which lists root causes (zero window, accept queue) before
// the symptoms they produce.
func Analyze(in Input) Report {
	a := newAnalysis(in)
	for _, rule := range rules {
		rule(a)
	}
	slices.SortStableFunc(a.out, func(x, y Finding) int {
		if c := cmp.Compare(y.Severity, x.Severity); c != 0 {
			return c
		}
		return cmp.Compare(y.Count, x.Count)
	})
	rep := Report{Findings: a.out, Sockets: len(in.Conns), RetransPct: -1, SSFilter: in.SSFilter}
	for _, c := range in.Conns {
		if c.State == "ESTAB" {
			rep.Estab++
		}
		if in.Unprivileged && procHidden(c) {
			rep.HiddenProcs++
		}
	}
	if pct, ok := a.retransPct(); ok {
		rep.RetransPct = pct
	}
	return rep
}

// minRetransSegs is the least outgoing traffic (segments per poll) for which
// a host-wide retransmit percentage means anything; below it, a single
// retransmitted keepalive reads as "33%".
const minRetransSegs = 1000

// retransPct returns the host-wide TCP retransmit rate over the last poll,
// when there was enough traffic for it to be meaningful.
func (a *analysis) retransPct() (float64, bool) {
	out, ok := a.delta("Tcp:OutSegs")
	if !ok || out < minRetransSegs {
		return 0, false
	}
	re, _ := a.delta("Tcp:RetransSegs")
	return float64(re) / float64(out) * 100, true
}

// analysis is the shared state rules read from and append to.
type analysis struct {
	in  Input
	out []Finding
	// byTuple indexes sockets by local+peer endpoint so a rule can find the
	// other end of a connection when both ends live on this host.
	byTuple map[string]*model.Connection
	// udpBacklog marks recv_backlog findings that include UDP sockets, so
	// the host UDP-drop counter only folds into findings it can explain.
	udpBacklog map[string]bool
}

func newAnalysis(in Input) *analysis {
	a := &analysis{in: in, byTuple: make(map[string]*model.Connection, len(in.Conns)), udpBacklog: map[string]bool{}}
	for _, c := range in.Conns {
		if c.Protocol == "tcp" {
			a.byTuple[endpoint(c.LocalAddr, c.LocalPort)+"|"+endpoint(c.PeerAddr, c.PeerPort)] = c
		}
	}
	return a
}

func (a *analysis) add(f Finding) { a.out = append(a.out, f) }

// localPeer returns the socket on this host at the other end of c, if any
// (loopback, or a connection between two local addresses).
func (a *analysis) localPeer(c *model.Connection) *model.Connection {
	return a.byTuple[endpoint(c.PeerAddr, c.PeerPort)+"|"+endpoint(c.LocalAddr, c.LocalPort)]
}

// delta returns how much a host counter grew over the last poll.
func (a *analysis) delta(key string) (int64, bool) {
	if a.in.Sys == nil || a.in.SysPrev == nil {
		return 0, false
	}
	return a.in.Sys.Delta(a.in.SysPrev, key)
}

// rate returns a host counter's growth per second over the last poll.
func (a *analysis) rate(key string) (float64, bool) {
	d, ok := a.delta(key)
	if !ok || a.in.Interval <= 0 {
		return 0, false
	}
	return float64(d) / a.in.Interval.Seconds(), true
}

// group is a set of sockets sharing one cause.
type group struct {
	key   string
	conns []*model.Connection
	sev   int
}

// groupBySignal buckets the sockets carrying any of the given signal types by
// keyFn, in a deterministic (key-sorted) order. A group's severity is the
// worst severity among its sockets' matching signals. keyFn returning ""
// leaves the socket out (a rule's way to exclude sockets another rule owns).
func (a *analysis) groupBySignal(keyFn func(*model.Connection) string, types ...model.SignalType) []*group {
	byKey := map[string]*group{}
	for _, c := range a.in.Conns {
		sev := 0
		for _, s := range c.Signals {
			if s.Severity > sev && slices.Contains(types, s.Type) {
				sev = s.Severity
			}
		}
		if sev == 0 {
			continue
		}
		k := keyFn(c)
		if k == "" {
			continue
		}
		g := byKey[k]
		if g == nil {
			g = &group{key: k}
			byKey[k] = g
		}
		g.conns = append(g.conns, c)
		g.sev = max(g.sev, sev)
	}
	groups := make([]*group, 0, len(byKey))
	for _, g := range byKey {
		groups = append(groups, g)
	}
	slices.SortFunc(groups, func(x, y *group) int { return strings.Compare(x.key, y.key) })
	return groups
}

// ---- formatting helpers -------------------------------------------------

// endpoint renders addr:port, bracketing IPv6 addresses.
func endpoint(addr, port string) string {
	if strings.Count(addr, ":") >= 2 {
		return "[" + addr + "]:" + port
	}
	return addr + ":" + port
}

// procHidden reports whether c has no process info although some process
// holds it open. Sockets with no file (inode 0: TIME-WAIT, SYN-RECV, and
// orphans the app already closed) belong to no process, even for root.
func procHidden(c *model.Connection) bool {
	return c.Process == nil && c.Inode != nil && *c.Inode != "0"
}

// procLabel names the process owning c ("nginx (pid 812)"). Without root,
// other users' sockets have no process info, so the label says how to get it.
func (a *analysis) procLabel(c *model.Connection) string {
	if c.Process == nil {
		if a.in.Unprivileged && procHidden(c) {
			return "unknown process (run with sudo to see it)"
		}
		return "unknown process"
	}
	if c.PID != nil {
		return fmt.Sprintf("%s (pid %d)", *c.Process, *c.PID)
	}
	return *c.Process
}

// procKey groups by process identity; sockets without process info (not
// visible to an unprivileged user) share one bucket.
func procKey(c *model.Connection) string {
	if c.PID != nil {
		return fmt.Sprintf("pid:%d", *c.PID)
	}
	if c.Process != nil {
		return "proc:" + *c.Process
	}
	return "unknown"
}

// procFilter returns a filter term selecting c's process, or "".
func procFilter(c *model.Connection) string {
	if c.PID != nil {
		return fmt.Sprintf("pid=%d", *c.PID)
	}
	if c.Process != nil && !strings.ContainsAny(*c.Process, " ()") {
		return "proc=" + *c.Process
	}
	return ""
}

// filterJoin joins non-empty filter terms with spaces (implicit AND).
func filterJoin(terms ...string) string {
	var out []string
	for _, t := range terms {
		if t != "" {
			out = append(out, t)
		}
	}
	return strings.Join(out, " ")
}

// sigFilter builds "(signal=A or signal=B)" for the given types.
func sigFilter(types ...model.SignalType) string {
	parts := make([]string, len(types))
	for i, t := range types {
		parts[i] = "signal=" + t.Label()
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return "(" + strings.Join(parts, " or ") + ")"
}

// plural renders "1 connection" / "3 connections".
func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// humanBytes renders a byte count with binary units.
func humanBytes(b float64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", b/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", b/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.0f KB", b/(1<<10))
	}
	return fmt.Sprintf("%.0f B", b)
}

// roundUpMB rounds a byte count up to a whole number of MiB (min 1 MiB), for
// suggesting sysctl values people can read.
func roundUpMB(b float64) int {
	mb := int(b+(1<<20)-1) >> 20
	return max(mb, 1) << 20
}

func deref(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

func signalOf(c *model.Connection, t model.SignalType) (model.Signal, bool) {
	for _, s := range c.Signals {
		if s.Type == t {
			return s, true
		}
	}
	return model.Signal{}, false
}

// topBy returns up to n labels with the highest counts, as "label ×count".
func topBy(counts map[string]int, n int) []string {
	type kv struct {
		k string
		v int
	}
	var all []kv
	for k, v := range counts {
		all = append(all, kv{k, v})
	}
	slices.SortFunc(all, func(x, y kv) int {
		if c := cmp.Compare(y.v, x.v); c != 0 {
			return c
		}
		return strings.Compare(x.k, y.k)
	})
	var out []string
	for i, e := range all {
		if i == n {
			break
		}
		out = append(out, fmt.Sprintf("%s ×%d", e.k, e.v))
	}
	return out
}

// ---- tracking across polls ----------------------------------------------

// Tracker remembers when each finding first appeared so the UI can say how
// long a problem has been going on. A finding that disappears is forgotten
// only after it has been absent for GraceMisses consecutive polls, so a
// problem that flickers for a poll keeps its original start time.
type Tracker struct {
	seen map[string]*trackState
}

type trackState struct {
	since  time.Time
	misses int
}

// GraceMisses is how many consecutive polls a finding may be absent before
// it counts as gone.
const GraceMisses = 3

// Update stamps Since on each finding (in place) and ages out ones that
// have been gone for a while.
func (t *Tracker) Update(fs []Finding, now time.Time) {
	if t.seen == nil {
		t.seen = make(map[string]*trackState)
	}
	present := make(map[string]bool, len(fs))
	for i := range fs {
		id := fs[i].ID
		present[id] = true
		st := t.seen[id]
		if st == nil {
			st = &trackState{since: now}
			t.seen[id] = st
		}
		st.misses = 0
		fs[i].Since = st.since
	}
	for id, st := range t.seen {
		if present[id] {
			continue
		}
		if st.misses++; st.misses > GraceMisses {
			delete(t.seen, id)
		}
	}
}
