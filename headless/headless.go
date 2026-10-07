// Package headless renders a findings timeline without the TUI: a
// plain-text or JSON health check (sstui check) and a markdown incident
// summary (sstui report).
package headless

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"sstui/model"
	"sstui/poller"
	"sstui/session"
)

// Exit codes follow the Nagios plugin convention, so check drops straight
// into monitoring agents: 0 OK, 1 warning, 2 critical, 3 unknown (couldn't
// analyse: bad arguments, ss failing, unreadable recording).
const (
	ExitOK       = 0
	ExitWarning  = 1
	ExitCritical = 2
	ExitUnknown  = 3
)

// Meta is what the renderers need besides the timeline.
type Meta struct {
	Version      string
	Host, Kernel string
	// Source is "live" or the recording's path.
	Source       string
	SSFilter     string
	Unprivileged bool
	Interval     time.Duration
	Sysctl       poller.Sysctls
	Final        []*model.Connection // sockets at the last poll
	// Failed counts polls where ss failed outright; LastErr is the most
	// recent error.
	Failed   int
	LastErr  error
	Unclosed bool // the recording wasn't closed cleanly (see session.Reader)
}

// Status names the overall result and its exit code. With no analysed
// polls the result is unknown.
func Status(tl *session.Timeline) (string, int) {
	if tl.Analyses == 0 {
		return "UNKNOWN", ExitUnknown
	}
	switch tl.Worst() {
	case 2:
		return "CRITICAL", ExitCritical
	case 1:
		return "WARNING", ExitWarning
	}
	return "OK", ExitOK
}

// counts renders "1 critical, 2 warnings" for the findings seen.
func counts(tl *session.Timeline) string {
	var parts []string
	if c := tl.Count(2); c > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", c))
	}
	if w := tl.Count(1); w > 0 {
		parts = append(parts, plural(w, "warning"))
	}
	if len(parts) == 0 {
		return "no problems found"
	}
	return strings.Join(parts, ", ")
}

// window renders how long the timeline covers and how many polls.
func window(tl *session.Timeline) string {
	return fmt.Sprintf("%s (%s)", fmtDur(tl.End.Sub(tl.Start)), plural(tl.Analyses, "poll"))
}

// socketsCommand is the sstui invocation that shows a finding's sockets in
// the TUI, or "" when the finding isn't about specific sockets: the live
// TUI for a live run, or a replay of the recording it came from (running
// sstui live on another machine would show that machine's sockets).
func socketsCommand(o *session.Occurrence, m Meta) string {
	f := o.Finding
	if f.Filter == "" {
		return ""
	}
	var cmd string
	switch {
	case m.Source != "live":
		cmd = "sstui replay"
	case m.Unprivileged:
		cmd = "sudo sstui"
	default:
		cmd = "sstui"
	}
	if m.Source == "live" && m.SSFilter != "" {
		cmd += " --ss-filter " + shellQuote(m.SSFilter)
	}
	if f.ShowListen {
		cmd += " --show-listen"
	}
	cmd += " --filter " + shellQuote(f.Filter)
	if m.Source != "live" {
		cmd += " " + shellQuote(m.Source)
	}
	return cmd
}

// seen describes when a finding was active: "active · seen in 3 of 3
// polls since 14:02:11" or "resolved · seen in 1 of 3 polls, 14:02:11".
func seen(o *session.Occurrence, tl *session.Timeline) string {
	state := "resolved"
	if o.Active {
		state = "active"
	}
	span := o.First.Format("15:04:05")
	if !o.Last.Equal(o.First) {
		span += "–" + o.Last.Format("15:04:05")
	}
	return fmt.Sprintf("%s · seen in %d of %d polls, %s", state, o.Polls, tl.Analyses, span)
}

func sevName(sev int) string {
	if sev >= 2 {
		return "critical"
	}
	return "warning"
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// fmtDur renders a window length compactly: "4s", "12m30s", "2h".
func fmtDur(d time.Duration) string {
	s := d.Round(time.Second).String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// stateCounts tallies the final sockets by state, most common first.
func stateCounts(conns []*model.Connection) []kv {
	m := map[string]int{}
	for _, c := range conns {
		m[c.Protocol+" "+c.State]++
	}
	return sortedKV(m)
}

// topProcesses tallies the final sockets by owning process.
func topProcesses(conns []*model.Connection, n int) []kv {
	m := map[string]int{}
	for _, c := range conns {
		name := "(unknown)"
		if c.Process != nil {
			name = *c.Process
			if c.PID != nil {
				name = fmt.Sprintf("%s (pid %d)", *c.Process, *c.PID)
			}
		}
		m[name]++
	}
	out := sortedKV(m)
	return out[:min(n, len(out))]
}

type kv struct {
	k string
	v int
}

func sortedKV(m map[string]int) []kv {
	out := make([]kv, 0, len(m))
	for _, k := range slices.Sorted(maps.Keys(m)) {
		out = append(out, kv{k, m[k]})
	}
	slices.SortStableFunc(out, func(x, y kv) int { return cmp.Compare(y.v, x.v) })
	return out
}
