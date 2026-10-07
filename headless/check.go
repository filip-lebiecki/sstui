package headless

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"sstui/session"

	"github.com/charmbracelet/lipgloss"
)

var (
	styleCrit = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff6b6b")).Bold(true)
	styleWarn = lipgloss.NewStyle().Foreground(lipgloss.Color("#ffa94d")).Bold(true)
	styleOK   = lipgloss.NewStyle().Foreground(lipgloss.Color("#51cf66")).Bold(true)
	styleBold = lipgloss.NewStyle().Bold(true)
	styleDim  = lipgloss.NewStyle().Foreground(lipgloss.Color("#888"))
	styleCmd  = lipgloss.NewStyle().Foreground(lipgloss.Color("#74c0fc"))
)

// WriteText writes the check result for a person or a log: a one-line
// verdict first (the Nagios plugin convention), then each finding with its
// evidence and next steps. Colour is applied only when the output is a
// terminal (lipgloss detects it). width wraps the text with a hanging
// indent; 0 leaves lines unwrapped, which suits logs and grep.
func WriteText(w io.Writer, tl *session.Timeline, m Meta, width int) {
	status, _ := Status(tl)
	if tl.Analyses == 0 {
		msg := "no polls completed"
		if m.LastErr != nil {
			msg = "ss failed: " + m.LastErr.Error()
		}
		fmt.Fprintf(w, "%s: %s\n", styleCrit.Render(status), msg)
		return
	}

	statusStyle := styleOK
	switch tl.Worst() {
	case 2:
		statusStyle = styleCrit
	case 1:
		statusStyle = styleWarn
	}
	stats := fmt.Sprintf("%s, %s, %d sockets (%d established)", m.Host, window(tl), tl.Last.Sockets, tl.Last.Estab)
	if tl.Last.RetransPct >= 0 {
		stats += fmt.Sprintf(", host retransmits %.2f%%", tl.Last.RetransPct)
	}
	fmt.Fprintf(w, "%s: %s — %s\n", statusStyle.Render(status), counts(tl), stats)

	note := func(s string) { fmt.Fprintln(w, render(styleDim, wrap("  "+s, width, 2))) }
	if m.Source != "live" {
		note("source: recording " + m.Source)
	}
	if n := tl.Last.HiddenProcs; n > 0 {
		if m.Source == "live" {
			note(fmt.Sprintf("not root: process names hidden for %s owned by other users — run with sudo to see them", plural(n, "socket")))
		} else {
			note(fmt.Sprintf("recorded without root: process names missing for %s owned by other users — record with sudo to capture them", plural(n, "socket")))
		}
	}
	if m.SSFilter != "" {
		note(fmt.Sprintf("scope: ss filter %q — socket checks see only matching sockets; kernel counters stay host-wide", m.SSFilter))
	}
	if m.Failed > 0 {
		note(fmt.Sprintf("%s failed (last error: %v)", plural(m.Failed, "poll"), m.LastErr))
	}
	if m.Unclosed {
		note("the recording wasn't closed cleanly (sstui was killed); every complete poll in it was analysed")
	}

	for _, o := range tl.Ranked() {
		f := o.Finding
		tag := styleWarn.Render("▲ WARN")
		if o.Worst >= 2 {
			tag = styleCrit.Render("✖ CRIT")
		}
		fmt.Fprintf(w, "\n%s  %s\n", tag, styleBold.Render(f.Title))
		line := func(indent int, bullet, text string, st lipgloss.Style) {
			fmt.Fprintln(w, render(st, wrap(strings.Repeat(" ", indent)+bullet+text, width, indent+len([]rune(bullet)))))
		}
		line(8, "", seen(o, tl), styleDim)
		line(8, "", f.Detail, styleDim.Italic(true))
		for _, e := range f.Evidence {
			line(8, "• ", e, lipgloss.NewStyle())
		}
		for _, a := range f.Actions {
			line(8, "→ ", a.Text, lipgloss.NewStyle())
			if a.Command != "" {
				line(10, "$ ", a.Command, styleCmd)
			}
		}
		if cmd := socketsCommand(o, m); cmd != "" {
			line(8, "sockets: ", cmd, styleDim)
		}
	}
}

// render styles each line separately: lipgloss pads a multi-line block to
// its widest line, which would leave trailing spaces in logs.
func render(st lipgloss.Style, s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = st.Render(l)
	}
	return strings.Join(lines, "\n")
}

// wrap word-wraps s to width with continuation lines indented by indent
// spaces. A width of 0 disables wrapping.
func wrap(s string, width, indent int) string {
	if width <= 0 || len([]rune(s)) <= width {
		return s
	}
	lead := len(s) - len(strings.TrimLeft(s, " "))
	words := strings.Fields(s)
	var b strings.Builder
	col := 0
	b.WriteString(s[:lead])
	col = lead
	for i, wd := range words {
		n := len([]rune(wd))
		if i > 0 {
			if col+1+n > width {
				b.WriteString("\n" + strings.Repeat(" ", indent))
				col = indent
			} else {
				b.WriteByte(' ')
				col++
			}
		}
		b.WriteString(wd)
		col += n
	}
	return b.String()
}

type jsonCheck struct {
	Status          string        `json:"status"`
	ExitCode        int           `json:"exit_code"`
	Host            string        `json:"host"`
	Kernel          string        `json:"kernel,omitempty"`
	Version         string        `json:"sstui_version"`
	Source          string        `json:"source"`
	Start           time.Time     `json:"start"`
	End             time.Time     `json:"end"`
	Polls           int           `json:"polls"`
	FailedPolls     int           `json:"failed_polls,omitempty"`
	LastError       string        `json:"last_error,omitempty"`
	Sockets         int           `json:"sockets"`
	Established     int           `json:"established"`
	RetransPct      *float64      `json:"retrans_pct,omitempty"`
	HiddenProcesses int           `json:"hidden_processes,omitempty"`
	SSFilter        string        `json:"ss_filter,omitempty"`
	Unprivileged    bool          `json:"unprivileged,omitempty"`
	Findings        []jsonFinding `json:"findings"`
}

type jsonFinding struct {
	ID         string       `json:"id"`
	Severity   string       `json:"severity"` // worst seen: "warning" or "critical"
	Active     bool         `json:"active"`   // still present at the last poll
	Title      string       `json:"title"`
	Detail     string       `json:"detail"`
	Evidence   []string     `json:"evidence,omitempty"`
	Actions    []jsonAction `json:"actions,omitempty"`
	Sockets    int          `json:"sockets,omitempty"`
	LiveFilter string       `json:"live_filter,omitempty"` // sstui --filter expression for the affected sockets
	FirstSeen  time.Time    `json:"first_seen"`
	LastSeen   time.Time    `json:"last_seen"`
	PollsSeen  int          `json:"polls_seen"`
}

type jsonAction struct {
	Text    string `json:"text"`
	Command string `json:"command,omitempty"`
}

// WriteJSON writes the check result as one JSON document, for scripts and
// monitoring agents.
func WriteJSON(w io.Writer, tl *session.Timeline, m Meta) error {
	status, code := Status(tl)
	out := jsonCheck{
		Status: strings.ToLower(status), ExitCode: code,
		Host: m.Host, Kernel: m.Kernel, Version: m.Version, Source: m.Source,
		Start: tl.Start, End: tl.End, Polls: tl.Analyses, FailedPolls: m.Failed,
		Sockets: tl.Last.Sockets, Established: tl.Last.Estab,
		HiddenProcesses: tl.Last.HiddenProcs, SSFilter: m.SSFilter, Unprivileged: m.Unprivileged,
		Findings: []jsonFinding{},
	}
	if m.LastErr != nil {
		out.LastError = m.LastErr.Error()
	}
	if tl.Last.RetransPct >= 0 && tl.Analyses > 0 {
		pct := tl.Last.RetransPct
		out.RetransPct = &pct
	}
	for _, o := range tl.Ranked() {
		f := o.Finding
		jf := jsonFinding{
			ID: f.ID, Severity: sevName(o.Worst), Active: o.Active,
			Title: f.Title, Detail: f.Detail, Evidence: f.Evidence,
			Sockets: f.Count, LiveFilter: f.Filter,
			FirstSeen: o.First, LastSeen: o.Last, PollsSeen: o.Polls,
		}
		for _, a := range f.Actions {
			jf.Actions = append(jf.Actions, jsonAction(a))
		}
		out.Findings = append(out.Findings, jf)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
