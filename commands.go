package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"sstui/findings"
	"sstui/headless"
	"sstui/parser"
	"sstui/poller"
	"sstui/session"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/term"
)

// subcommands maps a first argument to a command. Each returns the process
// exit code.
var subcommands = map[string]func(args []string) int{
	"check":  runCheck,
	"report": runReport,
	"record": runRecord,
	"replay": runReplay,
}

// Output streams for the commands; tests replace them.
var (
	stdout io.Writer = os.Stdout
	stderr io.Writer = os.Stderr
)

// stopSignals end a watch or a recording cleanly: Ctrl-C, kill, and the
// terminal going away (an SSH session dropping), so a recording is always
// closed properly.
var stopSignals = []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP}

func usage(fs *flag.FlagSet) {
	fmt.Fprintf(fs.Output(), `sstui: Linux socket triage that tells you what to fix.

Usage:
  sstui [flags]                 interactive TUI
  sstui check [flags] [FILE]    print findings and exit 0 OK, 1 warning, 2 critical, 3 unknown
  sstui report [flags] [FILE]   write a markdown incident summary
  sstui record [flags]          save polls to a file for replay or report later
  sstui replay [flags] FILE     open a recording in the TUI

check and report watch the live host, or analyse FILE (a recording) instead.
Run "sstui COMMAND -h" for a command's flags. Run with sudo to see the
process behind every socket.

Flags:
`)
	fs.PrintDefaults()
}

// parseArgs parses flags wherever they appear, not only before the first
// argument (the flag package's default), so "report FILE -o out.md" works.
// It returns the positional arguments; everything after "--" is positional.
// A request for help yields flag.ErrHelp.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		if used := len(args) - len(rest); used > 0 && args[used-1] == "--" {
			return append(pos, rest...), nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

// parseExit maps a flag parse error to an exit code: 0 for -h, else code.
func parseExit(err error, code int) int {
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	return code
}

// liveFlags are the polling options shared by every command that watches
// the live host.
type liveFlags struct {
	interval *time.Duration
	ssFilter *string
}

func addLiveFlags(fs *flag.FlagSet) liveFlags {
	return liveFlags{
		interval: fs.Duration("interval", poller.PollInterval, "poll cadence (e.g. 1s, 500ms); minimum 100ms"),
		ssFilter: fs.String("ss-filter", "", "filter passed to ss itself, e.g. 'dport = :443' or 'state established ( dst 10.0.0.0/8 )'; non-matching sockets aren't collected at all (see ss(8) FILTER)"),
	}
}

// setup applies the poll interval and validates the ss filter by running
// ss with it once.
func (l liveFlags) setup() (parser.SSFilter, error) {
	if *l.interval < 100*time.Millisecond {
		return parser.SSFilter{}, fmt.Errorf("interval too small (%s); minimum is 100ms", *l.interval)
	}
	poller.SetInterval(*l.interval)
	f, err := parser.ParseSSFilter(*l.ssFilter)
	if err == nil {
		err = parser.CheckSSFilter(f)
	}
	return f, err
}

// isSet reports whether the named flag was given on the command line.
func isSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) { set = set || f.Name == name })
	return set
}

// analysis feeds polls through a session and collects the findings
// timeline that check and report render.
type analysis struct {
	sess    *session.Session
	tl      session.Timeline
	failed  int
	lastErr error
}

func (a *analysis) add(p *session.Poll) {
	if p.Err != nil {
		a.lastErr = p.Err
	}
	if a.sess.Ingest(p) {
		a.tl.Add(a.sess.Report, p.Time, p.Sys)
	} else {
		a.failed++
	}
}

func (a *analysis) meta(source, host, kernel string) headless.Meta {
	m := headless.Meta{
		Version: version, Host: host, Kernel: kernel, Source: source,
		SSFilter: a.sess.SSFilter, Unprivileged: a.sess.Unprivileged,
		Interval: poller.PollInterval, Sysctl: a.sess.Sysctl,
		Failed: a.failed, LastErr: a.lastErr,
	}
	if snap := a.sess.Buf.GetLatest(); snap != nil {
		m.Final = snap.Conns
	}
	return m
}

// analyse runs the analysis for check and report: over a recording when
// one is named, otherwise by watching the live host for the duration.
func analyse(name string, fs *flag.FlagSet, files []string, live liveFlags, duration time.Duration) (*analysis, headless.Meta, error) {
	switch len(files) {
	case 0:
	case 1:
		for _, f := range []string{"interval", "ss-filter", "duration"} {
			if isSet(fs, f) {
				return nil, headless.Meta{}, fmt.Errorf("--%s applies to live polling; a recording keeps the settings it was made with", f)
			}
		}
		return analyseRecording(files[0])
	default:
		return nil, headless.Meta{}, fmt.Errorf("%s takes at most one recording, got %d: %q", name, len(files), files)
	}

	ssf, err := live.setup()
	if err != nil {
		return nil, headless.Meta{}, err
	}
	// Two polls at least: deltas (loss, drops, retransmit rates) need a
	// previous sample.
	polls := max(int(duration/poller.PollInterval)+1, 2)
	a := &analysis{sess: session.New(ssf.String(), os.Geteuid() != 0)}
	host, _ := os.Hostname()

	progress := stderr == io.Writer(os.Stderr) && term.IsTerminal(os.Stderr.Fd())
	if progress {
		fmt.Fprintf(stderr, "watching %s for %s (%d polls, Ctrl-C to stop early)…", host,
			time.Duration(polls-1)*poller.PollInterval, polls)
	}
	ctx, stop := signal.NotifyContext(context.Background(), stopSignals...)
	defer stop()
	watch(ctx, ssf, polls, a.add)
	if progress {
		fmt.Fprint(stderr, "\r\033[K")
	}
	return a, a.meta("live", host, session.KernelRelease()), nil
}

// analyseRecording replays a recording through the analysis.
func analyseRecording(path string) (*analysis, headless.Meta, error) {
	r, err := session.Open(path)
	if err != nil {
		return nil, headless.Meta{}, err
	}
	defer r.Close()
	poller.SetInterval(r.Header.Interval)
	a := &analysis{sess: session.New(r.Header.SSFilter, r.Header.Unprivileged)}
	for {
		p, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, headless.Meta{}, fmt.Errorf("%s: %w", path, err)
		}
		a.add(p)
	}
	m := a.meta(path, r.Header.Host, r.Header.Kernel)
	m.Unclosed = r.Unclosed
	return a, m, nil
}

// watch polls the live host every interval and hands each poll to fn,
// until polls polls are done (0: until ctx ends) or ctx ends.
func watch(ctx context.Context, f parser.SSFilter, polls int, fn func(*session.Poll)) {
	tick := time.NewTicker(poller.PollInterval)
	defer tick.Stop()
	for i := 0; polls == 0 || i < polls; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
		p := session.PollLive(f)
		// Ctrl-C reaches the whole foreground process group, so it kills a
		// running ss too; that poll's failure is ours, not the host's.
		if ctx.Err() != nil && p.Err != nil {
			return
		}
		fn(p)
		if ctx.Err() != nil {
			return
		}
	}
}

func runCheck(args []string) int {
	fs := flag.NewFlagSet("sstui check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), `Usage: sstui check [flags] [FILE]

Watch the host briefly (or analyse the recording FILE), print what is wrong
and what to do, and exit 0 OK, 1 warning, 2 critical, 3 unknown (the Nagios
plugin convention). A finding counts if it showed up in any poll.

Flags:
`)
		fs.PrintDefaults()
	}
	live := addLiveFlags(fs)
	duration := fs.Duration("duration", 2*poller.PollInterval, "how long to watch the live host")
	asJSON := fs.Bool("json", false, "print JSON instead of text")
	files, err := parseArgs(fs, args)
	if err != nil {
		return parseExit(err, headless.ExitUnknown)
	}
	a, m, err := analyse("check", fs, files, live, *duration)
	if err != nil {
		fmt.Fprintln(stderr, "sstui check:", err)
		return headless.ExitUnknown
	}
	if *asJSON {
		if err := headless.WriteJSON(stdout, &a.tl, m); err != nil {
			fmt.Fprintln(stderr, "sstui check:", err)
			return headless.ExitUnknown
		}
	} else {
		headless.WriteText(stdout, &a.tl, m, textWidth())
	}
	_, code := headless.Status(&a.tl)
	return code
}

// textWidth is the width to wrap check's text output at: the terminal's
// (capped for readability), or 0 (no wrapping) when output is redirected.
func textWidth() int {
	if stdout != io.Writer(os.Stdout) || !term.IsTerminal(os.Stdout.Fd()) {
		return 0
	}
	w, _, err := term.GetSize(os.Stdout.Fd())
	if err != nil || w <= 0 {
		return 100
	}
	return min(w, 120)
}

func runReport(args []string) int {
	fs := flag.NewFlagSet("sstui report", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), `Usage: sstui report [flags] [FILE]

Write a markdown incident summary: a timeline of every finding, each one in
full with evidence and next steps, the host counters that moved, the sockets
at the end and the kernel settings. Analyses the recording FILE, or watches
the live host for --duration.

Flags:
`)
		fs.PrintDefaults()
	}
	live := addLiveFlags(fs)
	duration := fs.Duration("duration", 30*time.Second, "how long to watch the live host")
	out := fs.String("o", "", "write the report to `FILE` instead of stdout")
	files, err := parseArgs(fs, args)
	if err != nil {
		return parseExit(err, 2)
	}
	a, m, err := analyse("report", fs, files, live, *duration)
	if err != nil {
		fmt.Fprintln(stderr, "sstui report:", err)
		return 1
	}
	if *out == "" {
		headless.WriteMarkdown(stdout, &a.tl, m)
		return 0
	}
	f, err := os.Create(*out)
	if err == nil {
		headless.WriteMarkdown(f, &a.tl, m)
		err = f.Close()
	}
	if err != nil {
		fmt.Fprintln(stderr, "sstui report:", err)
		return 1
	}
	fmt.Fprintf(stderr, "report written to %s\n", *out)
	return 0
}

func runRecord(args []string) int {
	fs := flag.NewFlagSet("sstui record", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), `Usage: sstui record [flags]

Poll the host and save every poll to a file until Ctrl-C (or --duration).
Open it later with "sstui replay FILE", or summarise it with "sstui report
FILE" or "sstui check FILE", on this machine or another. New and resolved
findings are printed as they happen.

A recording is JSON lines (one poll per line, readable with jq),
gzip-compressed when the name ends in .gz, and readable only by you: it
lists every socket's process and peer. Expect roughly 100-200 KB per 1000
sockets per poll compressed.

Flags:
`)
		fs.PrintDefaults()
	}
	live := addLiveFlags(fs)
	out := fs.String("o", "", "recording `FILE` (default sstui-HOST-TIME.jsonl.gz)")
	duration := fs.Duration("duration", 0, "stop after this long (default: until Ctrl-C)")
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseExit(err, 2)
	}
	if len(rest) > 0 {
		fmt.Fprintf(stderr, "sstui record: unexpected argument %q (use -o FILE)\n", rest[0])
		return 2
	}
	ssf, err := live.setup()
	if err != nil {
		fmt.Fprintln(stderr, "sstui record:", err)
		return 2
	}
	host, _ := os.Hostname()
	path := *out
	if path == "" {
		path = fmt.Sprintf("sstui-%s-%s.jsonl.gz", host, time.Now().Format("20060102-150405"))
	}
	unpriv := os.Geteuid() != 0
	rec, err := session.Create(path, session.NewHeader(version, ssf.String(), unpriv))
	if err != nil {
		fmt.Fprintln(stderr, "sstui record:", err)
		return 1
	}

	polls := 0
	if *duration > 0 {
		polls = int(*duration/poller.PollInterval) + 1
	}
	fmt.Fprintf(stderr, "recording %s every %s to %s; Ctrl-C to stop\n", host, poller.PollInterval, path)
	if unpriv {
		fmt.Fprintln(stderr, "not root: process names will be missing for other users' sockets (run with sudo to record them)")
	}

	sess := session.New(ssf.String(), unpriv)
	var changes changeLog
	n := 0
	var werr error
	ctx, stop := signal.NotifyContext(context.Background(), stopSignals...)
	defer stop()
	watch(ctx, ssf, polls, func(p *session.Poll) {
		if werr != nil {
			return
		}
		if werr = rec.Write(p); werr != nil {
			stop()
			return
		}
		n++
		if p.Err != nil {
			fmt.Fprintf(stderr, "%s  ss error: %v\n", p.Time.Format("15:04:05"), p.Err)
		}
		if sess.Ingest(p) {
			changes.update(stderr, sess.Report.Findings, p.Time)
		}
	})
	if cerr := rec.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		fmt.Fprintln(stderr, "sstui record:", werr)
		return 1
	}
	size := ""
	if st, err := os.Stat(path); err == nil {
		size = ", " + humanSize(st.Size())
	}
	fmt.Fprintf(stderr, "\nrecorded %d polls%s to %s\n  replay:  sstui replay %s\n  summary: sstui report %s\n", n, size, path, path, path)
	return 0
}

// humanSize renders a file size with binary units.
func humanSize(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(b)/(1<<10))
	}
	return fmt.Sprintf("%d B", b)
}

// changeLog prints findings as they appear and clear during a recording.
// Like the TUI's finding ages, it forgives a finding missing for a few
// polls (findings.GraceMisses), so one that flickers isn't reported as
// resolved and new again every poll.
type changeLog struct {
	active map[string]*logged
}

type logged struct {
	title  string
	misses int
}

func (l *changeLog) update(w io.Writer, fs []findings.Finding, at time.Time) {
	if l.active == nil {
		l.active = make(map[string]*logged)
	}
	ts := at.Format("15:04:05")
	present := make(map[string]bool, len(fs))
	for _, f := range fs {
		present[f.ID] = true
		if e := l.active[f.ID]; e != nil {
			e.title, e.misses = f.Title, 0
			continue
		}
		tag := "WARN"
		if f.Severity >= 2 {
			tag = "CRIT"
		}
		fmt.Fprintf(w, "%s  %s  %s\n", ts, tag, f.Title)
		l.active[f.ID] = &logged{title: f.Title}
	}
	var resolved []string
	for id, e := range l.active {
		if present[id] {
			continue
		}
		if e.misses++; e.misses > findings.GraceMisses {
			resolved = append(resolved, e.title)
			delete(l.active, id)
		}
	}
	slices.Sort(resolved)
	for _, t := range resolved {
		fmt.Fprintf(w, "%s  ok    resolved: %s\n", ts, t)
	}
}

func runReplay(args []string) int {
	fs := flag.NewFlagSet("sstui replay", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), `Usage: sstui replay [flags] FILE

Open a recording (from "sstui record" or "sstui --record") in the TUI. It
opens at the end of the recording; [ and ] step back and forward through it
({ and } ten polls at a time), and every tab, Findings included, shows that
moment. The TUI keeps the last %d polls of a longer recording.

Flags:
`, poller.BufferSize)
		fs.PrintDefaults()
	}
	disp := addTUIFlags(fs)
	files, err := parseArgs(fs, args)
	if err != nil {
		return parseExit(err, 2)
	}
	if len(files) != 1 {
		fs.Usage()
		return 2
	}
	app, n, err := loadReplay(files[0])
	if err != nil {
		fmt.Fprintln(stderr, "sstui replay:", err)
		return 1
	}
	if n > poller.BufferSize {
		fmt.Fprintf(stderr, "%s has %d polls; showing the last %d (sstui report covers all of it)\n", files[0], n, poller.BufferSize)
	}
	disp.apply(app)
	p := tea.NewProgram(app, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	return 0
}

// loadReplay reads a whole recording into a TUI that doesn't poll. It
// returns the app and how many polls the recording held.
func loadReplay(path string) (*AppModel, int, error) {
	r, err := session.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer r.Close()
	poller.SetInterval(r.Header.Interval)
	sess := session.New(r.Header.SSFilter, r.Header.Unprivileged)
	n := 0
	for {
		p, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, 0, fmt.Errorf("%s: %w", path, err)
		}
		sess.Ingest(p)
		n++
	}
	if sess.Buf.Count() == 0 {
		return nil, 0, fmt.Errorf("%s has no polls with data", path)
	}
	app := NewApp(sess)
	app.replay = path
	if r.Header.Host != "" {
		app.replay += " (" + r.Header.Host + ")"
	}
	app.syncTable()
	app.reselectFinding()
	return app, n, nil
}
