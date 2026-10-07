package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"sstui/findings"
	"sstui/model"
	"sstui/session"

	tea "github.com/charmbracelet/bubbletea"
)

// captureOutput points the commands' stdout/stderr at buffers for a test.
func captureOutput(t *testing.T) (out, errOut *bytes.Buffer) {
	out, errOut = &bytes.Buffer{}, &bytes.Buffer{}
	stdout, stderr = out, errOut
	t.Cleanup(func() { stdout, stderr = os.Stdout, os.Stderr })
	return out, errOut
}

func stalledConn() *model.Connection {
	persist, dur := "persist", "2sec"
	return &model.Connection{Protocol: "tcp", State: "ESTAB",
		LocalAddr: "10.0.0.1", LocalPort: "50001", PeerAddr: "10.0.0.5", PeerPort: "5432",
		TimerType: &persist, TimerDur: &dur}
}

// writeRecording makes a recording of three polls: healthy, then a socket
// whose peer stops reading (zero window) for the last two.
func writeRecording(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rec.jsonl.gz")
	rec, err := session.Create(path, session.NewHeader("test", "", false))
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 7, 14, 0, 0, 0, time.UTC)
	for i, conns := range [][]*model.Connection{
		snapWithAddr("10.0.0.1"),
		{stalledConn()},
		{stalledConn()},
	} {
		if err := rec.Write(&session.Poll{Time: t0.Add(time.Duration(i) * 2 * time.Second), Conns: conns}); err != nil {
			t.Fatal(err)
		}
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseArgs(t *testing.T) {
	newFS := func() (*flag.FlagSet, *string, *bool) {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		fs.SetOutput(&bytes.Buffer{})
		return fs, fs.String("o", "", ""), fs.Bool("json", false, "")
	}

	fs, o, js := newFS()
	pos, err := parseArgs(fs, []string{"rec.gz", "-o", "out.md", "--json"})
	if err != nil || !slices.Equal(pos, []string{"rec.gz"}) || *o != "out.md" || !*js {
		t.Errorf("flags after the file: pos=%q o=%q json=%v err=%v", pos, *o, *js, err)
	}

	fs, _, js = newFS()
	pos, _ = parseArgs(fs, []string{"a", "--", "-b", "--json"})
	if !slices.Equal(pos, []string{"a", "-b", "--json"}) || *js {
		t.Errorf("after --: pos=%q json=%v", pos, *js)
	}

	fs, _, _ = newFS()
	if _, err := parseArgs(fs, []string{"-h"}); !errors.Is(err, flag.ErrHelp) || parseExit(err, 3) != 0 {
		t.Errorf("-h: err=%v", err)
	}
	fs, _, _ = newFS()
	if _, err := parseArgs(fs, []string{"--nope"}); err == nil || parseExit(err, 3) != 3 {
		t.Errorf("unknown flag: err=%v", err)
	}
}

func TestCheckRecording(t *testing.T) {
	path := writeRecording(t)
	out, _ := captureOutput(t)
	if code := runCheck([]string{path, "--json"}); code != 2 {
		t.Fatalf("exit = %d, want 2 (critical)\n%s", code, out)
	}
	var res struct {
		Status   string `json:"status"`
		Source   string `json:"source"`
		Polls    int    `json:"polls"`
		Findings []struct {
			ID        string `json:"id"`
			PollsSeen int    `json:"polls_seen"`
			Active    bool   `json:"active"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if res.Status != "critical" || res.Source != path || res.Polls != 3 || len(res.Findings) != 1 ||
		!strings.HasPrefix(res.Findings[0].ID, "zero_window") || res.Findings[0].PollsSeen != 2 || !res.Findings[0].Active {
		t.Errorf("result = %+v", res)
	}

	out.Reset()
	if code := runCheck([]string{path}); code != 2 || !strings.Contains(out.String(), "sstui replay --filter") {
		t.Errorf("text check: exit %d\n%s", code, out)
	}
}

func TestCheckRejectsLiveFlagsWithRecording(t *testing.T) {
	path := writeRecording(t)
	_, errOut := captureOutput(t)
	if code := runCheck([]string{path, "--duration", "10s"}); code != 3 || !strings.Contains(errOut.String(), "--duration applies to live polling") {
		t.Errorf("exit %d, stderr %q", code, errOut)
	}
	errOut.Reset()
	if code := runCheck([]string{path, path}); code != 3 || !strings.Contains(errOut.String(), "at most one recording") {
		t.Errorf("exit %d, stderr %q", code, errOut)
	}
	errOut.Reset()
	if code := runCheck([]string{"-h"}); code != 0 || !strings.Contains(errOut.String(), "Usage: sstui check") {
		t.Errorf("-h: exit %d, stderr %q", code, errOut)
	}
}

func TestReportRecordingToFile(t *testing.T) {
	path := writeRecording(t)
	md := filepath.Join(t.TempDir(), "r.md")
	_, errOut := captureOutput(t)
	if code := runReport([]string{path, "-o", md}); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	data, err := os.ReadFile(md)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# Network report:", "**CRITICAL**", "peer not reading (zero window)", "sstui replay --filter"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("report missing %q:\n%s", want, data)
		}
	}
}

// TestReplayFindingsFollowScrub: a replay opens at the end of the
// recording, and stepping back shows the Findings of that moment.
func TestReplayFindingsFollowScrub(t *testing.T) {
	app, n, err := loadReplay(writeRecording(t))
	if err != nil || n != 3 {
		t.Fatalf("loadReplay: n=%d err=%v", n, err)
	}
	if cmd := app.Init(); cmd == nil {
		t.Fatal("Init should still ask for the window size")
	}
	m := feed(app, tea.WindowSizeMsg{Width: 160, Height: 40})
	v := m.View()
	for _, want := range []string{"peer not reading (zero window)", "the end of the recording", "replay: "} {
		if !strings.Contains(v, want) {
			t.Errorf("replay view missing %q:\n%s", want, v)
		}
	}
	m = feed(m, key("{")) // back to the first, healthy poll
	if v := m.View(); strings.Contains(v, "peer not reading") || !strings.Contains(v, "as of 14:00:00 (paused") {
		t.Errorf("after stepping back the Findings should be those of 14:00:00:\n%s", v)
	}
}

func TestLoadReplayErrors(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty.jsonl")
	rec, _ := session.Create(empty, session.NewHeader("test", "", false))
	rec.Close()
	if _, _, err := loadReplay(empty); err == nil || !strings.Contains(err.Error(), "no polls") {
		t.Errorf("empty recording: %v", err)
	}
	if _, _, err := loadReplay(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("missing file should fail")
	}
}

// TestPausedFindingsShowThatMoment: in the live TUI too, pausing and
// stepping back shows the findings of the moment on screen.
func TestPausedFindingsShowThatMoment(t *testing.T) {
	m := NewApp(nil)
	m = feed(m, tea.WindowSizeMsg{Width: 160, Height: 40})
	m = feed(m, polled([]*model.Connection{stalledConn()}))
	m = feed(m, polled(snapWithAddr("10.0.0.1")))
	if v := m.View(); strings.Contains(v, "peer not reading") {
		t.Fatalf("the newest poll is healthy:\n%s", v)
	}
	m = feed(m, key("["))
	if v := m.View(); !strings.Contains(v, "peer not reading (zero window)") || !strings.Contains(v, "1 crit") {
		t.Errorf("one poll back the stall should show, header pill included:\n%s", v)
	}
	m = feed(m, key(" "))
	if v := m.View(); strings.Contains(v, "peer not reading") {
		t.Errorf("resuming should return to the newest poll:\n%s", v)
	}
}

func TestChangeLogGrace(t *testing.T) {
	var b bytes.Buffer
	var l changeLog
	f := []findings.Finding{{ID: "a", Severity: 2, Title: "stall"}}
	now := time.Date(2026, 10, 7, 14, 0, 0, 0, time.UTC)
	l.update(&b, f, now)
	for range findings.GraceMisses {
		l.update(&b, nil, now) // a flicker: missing, but within the grace
	}
	l.update(&b, f, now)
	if got := b.String(); got != "14:00:00  CRIT  stall\n" {
		t.Errorf("a flickering finding should be logged once, got:\n%s", got)
	}
	b.Reset()
	for range findings.GraceMisses + 1 {
		l.update(&b, nil, now)
	}
	if got := b.String(); got != "14:00:00  ok    resolved: stall\n" {
		t.Errorf("got:\n%s", got)
	}
}

func TestHumanSize(t *testing.T) {
	for n, want := range map[int64]string{512: "512 B", 49854: "49 KB", 3 << 20: "3.0 MB"} {
		if got := humanSize(n); got != want {
			t.Errorf("humanSize(%d) = %q, want %q", n, got, want)
		}
	}
}
