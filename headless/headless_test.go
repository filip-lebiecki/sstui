package headless

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"sstui/findings"
	"sstui/poller"
	"sstui/session"
)

var t0 = time.Date(2026, 10, 7, 14, 0, 0, 0, time.UTC)

func stall(sev int) findings.Finding {
	return findings.Finding{
		ID: "zero_window|x", Severity: sev,
		Title:    "nginx (pid 812) → 10.0.0.5:5432: 1 connection stalled — peer not reading (zero window)",
		Detail:   "The receiver's buffer is full.",
		Evidence: []string{"1 socket · 1.7 MB waiting in Send-Q"},
		Actions:  []findings.Action{{Text: "See what its threads are doing", Command: "top -H -p 812"}},
		Filter:   "signal=ZERO_WIN peer==10.0.0.5",
		Count:    1,
	}
}

// timeline: the stall is seen in both polls; a warning only in the first.
func timeline() *session.Timeline {
	var tl session.Timeline
	sys0 := &poller.SysStat{Timestamp: t0, Counters: map[string]int64{"Tcp:OutSegs": 1000, "Tcp:RetransSegs": 10}}
	sys1 := &poller.SysStat{Timestamp: t0.Add(2 * time.Second), Counters: map[string]int64{"Tcp:OutSegs": 3000, "Tcp:RetransSegs": 30}}
	tl.Add(findings.Report{Findings: []findings.Finding{stall(2), {ID: "w", Severity: 1, Title: "a warning"}},
		Sockets: 10, Estab: 4, RetransPct: -1}, t0, sys0)
	tl.Add(findings.Report{Findings: []findings.Finding{stall(2)}, Sockets: 12, Estab: 5, RetransPct: 1, HiddenProcs: 3},
		t0.Add(2*time.Second), sys1)
	return &tl
}

func meta(source string) Meta {
	return Meta{Version: "v9", Host: "web-1", Kernel: "6.8.0", Source: source, Unprivileged: true,
		Interval: 2 * time.Second, Sysctl: poller.Sysctls{"net.core.somaxconn": "4096"}}
}

func TestStatus(t *testing.T) {
	var clean, warned session.Timeline
	clean.Add(findings.Report{}, t0, nil)
	warned.Add(findings.Report{Findings: []findings.Finding{{ID: "w", Severity: 1}}}, t0, nil)
	cases := map[*session.Timeline]string{
		{}: "UNKNOWN 3", &clean: "OK 0", &warned: "WARNING 1", timeline(): "CRITICAL 2",
	}
	for tl, want := range cases {
		if name, code := Status(tl); fmt.Sprintf("%s %d", name, code) != want {
			t.Errorf("Status = %s %d, want %s", name, code, want)
		}
	}
}

func TestWriteTextLive(t *testing.T) {
	var b bytes.Buffer
	WriteText(&b, timeline(), meta("live"), 0)
	out := b.String()
	for _, want := range []string{
		"CRITICAL: 1 critical, 1 warning — web-1, 2s (2 polls), 12 sockets (5 established), host retransmits 1.00%",
		"process names hidden for 3 sockets",
		"✖ CRIT  nginx (pid 812)",
		"active · seen in 2 of 2 polls, 14:00:00–14:00:02",
		"• 1 socket · 1.7 MB waiting in Send-Q",
		"$ top -H -p 812",
		"sockets: sudo sstui --filter 'signal=ZERO_WIN peer==10.0.0.5'",
		"▲ WARN  a warning",
		"resolved · seen in 1 of 2 polls, 14:00:00",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Index(out, "CRIT  nginx") > strings.Index(out, "WARN  a warning") {
		t.Error("the active critical finding should come first")
	}
}

// TestSocketsCommandForRecording: for a recording, the hint replays it
// rather than opening the live TUI (which would show another machine).
func TestSocketsCommandForRecording(t *testing.T) {
	var b bytes.Buffer
	WriteText(&b, timeline(), meta("/tmp/web 1.jsonl.gz"), 0)
	want := "sockets: sstui replay --filter 'signal=ZERO_WIN peer==10.0.0.5' '/tmp/web 1.jsonl.gz'"
	if !strings.Contains(b.String(), want) {
		t.Errorf("missing %q in:\n%s", want, b.String())
	}
	if strings.Contains(b.String(), "sudo sstui") || !strings.Contains(b.String(), "record with sudo") {
		t.Errorf("a recording's hint shouldn't run sstui live:\n%s", b.String())
	}
}

func TestWriteTextUnknown(t *testing.T) {
	var b bytes.Buffer
	m := meta("live")
	m.LastErr = errExample
	WriteText(&b, &session.Timeline{}, m, 0)
	if got := b.String(); got != "UNKNOWN: ss failed: ss: not found\n" {
		t.Errorf("got %q", got)
	}
}

var errExample = &exampleErr{}

type exampleErr struct{}

func (*exampleErr) Error() string { return "ss: not found" }

func TestWriteJSON(t *testing.T) {
	var b bytes.Buffer
	if err := WriteJSON(&b, timeline(), meta("live")); err != nil {
		t.Fatal(err)
	}
	var out struct {
		Status     string   `json:"status"`
		ExitCode   int      `json:"exit_code"`
		Polls      int      `json:"polls"`
		RetransPct *float64 `json:"retrans_pct"`
		Findings   []struct {
			ID, Severity, LiveFilter string
			Active                   bool
			PollsSeen                int `json:"polls_seen"`
			Actions                  []struct{ Text, Command string }
		} `json:"findings"`
	}
	if err := json.Unmarshal(b.Bytes(), &out); err != nil {
		t.Fatalf("%v\n%s", err, b.String())
	}
	if out.Status != "critical" || out.ExitCode != 2 || out.Polls != 2 || out.RetransPct == nil || *out.RetransPct != 1 {
		t.Errorf("summary = %+v", out)
	}
	if len(out.Findings) != 2 || out.Findings[0].Severity != "critical" || !out.Findings[0].Active ||
		out.Findings[0].PollsSeen != 2 || out.Findings[0].Actions[0].Command != "top -H -p 812" {
		t.Errorf("findings = %+v", out.Findings)
	}

	b.Reset()
	var clean session.Timeline
	clean.Add(findings.Report{RetransPct: -1}, t0, nil)
	WriteJSON(&b, &clean, meta("live"))
	if !strings.Contains(b.String(), `"findings": []`) || strings.Contains(b.String(), "retrans_pct") {
		t.Errorf("a clean check should list no findings as [] and omit an unknown retransmit rate:\n%s", b.String())
	}
}

func TestWriteMarkdown(t *testing.T) {
	var b bytes.Buffer
	WriteMarkdown(&b, timeline(), meta("rec.jsonl.gz"))
	out := b.String()
	for _, want := range []string{
		"# Network report: web-1",
		"| Status | **CRITICAL**: 1 critical, 1 warning |",
		"| Host | web-1 (Linux 6.8.0) |",
		"| Source | recording `rec.jsonl.gz` |",
		"| critical | nginx (pid 812) → 10.0.0.5:5432: 1 connection stalled — peer not reading (zero window) | 14:00:00 | 14:00:02 | 2 of 2 | **active** |",
		"| warning | a warning | 14:00:00 | 14:00:00 | 1 of 2 | resolved |",
		"### CRITICAL: nginx (pid 812)",
		"   ```sh\n   top -H -p 812\n   ```",
		"**Affected sockets** (1): `sstui replay --filter 'signal=ZERO_WIN peer==10.0.0.5' 'rec.jsonl.gz'`",
		"| TCP | ⚠ RetransSegs | 20 | 10.0 |",
		"TCP retransmit rate over the window: **1.00%** (20 of 2000 segments).",
		"| net.core.somaxconn | `4096` |",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestWrap(t *testing.T) {
	got := wrap("    • one two three four", 14, 6)
	want := "    • one two\n      three\n      four"
	if got != want {
		t.Errorf("wrap = %q, want %q", got, want)
	}
	if s := "    unchanged when width is 0"; wrap(s, 0, 4) != s {
		t.Error("width 0 should not wrap")
	}
}

func TestFmtDur(t *testing.T) {
	for d, want := range map[time.Duration]string{
		4 * time.Second: "4s", 12*time.Minute + 30*time.Second: "12m30s",
		30 * time.Minute: "30m", 2 * time.Hour: "2h",
	} {
		if got := fmtDur(d); got != want {
			t.Errorf("fmtDur(%v) = %q, want %q", d, got, want)
		}
	}
}
