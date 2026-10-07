package session

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sstui/findings"
	"sstui/model"
	"sstui/poller"
)

// stalled is a socket whose peer advertises a zero window (persist timer).
func stalled() *model.Connection {
	persist, dur := "persist", "2sec"
	return &model.Connection{Protocol: "tcp", State: "ESTAB",
		LocalAddr: "10.0.0.1", LocalPort: "50001", PeerAddr: "10.0.0.5", PeerPort: "5432",
		TimerType: &persist, TimerDur: &dur}
}

func healthy() *model.Connection {
	return &model.Connection{Protocol: "tcp", State: "ESTAB",
		LocalAddr: "10.0.0.1", LocalPort: "50002", PeerAddr: "10.0.0.6", PeerPort: "443"}
}

var t0 = time.Date(2026, 10, 7, 14, 0, 0, 0, time.UTC)

func at(i int) time.Time { return t0.Add(time.Duration(i) * 2 * time.Second) }

func TestRecordingRoundTrip(t *testing.T) {
	for _, name := range []string{"rec.jsonl", "rec.jsonl.gz"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name)
			h := NewHeader("v9", "dport = :443", true)
			rec, err := Create(path, h)
			if err != nil {
				t.Fatal(err)
			}
			sysctl := poller.Sysctls{"net.core.somaxconn": "4096"}
			changed := poller.Sysctls{"net.core.somaxconn": "8192"}
			polls := []*Poll{
				{Time: at(0), Conns: []*model.Connection{stalled(), healthy()}, Sysctl: sysctl,
					Sys: &poller.SysStat{Counters: map[string]int64{"Tcp:OutSegs": 10}}},
				{Time: at(1), Conns: []*model.Connection{stalled()}, Sysctl: sysctl, Drops: 2},
				{Time: at(2), Err: errors.New("ss: exit status 1"), Sysctl: changed},
			}
			for _, p := range polls {
				if err := rec.Write(p); err != nil {
					t.Fatal(err)
				}
			}
			if err := rec.Close(); err != nil {
				t.Fatal(err)
			}
			if err := rec.Close(); err != nil {
				t.Errorf("second Close: %v", err)
			}
			if err := rec.Write(polls[0]); err == nil {
				t.Error("Write after Close should fail")
			}
			if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
				t.Errorf("recording mode = %v, want 0600 (it names every process)", st.Mode().Perm())
			}

			r, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			if r.Header.Version != "v9" || r.Header.SSFilter != "dport = :443" || !r.Header.Unprivileged || r.Header.Interval != poller.PollInterval {
				t.Errorf("header = %+v", r.Header)
			}
			var got []*Poll
			for {
				p, err := r.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				got = append(got, p)
			}
			if len(got) != 3 || r.Unclosed {
				t.Fatalf("read %d polls (unclosed=%v), want 3 cleanly", len(got), r.Unclosed)
			}
			if !got[0].Time.Equal(at(0)) || len(got[0].Conns) != 2 || got[0].Conns[0].TimerType == nil {
				t.Errorf("poll 0 = %+v", got[0])
			}
			if v, _ := got[0].Sys.Get("Tcp:OutSegs"); v != 10 {
				t.Errorf("sys counters lost: %v", got[0].Sys)
			}
			if got[1].Drops != 2 || got[1].Sys != nil {
				t.Errorf("poll 1 = %+v", got[1])
			}
			// Kernel settings are stored only when they change.
			if got[0].Sysctl["net.core.somaxconn"] != "4096" || got[1].Sysctl != nil || got[2].Sysctl["net.core.somaxconn"] != "8192" {
				t.Errorf("sysctls = %v / %v / %v", got[0].Sysctl, got[1].Sysctl, got[2].Sysctl)
			}
			if got[2].Err == nil || got[2].Err.Error() != "ss: exit status 1" || len(got[2].Conns) != 0 {
				t.Errorf("poll 2 = %+v", got[2])
			}
		})
	}
}

// TestRecordingNotClosed: a recorder killed before Close leaves a gzip
// stream with no trailer, or a plain file with a cut-off last line. Every
// complete poll is still read, and the reader says the file wasn't closed.
func TestRecordingNotClosed(t *testing.T) {
	dir := t.TempDir()
	write := func(name string) string {
		path := filepath.Join(dir, name)
		rec, err := Create(path, NewHeader("v", "", false))
		if err != nil {
			t.Fatal(err)
		}
		for i := range 2 {
			if err := rec.Write(&Poll{Time: at(i), Conns: []*model.Connection{healthy()}}); err != nil {
				t.Fatal(err)
			}
		}
		return path // left open: each Write is flushed through
	}
	readAll := func(path string) (int, bool) {
		r, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		n := 0
		for {
			if _, err := r.Next(); err == io.EOF {
				return n, r.Unclosed
			} else if err != nil {
				t.Fatal(err)
			}
			n++
		}
	}

	if n, unclosed := readAll(write("killed.jsonl.gz")); n != 2 || !unclosed {
		t.Errorf("gzip without trailer: %d polls, unclosed=%v; want 2, true", n, unclosed)
	}

	plain := write("cut.jsonl")
	data, _ := os.ReadFile(plain)
	os.WriteFile(plain, data[:len(data)-20], 0o600)
	if n, unclosed := readAll(plain); n != 1 || !unclosed {
		t.Errorf("cut-off line: %d polls, unclosed=%v; want 1, true", n, unclosed)
	}
}

func TestOpenRejectsOtherFiles(t *testing.T) {
	dir := t.TempDir()
	export := filepath.Join(dir, "export.json")
	os.WriteFile(export, []byte(`{"exported_at":"2026-10-07T14:00:00Z","snapshots":[]}`), 0o600)
	if _, err := Open(export); err == nil || !strings.Contains(err.Error(), "not an sstui recording") {
		t.Errorf("JSON export: err = %v", err)
	}
	future := filepath.Join(dir, "future.jsonl")
	os.WriteFile(future, []byte(`{"sstui_recording":99,"interval_ns":2000000000}`+"\n"), 0o600)
	if _, err := Open(future); err == nil || !strings.Contains(err.Error(), "upgrade sstui") {
		t.Errorf("newer format: err = %v", err)
	}
}

func TestIngestKeepsReportPerSnapshot(t *testing.T) {
	s := New("", false)
	if !s.Ingest(&Poll{Time: at(0), Conns: []*model.Connection{stalled(), healthy()}}) {
		t.Fatal("first poll not ingested")
	}
	if !s.Ingest(&Poll{Time: at(1), Conns: []*model.Connection{healthy()}}) {
		t.Fatal("second poll not ingested")
	}
	// A poll where ss failed outright keeps the last good snapshot.
	if s.Ingest(&Poll{Time: at(2), Err: errors.New("boom")}) {
		t.Error("failed poll should not produce a snapshot")
	}
	if s.LastErr == nil || s.Buf.Count() != 2 || !s.ReportAt.Equal(at(1)) {
		t.Errorf("after failure: err=%v snapshots=%d reportAt=%v", s.LastErr, s.Buf.Count(), s.ReportAt)
	}

	old, ok := s.ReportFor(at(0))
	if !ok || len(old.Findings) != 1 || !strings.HasPrefix(old.Findings[0].ID, "zero_window") {
		t.Errorf("report at the first poll should hold the zero-window finding: %+v", old.Findings)
	}
	if now, ok := s.ReportFor(at(1)); !ok || len(now.Findings) != 0 {
		t.Errorf("report at the second poll should be clean: %+v", now.Findings)
	}
	if _, ok := s.ReportFor(at(5)); ok {
		t.Error("no report should exist for a time with no snapshot")
	}
	if snap := s.Buf.GetLatest(); !snap.Timestamp.Equal(at(1)) {
		t.Errorf("snapshot should carry the poll's time, got %v", snap.Timestamp)
	}
}

func TestTimeline(t *testing.T) {
	warn := findings.Finding{ID: "w", Severity: 1, Title: "warned"}
	crit := findings.Finding{ID: "c", Severity: 2, Title: "crit"}
	critLater := findings.Finding{ID: "c", Severity: 1, Title: "crit, now milder"}
	var tl Timeline
	tl.Add(findings.Report{Findings: []findings.Finding{crit}}, at(0), nil)
	tl.Add(findings.Report{Findings: []findings.Finding{critLater, warn}}, at(1), nil)
	tl.Add(findings.Report{Findings: []findings.Finding{warn}}, at(2), nil)

	if tl.Analyses != 3 || !tl.Start.Equal(at(0)) || !tl.End.Equal(at(2)) {
		t.Errorf("window = %v..%v over %d", tl.Start, tl.End, tl.Analyses)
	}
	if tl.Worst() != 2 || tl.Count(2) != 1 || tl.Count(1) != 1 {
		t.Errorf("worst=%d crit=%d warn=%d", tl.Worst(), tl.Count(2), tl.Count(1))
	}
	r := tl.Ranked()
	// Still active outranks resolved, even when the resolved one was worse.
	if len(r) != 2 || r[0].Finding.ID != "w" || !r[0].Active || r[1].Active {
		t.Fatalf("ranking = %+v", r)
	}
	c := r[1]
	if c.Worst != 2 || c.Polls != 2 || c.Finding.Title != "crit, now milder" || !c.First.Equal(at(0)) || !c.Last.Equal(at(1)) {
		t.Errorf("crit occurrence = %+v", c)
	}
}
