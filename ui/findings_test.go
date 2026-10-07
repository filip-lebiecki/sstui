package ui

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"sstui/findings"
	"sstui/model"
)

// TestFindingSignalLiteralsResolve: findings build Live filters from
// hand-written "signal=NAME" literals. A name the parser doesn't know makes
// the finding's Enter fail, and the test above only exercises the findings its
// fixture raises, so check every literal in the findings sources directly.
func TestFindingSignalLiteralsResolve(t *testing.T) {
	files, err := filepath.Glob("../findings/*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no findings sources: %v", err)
	}
	lit := regexp.MustCompile(`signal=([A-Za-z_]+)`)
	n := 0
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(src), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue // doc examples like "signal=A"
			}
			for _, m := range lit.FindAllStringSubmatch(line, -1) {
				n++
				if _, ok := model.ParseSignalType(m[1]); !ok {
					t.Errorf("%s: filter literal signal=%s names no signal", filepath.Base(path), m[1])
				}
			}
		}
	}
	if n == 0 {
		t.Fatal("found no signal= literals; has the filter syntax changed?")
	}
}

// TestFindingFiltersSelectAffectedSockets runs every per-socket rule on one
// busy host and checks each finding's Live filter (through the real filter
// parser) selects exactly the sockets the finding counts.
func TestFindingFiltersSelectAffectedSockets(t *testing.T) {
	i := func(v int) *int { return &v }
	s := func(v string) *string { return &v }
	sig := func(t model.SignalType, sev int) []model.Signal { return []model.Signal{{Type: t, Severity: sev}} }
	mk := func(state, la, lp, pa, pp string, sg []model.Signal) *model.Connection {
		return &model.Connection{Protocol: "tcp", State: state, LocalAddr: la, LocalPort: lp, PeerAddr: pa, PeerPort: pp,
			Process: s("app"), PID: i(10), Signals: sg}
	}
	var conns []*model.Connection
	conns = append(conns, mk("ESTAB", "10.0.0.1", "50001", "10.0.0.5", "5432", sig(model.SignalZeroWindow, 2)))
	conns = append(conns, mk("ESTAB", "10.0.0.1", "50002", "10.0.0.5", "5432", sig(model.SignalZeroWindow, 2)))
	l := mk("LISTEN", "0.0.0.0", "8080", "0.0.0.0", "*", sig(model.SignalListenQueueFull, 2))
	l.RecvQ, l.SendQ = i(128), i(128)
	conns = append(conns, l)
	conns = append(conns, mk("SYN-SENT", "10.0.0.1", "50003", "10.9.9.9", "443", sig(model.SignalSynStall, 1)))
	conns = append(conns, mk("ESTAB", "10.0.0.1", "50004", "203.0.113.7", "443", sig(model.SignalRTOFiring, 2)))
	conns = append(conns, mk("ESTAB", "10.0.0.1", "50005", "203.0.113.8", "443", sig(model.SignalReordering, 1)))
	conns = append(conns, mk("ESTAB", "10.0.0.1", "50006", "203.0.113.9", "443", sig(model.SignalPMTUMismatch, 1)))
	for p := 0; p < 25; p++ {
		cw := mk("CLOSE-WAIT", "10.0.0.1", strconv.Itoa(8000+p), "10.0.0.20", strconv.Itoa(40000+p), sig(model.SignalCloseWaitLeak, 1))
		cw.PID = i(77)
		conns = append(conns, cw)
	}
	for p := 0; p < 5; p++ {
		conns = append(conns, mk("TIME-WAIT", "10.0.0.1", strconv.Itoa(51000+p), "10.0.0.30", "80", sig(model.SignalTimeWaitStorm, 1)))
	}
	rx := mk("ESTAB", "10.0.0.1", "443", "198.51.100.4", "51000", sig(model.SignalInboundLoss, 1))
	rx.DeltaRcvOOOPack, rx.DeltaDataSegsIn = i(50), i(1000)
	conns = append(conns, rx)
	// A slow reader (drops, no loss) and loss-recovery drops on the same
	// process: the backlog filter must select only the former.
	slow := mk("ESTAB", "10.0.0.1", "9000", "10.0.0.40", "51000", sig(model.SignalSocketDrops, 1))
	slow.DeltaSkmemD = i(3)
	lossDrop := mk("ESTAB", "10.0.0.1", "9001", "198.51.100.4", "51001",
		[]model.Signal{{Type: model.SignalSocketDrops, Severity: 1}, {Type: model.SignalInboundLoss, Severity: 1}})
	lossDrop.DeltaSkmemD, lossDrop.DeltaRcvOOOPack, lossDrop.DeltaDataSegsIn = i(2), i(40), i(800)
	conns = append(conns, slow, lossDrop)
	// Healthy noise that no filter should pick up.
	conns = append(conns, mk("ESTAB", "10.0.0.1", "50100", "10.0.0.5", "5432", nil))

	rep := findings.Analyze(findings.Input{Conns: conns})
	if len(rep.Findings) < 7 {
		t.Fatalf("expected findings from every rule, got %d", len(rep.Findings))
	}
	for _, f := range rep.Findings {
		if f.Filter == "" {
			continue
		}
		flt := &Filter{HideListen: !f.ShowListen}
		if err := flt.SetQuery(f.Filter); err != nil {
			t.Errorf("%s: filter %q rejected: %v", f.ID, f.Filter, err)
			continue
		}
		n := 0
		for _, c := range conns {
			if flt.Matches(c) {
				n++
			}
		}
		if n != f.Count {
			t.Errorf("%s: filter %q matches %d sockets, finding counts %d", f.ID, f.Filter, n, f.Count)
		}
	}
}

func TestRenderFindingsKeepsSelectionVisible(t *testing.T) {
	var fs []findings.Finding
	for n := 0; n < 30; n++ {
		fs = append(fs, findings.Finding{ID: strconv.Itoa(n), Severity: 1, Title: "finding " + strconv.Itoa(n),
			Detail: "detail", Evidence: []string{"e"}, Actions: []findings.Action{{Text: "do", Command: "cmd"}}})
	}
	out := RenderFindings(findings.Report{Findings: fs}, 25, 100, 15, time.Now(), "", "")
	if !strings.Contains(out, "finding 25") {
		t.Errorf("selected finding should be scrolled into view:\n%s", out)
	}
	if lines := strings.Count(out, "\n") + 1; lines > 15 {
		t.Errorf("rendered %d lines into a 15-line area", lines)
	}
}

func TestRenderFindingsNotRootNote(t *testing.T) {
	var fs []findings.Finding
	for n := 0; n < 30; n++ {
		fs = append(fs, findings.Finding{ID: strconv.Itoa(n), Severity: 1, Title: "finding " + strconv.Itoa(n)})
	}
	rep := findings.Report{Findings: fs, HiddenProcs: 7, SSFilter: "dport = :443"}
	out := RenderFindings(rep, 0, 200, 15, time.Now(), "polling failed", "as of 14:02:11 (paused)")
	if !strings.Contains(out, "process names hidden for 7 sockets") || !strings.Contains(out, "sudo") {
		t.Errorf("missing not-root note:\n%s", out)
	}
	if lines := strings.Count(out, "\n") + 1; lines > 15 {
		t.Errorf("rendered %d lines into a 15-line area", lines)
	}
	if out := RenderFindings(findings.Report{Findings: fs}, 0, 200, 15, time.Now(), "", ""); strings.Contains(out, "sudo") {
		t.Errorf("note shown with no hidden processes:\n%s", out)
	}
}
