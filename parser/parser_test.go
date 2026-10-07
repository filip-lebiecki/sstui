package parser

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"sstui/model"
)

// sampleSS is representative `ss -atunpeimOH` output: TCP with a process
// name containing spaces and parens, BBR, retransmits, a zero-window sender
// (persist timer, no snd_wnd), TIME-WAIT, IPv6, a listener, connected and
// unconnected UDP, plus a protocol we don't track.
const sampleSS = `tcp   ESTAB     0      0      10.0.0.1:443   10.0.0.2:51000 users:(("Web Content (x)",pid=4242,fd=7),("nginx",pid=9,fd=3)) timer:(keepalive,50sec,0) uid:1000 ino:111 sk:1 cgroup:/system.slice/cups-lp.service <-> skmem:(r0,rb131072,t0,tb87040,f0,w0,o0,bl0,d2) ts sack bbr wscale:13,10 rto:211 rtt:10.083/0.776 ato:42 mss:1440 pmtu:1500 rcvmss:1440 advmss:1448 cwnd:38 ssthresh:20 bytes_sent:40811 bytes_retrans:1440 bytes_acked:40812 bytes_received:4541 segs_out:45 segs_in:23 data_segs_out:30 data_segs_in:14 bbr:(bw:12345678bps,mrtt:9.5,pacing_gain:2.88672,cwnd_gain:2.88672) send 43415650bps lastsnd:9042 lastrcv:4530 lastack:4530 pacing_rate 86824840bps/90000000bps delivery_rate 20044464bps delivered:31 app_limited busy:31ms rwnd_limited:20ms(64.5%) sndbuf_limited:5ms(16.1%) unacked:3 retrans:1/7 lost:2 dsack_dups:1 reordering:5 reord_seen:2 rcv_rtt:965 rcv_space:14480 rcv_ssthresh:76850 minrtt:9.847 rcv_ooopack:4 snd_wnd:131072 rcv_wnd:77824
tcp   ESTAB     0      1789952 127.0.0.1:60080 127.0.0.1:47123 timer:(persist,2.456sec,0) uid:1000 ino:222 sk:2 <-> skmem:(r0,rb131072,t0,tb2626560,f0,w0,o0,bl0,d0) ts sack cubic wscale:0,10 rto:206 backoff:4 rtt:5.106/10.154 mss:2048 cwnd:10 bytes_sent:4096 bytes_acked:4097 segs_out:8 segs_in:6 busy:4002ms rwnd_limited:4002ms(100.0%) notsent:1789952 minrtt:0.031 rcv_wnd:65536
tcp   TIME-WAIT 0      0      [2001:db8::1]:47884 [2606:4700::1]:443 timer:(timewait,50sec,0) ino:0 sk:500a
tcp   LISTEN    0      4096   0.0.0.0:8025   0.0.0.0:*      ino:333 sk:3 cgroup:/system.slice/docker.service <-> skmem:(r0,rb131072,t0,tb16384,f0,w0,o0,bl0,d0) cubic cwnd:10
udp   ESTAB     0      0      10.0.0.1:5353  10.0.0.9:53    ino:444 sk:4 <-> skmem:(r0,rb212992,t0,tb212992,f0,w0,o0,bl0,d7)
udp   UNCONN    0      0      0.0.0.0:68     0.0.0.0:*      ino:555 sk:5 <-> skmem:(r0,rb212992,t0,tb212992,f0,w0,o0,bl0,d0)
mptcp ESTAB     0      0      10.0.0.1:1     10.0.0.2:2
tcp   ESTAB     0`

func TestScanRecordsSample(t *testing.T) {
	conns, drops, err := scanRecords(strings.NewReader(sampleSS), "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	postProcess(conns)
	if drops != 1 {
		t.Errorf("drops = %d, want 1 (the truncated last record; mptcp is skipped, not dropped)", drops)
	}
	if len(conns) != 6 {
		t.Fatalf("got %d conns, want 6", len(conns))
	}
	i := func(p *int) int {
		if p == nil {
			return -1
		}
		return *p
	}
	f := func(p *float64) float64 {
		if p == nil {
			return -1
		}
		return *p
	}
	s := func(p *string) string {
		if p == nil {
			return "<nil>"
		}
		return *p
	}

	c := conns[0]
	checks := []struct {
		name      string
		got, want any
	}{
		{"proto", c.Protocol, "tcp"},
		{"state", c.State, "ESTAB"},
		{"local", c.LocalAddr + "|" + c.LocalPort, "10.0.0.1|443"},
		{"process", s(c.Process), "Web Content (x)"},
		{"pid", i(c.PID), 4242},
		{"uid", i(c.UID), 1000},
		{"inode", s(c.Inode), "111"},
		{"cgroup", s(c.Cgroup), "/system.slice/cups-lp.service"},
		{"timer", s(c.TimerType) + "," + s(c.TimerDur), "keepalive,50sec"},
		{"timer retrans", i(c.TimerRetrans), 0},
		{"skmem rb", i(c.SkmemRB), 131072},
		{"skmem tb", i(c.SkmemTB), 87040},
		{"skmem d", i(c.SkmemD), 2},
		{"congalgo", s(c.CongAlgo), "bbr"},
		{"wscale", [2]int{i(c.WscaleSnd), i(c.WscaleRcv)}, [2]int{13, 10}},
		{"rto", f(c.RTO), 211.0},
		{"rtt", [2]float64{f(c.RTT), f(c.RTTVar)}, [2]float64{10.083, 0.776}},
		{"ato", f(c.ATO), 42.0},
		{"mss/pmtu/rcvmss/advmss", [4]int{i(c.MSS), i(c.PMTU), i(c.RcvMSS), i(c.AdvMSS)}, [4]int{1440, 1500, 1440, 1448}},
		{"cwnd/ssthresh", [2]int{i(c.CWnd), i(c.SSThresh)}, [2]int{38, 20}},
		{"bytes", [4]int{i(c.BytesSent), i(c.BytesRetrans), i(c.BytesAcked), i(c.BytesReceived)}, [4]int{40811, 1440, 40812, 4541}},
		{"segs", [4]int{i(c.SegsOut), i(c.SegsIn), i(c.DataSegsOut), i(c.DataSegsIn)}, [4]int{45, 23, 30, 14}},
		{"bbr", [4]float64{float64(i(c.BBRBW)), f(c.BBRMRTT), f(c.BBRPacingGain), f(c.BBRCWndGain)}, [4]float64{12345678, 9.5, 2.88672, 2.88672}},
		{"send", i(c.SendBPS), 43415650},
		{"pacing (first of pair)", i(c.PacingRate), 86824840},
		{"delivery", i(c.DeliveryRate), 20044464},
		{"last", [3]int{i(c.LastSnd), i(c.LastRcv), i(c.LastAck)}, [3]int{9042, 4530, 4530}},
		{"delivered", i(c.Delivered), 31},
		{"app_limited", c.AppLimited, 1},
		{"busy/rwnd/sndbuf", [3]float64{f(c.BusyMS), f(c.RwndLimitedMS), f(c.SndbufLimitedMS)}, [3]float64{31, 20, 5}},
		{"unacked", i(c.Unacked), 3},
		{"retrans", [2]int{i(c.RetransNow), i(c.Retrans)}, [2]int{1, 7}},
		{"lost", i(c.Lost), 2},
		{"dsack/reordering/reord_seen", [3]int{i(c.DSACKDups), i(c.Reordering), i(c.ReordSeen)}, [3]int{1, 5, 2}},
		{"rcv_rtt", f(c.RcvRTT), 965.0},
		{"rcv_space/ssthresh", [2]int{i(c.RcvSpace), i(c.RcvSSThresh)}, [2]int{14480, 76850}},
		{"minrtt", f(c.MinRTT), 9.847},
		{"rcv_ooopack", i(c.RcvOOOPack), 4},
		{"wnd", [2]int{i(c.SndWnd), i(c.RcvWnd)}, [2]int{131072, 77824}},

		// Zero-window sender: no snd_wnd printed, persist timer armed.
		{"zw timer", s(conns[1].TimerType), "persist"},
		{"zw snd_wnd absent", i(conns[1].SndWnd), -1},
		{"zw sendq", i(conns[1].SendQ), 1789952},
		{"zw bytes_retrans zero-filled", i(conns[1].BytesRetrans), 0},

		{"tw v6 addr", conns[2].LocalAddr + "|" + conns[2].LocalPort, "2001:db8::1|47884"},
		{"tw not zero-filled", i(conns[2].BytesSent), -1},
		{"listen peer port", conns[3].PeerPort, "*"},
		{"udp estab state", conns[4].State, "UDP_ESTAB"},
		{"udp proto", conns[4].Protocol, "udp"},
		{"udp drops", i(conns[4].SkmemD), 7},
		{"udp unconn state", conns[5].State, "UDP_IDLE"},
	}
	for _, ck := range checks {
		if ck.got != ck.want {
			t.Errorf("%s = %v, want %v", ck.name, ck.got, ck.want)
		}
	}
}

func TestMergeResults(t *testing.T) {
	tcp := []*model.Connection{{Protocol: "tcp"}}
	udp := []*model.Connection{{Protocol: "udp"}}
	boom := errors.New("boom")

	if c, err := mergeResults(tcp, nil, udp, nil); err != nil || len(c) != 2 {
		t.Errorf("both ok: got %d conns, err %v", len(c), err)
	}
	if c, err := mergeResults(nil, boom, nil, boom); c != nil || err == nil {
		t.Errorf("both failed: want nil conns and error, got %d, %v", len(c), err)
	}
	if c, err := mergeResults(nil, boom, udp, nil); len(c) != 1 || err == nil || !strings.Contains(err.Error(), "UDP only") {
		t.Errorf("tcp failed: want UDP-only + error, got %d, %v", len(c), err)
	}
	if c, err := mergeResults(tcp, nil, nil, boom); len(c) != 1 || err == nil || !strings.Contains(err.Error(), "TCP only") {
		t.Errorf("udp failed: want TCP-only + error, got %d, %v", len(c), err)
	}
}

// TestScanRecordsFixedProtocol: per-protocol fallback output has no Netid
// column; the protocol is applied from the caller.
func TestScanRecordsFixedProtocol(t *testing.T) {
	in := "UNCONN 0 0 0.0.0.0:68 0.0.0.0:* ino:5 sk:5 <-> skmem:(r0,rb1,t0,tb1,f0,w0,o0,bl0,d0)\n"
	conns, drops, err := scanRecords(strings.NewReader(in), "udp", "", time.Now())
	if err != nil || drops != 0 || len(conns) != 1 || conns[0].Protocol != "udp" || conns[0].LocalPort != "68" {
		t.Fatalf("got %d conns (drops %d, err %v)", len(conns), drops, err)
	}
}

func BenchmarkParseLine(b *testing.B) {
	line := strings.SplitN(sampleSS, "\n", 2)[0]
	line = line[strings.Index(line, "ESTAB"):]
	b.ReportAllocs()
	for b.Loop() {
		ParseLine(line)
	}
}

// TestParseLineLimitedMetrics verifies the bottleneck-attribution fields
// (rwnd_limited / sndbuf_limited) are extracted from a representative ss -i line.
func TestParseLineLimitedMetrics(t *testing.T) {
	line := "ESTAB 0 0 10.0.0.1:1234 10.0.0.2:443 " +
		"cubic wscale:7,7 rtt:1.2/0.5 busy:500ms rwnd_limited:1800ms(45.0%) sndbuf_limited:120ms(3.0%)"
	c, err := ParseLine(line)
	if err != nil || c == nil {
		t.Fatalf("ParseLine failed: %v", err)
	}
	if c.RwndLimitedMS == nil || *c.RwndLimitedMS != 1800 {
		t.Errorf("RwndLimitedMS = %v, want 1800", c.RwndLimitedMS)
	}
	if c.SndbufLimitedMS == nil || *c.SndbufLimitedMS != 120 {
		t.Errorf("SndbufLimitedMS = %v, want 120", c.SndbufLimitedMS)
	}
}

// TestRunSSIntegration exercises the real ss binary when present so we catch
// regressions in flag handling / parsing end to end.
func TestRunSSIntegration(t *testing.T) {
	conns, drops, err := RunSS(SSFilter{})
	if err != nil {
		t.Skipf("RunSS returned error (ss unavailable or restricted?): %v", err)
	}
	if drops < 0 {
		t.Errorf("drop count should never be negative, got %d", drops)
	}
	if len(conns) == 0 {
		t.Skip("no sockets reported; nothing to assert")
	}
	for _, c := range conns {
		if c.Protocol != "tcp" && c.Protocol != "udp" {
			t.Errorf("unexpected protocol %q", c.Protocol)
		}
	}
}

// TestParseLineCongAlgoIgnoresIdentity: congestion-control names are bare
// words, so they must only be matched in the tcp_info section — not in a
// process name or cgroup path.
func TestParseLineCongAlgoIgnoresIdentity(t *testing.T) {
	line := `ESTAB 0 0 10.0.0.1:5000 10.0.0.2:443 users:(("reno",pid=1,fd=3)) ino:1 ` +
		`cgroup:/system.slice/cups-lp.service <-> skmem:(r0,rb1,t0,tb1,f0,w0,o0,bl0,d0) ts sack bbr wscale:7,7 rtt:1/1 cwnd:10`
	c, err := ParseLine(line)
	if err != nil || c == nil {
		t.Fatalf("ParseLine failed: %v", err)
	}
	if c.CongAlgo == nil || *c.CongAlgo != "bbr" {
		t.Errorf("CongAlgo = %v, want bbr", c.CongAlgo)
	}
	if c.Process == nil || *c.Process != "reno" {
		t.Errorf("Process = %v, want reno", c.Process)
	}
}

// TestFillOmittedZeros: ss omits bytes_retrans etc. while they're 0. When the
// kernel is known to report the group (some socket shows the sentinel), absent
// counters on tcp_info sockets become 0 so the first loss burst yields a delta.
// Info-less sockets (TIME-WAIT) are left alone.
func TestFillOmittedZeros(t *testing.T) {
	clean, _ := ParseLine("ESTAB 0 0 10.0.0.1:1 10.0.0.2:443 cubic rtt:1/1 cwnd:10 bytes_sent:1000 segs_out:5 busy:3ms")
	clean.Protocol = "tcp"
	tw, _ := ParseLine("TIME-WAIT 0 0 10.0.0.1:2 10.0.0.2:443 timer:(timewait,30sec,0) ino:0")
	tw.Protocol = "tcp"
	fillOmittedZeros([]*model.Connection{clean, tw})

	if clean.BytesRetrans == nil || *clean.BytesRetrans != 0 {
		t.Errorf("BytesRetrans = %v, want 0", clean.BytesRetrans)
	}
	if clean.DSACKDups == nil || clean.RwndLimitedMS == nil || clean.BytesReceived == nil {
		t.Errorf("omitted counters should be zero-filled: dsack=%v rwnd=%v rx=%v",
			clean.DSACKDups, clean.RwndLimitedMS, clean.BytesReceived)
	}
	if clean.RcvOOOPack != nil {
		t.Errorf("no socket showed snd_wnd, so rcv_ooopack support is unknown and must stay nil")
	}
	if tw.BytesRetrans != nil || tw.BytesSent != nil {
		t.Errorf("TIME-WAIT has no tcp_info and must not be zero-filled")
	}
}

// TestFillOmittedZerosOldKernel: a kernel that never reports bytes_sent (pre-
// 4.19) must not get a fake 0 — that would show 0B/s TX and false IDLE.
func TestFillOmittedZerosOldKernel(t *testing.T) {
	c, _ := ParseLine("ESTAB 0 0 10.0.0.1:1 10.0.0.2:443 cubic rtt:1/1 cwnd:10 segs_out:5 bytes_received:10")
	c.Protocol = "tcp"
	fillOmittedZeros([]*model.Connection{c})
	if c.BytesSent != nil || c.BytesRetrans != nil {
		t.Errorf("unsupported group must stay nil, got sent=%v retrans=%v", c.BytesSent, c.BytesRetrans)
	}
}

func TestParseSSFilter(t *testing.T) {
	f, err := ParseSSFilter("state established (dport = :443 or sport = :22)")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"state", "established", "(", "dport", "=", ":443", "or", "sport", "=", ":22", ")"}
	if strings.Join(f.args, " ") != strings.Join(want, " ") {
		t.Errorf("args = %q, want %q", f.args, want)
	}
	if f.impliedState != "ESTAB" {
		t.Errorf("single-state filter should imply ESTAB, got %q", f.impliedState)
	}
	for expr, implied := range map[string]string{
		"state Established":                "ESTAB", // ss accepts any case
		"state established state syn-sent": "",      // two states: ss keeps the column
		"state connected":                  "",      // a group
		"exclude established":              "",
		"dport = :443":                     "",
		"state time-wait":                  "TIME-WAIT",
	} {
		if f, _ := ParseSSFilter(expr); f.impliedState != implied {
			t.Errorf("%q: impliedState = %q, want %q", expr, f.impliedState, implied)
		}
	}
	// Options would reach ss as flags; -K kills sockets.
	for _, bad := range []string{"-K dport = :22", "dport = :22 --kill"} {
		if _, err := ParseSSFilter(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
	if f, _ := ParseSSFilter("   "); f.Active() {
		t.Errorf("blank filter should be inactive")
	}
}

// TestImpliedStateFillsMissingColumn: with a single-state filter ss prints no
// State column; the parser must not shift every field by one.
func TestImpliedStateFillsMissingColumn(t *testing.T) {
	in := "tcp 0      0      10.0.0.1:443 10.0.0.2:51000 ino:9 sk:1 <-> skmem:(r0,rb1,t0,tb1,f0,w0,o0,bl0,d0) cubic cwnd:10\n"
	conns, drops, err := scanRecords(strings.NewReader(in), "", "ESTAB", time.Now())
	if err != nil || drops != 0 || len(conns) != 1 {
		t.Fatalf("got %d conns, %d drops, err %v", len(conns), drops, err)
	}
	c := conns[0]
	if c.State != "ESTAB" || c.LocalPort != "443" || c.PeerAddr != "10.0.0.2" || c.RecvQ == nil || *c.RecvQ != 0 {
		t.Errorf("fields shifted: state=%q local=%s:%s peer=%s", c.State, c.LocalAddr, c.LocalPort, c.PeerAddr)
	}
}

// TestMissingStateColumnDetectedWithoutHint: even when the filter text gives
// no implied state, a record without the State column must not shift fields.
func TestMissingStateColumnDetectedWithoutHint(t *testing.T) {
	in := "tcp 0      0      10.0.0.1:443 10.0.0.2:51000 ino:9 sk:1\n"
	conns, _, _ := scanRecords(strings.NewReader(in), "", "", time.Now())
	if len(conns) != 1 || conns[0].State != "UNKNOWN" || conns[0].LocalPort != "443" {
		t.Fatalf("got %+v", conns)
	}
}

// TestRunSSWithFilter exercises real ss filtering when ss is available.
func TestRunSSWithFilter(t *testing.T) {
	if _, err := exec.LookPath("ss"); err != nil {
		t.Skip("ss not installed")
	}
	if err := CheckSSFilter(mustFilter(t, "dport = :443 andd")); err == nil || !strings.Contains(err.Error(), "andd") {
		t.Errorf("malformed filter should fail with ss's message, got %v", err)
	}
	f := mustFilter(t, "state established")
	if err := CheckSSFilter(f); err != nil {
		t.Skipf("ss unavailable: %v", err)
	}
	conns, drops, err := RunSS(f)
	if err != nil {
		t.Skipf("RunSS: %v", err)
	}
	if drops != 0 {
		t.Errorf("%d records failed to parse with a single-state filter", drops)
	}
	for _, c := range conns {
		if c.State != "ESTAB" && c.State != "UDP_ESTAB" {
			t.Errorf("state established returned a %s socket", c.State)
		}
	}
}

func mustFilter(t *testing.T, expr string) SSFilter {
	t.Helper()
	f, err := ParseSSFilter(expr)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
