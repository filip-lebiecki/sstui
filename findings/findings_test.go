package findings

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"sstui/classifier"
	"sstui/model"
	"sstui/poller"
)

func ip(v int) *int         { return &v }
func sp(v string) *string   { return &v }
func fp(v float64) *float64 { return &v }

func conn(state, laddr, lport, paddr, pport string, sigs ...model.Signal) *model.Connection {
	return &model.Connection{Protocol: "tcp", State: state,
		LocalAddr: laddr, LocalPort: lport, PeerAddr: paddr, PeerPort: pport, Signals: sigs}
}

func sig(t model.SignalType, sev int) model.Signal { return model.Signal{Type: t, Severity: sev} }

func byID(r Report, prefix string) *Finding {
	for i := range r.Findings {
		if strings.HasPrefix(r.Findings[i].ID, prefix) {
			return &r.Findings[i]
		}
	}
	return nil
}

func hasCommand(f *Finding, sub string) bool {
	for _, a := range f.Actions {
		if strings.Contains(a.Command, sub) {
			return true
		}
	}
	return false
}

func hasText(lines []string, sub string) bool {
	for _, l := range lines {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

func TestNoFindingsOnHealthyHost(t *testing.T) {
	r := Analyze(Input{Conns: []*model.Connection{
		conn("ESTAB", "10.0.0.1", "40000", "10.0.0.2", "443", sig(model.SignalIdle, 0)),
	}})
	if len(r.Findings) != 0 {
		t.Fatalf("healthy host should have no findings, got %+v", r.Findings)
	}
	if r.Sockets != 1 || r.Estab != 1 || r.RetransPct != -1 {
		t.Errorf("summary = %+v", r)
	}
}

// Zero-window senders are grouped per (process, peer); when the receiver is
// on this host it's named, and the filter selects exactly the stalled sockets.
func TestZeroWindowNamesLocalReceiver(t *testing.T) {
	var conns []*model.Connection
	for _, port := range []string{"50001", "50002", "50003"} {
		c := conn("ESTAB", "127.0.0.1", port, "127.0.0.1", "5432", sig(model.SignalZeroWindow, 2))
		c.Process, c.PID, c.SendQ = sp("app"), ip(100), ip(1<<20)
		conns = append(conns, c)
		rcv := conn("ESTAB", "127.0.0.1", "5432", "127.0.0.1", port, sig(model.SignalRecvBufferPressure, 2))
		rcv.Process, rcv.PID, rcv.RecvQ = sp("postgres"), ip(200), ip(4096)
		conns = append(conns, rcv)
	}
	r := Analyze(Input{Conns: conns})
	f := byID(r, "zero_window|")
	if f == nil {
		t.Fatal("expected a zero-window finding")
	}
	if f.Severity != 2 || f.Count != 3 {
		t.Errorf("severity/count = %d/%d, want 2/3", f.Severity, f.Count)
	}
	if !hasText(f.Evidence, "3.0 MB waiting in Send-Q") || !hasText(f.Evidence, "receiver is postgres (pid 200)") {
		t.Errorf("evidence = %q", f.Evidence)
	}
	if !hasCommand(f, "top -H -p 200") {
		t.Errorf("should suggest inspecting the receiver's threads: %+v", f.Actions)
	}
	if f.Filter != "signal=ZERO_WIN pid=100 peer==127.0.0.1 dport=5432" {
		t.Errorf("filter = %q", f.Filter)
	}
	// The receiving process gets its own "not reading" finding.
	g := byID(r, "recv_backlog|pid:200")
	if g == nil || g.Count != 3 {
		t.Fatalf("expected recv-backlog finding for postgres, got %+v", g)
	}
	if !hasText(g.Evidence, "stalling 3 local senders") {
		t.Errorf("receiver finding should link to the stalled senders: %q", g.Evidence)
	}
	if r.Findings[0].ID != f.ID {
		t.Errorf("at equal severity and count, the zero-window root cause should rank first, got %s", r.Findings[0].ID)
	}
}

// The accept-queue finding distinguishes somaxconn capping the backlog from
// an app that chose a small backlog itself.
func TestListenQueueBacklogSource(t *testing.T) {
	mk := func(sq int) []*model.Connection {
		c := conn("LISTEN", "0.0.0.0", "8080", "0.0.0.0", "*", sig(model.SignalListenQueueFull, 2))
		c.RecvQ, c.SendQ, c.Process, c.PID = ip(sq), ip(sq), sp("nginx"), ip(7)
		return []*model.Connection{c}
	}
	sysctl := poller.Sysctls{"net.core.somaxconn": "4096"}

	capped := byID(Analyze(Input{Conns: mk(4096), Sysctl: sysctl}), "listen_queue|")
	if capped == nil || !hasCommand(capped, "net.core.somaxconn=8192") || !capped.ShowListen {
		t.Errorf("somaxconn-capped backlog should suggest raising somaxconn: %+v", capped)
	}
	appChosen := byID(Analyze(Input{Conns: mk(511), Sysctl: sysctl}), "listen_queue|")
	if appChosen == nil || hasCommand(appChosen, "somaxconn") || !hasText(appChosen.Evidence, "app asked for a backlog of 511") {
		t.Errorf("app-chosen backlog should point at the app config, not somaxconn: %+v", appChosen)
	}
}

// Loss toward one peer is that peer's problem; loss toward many peers at
// once is this host's.
func TestPathLossLocalVsRemote(t *testing.T) {
	one := []*model.Connection{
		conn("ESTAB", "10.0.0.1", "1", "203.0.113.9", "443", sig(model.SignalRTOFiring, 2)),
		conn("ESTAB", "10.0.0.1", "2", "198.51.100.1", "443"),
	}
	r := Analyze(Input{Conns: one})
	if f := byID(r, "loss|203.0.113.9"); f == nil || !hasCommand(f, "mtr -rwzbc 100 203.0.113.9") {
		t.Errorf("single-peer loss should get a per-peer finding with mtr: %+v", r.Findings)
	}

	var many []*model.Connection
	for i := 0; i < 6; i++ {
		many = append(many, conn("ESTAB", "10.0.0.1", "1", "203.0.113."+strconv.Itoa(i+1), "443", sig(model.SignalPathLoss, 1)))
	}
	r = Analyze(Input{Conns: many})
	if f := byID(r, "loss_local"); f == nil || f.Count != 6 || !hasCommand(f, "ip -s link") {
		t.Errorf("loss toward many peers should be one local finding: %+v", r.Findings)
	}
	if byID(r, "loss|") != nil {
		t.Errorf("per-peer loss findings should be replaced by the local one")
	}
}

func TestPMTUBlackHole(t *testing.T) {
	ip := func(v int) *int { return &v }
	hung := func(peer string, delivered, mss int) *model.Connection {
		c := conn("ESTAB", "10.0.0.1", "1", peer, "443", sig(model.SignalRTOFiring, 2))
		c.Delivered, c.Unacked, c.MSS, c.TimerRetrans = ip(delivered), ip(11), ip(mss), ip(5)
		return c
	}
	r := Analyze(Input{
		Conns:  []*model.Connection{hung("203.0.113.9", 1, 1448), conn("ESTAB", "10.0.0.1", "2", "198.51.100.1", "443")},
		Sysctl: poller.Sysctls{"net.ipv4.tcp_mtu_probing": "0"},
	})
	f := byID(r, "pmtu_blackhole|203.0.113.9")
	if f == nil || !hasCommand(f, "ping -M do -c 3 -s 1472 203.0.113.9") || !hasCommand(f, "tcp_mtu_probing=1") {
		t.Fatalf("hung after the handshake should be a black-hole finding with a DF ping: %+v", r.Findings)
	}
	if byID(r, "loss|") != nil {
		t.Errorf("the black-hole connection shouldn't also be reported as loss: %+v", r.Findings)
	}

	// Many unrelated peers at once: this host's own MTU.
	var many []*model.Connection
	for i := 1; i <= 6; i++ {
		many = append(many, hung("203.0.113."+strconv.Itoa(i), 1, 1448))
	}
	r = Analyze(Input{Conns: many})
	if f := byID(r, "pmtu_blackhole_local"); f == nil || f.Count != 6 || !hasCommand(f, "ip link") || byID(r, "pmtu_blackhole|") != nil {
		t.Errorf("black holes toward many peers should be one local finding: %+v", r.Findings)
	}

	// Data acknowledged before the stall, or segments small enough for any
	// path: plain loss.
	for _, c := range []*model.Connection{hung("203.0.113.9", 500, 1448), hung("203.0.113.9", 1, 536)} {
		r := Analyze(Input{Conns: []*model.Connection{c}})
		if byID(r, "pmtu_blackhole") != nil || byID(r, "loss|203.0.113.9") == nil {
			t.Errorf("delivered=%d mss=%d should be loss, not a black hole: %+v", *c.Delivered, *c.MSS, r.Findings)
		}
	}
}

func TestTimeWaitSuggestsTwReuse(t *testing.T) {
	var conns []*model.Connection
	for i := 0; i < 3; i++ {
		conns = append(conns, conn("TIME-WAIT", "10.0.0.1", strconv.Itoa(40000+i), "10.0.0.9", "80", sig(model.SignalTimeWaitStorm, 1)))
	}
	f := byID(Analyze(Input{Conns: conns, Sysctl: poller.Sysctls{"net.ipv4.tcp_tw_reuse": "2"}}), "time_wait|")
	if f == nil || !hasCommand(f, "tcp_tw_reuse=1") {
		t.Fatalf("expected tw_reuse suggestion: %+v", f)
	}
	if !strings.Contains(f.Actions[1].Text, "loopback only") {
		t.Errorf("should explain the current value 2: %q", f.Actions[1].Text)
	}
	if f2 := byID(Analyze(Input{Conns: conns, Sysctl: poller.Sysctls{"net.ipv4.tcp_tw_reuse": "1"}}), "time_wait|"); hasCommand(f2, "tcp_tw_reuse") {
		t.Errorf("tw_reuse already 1: shouldn't suggest it again")
	}
}

func TestEphemeralPorts(t *testing.T) {
	var conns []*model.Connection
	for p := 40000; p < 40090; p++ {
		conns = append(conns, conn("ESTAB", "10.0.0.1", strconv.Itoa(p), "10.0.0.9", "443"))
	}
	f := byID(Analyze(Input{Conns: conns, Sysctl: poller.Sysctls{"net.ipv4.ip_local_port_range": "40000 40099"}}), "ephemeral_ports")
	if f == nil || f.Severity != 2 || f.Count != 90 {
		t.Fatalf("90/100 ports used should be crit: %+v", f)
	}
}

func sysPair(prev, cur map[string]int64) (*poller.SysStat, *poller.SysStat) {
	return &poller.SysStat{Counters: cur}, &poller.SysStat{Counters: prev}
}

// A listener's drops belong to that listener's accept-queue finding (even
// when the queue isn't full at the moment of the poll), never to "isn't
// reading fast enough", and the host-wide overflow finding folds into it.
// The host counters say what the drops were: accept-queue overflows,
// other refusals (ListenDrops only), or neither (stray handshake segments
// discarded, e.g. under packet loss), which isn't reported.
func TestListenerDropsAreAcceptQueueOverflow(t *testing.T) {
	sys, prev := sysPair(map[string]int64{"TcpExt:ListenOverflows": 0}, map[string]int64{"TcpExt:ListenOverflows": 20})
	lst := conn("LISTEN", "0.0.0.0", "80", "0.0.0.0", "*", sig(model.SignalSocketDrops, 2))
	lst.RecvQ, lst.SendQ, lst.DeltaSkmemD = ip(2), ip(511), ip(21)
	lst.Process, lst.PID = sp("nginx"), ip(7)
	r := Analyze(Input{Conns: []*model.Connection{lst}, Sys: sys, SysPrev: prev, Interval: 2 * time.Second})

	f := byID(r, "listen_queue|")
	if f == nil || f.Severity != 2 || !strings.Contains(f.Title, "overflowed") || !hasText(f.Evidence, "21 connection attempts dropped at this listener") {
		t.Fatalf("listener drops should be an accept-queue overflow on that listener: %+v", r.Findings)
	}
	if byID(r, "recv_backlog|") != nil {
		t.Errorf("a listener isn't a slow reader: %+v", r.Findings)
	}
	if byID(r, "listen_overflow_host") != nil {
		t.Errorf("the host-wide overflow finding should fold into the listener's")
	}

	// Refusals without accept-queue overflows aren't blamed on accept().
	sys, prev = sysPair(map[string]int64{"TcpExt:ListenDrops": 0, "TcpExt:ListenOverflows": 0},
		map[string]int64{"TcpExt:ListenDrops": 20, "TcpExt:ListenOverflows": 0})
	r = Analyze(Input{Conns: []*model.Connection{lst}, Sys: sys, SysPrev: prev, Interval: 2 * time.Second})
	if f := byID(r, "listen_queue|"); f == nil || !strings.Contains(f.Title, "is dropping connection attempts") {
		t.Errorf("ListenDrops without ListenOverflows shouldn't claim the accept queue overflowed: %+v", r.Findings)
	}
	// Neither counter: stray segments discarded at the listener, not a problem.
	if r := Analyze(Input{Conns: []*model.Connection{lst}}); byID(r, "listen_queue|") != nil || byID(r, "recv_backlog|") != nil {
		t.Errorf("drops the host didn't count as refusals shouldn't be reported: %+v", r.Findings)
	}

	// SO_REUSEPORT: describe the full listener on the port, whichever comes first.
	full := conn("LISTEN", "0.0.0.0", "80", "0.0.0.0", "*", sig(model.SignalListenQueueFull, 2))
	full.RecvQ, full.SendQ = ip(512), ip(511)
	f = byID(Analyze(Input{Conns: []*model.Connection{lst, full}}), "listen_queue|")
	if f == nil || !strings.Contains(f.Title, "Accept queue full") || !hasText(f.Evidence, "queue 512 / 511") || f.Count != 2 {
		t.Errorf("a full reuseport listener should set the title and queue evidence: %+v", f)
	}
}

// Kernel ListenOverflows with no currently-full listener is a burst problem
// (host finding); with a full listener it folds into that finding instead.
func TestListenOverflowHost(t *testing.T) {
	sys, prev := sysPair(map[string]int64{"TcpExt:ListenOverflows": 0}, map[string]int64{"TcpExt:ListenOverflows": 20})
	lst := conn("LISTEN", "0.0.0.0", "80", "0.0.0.0", "*")
	lst.RecvQ, lst.SendQ = ip(3), ip(511)
	in := Input{Conns: []*model.Connection{lst}, Sys: sys, SysPrev: prev, Interval: 2 * time.Second}

	f := byID(Analyze(in), "listen_overflow_host")
	if f == nil || !hasText(f.Evidence, "ListenOverflows +10.0/s") || !hasText(f.Evidence, ":80") {
		t.Fatalf("expected burst-overflow host finding naming :80: %+v", f)
	}

	lst.Signals = []model.Signal{sig(model.SignalListenQueueFull, 2)}
	r := Analyze(in)
	if byID(r, "listen_overflow_host") != nil {
		t.Errorf("with a full listener, the host finding should fold into it")
	}
	if g := byID(r, "listen_queue|"); g == nil || !hasText(g.Evidence, "ListenOverflows +10.0/s") {
		t.Errorf("listener finding should carry the kernel counter: %+v", g)
	}
}

func TestRetransHostNeedsTraffic(t *testing.T) {
	sys, prev := sysPair(
		map[string]int64{"Tcp:OutSegs": 0, "Tcp:RetransSegs": 0},
		map[string]int64{"Tcp:OutSegs": 10000, "Tcp:RetransSegs": 500})
	r := Analyze(Input{Sys: sys, SysPrev: prev, SysSlots: []*poller.SysStat{prev, sys}, Interval: 2 * time.Second})
	if f := byID(r, "retrans_host"); f == nil || f.Severity != 1 || r.RetransPct != 5 {
		t.Errorf("5%% retransmits over 10k segs should warn: %+v (pct %.1f)", f, r.RetransPct)
	} else if !hasText(f.Evidence, "500 of 10000 TCP segments retransmitted over the last 12s, in 1 of 1 slots") {
		t.Errorf("evidence should cover the same window as the verdict: %q", f.Evidence)
	}
	sys, prev = sysPair(
		map[string]int64{"Tcp:OutSegs": 0, "Tcp:RetransSegs": 0},
		map[string]int64{"Tcp:OutSegs": 100, "Tcp:RetransSegs": 50})
	if byID(Analyze(Input{Sys: sys, SysPrev: prev, SysSlots: []*poller.SysStat{prev, sys}, Interval: 2 * time.Second}), "retrans_host") != nil {
		t.Errorf("100 segments is too little traffic for a host-wide verdict")
	}
}

func TestRankingCritFirst(t *testing.T) {
	r := Analyze(Input{Conns: []*model.Connection{
		conn("ESTAB", "10.0.0.1", "1", "10.0.0.2", "443", sig(model.SignalReordering, 1)),
		conn("SYN-SENT", "10.0.0.1", "2", "10.0.0.3", "443", sig(model.SignalSynStall, 2)),
	}})
	if len(r.Findings) != 2 || r.Findings[0].Severity != 2 || r.Crit() != 1 || r.Warn() != 1 {
		t.Errorf("crit should rank first: %+v", r.Findings)
	}
}

func TestRwndLimitedWindowScaling(t *testing.T) {
	c := conn("ESTAB", "10.0.0.1", "1", "10.0.0.2", "443", model.Signal{Type: model.SignalRwndLimited, Severity: 2, Value: "90% of poll"})
	c.SndWnd, c.RTT = ip(65535), fp(80)
	f := byID(Analyze(Input{Conns: []*model.Connection{c}, Sysctl: poller.Sysctls{"net.ipv4.tcp_window_scaling": "0"}}), "rwnd|")
	if f == nil {
		t.Fatal("expected rwnd finding")
	}
	if !hasText(f.Evidence, "window scaling wasn't negotiated") || !hasText(f.Evidence, "advertises 64 KB; at 80 ms RTT that caps a connection at ≈800 KB/s") {
		t.Errorf("evidence = %q", f.Evidence)
	}
	if !hasCommand(f, "tcp_window_scaling=1") {
		t.Errorf("should suggest enabling window scaling: %+v", f.Actions)
	}
}

// TestRecvBacklogTCPBufferAdvice: raising tcp_rmem max only helps a TCP
// socket whose buffer autotuning has already grown to it.
func TestRecvBacklogTCPBufferAdvice(t *testing.T) {
	rmem := poller.Sysctls{"net.ipv4.tcp_rmem": "4096 131072 6291456"}
	for _, tt := range []struct {
		rb   int
		want bool
	}{{131_072, false}, {6_291_456, true}} {
		c := conn("ESTAB", "10.0.0.1", "5001", "10.0.0.2", "40000", sig(model.SignalRecvBufferPressure, 2))
		c.Protocol, c.PID, c.RecvQ, c.SkmemRB = "tcp", ip(9), ip(70_000), ip(tt.rb)
		f := byID(Analyze(Input{Conns: []*model.Connection{c}, Sysctl: rmem}), "recv_backlog|pid:9")
		if f == nil || hasCommand(f, "tcp_rmem") != tt.want {
			t.Errorf("rb %d: tcp_rmem advice %v, want %v: %+v", tt.rb, f != nil && hasCommand(f, "tcp_rmem"), tt.want, f)
		}
	}
}

// TestSndbufLimitedCause: a full buffer below tcp_wmem max means the app
// fixed its size (SO_SNDBUF); one at the max needs a higher max.
func TestSndbufLimitedCause(t *testing.T) {
	wmem := poller.Sysctls{"net.ipv4.tcp_wmem": "4096 16384 4194304", "net.core.wmem_max": "212992"}
	mk := func(tb int) *model.Connection {
		c := conn("ESTAB", "10.0.0.1", "40000", "10.0.0.2", "5001", model.Signal{Type: model.SignalSndbufLimited, Severity: 1, Value: "buffer full, all 70 KB in flight"})
		c.Process, c.PID, c.SendQ, c.SkmemTB, c.RTT = sp("uploader"), ip(5), ip(72_000), ip(tb), fp(40)
		return c
	}
	f := byID(Analyze(Input{Conns: []*model.Connection{mk(131_072)}, Sysctl: wmem}), "sndbuf|")
	if f == nil || !hasText(f.Evidence, "caps a connection at ≈1.7 MB/s") || !hasText(f.Evidence, "not at tcp_wmem max") || hasCommand(f, "tcp_wmem") {
		t.Errorf("buffer below the max: want SO_SNDBUF named, no tcp_wmem advice: %+v", f)
	}
	f = byID(Analyze(Input{Conns: []*model.Connection{mk(4_194_304)}, Sysctl: wmem}), "sndbuf|")
	if f == nil || !hasCommand(f, `tcp_wmem="4096 16384 8388608"`) {
		t.Errorf("buffer at the max: want the tcp_wmem advice: %+v", f)
	}
	// SO_SNDBUF can exceed tcp_wmem max; raising the max wouldn't touch it.
	f = byID(Analyze(Input{Conns: []*model.Connection{mk(8_388_608)}, Sysctl: wmem}), "sndbuf|")
	if f == nil || hasCommand(f, "tcp_wmem") {
		t.Errorf("buffer above the max: want SO_SNDBUF named, no tcp_wmem advice: %+v", f)
	}
}

// TestRTTInflationPointsAlongThePath: the queue is usually at the bottleneck
// on the path, not this host, so the finding says how to find it there too.
func TestRTTInflationPointsAlongThePath(t *testing.T) {
	c := conn("ESTAB", "10.0.0.1", "40000", "10.0.0.2", "5001", sig(model.SignalRTTSpike, 2))
	c.RTT, c.MinRTT = fp(1252), fp(40)
	f := byID(Analyze(Input{Conns: []*model.Connection{c}}), "rtt|10.0.0.2")
	if f == nil || !hasText(f.Evidence, "RTT 1252.0 ms vs 40.0 ms minimum") || !hasCommand(f, "tc -s qdisc show") || !hasCommand(f, "mtr -rwzbc 100 10.0.0.2") {
		t.Errorf("want local and on-path checks: %+v", f)
	}
}

// TestSynBacklogNamesListener: with syncookies on, a listener's SYN queue is
// its backlog, so the finding names the listener and never suggests
// tcp_max_syn_backlog (TestSynFlood in the lab: 17 half-open against a
// backlog of 16 while tcp_max_syn_backlog was 2048).
func TestSynBacklogNamesListener(t *testing.T) {
	sys, prev := sysPair(map[string]int64{"TcpExt:SyncookiesSent": 0}, map[string]int64{"TcpExt:SyncookiesSent": 332})
	lst := conn("LISTEN", "0.0.0.0", "5001", "0.0.0.0", "*")
	lst.Process, lst.PID, lst.SendQ = sp("server"), ip(3), ip(16)
	conns := []*model.Connection{lst}
	for i := range 17 {
		conns = append(conns, conn("SYN-RECV", "10.0.0.1", "5001", "10.0.0.9", strconv.Itoa(40000+i)))
	}
	ctl := poller.Sysctls{"net.core.somaxconn": "4096", "net.ipv4.tcp_max_syn_backlog": "2048"}
	f := byID(Analyze(Input{Conns: conns, Sys: sys, SysPrev: prev, Interval: 2 * time.Second, Sysctl: ctl}), "syn_backlog")
	if f == nil || !hasText(f.Evidence, "listener :5001 (server (pid 3)): 17 half-open, backlog 16") || hasCommand(f, "tcp_max_syn_backlog") || hasCommand(f, "somaxconn") {
		t.Errorf("want the listener and its own backlog named, no sysctl advice: %+v", f)
	}
	lst.SendQ = ip(4096) // capped by somaxconn
	f = byID(Analyze(Input{Conns: conns, Sys: sys, SysPrev: prev, Interval: 2 * time.Second, Sysctl: ctl}), "syn_backlog")
	if f == nil || !hasCommand(f, "sysctl -w net.core.somaxconn=8192") {
		t.Errorf("backlog at somaxconn: want the somaxconn advice: %+v", f)
	}
	// A second listening socket on the port (SO_REUSEPORT): one line, not two.
	lst2 := conn("LISTEN", "0.0.0.0", "5001", "0.0.0.0", "*")
	lst2.Process, lst2.PID, lst2.SendQ = sp("server"), ip(4), ip(4096)
	f = byID(Analyze(Input{Conns: append(conns, lst2), Sys: sys, SysPrev: prev, Interval: 2 * time.Second, Sysctl: ctl}), "syn_backlog")
	if f == nil || len(f.Evidence) != 2 || !hasText(f.Evidence, "across 2 listening sockets") {
		t.Errorf("want one line for the port: %q", f.Evidence)
	}

	// No listener in view (an ss filter): say how to find it, not somaxconn.
	f = byID(Analyze(Input{Sys: sys, SysPrev: prev, Interval: 2 * time.Second, Sysctl: ctl, SSFilter: "sport = :22"}), "syn_backlog")
	if f == nil || hasCommand(f, "somaxconn") || !hasCommand(f, "ss -ltn") || f.Filter != "" {
		t.Errorf("no listener in view: want how to find it: %+v", f)
	}
}

// TestRcvbufLimitedCause: a buffer at tcp_rmem max needs a higher max; one
// held anywhere else was fixed by the app (SO_RCVBUF).
func TestRcvbufLimitedCause(t *testing.T) {
	rmem := poller.Sysctls{"net.ipv4.tcp_rmem": "4096 131072 131072", "net.core.rmem_max": "212992"}
	mk := func(rb int) *model.Connection {
		c := conn("ESTAB", "10.0.0.2", "5001", "10.0.0.1", "40000", model.Signal{Type: model.SignalRcvbufLimited, Severity: 1, Value: "100% of the 75 KB window arrives every round trip"})
		c.Process, c.PID, c.SkmemRB, c.RcvWnd, c.RcvRTT = sp("server"), ip(8), ip(rb), ip(76_928), fp(40)
		return c
	}
	f := byID(Analyze(Input{Conns: []*model.Connection{mk(131_072)}, Sysctl: rmem}), "rcvbuf|pid:8")
	if f == nil || !hasText(f.Evidence, "caps a connection at ≈1.8 MB/s") || !hasText(f.Evidence, "grown to tcp_rmem max (128 KB)") || !hasCommand(f, `tcp_rmem="4096 131072 1048576"`) {
		t.Errorf("buffer at the max: want the tcp_rmem advice: %+v", f)
	}
	f = byID(Analyze(Input{Conns: []*model.Connection{mk(65_536)}, Sysctl: rmem}), "rcvbuf|pid:8")
	if f == nil || hasCommand(f, "tcp_rmem") || !strings.Contains(f.Actions[0].Text, "most likely sets SO_RCVBUF") {
		t.Errorf("buffer below the max: want SO_RCVBUF named, no tcp_rmem advice: %+v", f)
	}
}

// TestListenOverflowHostBacklogAdvice: overflows with no full listener in
// view (an ss filter, or a burst already drained) mustn't blindly advise
// somaxconn: the listener's own backlog is usually the limit. A listener
// with connections waiting tells which; otherwise the finding says how to
// find it.
func TestListenOverflowHostBacklogAdvice(t *testing.T) {
	sys, prev := sysPair(map[string]int64{"TcpExt:ListenOverflows": 0}, map[string]int64{"TcpExt:ListenOverflows": 384})
	ctl := poller.Sysctls{"net.core.somaxconn": "4096"}
	idle := conn("LISTEN", "0.0.0.0", "22", "0.0.0.0", "*")
	idle.SendQ, idle.RecvQ = ip(128), ip(0)
	f := byID(Analyze(Input{Conns: []*model.Connection{idle}, Sys: sys, SysPrev: prev, Interval: 2 * time.Second, Sysctl: ctl, SSFilter: "sport = :22"}), "listen_overflow_host")
	if f == nil || hasText(f.Evidence, "fullest listeners") || !hasCommand(f, "ss -ltn") || hasCommand(f, "somaxconn") || !hasText(f.Evidence, "ss filter 'sport = :22'") {
		t.Errorf("no listener with a queue: want how to find it, no somaxconn advice, the filter named: %+v", f)
	}

	busy := conn("LISTEN", "0.0.0.0", "5001", "0.0.0.0", "*")
	busy.Process, busy.PID, busy.SendQ, busy.RecvQ = sp("server"), ip(3), ip(4), ip(3)
	f = byID(Analyze(Input{Conns: []*model.Connection{idle, busy}, Sys: sys, SysPrev: prev, Interval: 2 * time.Second, Sysctl: ctl}), "listen_overflow_host")
	if f == nil || !hasText(f.Evidence, "fullest listeners: :5001 server (pid 3) (3/4)") || hasCommand(f, "somaxconn") ||
		!strings.HasPrefix(f.Actions[0].Text, "Raise the backlog in server (pid 3)'s config") {
		t.Errorf("listener with connections waiting: want it named and its own backlog raised: %+v", f)
	}
}

// TestSelectiveStall: a connection stalled on RTO while another to the same
// peer gets data acknowledged isn't plain loss (TestPMTUBlackHoleMidConnection
// in the lab: an MTU black hole that began mid-connection). Both stalled, or
// a still-moving lossy connection, is.
func TestSelectiveStall(t *testing.T) {
	stalled := conn("ESTAB", "10.0.0.1", "40000", "10.0.0.2", "5001", sig(model.SignalRTOFiring, 2), sig(model.SignalPeerNoAck, 2))
	stalled.Delivered, stalled.MSS, stalled.TimerRetrans, stalled.LastAck = ip(23056), ip(1448), ip(4), ip(5445)
	chatty := conn("ESTAB", "10.0.0.1", "40001", "10.0.0.2", "5002")
	chatty.DeltaBytesAcked = ip(13)
	ctl := poller.Sysctls{"net.ipv4.tcp_mtu_probing": "0"}

	f := byID(Analyze(Input{Conns: []*model.Connection{stalled, chatty}, Sysctl: ctl}), "loss|10.0.0.2")
	if f == nil || !strings.Contains(f.Title, "stall while others to it get through") ||
		!hasText(f.Evidence, "1 other connection to 10.0.0.2 had data acknowledged") ||
		!hasCommand(f, "ping -M do -c 3 -s 1472 10.0.0.2") || !hasCommand(f, "tcp_mtu_probing=1") {
		t.Errorf("stall beside a working sibling: want the selective-stall finding: %+v", f)
	}

	other := conn("ESTAB", "10.0.9.1", "40003", "10.0.0.2", "5002") // another uplink
	other.DeltaBytesAcked = ip(13)
	chatty.DeltaBytesAcked = ip(0) // the sibling gets nothing through either
	if f := byID(Analyze(Input{Conns: []*model.Connection{stalled, chatty, other}}), "loss|10.0.0.2"); f == nil || strings.Contains(f.Title, "others to it get through") {
		t.Errorf("working only from another local address: want plain loss: %+v", f)
	}
	if f := byID(Analyze(Input{Conns: []*model.Connection{stalled, chatty}}), "loss|10.0.0.2"); f == nil || strings.Contains(f.Title, "others to it get through") {
		t.Errorf("no working sibling: want plain loss: %+v", f)
	}

	lossy := conn("ESTAB", "10.0.0.1", "40002", "10.0.0.2", "5001", sig(model.SignalPathLoss, 1))
	chatty.DeltaBytesAcked = ip(13)
	if f := byID(Analyze(Input{Conns: []*model.Connection{lossy, chatty}}), "loss|10.0.0.2"); f == nil || strings.Contains(f.Title, "others to it get through") {
		t.Errorf("a lossy connection still moving data: want plain loss: %+v", f)
	}

	// A loss episode: two RTOs, acked a second ago. Plain loss.
	stalled.TimerRetrans, stalled.LastAck = ip(2), ip(1200)
	if f := byID(Analyze(Input{Conns: []*model.Connection{stalled, chatty}}), "loss|10.0.0.2"); f == nil || strings.Contains(f.Title, "others to it get through") {
		t.Errorf("a short RTO episode: want plain loss: %+v", f)
	}
}

// TestRcvMemPressure: TCP short of memory host-wide shows as its level
// against tcp_mem (steady, in the machine's own namespace), and as sockets
// dropping data with empty buffers (anywhere, between bursts of pruning),
// whose drops then aren't blamed on their reader.
func TestRcvMemPressure(t *testing.T) {
	ctl := poller.Sysctls{"net.ipv4.tcp_mem": "32 48 64"}
	host := &poller.SysStat{Counters: map[string]int64{"Sockstat:TCPMem": 707, "Sockstat:TCPOrphan": 77}}
	f := byID(Analyze(Input{Sys: host, SysPrev: host, Sysctl: ctl, Interval: 2 * time.Second}), "rcv_mem_pressure")
	if f == nil || f.Severity != 2 || !hasText(f.Evidence, "TCP holds 707 pages (2.8 MB) host-wide; tcp_mem pressure starts at 48, hard limit 64") || !hasText(f.Evidence, "77 orphaned sockets") {
		t.Errorf("over the hard limit: want a critical finding with the level: %+v", f)
	}
	if byID(Analyze(Input{Sys: host, SysPrev: host, Sysctl: poller.Sysctls{"net.ipv4.tcp_mem": "38379 51174 76758"}, Interval: 2 * time.Second}), "rcv_mem_pressure") != nil {
		t.Errorf("well under the limits: want nothing")
	}

	// In a namespace (no tcp_mem) between bursts: the sockets prove it.
	starved := conn("ESTAB", "10.0.0.2", "5001", "10.0.0.1", "41376", model.Signal{Type: model.SignalSocketDrops, Severity: 2, Value: 30})
	starved.Protocol, starved.PID, starved.SkmemR, starved.SkmemRB, starved.RecvQ = "tcp", ip(4), ip(0), ip(726_839), ip(0)
	r := Analyze(Input{Conns: []*model.Connection{starved}, Sys: host, SysPrev: host, Interval: 2 * time.Second})
	if f := byID(r, "rcv_mem_pressure"); f == nil || f.Severity != 2 || !hasText(f.Evidence, "1 socket dropped data while holding almost no receive memory") {
		t.Errorf("starved socket: want the memory finding to name it: %+v", r.Findings)
	}
	if byID(r, "recv_backlog|") != nil {
		t.Errorf("drops refused memory host-wide mustn't blame the reader: %+v", r.Findings)
	}
}

// TestRcvPrune: the kernel discarding queued data, with TCP's memory under
// tcp_mem and no starved socket, is one queue outgrowing its own buffer: not
// blamed on tcp_mem. Collapsing alone, nothing lost, isn't a finding.
func TestRcvPrune(t *testing.T) {
	ctl := poller.Sysctls{"net.ipv4.tcp_mem": "38379 51174 76758"}
	prev := &poller.SysStat{Counters: map[string]int64{"Sockstat:TCPMem": 597, "TcpExt:PruneCalled": 10, "TcpExt:RcvPruned": 10}}
	cur := &poller.SysStat{Counters: map[string]int64{"Sockstat:TCPMem": 597, "TcpExt:PruneCalled": 14, "TcpExt:RcvPruned": 14}}
	r := Analyze(Input{Sys: cur, SysPrev: prev, Sysctl: ctl, Interval: 2 * time.Second})
	if byID(r, "rcv_mem_pressure") != nil {
		t.Errorf("pruning under tcp_mem: want no host-wide finding: %+v", r.Findings)
	}
	f := byID(r, "rcv_prune")
	if f == nil || f.Severity != 1 || !hasText(f.Evidence, "RcvPruned +2.0/s") || !hasText(f.Evidence, "under tcp_mem's low mark 38379: not a host-wide shortage") || strings.Contains(fmt.Sprint(f.Actions), "raise tcp_mem") {
		t.Errorf("discards: want a warning that blames no limit: %+v", f)
	}

	// Between the low mark and the pressure threshold the kernel may still
	// be squeezing from an earlier crossing: said, not claimed.
	band := poller.Sysctls{"net.ipv4.tcp_mem": "500 700 900"}
	if f := byID(Analyze(Input{Sys: cur, SysPrev: prev, Sysctl: band, Interval: 2 * time.Second}), "rcv_prune"); f == nil || !hasText(f.Evidence, "above tcp_mem's low mark 500: if it went past 700 earlier") {
		t.Errorf("in the hysteresis band: want the possibility named: %+v", f)
	}

	// In a namespace tcp_mem can't be read: still no host-wide claim.
	if r := Analyze(Input{Sys: cur, SysPrev: prev, Interval: 2 * time.Second}); byID(r, "rcv_mem_pressure") != nil || byID(r, "rcv_prune") == nil {
		t.Errorf("pruning without tcp_mem: want rcv_prune only: %+v", r.Findings)
	}

	cur.Counters["TcpExt:RcvPruned"] = 10
	if r := Analyze(Input{Sys: cur, SysPrev: prev, Sysctl: ctl, Interval: 2 * time.Second}); byID(r, "rcv_prune") != nil || byID(r, "rcv_mem_pressure") != nil {
		t.Errorf("collapsing only: want nothing: %+v", r.Findings)
	}
}

// TestRwndLimitedCause: a remote receiver could be a slow reader or a small
// buffer, so the finding names both; a receiver on this host shows which.
func TestRwndLimitedCause(t *testing.T) {
	snd := conn("ESTAB", "127.0.0.1", "40000", "127.0.0.1", "5001", sig(model.SignalRwndLimited, 2))
	rcv := conn("ESTAB", "127.0.0.1", "5001", "127.0.0.1", "40000")
	rcv.Process, rcv.PID, rcv.RecvQ = sp("reader"), ip(7), ip(250_000)
	rmem := poller.Sysctls{"net.ipv4.tcp_rmem": "4096 131072 6291456"}

	snd2 := conn("ESTAB", "127.0.0.1", "40001", "127.0.0.1", "443", sig(model.SignalRwndLimited, 1))
	f := byID(Analyze(Input{Conns: []*model.Connection{snd, snd2}, Sysctl: rmem}), "rwnd|")
	if f == nil || !strings.Contains(f.Detail, "reads slowly") || !hasCommand(f, "ss -tmn 'sport = :443 or sport = :5001'") {
		t.Errorf("remote receiver: want both causes and how to tell them apart: %+v", f)
	}

	rcv.Signals = []model.Signal{{Type: model.SignalRecvBufferPressure, Severity: 1}}
	f = byID(Analyze(Input{Conns: []*model.Connection{snd, rcv}, Sysctl: rmem}), "rwnd|")
	if f == nil || !hasText(f.Evidence, "has 244 KB waiting in Recv-Q") || !hasCommand(f, "top -H -p 7") || hasCommand(f, "tcp_rmem") {
		t.Errorf("local slow reader: want the reader named and no buffer advice: %+v", f)
	}

	rcv.Signals, rcv.RecvQ = nil, ip(0)
	f = byID(Analyze(Input{Conns: []*model.Connection{snd, rcv}, Sysctl: rmem}), "rwnd|")
	if f == nil || !hasCommand(f, `tcp_rmem="4096 131072 12582912"`) {
		t.Errorf("local receiver keeping up: want the tcp_rmem advice: %+v", f)
	}

	// The local receiver reports its capped buffer itself: one finding.
	rcv.Signals = []model.Signal{{Type: model.SignalRcvbufLimited, Severity: 1}}
	r := Analyze(Input{Conns: []*model.Connection{snd, rcv}, Sysctl: rmem})
	if byID(r, "rwnd|") != nil || byID(r, "rcvbuf|") == nil {
		t.Errorf("local capped receiver: want only the rcvbuf finding: %+v", r.Findings)
	}
}

func TestTrackerSinceAndGrace(t *testing.T) {
	var tr Tracker
	t0 := time.Unix(1000, 0)
	fs := []Finding{{ID: "a"}}
	tr.Update(fs, t0)
	if !fs[0].Since.Equal(t0) {
		t.Fatalf("first sighting should start the clock")
	}
	// Absent for two polls (within grace), then back: keeps its start time.
	tr.Update(nil, t0.Add(2*time.Second))
	tr.Update(nil, t0.Add(4*time.Second))
	fs = []Finding{{ID: "a"}}
	tr.Update(fs, t0.Add(6*time.Second))
	if !fs[0].Since.Equal(t0) {
		t.Errorf("a brief gap should not reset Since, got %v", fs[0].Since)
	}
	// Absent beyond the grace period: forgotten, so it restarts.
	for i := 0; i <= GraceMisses; i++ {
		tr.Update(nil, t0.Add(time.Duration(10+i)*time.Second))
	}
	fs = []Finding{{ID: "a"}}
	now := t0.Add(time.Minute)
	tr.Update(fs, now)
	if !fs[0].Since.Equal(now) {
		t.Errorf("after the grace period the clock should restart, got %v", fs[0].Since)
	}
}

// The UDP drop counter only folds into a finding that includes UDP sockets;
// a TCP-only backlog finding must not swallow the host UDP finding.
func TestUDPDropsDontFoldIntoTCPBacklog(t *testing.T) {
	sys, prev := sysPair(map[string]int64{"Udp:RcvbufErrors": 0}, map[string]int64{"Udp:RcvbufErrors": 40})
	tcp := conn("ESTAB", "10.0.0.1", "80", "10.0.0.2", "5000", sig(model.SignalRecvBufferPressure, 1))
	r := Analyze(Input{Conns: []*model.Connection{tcp}, Sys: sys, SysPrev: prev, Interval: 2 * time.Second})
	if byID(r, "udp_rcvbuf_host") == nil {
		t.Errorf("UDP drops with only a TCP backlog finding should still raise the host UDP finding")
	}
	if f := byID(r, "recv_backlog|"); f == nil || hasText(f.Evidence, "RcvbufErrors") {
		t.Errorf("TCP-only finding shouldn't carry the UDP counter: %+v", f)
	}

	udp := conn("UDP_ESTAB", "10.0.0.1", "53", "10.0.0.3", "5353", sig(model.SignalSocketDrops, 2))
	udp.Protocol = "udp"
	r = Analyze(Input{Conns: []*model.Connection{udp}, Sys: sys, SysPrev: prev, Interval: 2 * time.Second})
	if byID(r, "udp_rcvbuf_host") != nil {
		t.Errorf("visible UDP drops should fold the counter into their finding")
	}

	// Collecting through an ss filter: the dropping sockets are likely
	// outside it, and the finding says so.
	r = Analyze(Input{Sys: sys, SysPrev: prev, Interval: 2 * time.Second, SSFilter: "sport = :22"})
	if f := byID(r, "udp_rcvbuf_host"); f == nil || !hasText(f.Evidence, "ss filter 'sport = :22'") || f.Filter != "" {
		t.Errorf("with an ss filter, the host finding should name it: %+v", f)
	}
}

// A single poll's burst (slow-start overshoot, a request burst) isn't a host
// problem: the rate is judged over the window, and not at all before the
// window has filled.
func TestRetransHostJudgedOverWindow(t *testing.T) {
	window := &poller.SysStat{Counters: map[string]int64{"Tcp:OutSegs": 0, "Tcp:RetransSegs": 0}}
	prev := &poller.SysStat{Counters: map[string]int64{"Tcp:OutSegs": 95_000, "Tcp:RetransSegs": 100}}
	sys := &poller.SysStat{Counters: map[string]int64{"Tcp:OutSegs": 100_000, "Tcp:RetransSegs": 1100}}
	r := Analyze(Input{Sys: sys, SysPrev: prev, SysSlots: []*poller.SysStat{window, prev, sys}, Interval: 2 * time.Second})
	if r.RetransPct != 20 {
		t.Fatalf("last poll's rate = %.1f, want 20", r.RetransPct)
	}
	if f := byID(r, "retrans_host"); f != nil {
		t.Errorf("1.1%% over the window shouldn't warn, despite 20%% in the last poll: %+v", f)
	}
	if f := byID(Analyze(Input{Sys: sys, SysPrev: prev, Interval: 2 * time.Second}), "retrans_host"); f != nil {
		t.Errorf("no finding before the window has filled: %+v", f)
	}
}

// TestRetransHostNeedsSteadyLoss: BBR's startup in the lab resent 1176 of
// its first 15k segments and nothing after, which a 12 s rate can count as
// 2% or more; loss that keeps coming (every slot) is the host problem.
func TestRetransHostNeedsSteadyLoss(t *testing.T) {
	slots := func(retrans ...int64) []*poller.SysStat {
		var out, re int64
		ss := []*poller.SysStat{{Counters: map[string]int64{"Tcp:OutSegs": 0, "Tcp:RetransSegs": 0}}}
		for _, r := range retrans {
			out, re = out+8_000, re+r
			ss = append(ss, &poller.SysStat{Counters: map[string]int64{"Tcp:OutSegs": out, "Tcp:RetransSegs": re}})
		}
		return ss
	}
	for _, tt := range []struct {
		name string
		ss   []*poller.SysStat
		want bool
	}{
		{"startup burst, then nothing", slots(1176, 0, 0, 0, 0, 0), false},
		{"every slot", slots(200, 200, 200, 200, 200, 200), true},
		{"half the slots", slots(400, 0, 400, 0, 400, 0), true},
	} {
		n := len(tt.ss)
		r := Analyze(Input{Sys: tt.ss[n-1], SysPrev: tt.ss[n-2], SysSlots: tt.ss, Interval: 2 * time.Second})
		if got := byID(r, "retrans_host") != nil; got != tt.want {
			t.Errorf("%s: retrans_host %v, want %v", tt.name, got, tt.want)
		}
	}
}

// One lossy peer doesn't explain a high retransmit rate across the host.
func TestRetransHostNotHiddenByOnePeer(t *testing.T) {
	sys, prev := sysPair(
		map[string]int64{"Tcp:OutSegs": 0, "Tcp:RetransSegs": 0},
		map[string]int64{"Tcp:OutSegs": 20000, "Tcp:RetransSegs": 2400})
	c := conn("ESTAB", "10.0.0.1", "1", "203.0.113.9", "443", sig(model.SignalRTOFiring, 2))
	r := Analyze(Input{Conns: []*model.Connection{c}, Sys: sys, SysPrev: prev, SysSlots: []*poller.SysStat{prev, sys}, Interval: 2 * time.Second})
	if byID(r, "loss|") == nil || byID(r, "retrans_host") == nil {
		t.Errorf("want both the per-peer loss and the host-wide 12%% finding: %+v", r.Findings)
	}
}

// Inbound loss from one peer is that path's problem; from many peers at
// once it's this host's receive path.
func TestInboundLossLocalVsRemote(t *testing.T) {
	rx := func(peer string) *model.Connection {
		c := conn("ESTAB", "10.0.0.1", "443", peer, "51000", sig(model.SignalInboundLoss, 1))
		t0 := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
		c.RecvSlots = []model.RecvSlot{{Start: t0, End: t0.Add(12 * time.Second), Segs: 1000, OOO: 50}}
		return c
	}
	r := Analyze(Input{Conns: []*model.Connection{rx("198.51.100.7"), conn("ESTAB", "10.0.0.1", "443", "198.51.100.8", "1")}})
	f := byID(r, "rx_loss|198.51.100.7")
	if f == nil || !hasText(f.Evidence, "5.0% of 1000 data segments received over the last 12s") || f.Filter != "peer==198.51.100.7 signal=RX_LOSS" {
		t.Errorf("want a per-peer inbound-loss finding: %+v", r.Findings)
	}

	var many []*model.Connection
	for i := 1; i <= 6; i++ {
		many = append(many, rx("198.51.100."+strconv.Itoa(i)))
	}
	// One of them also has loss-recovery drops (info, as the classifier
	// raises them): the host-wide finding must mention them.
	many[0].Signals = append(many[0].Signals, model.Signal{Type: model.SignalSocketDrops, Severity: 0})
	many[0].DeltaSkmemD, many[0].DeltaRcvOOOPack = ip(1), ip(40)
	r = Analyze(Input{Conns: many})
	f = byID(r, "rx_loss_local")
	if f == nil || f.Count != 6 || !hasCommand(f, "ethtool -g") {
		t.Fatalf("inbound loss from many peers should be one local finding: %+v", r.Findings)
	}
	if !hasText(f.Evidence, "discarded 1 out-of-order segment ") {
		t.Errorf("local finding should carry the discard: %q", f.Evidence)
	}
	if byID(r, "rx_loss|") != nil {
		t.Errorf("per-peer inbound findings should be replaced by the local one")
	}
}

// The live netem run: a receiver under 3% inbound loss with an empty receive
// queue showed kernel drops. Those are discarded out-of-order data, so they
// belong to the inbound-loss finding, not "isn't reading fast enough". The
// connections run through the classifier, which decides what the drops are.
func TestLossDropsAttributedToInboundLoss(t *testing.T) {
	t0 := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	mk := func(rxLoss bool, recvQ int) *model.Connection {
		c := conn("ESTAB", "127.0.0.1", "47200", "127.0.0.1", "48618")
		c.Protocol, c.Process, c.PID = "tcp", sp("python3"), ip(42)
		c.RecvQ, c.PrevRecvQ, c.SkmemRB = ip(recvQ), ip(recvQ), ip(212_992)
		c.DeltaSkmemD, c.DeltaRcvOOOPack = ip(2), ip(32)
		if rxLoss { // seconds of steady gaps with no queue: the RX_LOSS verdict
			c.MinRTT, c.Timestamps = fp(40), true
			for i := range 6 {
				c.RecvSlots = append(c.RecvSlots, model.RecvSlot{Start: t0.Add(time.Duration(2*i) * time.Second),
					End: t0.Add(time.Duration(2*i+2) * time.Second), Segs: 1000, OOO: 60, RTTMS: []float64{40, 40}})
			}
		}
		c.Signals = classifier.Classify(c)
		return c
	}
	r := Analyze(Input{Conns: []*model.Connection{mk(true, 0)}})
	if f := byID(r, "recv_backlog|"); f != nil {
		t.Errorf("loss-recovery drops must not blame the reader: %+v", f)
	}
	f := byID(r, "rx_loss|127.0.0.1")
	if f == nil || !hasText(f.Evidence, "discarded 2 out-of-order segments") {
		t.Fatalf("inbound-loss finding should carry the discards: %+v", r.Findings)
	}

	// Gaps but no RX_LOSS verdict (congestion, or loss too recent to judge):
	// still discards, not a slow reader.
	if r := Analyze(Input{Conns: []*model.Connection{mk(false, 0)}}); len(r.Findings) > 0 {
		t.Errorf("drops with gaps and an empty queue should report nothing: %+v", r.Findings)
	}

	// With a genuinely full receive queue the reader is slow after all.
	if byID(Analyze(Input{Conns: []*model.Connection{mk(true, 200_000)}}), "recv_backlog|pid:42") == nil {
		t.Errorf("drops with a full receive queue should still be a reader problem")
	}
}

// Reordering is reported from the sender's view (packets *to* the peer) and
// flagged as unreliable when the same connections are losing packets.
func TestReorderingDirectionAndLossCaveat(t *testing.T) {
	c := conn("ESTAB", "10.0.0.1", "1", "203.0.113.5", "443", sig(model.SignalReordering, 1), sig(model.SignalRTOFiring, 2))
	t0 := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	c.MSS = ip(1000)
	c.SendSlots = []model.SendSlot{
		{Start: t0, End: t0.Add(2 * time.Second), Sent: 100_000, Reord: 1},
		{Start: t0.Add(2 * time.Second), End: t0.Add(8 * time.Second), Sent: 100_000, Reord: 3},
	}
	f := byID(Analyze(Input{Conns: []*model.Connection{c}}), "reorder|")
	if f == nil || !strings.HasPrefix(f.Title, "Packets to 203.0.113.5") {
		t.Fatalf("title should describe packets to the peer: %+v", f)
	}
	if !hasText(f.Evidence, "4 reordering events over the last 8s (2.00% of segments)") || !hasText(f.Evidence, "caution: 1 of these connections also show packet loss") {
		t.Errorf("evidence = %q", f.Evidence)
	}
}

func TestUnprivilegedSaysHowToSeeProcesses(t *testing.T) {
	withIno := func(c *model.Connection, ino string) *model.Connection { c.Inode = sp(ino); return c }
	owned := withIno(conn("ESTAB", "10.0.0.1", "8080", "10.0.0.9", "5003"), "103")
	owned.Process, owned.PID = sp("nginx"), ip(812)
	conns := []*model.Connection{
		withIno(conn("CLOSE-WAIT", "10.0.0.1", "8080", "10.0.0.9", "5000", sig(model.SignalCloseWaitLeak, 1)), "100"),
		withIno(conn("ESTAB", "10.0.0.1", "8080", "10.0.0.9", "5001"), "101"),
		// No file, so no process even for root: TIME-WAIT and an orphan.
		withIno(conn("TIME-WAIT", "10.0.0.1", "8080", "10.0.0.9", "5002"), "0"),
		withIno(conn("FIN-WAIT-2", "10.0.0.1", "8080", "10.0.0.9", "5004"), "0"),
		owned,
	}

	rep := Analyze(Input{Conns: conns, Unprivileged: true})
	if rep.HiddenProcs != 2 {
		t.Errorf("HiddenProcs = %d, want 2 (CLOSE-WAIT + ESTAB without a process)", rep.HiddenProcs)
	}
	f := byID(rep, "close_wait|")
	if f == nil || !strings.Contains(f.Title, "run with sudo") {
		t.Fatalf("unprivileged CLOSE-WAIT title should say to run with sudo, got %+v", f)
	}

	rep = Analyze(Input{Conns: conns})
	if rep.HiddenProcs != 0 {
		t.Errorf("as root HiddenProcs = %d, want 0", rep.HiddenProcs)
	}
	if f := byID(rep, "close_wait|"); f == nil || strings.Contains(f.Title, "sudo") {
		t.Errorf("as root the title shouldn't mention sudo, got %+v", f)
	}
}
