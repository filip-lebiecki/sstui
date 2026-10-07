package findings

import (
	"strconv"
	"strings"
	"testing"
	"time"

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
		many = append(many, conn("ESTAB", "10.0.0.1", "1", "203.0.113."+strconv.Itoa(i+1), "443", sig(model.SignalHighRetransRate, 1)))
	}
	r = Analyze(Input{Conns: many})
	if f := byID(r, "loss_local"); f == nil || f.Count != 6 || !hasCommand(f, "ip -s link") {
		t.Errorf("loss toward many peers should be one local finding: %+v", r.Findings)
	}
	if byID(r, "loss|") != nil {
		t.Errorf("per-peer loss findings should be replaced by the local one")
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
	r := Analyze(Input{Sys: sys, SysPrev: prev, Interval: 2 * time.Second})
	if f := byID(r, "retrans_host"); f == nil || f.Severity != 1 || r.RetransPct != 5 {
		t.Errorf("5%% retransmits over 10k segs should warn: %+v (pct %.1f)", f, r.RetransPct)
	}
	sys, prev = sysPair(
		map[string]int64{"Tcp:OutSegs": 0, "Tcp:RetransSegs": 0},
		map[string]int64{"Tcp:OutSegs": 100, "Tcp:RetransSegs": 50})
	if byID(Analyze(Input{Sys: sys, SysPrev: prev, Interval: 2 * time.Second}), "retrans_host") != nil {
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
	c.DeliveryRate, c.RTT = ip(100_000_000), fp(80) // 100 Mbit/s × 80 ms = 1 MB BDP
	f := byID(Analyze(Input{Conns: []*model.Connection{c}, Sysctl: poller.Sysctls{"net.ipv4.tcp_window_scaling": "0"}}), "rwnd|")
	if f == nil {
		t.Fatal("expected rwnd finding")
	}
	if !hasText(f.Evidence, "window scaling wasn't negotiated") || !hasText(f.Evidence, "≈977 KB") {
		t.Errorf("evidence = %q", f.Evidence)
	}
	if !hasCommand(f, "tcp_window_scaling=1") {
		t.Errorf("should suggest enabling window scaling: %+v", f.Actions)
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
}

// One lossy peer doesn't explain a high retransmit rate across the host.
func TestRetransHostNotHiddenByOnePeer(t *testing.T) {
	sys, prev := sysPair(
		map[string]int64{"Tcp:OutSegs": 0, "Tcp:RetransSegs": 0},
		map[string]int64{"Tcp:OutSegs": 20000, "Tcp:RetransSegs": 2400})
	c := conn("ESTAB", "10.0.0.1", "1", "203.0.113.9", "443", sig(model.SignalRTOFiring, 2))
	r := Analyze(Input{Conns: []*model.Connection{c}, Sys: sys, SysPrev: prev, Interval: 2 * time.Second})
	if byID(r, "loss|") == nil || byID(r, "retrans_host") == nil {
		t.Errorf("want both the per-peer loss and the host-wide 12%% finding: %+v", r.Findings)
	}
}

// Inbound loss from one peer is that path's problem; from many peers at
// once it's this host's receive path.
func TestInboundLossLocalVsRemote(t *testing.T) {
	rx := func(peer string) *model.Connection {
		c := conn("ESTAB", "10.0.0.1", "443", peer, "51000", sig(model.SignalInboundLoss, 1))
		c.DeltaRcvOOOPack, c.DeltaDataSegsIn = ip(50), ip(1000)
		return c
	}
	r := Analyze(Input{Conns: []*model.Connection{rx("198.51.100.7"), conn("ESTAB", "10.0.0.1", "443", "198.51.100.8", "1")}})
	f := byID(r, "rx_loss|198.51.100.7")
	if f == nil || !hasText(f.Evidence, "5.0% of 1000 data segments") || f.Filter != "peer==198.51.100.7 signal=RX_LOSS" {
		t.Errorf("want a per-peer inbound-loss finding: %+v", r.Findings)
	}

	var many []*model.Connection
	for i := 1; i <= 6; i++ {
		many = append(many, rx("198.51.100."+strconv.Itoa(i)))
	}
	// One of them also has loss-recovery drops: the host-wide finding must
	// carry them and take the DROPS severity.
	many[0].Signals = append(many[0].Signals, model.Signal{Type: model.SignalSocketDrops, Severity: 2})
	many[0].DeltaSkmemD = ip(1)
	r = Analyze(Input{Conns: many})
	f = byID(r, "rx_loss_local")
	if f == nil || f.Count != 6 || !hasCommand(f, "ethtool -g") {
		t.Fatalf("inbound loss from many peers should be one local finding: %+v", r.Findings)
	}
	if f.Severity != 2 || !hasText(f.Evidence, "discarded 1 out-of-order segment ") {
		t.Errorf("local finding should carry the discard and its severity: sev %d, %q", f.Severity, f.Evidence)
	}
	if byID(r, "rx_loss|") != nil {
		t.Errorf("per-peer inbound findings should be replaced by the local one")
	}
}

// The live netem run: a receiver under 3% inbound loss with an empty receive
// queue showed kernel drops. Those are discarded out-of-order data, so they
// belong to the inbound-loss finding, not "isn't reading fast enough".
func TestLossDropsAttributedToInboundLoss(t *testing.T) {
	c := conn("ESTAB", "127.0.0.1", "47200", "127.0.0.1", "48618",
		model.Signal{Type: model.SignalSocketDrops, Severity: 1, Value: 2},
		model.Signal{Type: model.SignalInboundLoss, Severity: 1})
	c.Process, c.PID = sp("python3"), ip(42)
	c.RecvQ, c.DeltaSkmemD, c.DeltaRcvOOOPack, c.DeltaDataSegsIn = ip(0), ip(2), ip(32), ip(643)
	r := Analyze(Input{Conns: []*model.Connection{c}})
	if f := byID(r, "recv_backlog|"); f != nil {
		t.Errorf("loss-recovery drops must not blame the reader: %+v", f)
	}
	f := byID(r, "rx_loss|127.0.0.1")
	if f == nil || !hasText(f.Evidence, "discarded 2 out-of-order segments") {
		t.Fatalf("inbound-loss finding should carry the discards: %+v", f)
	}

	// With a genuinely full receive queue the reader is slow after all.
	c.Signals = append(c.Signals, model.Signal{Type: model.SignalRecvBufferPressure, Severity: 1})
	c.RecvQ = ip(200_000)
	if byID(Analyze(Input{Conns: []*model.Connection{c}}), "recv_backlog|pid:42") == nil {
		t.Errorf("drops with a full receive queue should still be a reader problem")
	}
}

// Reordering is reported from the sender's view (packets *to* the peer) and
// flagged as unreliable when the same connections are losing packets.
func TestReorderingDirectionAndLossCaveat(t *testing.T) {
	c := conn("ESTAB", "10.0.0.1", "1", "203.0.113.5", "443", sig(model.SignalReordering, 1), sig(model.SignalRTOFiring, 2))
	c.DeltaReordSeen = ip(4)
	f := byID(Analyze(Input{Conns: []*model.Connection{c}}), "reorder|")
	if f == nil || !strings.HasPrefix(f.Title, "Packets to 203.0.113.5") {
		t.Fatalf("title should describe packets to the peer: %+v", f)
	}
	if !hasText(f.Evidence, "4 reordering events") || !hasText(f.Evidence, "caution: 1 of these connections also show packet loss") {
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
