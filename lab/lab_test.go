//go:build lab

// Package lab proves sstui's diagnoses on real failures. Each scenario builds
// a client and a server namespace joined through a router namespace, shapes
// the router's links with tc netem,
// runs small workloads that recreate a problem (a reader that stops reading,
// a server that never accepts, packet loss, ...), records the namespace with
// the real `sstui record`, and checks `sstui check --json` names the problem.
// Healthy controls run the same way and must come out clean, so a noisy rule
// fails the lab as surely as a missed diagnosis.
//
// It needs root, iproute2 (ip, ss) and tc with the netem qdisc. Run it with
// scripts/lab.sh, which builds sstui and the test binary as you and runs the
// scenarios under sudo.
package lab

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"sstui/poller"
	"sstui/session"
)

// Every lab is client a — router r — server b, on two subnets.
const (
	addrA  = "10.231.1.1"
	addrRA = "10.231.1.254" // router, a's side
	addrB  = "10.231.2.1"
	addrRB = "10.231.2.254" // router, b's side
)

// nsPrefix marks the lab's namespaces so stale ones can be swept up.
const nsPrefix = "sstlab"

func TestMain(m *testing.M) {
	if os.Getenv(roleEnv) != "" {
		// Re-executed inside a namespace to run a workload (see start).
		if err := runRole(os.Args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, "lab role:", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if os.Geteuid() == 0 {
		sweepNamespaces()
	}
	os.Exit(m.Run())
}

// sweepNamespaces deletes lab namespaces left behind by an interrupted run.
func sweepNamespaces() {
	out, _ := exec.Command("ip", "netns", "list").Output()
	for _, line := range strings.Split(string(out), "\n") {
		if name, _, _ := strings.Cut(line, " "); strings.HasPrefix(name, nsPrefix) {
			exec.Command("ip", "netns", "del", name).Run()
		}
	}
}

// sstuiBin is the sstui binary under test, built by scripts/lab.sh.
func sstuiBin(t *testing.T) string {
	bin := os.Getenv("SSTUI_BIN")
	if bin == "" {
		t.Skip("SSTUI_BIN not set; run the lab with scripts/lab.sh")
	}
	return bin
}

func requireLab(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("the lab needs root (network namespaces, tc); run it with scripts/lab.sh")
	}
	for _, tool := range []string{"ip", "tc", "ss"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found", tool)
		}
	}
}

// lab is one scenario's namespaces.
type lab struct {
	t        *testing.T
	a, r, b  string // client, router, server namespaces
	bin      string // sstui binary
	ssFilter string // passed to `sstui record --ss-filter` when set
}

var labSeq atomic.Int32

// newLab creates client a and server b, each linked to router r, and removes
// them, with every process inside, when the test ends. All shaping happens on
// the router (see path), as on a real network: when the bottleneck queue sat
// on the sender itself, overflow was a local drop that silently cut cwnd
// instead of a loss the sender has to detect and retransmit.
func newLab(t *testing.T) *lab {
	t.Helper()
	requireLab(t)
	bin := sstuiBin(t)
	id := fmt.Sprintf("%d", labSeq.Add(1))
	l := &lab{t: t, a: nsPrefix + id + "a", r: nsPrefix + id + "r", b: nsPrefix + id + "b", bin: bin}
	t.Cleanup(func() {
		for _, ns := range []string{l.a, l.r, l.b} {
			exec.Command("ip", "netns", "del", ns).Run()
		}
	})
	for _, ns := range []string{l.a, l.r, l.b} {
		l.sh("ip", "netns", "add", ns)
		l.sh("ip", "-n", ns, "link", "set", "lo", "up")
	}
	l.sh("ip", "netns", "exec", l.r, "sysctl", "-qw", "net.ipv4.ip_forward=1")
	for _, end := range []struct{ ns, dev, addr, gw string }{
		{l.a, "toa", addrA, addrRA},
		{l.b, "tob", addrB, addrRB},
	} {
		l.sh("ip", "link", "add", "veth0", "netns", end.ns, "type", "veth", "peer", "name", end.dev, "netns", l.r)
		l.sh("ip", "-n", end.ns, "addr", "add", end.addr+"/24", "dev", "veth0")
		l.sh("ip", "-n", l.r, "addr", "add", end.gw+"/24", "dev", end.dev)
		for _, ifc := range []struct{ ns, dev string }{{end.ns, "veth0"}, {l.r, end.dev}} {
			// Wire-sized packets: veth otherwise passes 64 KB GSO
			// super-packets, and netem counts each as one packet, so a
			// 500-packet queue would hold tens of MB (bufferbloat in every
			// scenario) and 1% loss would hit 1% of super-packets.
			l.sh("ip", "-n", ifc.ns, "link", "set", ifc.dev, "gso_max_segs", "1")
			l.sh("ip", "-n", ifc.ns, "link", "set", ifc.dev, "up")
		}
		l.sh("ip", "-n", end.ns, "route", "add", "default", "via", end.gw)
	}
	return l
}

// sh runs a setup command and fails the test if it fails.
func (l *lab) sh(args ...string) {
	l.t.Helper()
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		l.t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// link describes one direction of the path through the router.
type link struct {
	Delay  string // one-way delay, e.g. "20ms"
	Rate   string // bottleneck rate, e.g. "100mbit"
	Buffer int    // bottleneck queue in packets: what a router buffers before it drops
	Netem  string // extra impairments for netem, e.g. "loss 1%"
}

// with returns the link with extra netem impairments.
func (k link) with(netem string) link { k.Netem = netem; return k }

// path shapes the router: toB for traffic from a to b (a's uploads, requests
// and ACKs), toA for b to a. Each direction is netem (delay and impairments,
// with room for everything in flight so it never drops on its own) feeding a
// tbf rate limiter whose queue is the bottleneck buffer. netem alone can't
// model the buffer: its packet limit also counts the packets it is delaying,
// so a small limit becomes random loss rather than a shallow queue.
func (l *lab) path(toB, toA link) {
	l.t.Helper()
	for _, d := range []struct {
		dev string
		k   link
	}{{"tob", toB}, {"toa", toA}} {
		l.sh(append([]string{"tc", "-n", l.r, "qdisc", "replace", "dev", d.dev, "root", "handle", "1:",
			"netem", "delay", d.k.Delay, "limit", "100000"}, strings.Fields(d.k.Netem)...)...)
		l.sh("tc", "-n", l.r, "qdisc", "replace", "dev", d.dev, "parent", "1:1", "handle", "10:",
			"tbf", "rate", d.k.Rate, "burst", "32kb", "limit", strconv.Itoa(d.k.Buffer*1514))
	}
}

// reorder adds a reordering stage on namespace ns's own link: netem delays
// its packets by 1 ms and lets pct of them skip the delay, so they overtake
// up to 1 ms of traffic, a few packets at 100 Mbit/s, as with ECMP or LACP
// hashing. (On the router's 20 ms stage they would overtake ~170 packets.)
func (l *lab) reorder(ns, pct string) {
	l.t.Helper()
	l.sh("tc", "-n", ns, "qdisc", "replace", "dev", "veth0", "root", "netem", "delay", "1ms", "reorder", pct)
}

// lossyNIC drops pct of the packets namespace ns sends, on its own link: a
// bad NIC, cable or driver. netem reports its drops to the stack as sent,
// so TCP has to detect them like any loss on the wire.
func (l *lab) lossyNIC(ns, pct string) {
	l.t.Helper()
	l.sh("tc", "-n", ns, "qdisc", "replace", "dev", "veth0", "root", "netem", "loss", pct)
}

// moreAddrs gives namespace ns (l.a or l.b) n addresses in all: its own
// and n-1 more on the same subnet (.2, .3, ...), so it looks like n
// different hosts to the other end. Returns them, its own first.
func (l *lab) moreAddrs(ns string, n int) []string {
	l.t.Helper()
	own := map[string]string{l.a: addrA, l.b: addrB}[ns]
	addrs := []string{own}
	prefix := own[:strings.LastIndex(own, ".")+1]
	for i := 2; len(addrs) < n; i++ {
		a := prefix + strconv.Itoa(i)
		if a == own {
			continue
		}
		l.sh("ip", "-n", ns, "addr", "add", a+"/24", "dev", "veth0")
		addrs = append(addrs, a)
	}
	return addrs
}

// sysctl sets a sysctl inside namespace ns (the net.* ones are per namespace).
func (l *lab) sysctl(ns, kv string) {
	l.t.Helper()
	l.sh("ip", "netns", "exec", ns, "sysctl", "-qw", kv)
}

// narrowLink lowers the MTU of the router's link toward b to mtu, like a
// tunnel in the middle of the path: both ends keep a 1500-byte MTU and learn
// the smaller one only from the router's ICMP "fragmentation needed". b's
// packets toward the router must fit too (veth drops what's over the
// receiving end's MTU), so b should only send ACKs.
func (l *lab) narrowLink(mtu int) {
	l.t.Helper()
	l.sh("ip", "-n", l.r, "link", "set", "tob", "mtu", strconv.Itoa(mtu))
}

// mismatchedMTU makes the router's end of a's link silently discard what
// a sends in packets over mtu bytes while a's end still says 1500: a link
// MTU misconfigured on one side (a VPN or container interface, say).
// Oversized frames vanish on arrival, before any router could answer with
// ICMP. (Lowering the router's veth MTU instead makes a's own transmit
// fail, which TCP sees as a local error and gives up on within seconds; a
// real NIC can't know the other end's MTU.)
func (l *lab) mismatchedMTU(mtu int) {
	l.t.Helper()
	l.sh("tc", "-n", l.r, "qdisc", "add", "dev", "toa", "ingress")
	l.sh("tc", "-n", l.r, "filter", "add", "dev", "toa", "ingress", "protocol", "ip",
		"basic", "match", fmt.Sprintf("cmp(u16 at 2 layer network gt %d)", mtu), "action", "drop")
}

// dropICMP discards every ICMP packet arriving at namespace ns, like a
// firewall that filters ICMP wholesale.
func (l *lab) dropICMP(ns string) {
	l.t.Helper()
	l.sh("tc", "-n", ns, "qdisc", "add", "dev", "veth0", "ingress")
	l.sh("tc", "-n", ns, "filter", "add", "dev", "veth0", "ingress", "protocol", "ip",
		"u32", "match", "ip", "protocol", "1", "0xff", "action", "drop")
}

// dropSynAcks discards every SYN-ACK arriving at namespace ns, so its
// handshakes never complete and the server is left with half-open
// connections, as in a SYN flood. (TCP flags sit at byte 33 of a packet
// without IP options.)
func (l *lab) dropSynAcks(ns string) {
	l.t.Helper()
	l.sh("tc", "-n", ns, "qdisc", "add", "dev", "veth0", "ingress")
	l.sh("tc", "-n", ns, "filter", "add", "dev", "veth0", "ingress", "protocol", "ip",
		"u32", "match", "ip", "protocol", "6", "0xff", "match", "u8", "0x12", "0xff", "at", "33", "action", "drop")
}

// hostWide skips a scenario that changes host-wide settings unless
// SSTUI_LAB_HOSTWIDE=1 asks for it: some kernel limits (tcp_mem) have no
// per-namespace copy, so changing them touches every socket on the machine.
func hostWide(t *testing.T) {
	t.Helper()
	if os.Getenv("SSTUI_LAB_HOSTWIDE") != "1" {
		t.Skip("changes host-wide tcp_mem; run with SSTUI_LAB_HOSTWIDE=1 on a disposable machine")
	}
}

// squeezeTCPMem sets the host-wide TCP memory limits (tcp_mem, in pages)
// for the rest of the test. A watchdog in its own session restores the
// original after 90 s even if the test is killed (or its ssh session
// drops); the test's cleanup restores it at once.
func (l *lab) squeezeTCPMem(pages string) {
	l.t.Helper()
	const path = "/proc/sys/net/ipv4/tcp_mem"
	b, err := os.ReadFile(path)
	if err != nil {
		l.t.Fatal(err)
	}
	orig := strings.Join(strings.Fields(string(b)), " ")
	restore := func() error { return os.WriteFile(path, []byte(orig), 0o644) }
	watchdog := exec.Command("setsid", "sh", "-c", fmt.Sprintf("sleep 90; echo '%s' > %s", orig, path))
	if err := watchdog.Start(); err != nil {
		l.t.Fatal(err)
	}
	l.t.Cleanup(func() {
		if err := restore(); err != nil {
			l.t.Errorf("restoring tcp_mem to %s: %v (the watchdog retries within 90 s)", orig, err)
			return
		}
		syscall.Kill(-watchdog.Process.Pid, syscall.SIGKILL) // its whole session: sh and sleep
		watchdog.Wait()
	})
	if err := os.WriteFile(path, []byte(pages), 0o644); err != nil {
		l.t.Fatal(err)
	}
	l.t.Logf("tcp_mem %s -> %s (pages)", orig, pages)
}

// start runs a workload role (see runRole) inside namespace ns until the test
// ends.
func (l *lab) start(ns string, role ...string) {
	l.t.Helper()
	self, err := os.Executable()
	if err != nil {
		l.t.Fatal(err)
	}
	cmd := exec.Command("ip", append([]string{"netns", "exec", ns, self}, role...)...)
	cmd.Env = append(os.Environ(), roleEnv+"=1")
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		l.t.Fatalf("start %v: %v", role, err)
	}
	l.t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
}

// record runs `sstui record` inside namespace ns ("" for the machine's own,
// where host-wide limits like tcp_mem live) for d and returns the
// recording's path. With SSTUI_LAB_KEEP set to a directory, every recording
// is also copied there (named after the test and the side) for inspection or
// demos.
func (l *lab) record(ns string, d time.Duration) string {
	l.t.Helper()
	return l.startRecord(ns, d)()
}

// startRecord starts recording namespace ns for d and returns a function
// that waits for the recording and returns its path, so both ends of a path
// can be recorded at once.
func (l *lab) startRecord(ns string, d time.Duration) func() string {
	l.t.Helper()
	path := filepath.Join(l.t.TempDir(), "rec.jsonl.gz")
	args := []string{l.bin, "record", "--interval", "500ms", "--duration", d.String(), "-o", path}
	if l.ssFilter != "" {
		args = append(args, "--ss-filter", l.ssFilter)
	}
	if ns != "" {
		args = append([]string{"ip", "netns", "exec", ns}, args...)
	}
	cmd := exec.Command(args[0], args[1:]...)
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		l.t.Fatalf("sstui record: %v", err)
	}
	// Stops it if the test fails before waiting (or while waiting on the
	// other end's recording); harmless once it has exited.
	l.t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	return func() string {
		l.t.Helper()
		if err := cmd.Wait(); err != nil {
			l.t.Fatalf("sstui record: %v\n%s", err, out.String())
		}
		l.keep(path, l.side(ns))
		return path
	}
}

// side names namespace ns for logs and kept recordings.
func (l *lab) side(ns string) string {
	switch ns {
	case l.a:
		return "client"
	case l.b:
		return "server"
	case "":
		return "host"
	}
	return "router"
}

// keep copies a recording to SSTUI_LAB_KEEP, when set.
func (l *lab) keep(path, side string) {
	l.t.Helper()
	dir := os.Getenv("SSTUI_LAB_KEEP")
	if dir == "" {
		return
	}
	dst := filepath.Join(dir, strings.ReplaceAll(l.t.Name(), "/", "_")+"-"+side+".jsonl.gz")
	b, err := os.ReadFile(path)
	if err == nil {
		err = os.WriteFile(dst, b, 0o644)
	}
	if err != nil {
		l.t.Errorf("keeping the recording: %v", err)
	}
	// Hand it back to the user who ran sudo.
	uid, errU := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, errG := strconv.Atoi(os.Getenv("SUDO_GID"))
	if errU == nil && errG == nil {
		os.Chown(dst, uid, gid)
	}
}

// report is the part of `sstui check --json` the lab asserts on, plus the
// warn/crit socket signals a replay of the recording raised (see
// signalPolls), which Live and Detail would have shown.
type report struct {
	side    string // "client" or "server"
	signals string // "none", or "LABEL=polls ..."

	Status   string `json:"status"`
	Polls    int    `json:"polls"`
	Findings []struct {
		ID        string `json:"id"`
		Severity  string `json:"severity"`
		Title     string `json:"title"`
		PollsSeen int    `json:"polls_seen"`
	} `json:"findings"`
}

// check runs `sstui check --json` on a recording of side and logs what it
// found and which socket signals fired, so a failing scenario shows its
// evidence.
func (l *lab) check(path, side string) *report {
	l.t.Helper()
	out, err := exec.Command(l.bin, "check", "--json", path).Output()
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) { // non-zero exit is the verdict, not an error
		l.t.Fatalf("sstui check: %v", err)
	}
	var r report
	if err := json.Unmarshal(out, &r); err != nil {
		l.t.Fatalf("sstui check output: %v\n%s", err, out)
	}
	r.side = side
	l.t.Logf("%s check: %s over %d polls", side, r.Status, r.Polls)
	for _, f := range r.Findings {
		l.t.Logf("  finding %-28s %-8s %2d polls  %s", f.ID, f.Severity, f.PollsSeen, f.Title)
	}
	r.signals = signalPolls(l.t, path)
	l.t.Logf("  signals (polls with a warn/crit socket): %s", r.signals)
	return &r
}

// recordAndCheck records namespace ns for d and checks the recording.
func (l *lab) recordAndCheck(ns string, d time.Duration) *report {
	l.t.Helper()
	return l.check(l.record(ns, d), l.side(ns))
}

// recordBoth records the client and the server at the same time, for d, and
// checks both recordings: the sender sees its retransmits, the receiver only
// the gaps in what arrives.
func (l *lab) recordBoth(d time.Duration) (client, server *report) {
	l.t.Helper()
	wa, wb := l.startRecord(l.a, d), l.startRecord(l.b, d)
	pa, pb := wa(), wb()
	return l.check(pa, "client"), l.check(pb, "server")
}

// kind is a finding ID without its "|key" suffix ("zero_window").
func kind(id string) string {
	k, _, _ := strings.Cut(id, "|")
	return k
}

// expect fails unless a finding of this kind was reported at least at
// severity ("warning" or "critical").
func (r *report) expect(t *testing.T, k, severity string) {
	t.Helper()
	for _, f := range r.Findings {
		if kind(f.ID) == k && (severity == "warning" || f.Severity == "critical") {
			return
		}
	}
	t.Errorf("%s: want a %s finding at %s or worse; got %s", r.side, k, severity, r.kinds())
}

// expectTitle fails unless a finding of this kind was reported with title
// containing text, for kinds whose title tells two diagnoses apart.
func (r *report) expectTitle(t *testing.T, k, text string) {
	t.Helper()
	for _, f := range r.Findings {
		if kind(f.ID) == k && strings.Contains(f.Title, text) {
			return
		}
	}
	t.Errorf("%s: want a %s finding titled \"…%s…\"; got %s", r.side, k, text, r.kinds())
}

// expectNone fails if a finding of this kind was reported.
func (r *report) expectNone(t *testing.T, k string) {
	t.Helper()
	for _, f := range r.Findings {
		if kind(f.ID) == k {
			t.Errorf("%s: want no %s finding; got %s", r.side, k, r.kinds())
			return
		}
	}
}

// expectClean fails if anything was reported, as a finding or as a warn/crit
// signal on any socket: healthy traffic shouldn't light up Live either.
func (r *report) expectClean(t *testing.T) {
	t.Helper()
	if len(r.Findings) > 0 {
		t.Errorf("%s: healthy traffic should report nothing; got %s", r.side, r.kinds())
	}
	if r.signals != "none" {
		t.Errorf("%s: healthy traffic should raise no warn/crit signals; got %s", r.side, r.signals)
	}
}

func (r *report) kinds() string {
	if len(r.Findings) == 0 {
		return "no findings"
	}
	var ks []string
	for _, f := range r.Findings {
		ks = append(ks, kind(f.ID)+"/"+f.Severity)
	}
	return strings.Join(ks, ", ")
}

// signalPolls replays a recording through the same pipeline as sstui and
// counts, per signal label, the polls in which some socket had it at warn or
// crit.
func signalPolls(t *testing.T, path string) string {
	r, err := session.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	poller.SetInterval(r.Header.Interval)
	s := session.New(r.Header.SSFilter, r.Header.Unprivileged)
	counts := map[string]int{}
	for {
		p, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if !s.Ingest(p) {
			continue
		}
		seen := map[string]bool{}
		for _, c := range s.Buf.GetLatest().Conns {
			for _, sg := range c.Signals {
				if sg.Severity > 0 {
					seen[sg.Type.Label()] = true
				}
			}
		}
		for l := range seen {
			counts[l]++
		}
	}
	if len(counts) == 0 {
		return "none"
	}
	var parts []string
	for l, n := range counts {
		parts = append(parts, l+"="+strconv.Itoa(n))
	}
	slices.Sort(parts)
	return strings.Join(parts, " ")
}
