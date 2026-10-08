package poller

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"time"
)

// SysStat is a point-in-time read of host-wide networking counters from
// /proc/net/snmp and /proc/net/netstat. Counters are keyed "Prefix:Field",
// e.g. "Tcp:RetransSegs", "TcpExt:ListenOverflows", "Udp:RcvbufErrors". These
// capture things per-socket ss output can't see — SYN floods that never become
// sockets, accept-queue overflows, global retransmit and pruning rates.
// Levels from /proc/net/sockstat sit alongside as "Sockstat:<Proto><Field>"
// (e.g. "Sockstat:TCPMem", pages of memory TCP holds host-wide): gauges, so
// read them with Get, not Delta. "Sockstat:PageSize" is the size in bytes of
// those pages (and tcp_mem's): 4 KB on most machines, 16 or 64 KB on some
// arm64 and ppc64 ones.
type SysStat struct {
	Timestamp time.Time
	Counters  map[string]int64
}

// Get returns a counter value and whether it was present.
func (s *SysStat) Get(key string) (int64, bool) {
	if s == nil {
		return 0, false
	}
	v, ok := s.Counters[key]
	return v, ok
}

// Delta returns cur-prev for key when both snapshots have it and the result is
// non-negative (these are monotonic counters; a counter reset yields !ok).
func (s *SysStat) Delta(prev *SysStat, key string) (int64, bool) {
	cur, ok := s.Get(key)
	if !ok || prev == nil {
		return 0, false
	}
	p, ok := prev.Get(key)
	if !ok {
		return 0, false
	}
	d := cur - p
	if d < 0 {
		return 0, false
	}
	return d, true
}

// tcpBufferDropCounters count every segment TCP drops for want of buffer or
// memory: a full receive queue or memory refused (TCPRcvQDrop), a zero
// window (TCPZeroWindowDrop), out-of-order data (TCPOFODrop), pruning
// (RcvPruned, OfoPruned) and a full socket backlog (TCPBacklogDrop).
var tcpBufferDropCounters = []string{"TcpExt:TCPRcvQDrop", "TcpExt:TCPZeroWindowDrop", "TcpExt:TCPOFODrop", "TcpExt:RcvPruned", "TcpExt:OfoPruned", "TcpExt:TCPBacklogDrop"}

// TCPBufferDrops reports whether TCP dropped anything for want of buffer or
// memory between prev and s; ok is false when the counters can't tell.
func (s *SysStat) TCPBufferDrops(prev *SysStat) (dropped, ok bool) {
	for _, k := range tcpBufferDropCounters {
		if d, known := s.Delta(prev, k); known {
			ok = true
			dropped = dropped || d > 0
		}
	}
	return dropped, ok
}

// ReadSysStat reads and parses the host networking counters. /proc/net/snmp is
// required; /proc/net/netstat is best-effort (its absence isn't fatal).
func ReadSysStat() (*SysStat, error) {
	counters := make(map[string]int64)
	if err := parseProcNet("/proc/net/snmp", counters); err != nil {
		return nil, err
	}
	_ = parseProcNet("/proc/net/netstat", counters)
	if parseSockstat("/proc/net/sockstat", counters) == nil {
		counters["Sockstat:PageSize"] = int64(os.Getpagesize())
	}
	return &SysStat{Timestamp: time.Now(), Counters: counters}, nil
}

// parseSockstat parses /proc/net/sockstat lines of name/value pairs, e.g.
//
//	TCP: inuse 4 orphan 0 tw 0 alloc 5 mem 976
//
// into "Sockstat:TCPInuse", ..., "Sockstat:TCPMem".
func parseSockstat(path string, out map[string]int64) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(b), "\n") {
		proto, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		for i := 0; i+1 < len(f); i += 2 {
			if v, err := strconv.ParseInt(f[i+1], 10, 64); err == nil && f[i] != "" {
				out["Sockstat:"+proto+strings.ToUpper(f[i][:1])+f[i][1:]] = v
			}
		}
	}
	return nil
}

// parseProcNet parses the /proc/net/{snmp,netstat} format: alternating lines
// sharing a prefix, the first naming fields and the second giving values, e.g.
//
//	Tcp: RtoAlgorithm RtoMin ... RetransSegs InErrs OutRsts
//	Tcp: 1 200 ... 12345 0 6
//
// A line whose fields are all integers is a value row; otherwise it's a header
// row remembered for that prefix. Values are stored as "Prefix:Field".
func parseProcNet(path string, out map[string]int64) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	headers := make(map[string][]string)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		prefix := line[:colon]
		fields := strings.Fields(line[colon+1:])
		if len(fields) == 0 {
			continue
		}
		if allInts(fields) {
			names := headers[prefix]
			for i, v := range fields {
				if i >= len(names) {
					break
				}
				if n, err := strconv.ParseInt(v, 10, 64); err == nil {
					out[prefix+":"+names[i]] = n
				}
			}
		} else {
			headers[prefix] = fields
		}
	}
	return sc.Err()
}

func allInts(fields []string) bool {
	for _, f := range fields {
		if _, err := strconv.ParseInt(f, 10, 64); err != nil {
			return false
		}
	}
	return true
}

// Counter describes one host counter for display. Alert marks counters
// where any increase is bad (errors, drops, overflows).
type Counter struct {
	Label, Key string
	Alert      bool
}

// CounterGroup is a titled set of related counters.
type CounterGroup struct {
	Title    string
	Counters []Counter
}

// CounterGroups lists the host counters worth showing, grouped. The System
// tab and the markdown report both render from it.
var CounterGroups = []CounterGroup{
	{"TCP", []Counter{
		{"CurrEstab", "Tcp:CurrEstab", false},
		{"ActiveOpens", "Tcp:ActiveOpens", false},
		{"PassiveOpens", "Tcp:PassiveOpens", false},
		{"InSegs", "Tcp:InSegs", false},
		{"OutSegs", "Tcp:OutSegs", false},
		{"RetransSegs", "Tcp:RetransSegs", true},
		{"AttemptFails", "Tcp:AttemptFails", true},
		{"EstabResets", "Tcp:EstabResets", true},
		{"OutRsts", "Tcp:OutRsts", false},
		{"InErrs", "Tcp:InErrs", true},
	}},
	{"Accept queue / SYN", []Counter{
		{"ListenOverflows", "TcpExt:ListenOverflows", true},
		{"ListenDrops", "TcpExt:ListenDrops", true},
		{"SyncookiesSent", "TcpExt:SyncookiesSent", true},
		{"SyncookiesRecv", "TcpExt:SyncookiesRecv", true},
		{"TCPReqQFullDrop", "TcpExt:TCPReqQFullDrop", true},
	}},
	{"Loss / retransmit", []Counter{
		{"TCPSynRetrans", "TcpExt:TCPSynRetrans", false},
		{"TCPTimeouts", "TcpExt:TCPTimeouts", false},
		{"TCPLostRetransmit", "TcpExt:TCPLostRetransmit", true},
		{"TCPFastRetrans", "TcpExt:TCPFastRetrans", false},
		{"TCPSpuriousRTOs", "TcpExt:TCPSpuriousRTOs", false},
	}},
	{"Buffer pressure / OFO", []Counter{
		{"PruneCalled", "TcpExt:PruneCalled", true},
		{"RcvPruned", "TcpExt:RcvPruned", true},
		{"OfoPruned", "TcpExt:OfoPruned", true},
		{"TCPOFOQueue", "TcpExt:TCPOFOQueue", false},
		{"TCPBacklogDrop", "TcpExt:TCPBacklogDrop", true},
	}},
	{"UDP", []Counter{
		{"InDatagrams", "Udp:InDatagrams", false},
		{"OutDatagrams", "Udp:OutDatagrams", false},
		{"InErrors", "Udp:InErrors", true},
		{"RcvbufErrors", "Udp:RcvbufErrors", true},
		{"SndbufErrors", "Udp:SndbufErrors", true},
		{"NoPorts", "Udp:NoPorts", false},
	}},
}
