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

// ReadSysStat reads and parses the host networking counters. /proc/net/snmp is
// required; /proc/net/netstat is best-effort (its absence isn't fatal).
func ReadSysStat() (*SysStat, error) {
	counters := make(map[string]int64)
	if err := parseProcNet("/proc/net/snmp", counters); err != nil {
		return nil, err
	}
	_ = parseProcNet("/proc/net/netstat", counters)
	return &SysStat{Timestamp: time.Now(), Counters: counters}, nil
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
