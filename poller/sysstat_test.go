package poller

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseProcNet(t *testing.T) {
	dir := t.TempDir()
	// Mimic /proc/net/snmp (Tcp/Udp) and netstat (TcpExt) shapes: a header line
	// of names followed by a value line sharing the prefix.
	snmp := "" +
		"Tcp: RtoAlgorithm RtoMin RetransSegs InErrs CurrEstab\n" +
		"Tcp: 1 200 12345 7 42\n" +
		"Udp: InDatagrams OutDatagrams InErrors RcvbufErrors\n" +
		"Udp: 1000 2000 3 9\n"
	path := filepath.Join(dir, "snmp")
	if err := os.WriteFile(path, []byte(snmp), 0o644); err != nil {
		t.Fatal(err)
	}

	out := map[string]int64{}
	if err := parseProcNet(path, out); err != nil {
		t.Fatalf("parseProcNet: %v", err)
	}

	want := map[string]int64{
		"Tcp:RetransSegs": 12345, "Tcp:InErrs": 7, "Tcp:CurrEstab": 42,
		"Udp:InErrors": 3, "Udp:RcvbufErrors": 9, "Udp:InDatagrams": 1000,
	}
	for k, v := range want {
		if got := out[k]; got != v {
			t.Errorf("%s = %d, want %d", k, got, v)
		}
	}
}

func TestParseSockstat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sockstat")
	data := "sockets: used 200\n" +
		"TCP: inuse 4 orphan 77 tw 0 alloc 82 mem 976\n" +
		"UDP: inuse 2 mem 3\n" +
		"FRAG: inuse 0 memory 0\n"
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	out := map[string]int64{}
	if err := parseSockstat(path, out); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]int64{"Sockstat:TCPMem": 976, "Sockstat:TCPOrphan": 77, "Sockstat:UDPMem": 3, "Sockstat:socketsUsed": 200} {
		if got, ok := out[k]; !ok || got != v {
			t.Errorf("%s = %d (present %v), want %d", k, got, ok, v)
		}
	}
}

func TestSysStatDelta(t *testing.T) {
	prev := &SysStat{Counters: map[string]int64{"Tcp:RetransSegs": 100, "Tcp:InErrs": 5}}
	cur := &SysStat{Counters: map[string]int64{"Tcp:RetransSegs": 150, "Tcp:InErrs": 5, "Tcp:OutSegs": 9}}

	if d, ok := cur.Delta(prev, "Tcp:RetransSegs"); !ok || d != 50 {
		t.Errorf("RetransSegs delta = %d (ok=%v), want 50", d, ok)
	}
	if d, ok := cur.Delta(prev, "Tcp:InErrs"); !ok || d != 0 {
		t.Errorf("InErrs delta = %d (ok=%v), want 0", d, ok)
	}
	// Missing in prev -> not ok (e.g. counter appeared this poll).
	if _, ok := cur.Delta(prev, "Tcp:OutSegs"); ok {
		t.Errorf("OutSegs absent from prev should yield !ok")
	}
	// Counter reset (cur < prev) -> not ok.
	reset := &SysStat{Counters: map[string]int64{"Tcp:RetransSegs": 10}}
	if _, ok := reset.Delta(prev, "Tcp:RetransSegs"); ok {
		t.Errorf("a counter reset should yield !ok")
	}
}

// TestReadSysStat is a light end-to-end check on the live host: /proc/net/snmp
// should yield at least the common TCP counters when present.
func TestReadSysStat(t *testing.T) {
	if _, err := os.Stat("/proc/net/snmp"); err != nil {
		t.Skip("/proc/net/snmp not available")
	}
	s, err := ReadSysStat()
	if err != nil {
		t.Fatalf("ReadSysStat: %v", err)
	}
	if _, ok := s.Get("Tcp:OutSegs"); !ok {
		t.Errorf("expected Tcp:OutSegs to be present")
	}
}
