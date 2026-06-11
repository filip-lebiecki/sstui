package parser

import (
	"errors"
	"strings"
	"testing"

	"sstui/model"
)

func tcpConn() *model.Connection { return &model.Connection{Protocol: "tcp", State: "ESTAB"} }
func udpConn() *model.Connection { return &model.Connection{Protocol: "udp", State: "ESTAB"} }

func TestMergeResultsBothOK(t *testing.T) {
	conns, err := mergeResults([]*model.Connection{tcpConn()}, nil, []*model.Connection{udpConn()}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(conns) != 2 {
		t.Fatalf("got %d conns, want 2", len(conns))
	}
	// UDP synthetic state must be applied during merge.
	if conns[1].State != "UDP_ESTAB" {
		t.Errorf("udp state = %q, want UDP_ESTAB", conns[1].State)
	}
}

func TestMergeResultsBothFail(t *testing.T) {
	conns, err := mergeResults(nil, errors.New("boom-tcp"), nil, errors.New("boom-udp"))
	if conns != nil {
		t.Errorf("expected nil conns on total failure, got %d", len(conns))
	}
	if err == nil || !strings.Contains(err.Error(), "boom-tcp") || !strings.Contains(err.Error(), "boom-udp") {
		t.Errorf("error %v should mention both failures", err)
	}
}

func TestMergeResultsTCPFails(t *testing.T) {
	conns, err := mergeResults(nil, errors.New("nope"), []*model.Connection{udpConn()}, nil)
	if len(conns) != 1 || conns[0].Protocol != "udp" {
		t.Fatalf("expected UDP-only data, got %v", conns)
	}
	if err == nil || !strings.Contains(err.Error(), "showing UDP only") {
		t.Errorf("expected partial-failure error, got %v", err)
	}
}

func TestMergeResultsUDPFails(t *testing.T) {
	conns, err := mergeResults([]*model.Connection{tcpConn()}, nil, nil, errors.New("nope"))
	if len(conns) != 1 || conns[0].Protocol != "tcp" {
		t.Fatalf("expected TCP-only data, got %v", conns)
	}
	if err == nil || !strings.Contains(err.Error(), "showing TCP only") {
		t.Errorf("expected partial-failure error, got %v", err)
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
	conns, drops, err := RunSS()
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
