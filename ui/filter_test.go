package ui

import (
	"testing"

	"sstui/model"
)

func sp(s string) *string { return &s }
func ip(i int) *int       { return &i }

func conn(local, lport, peer, pport, state string, pid *int, proc *string) *model.Connection {
	return &model.Connection{
		LocalAddr: local, LocalPort: lport,
		PeerAddr: peer, PeerPort: pport,
		State: state, PID: pid, Process: proc,
	}
}

func TestFilterExpressions(t *testing.T) {
	c := conn("10.1.0.1", "1234", "10.0.0.1", "8389", "ESTAB", ip(3552), sp("sing-box"))

	tests := []struct {
		query string
		want  bool
	}{
		{"", true},
		{"peer=10.0.0.1", true},
		{"peer=10.9.9.9", false},
		{"sport=1234", true},
		{"sport=9999", false},
		{"dport=8389", true},
		{"dport=443", false},
		{"pid=3552", true},
		{"pid=1", false},
		{"proc=sing", true},
		{"proc=NGINX", false},
		{"state=ESTAB", true},
		{"state=listen", false},
		// boolean operators
		{"peer=10.0.0.1 and sport=1234", true},
		{"peer=10.0.0.1 and sport=9999", false},
		{"peer=10.9.9.9 or sport=1234", true},
		{"peer=10.9.9.9 or sport=9999", false},
		{"not peer=10.9.9.9", true},
		{"not peer=10.0.0.1", false},
		// implicit AND (space)
		{"peer=10.0.0.1 sport=1234", true},
		{"peer=10.0.0.1 sport=9999", false},
		// grouping with precedence
		{"(peer=10.0.0.1 or peer=10.1.0.1) and sport=1234", true},
		{"(peer=10.9.9.9 or peer=10.8.8.8) and sport=1234", false},
		{"(peer=10.0.0.1 or peer=10.1.0.1) and sport=9999", false},
	}

	for _, tt := range tests {
		f := &Filter{}
		f.SetQuery(tt.query)
		if got := f.Matches(c); got != tt.want {
			t.Errorf("query %q: got %v, want %v", tt.query, got, tt.want)
		}
	}
}

func TestFilterHideListen(t *testing.T) {
	c := conn("0.0.0.0", "80", "0.0.0.0", "*", "LISTEN", nil, nil)
	f := &Filter{HideListen: true}
	if f.Matches(c) {
		t.Errorf("LISTEN connection should be hidden when HideListen is set")
	}
	f.HideListen = false
	if !f.Matches(c) {
		t.Errorf("LISTEN connection should match when HideListen is off and no query")
	}
}
