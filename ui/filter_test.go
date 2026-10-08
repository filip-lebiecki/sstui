package ui

import (
	"strings"
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
		// barewords match local addr, peer addr, or process name
		{"10.1.0.1", true},  // local addr
		{"10.0.0.1", true},  // peer addr
		{"sing", true},      // process name substring
		{"10.9.9.9", false}, // matches nothing
		{"ESTAB", true},     // known state name
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

// TestFilterSignalNames: signal= takes a label or type name in any case;
// unknown or removed names and unknown keys are rejected with a reason and
// leave the active filter unchanged instead of silently matching nothing.
func TestFilterSignalNames(t *testing.T) {
	c := &model.Connection{State: "ESTAB", Signals: []model.Signal{{Type: model.SignalRetransInFlight}}}
	for _, q := range []string{"signal=RETRANS", "signal=retrans", "signal=retrans_in_flight", "=ESTAB"} {
		f := &Filter{}
		if err := f.SetQuery(q); err != nil || !f.Matches(c) {
			t.Errorf("%q: err=%v, matches=%v; want a match", q, err, f.Matches(c))
		}
	}
	f := &Filter{}
	if err := f.SetQuery("signal=LOSS"); err != nil || f.Matches(c) {
		t.Errorf("signal=LOSS: err=%v, should parse and not match a RETRANS socket", err)
	}

	for _, tt := range []struct{ query, wantErr string }{
		{"signal=DEL_DROP", "signal DEL_DROP was removed"},
		{"proc=nginx and signal=bbr_underutil", "signal BBR_LOW was removed"},
		{"signal=RETRANZ", `unknown signal "RETRANZ"`},
		{"sigal=RETRANS", `unknown filter key "sigal"`},
		{"signal=DROPS:loud", `unknown signal level "loud"`},
	} {
		f := &Filter{}
		if err := f.SetQuery("state=ESTAB"); err != nil {
			t.Fatal(err)
		}
		err := f.SetQuery(tt.query)
		if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
			t.Errorf("%q: err = %v, want it to contain %q", tt.query, err, tt.wantErr)
		}
		if f.Query() != "state=ESTAB" || !f.IsActive() {
			t.Errorf("%q: rejected query replaced the active filter (now %q)", tt.query, f.Query())
		}
	}
}

// TestFilterSignalLevel: "signal=X:warn" matches X at warn or crit, not as
// info; ":crit" only at crit.
func TestFilterSignalLevel(t *testing.T) {
	at := func(sev int) *model.Connection {
		return &model.Connection{Signals: []model.Signal{{Type: model.SignalSocketDrops, Severity: sev}}}
	}
	for _, tt := range []struct {
		query string
		want  [3]bool // matches at info, warn, crit
	}{
		{"signal=DROPS", [3]bool{true, true, true}},
		{"signal=DROPS:warn", [3]bool{false, true, true}},
		{"signal=drops:CRIT", [3]bool{false, false, true}},
		{"not signal=DROPS:warn", [3]bool{true, false, false}},
	} {
		f := &Filter{}
		if err := f.SetQuery(tt.query); err != nil {
			t.Fatalf("%q: %v", tt.query, err)
		}
		for sev, want := range tt.want {
			if got := f.Matches(at(sev)); got != want {
				t.Errorf("%q at severity %d: match %v, want %v", tt.query, sev, got, want)
			}
		}
	}
}

func TestFilterExactAddress(t *testing.T) {
	near := &model.Connection{State: "ESTAB", PeerAddr: "10.0.0.50"}
	exact := &model.Connection{State: "ESTAB", PeerAddr: "10.0.0.5"}
	f := &Filter{}
	f.SetQuery("peer==10.0.0.5")
	if !f.Matches(exact) || f.Matches(near) {
		t.Errorf("peer== should match only the exact address")
	}
	f.SetQuery("peer=10.0.0.5")
	if !f.Matches(exact) || !f.Matches(near) {
		t.Errorf("peer= stays a substring match")
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
