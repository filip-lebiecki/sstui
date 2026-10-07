package ui

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"sstui/model"
)

// Filter holds the current filter state: a parsed boolean expression plus the
// always-on "hide LISTEN" toggle, which is controlled separately from the query.
type Filter struct {
	root       filterNode // nil matches every connection
	raw        string     // original query text, for display and IsActive
	HideListen bool
}

// Matches returns true if a connection matches the filter criteria.
func (f *Filter) Matches(c *model.Connection) bool {
	if f.HideListen && c.State == "LISTEN" {
		return false
	}
	if f.root == nil {
		return true
	}
	return f.root.eval(c)
}

// SetQuery parses query into the filter expression; an empty query matches
// everything. A query naming an unknown key or signal is rejected with an
// error and the filter is left unchanged: such a term can never match, so
// applying it would show an empty table that looks like "no problems".
func (f *Filter) SetQuery(query string) error {
	q := strings.TrimSpace(query)
	root, err := parseFilter(q)
	if err != nil {
		return err
	}
	f.raw, f.root = q, root
	return nil
}

// Query returns the raw query text.
func (f *Filter) Query() string {
	return f.raw
}

// IsActive returns true if a filter expression is set.
func (f *Filter) IsActive() bool {
	return f.root != nil
}

// Reset clears the filter expression (HideListen is left untouched).
func (f *Filter) Reset() {
	f.root = nil
	f.raw = ""
}

// filterNode is a node in the parsed filter expression tree.
type filterNode interface {
	eval(c *model.Connection) bool
}

type andNode struct{ left, right filterNode }

func (n andNode) eval(c *model.Connection) bool { return n.left.eval(c) && n.right.eval(c) }

type orNode struct{ left, right filterNode }

func (n orNode) eval(c *model.Connection) bool { return n.left.eval(c) || n.right.eval(c) }

type notNode struct{ child filterNode }

func (n notNode) eval(c *model.Connection) bool { return !n.child.eval(c) }

// predNode is a single "key=value" condition or bareword, with its matcher
// resolved when parsed.
type predNode struct {
	match func(c *model.Connection, value string) bool
	value string
}

func (n predNode) eval(c *model.Connection) bool { return n.match(c, n.value) }

// signalNode is a "signal=<name>" condition, resolved to its type when parsed.
type signalNode struct{ typ model.SignalType }

func (n signalNode) eval(c *model.Connection) bool {
	for _, s := range c.Signals {
		if s.Type == n.typ {
			return true
		}
	}
	return false
}

// removedSignals are signals sstui no longer raises, so an old query or
// runbook is told why instead of getting an empty table.
var removedSignals = map[string]string{
	"del_drop": "DEL_DROP", "delivery_drop": "DEL_DROP",
	"bbr_low": "BBR_LOW", "bbr_underutil": "BBR_LOW",
}

var knownStates = []string{
	"ESTAB", "LISTEN", "TIME-WAIT", "CLOSE-WAIT", "FIN-WAIT-1", "FIN-WAIT-2",
	"LAST-ACK", "SYN-SENT", "SYN-RECV", "CLOSING", "CLOSED",
	"UDP_ESTAB", "UDP_ACTIVE", "UDP_IDLE",
}

// keyMatchers holds the condition for each "key=value" filter key. It is
// also the list of valid keys; "signal" is parsed separately (signalNode).
var keyMatchers = map[string]func(c *model.Connection, value string) bool{
	"proto": func(c *model.Connection, v string) bool { return strings.EqualFold(c.Protocol, v) },
	"local": func(c *model.Connection, v string) bool { return matchAddr(c.LocalAddr, v) },
	"peer":  func(c *model.Connection, v string) bool { return matchAddr(c.PeerAddr, v) },
	"sport": func(c *model.Connection, v string) bool { return c.LocalPort == v },
	"dport": func(c *model.Connection, v string) bool { return c.PeerPort == v },
	"state": func(c *model.Connection, v string) bool { return c.State == strings.ToUpper(v) },
	"proc": func(c *model.Connection, v string) bool {
		return c.Process != nil && strings.Contains(strings.ToLower(*c.Process), strings.ToLower(v))
	},
	"pid": func(c *model.Connection, v string) bool { return c.PID != nil && strconv.Itoa(*c.PID) == v },
}

// filterKeys lists the valid keys, sorted, for error messages.
func filterKeys() string {
	keys := append(slices.Collect(maps.Keys(keyMatchers)), "signal")
	slices.Sort(keys)
	return strings.Join(keys, " ")
}

// matchAddr is a substring match ("peer=10.0" selects a range), or an exact
// match with a doubled "=" ("peer==10.0.0.5" excludes 10.0.0.50). The token
// "peer==x" parses as key "peer", value "=x".
func matchAddr(addr, value string) bool {
	if exact, ok := strings.CutPrefix(value, "="); ok {
		return addr == exact
	}
	return strings.Contains(addr, value)
}

// matchBareword matches a token with no "key=": a known state name filters by
// state, otherwise it's a substring match against either endpoint address or
// the process name — whichever the user most likely meant. Restricting it to
// the local address (as it once did) silently missed the common cases of
// filtering by peer host or process.
func matchBareword(c *model.Connection, value string) bool {
	up := strings.ToUpper(value)
	for _, s := range knownStates {
		if up == s {
			return c.State == s
		}
	}
	if strings.Contains(c.LocalAddr, value) || strings.Contains(c.PeerAddr, value) {
		return true
	}
	if c.Process != nil && strings.Contains(strings.ToLower(*c.Process), strings.ToLower(value)) {
		return true
	}
	return false
}

// --- query parsing -------------------------------------------------------
//
// Grammar (lowest to highest precedence):
//
//	or   := and ( "or" and )*
//	and  := not ( "and"? not )*      // adjacent terms are implicitly AND-ed
//	not  := ("not" | "!") not | primary
//	primary := "(" or ")" | "key=value" | bareword

func parseFilter(s string) (filterNode, error) {
	p := &filterParser{toks: tokenizeFilter(s)}
	root := p.parseOr()
	return root, p.err
}

// tokenizeFilter splits the query on whitespace, treating parentheses as their
// own tokens even when adjacent to a term (e.g. "(peer=1.2.3.4").
func tokenizeFilter(s string) []string {
	var toks []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			toks = append(toks, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		switch r {
		case '(', ')':
			flush()
			toks = append(toks, string(r))
		case ' ', '\t':
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return toks
}

type filterParser struct {
	toks []string
	pos  int
	err  error // first unknown key or signal name
}

func (p *filterParser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *filterParser) advance() { p.pos++ }

func (p *filterParser) parseOr() filterNode {
	left := p.parseAnd()
	for strings.EqualFold(p.peek(), "or") {
		p.advance()
		right := p.parseAnd()
		if right == nil {
			break
		}
		if left == nil {
			left = right
			continue
		}
		left = orNode{left, right}
	}
	return left
}

func (p *filterParser) parseAnd() filterNode {
	left := p.parseNot()
	for {
		t := p.peek()
		if t == "" || t == ")" || strings.EqualFold(t, "or") {
			break
		}
		if strings.EqualFold(t, "and") {
			p.advance()
		}
		right := p.parseNot()
		if right == nil {
			break
		}
		if left == nil {
			left = right
			continue
		}
		left = andNode{left, right}
	}
	return left
}

func (p *filterParser) parseNot() filterNode {
	if t := p.peek(); strings.EqualFold(t, "not") || t == "!" {
		p.advance()
		child := p.parseNot()
		if child == nil {
			return nil
		}
		return notNode{child}
	}
	return p.parsePrimary()
}

func (p *filterParser) parsePrimary() filterNode {
	t := p.peek()
	switch t {
	case "":
		return nil
	case "(":
		p.advance()
		node := p.parseOr()
		if p.peek() == ")" {
			p.advance()
		}
		return node
	case ")":
		return nil
	}
	p.advance()
	return p.makePred(t)
}

func (p *filterParser) makePred(tok string) filterNode {
	key, value, ok := strings.Cut(tok, "=")
	switch {
	case !ok:
		return predNode{matchBareword, tok}
	case key == "": // "=x" has always been the bareword x
		return predNode{matchBareword, value}
	}
	key = strings.ToLower(key)
	if key == "signal" {
		return p.makeSignal(value)
	}
	match, known := keyMatchers[key]
	if !known {
		p.fail(fmt.Errorf("unknown filter key %q (keys: %s)", key, filterKeys()))
		return signalNode{} // never evaluated: the query is rejected
	}
	return predNode{match, value}
}

func (p *filterParser) makeSignal(name string) filterNode {
	if t, ok := model.ParseSignalType(name); ok {
		return signalNode{t}
	}
	if label, ok := removedSignals[strings.ToLower(name)]; ok {
		p.fail(fmt.Errorf("signal %s was removed (it fired on healthy traffic); a slow sender shows RWND_LIM, SNDBUF_LIM, LOSS or HI_RETRANS", label))
	} else {
		p.fail(fmt.Errorf("unknown signal %q (signals: %s)", name, strings.Join(model.SignalLabels(), " ")))
	}
	return signalNode{}
}

func (p *filterParser) fail(err error) {
	if p.err == nil {
		p.err = err
	}
}
