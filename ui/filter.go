package ui

import (
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

// SetQuery parses query into the filter expression. An empty or malformed query
// matches everything.
func (f *Filter) SetQuery(query string) {
	f.raw = strings.TrimSpace(query)
	f.root = parseFilter(f.raw)
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

// predNode is a single "key=value" condition. An empty key is a bareword.
type predNode struct{ key, value string }

func (n predNode) eval(c *model.Connection) bool { return matchPred(n.key, n.value, c) }

var knownStates = []string{
	"ESTAB", "LISTEN", "TIME-WAIT", "CLOSE-WAIT", "FIN-WAIT-1", "FIN-WAIT-2",
	"LAST-ACK", "SYN-SENT", "SYN-RECV", "CLOSING", "CLOSED",
	"UDP_ESTAB", "UDP_ACTIVE", "UDP_IDLE",
}

func matchPred(key, value string, c *model.Connection) bool {
	switch key {
	case "local":
		return strings.Contains(c.LocalAddr, value)
	case "peer":
		return strings.Contains(c.PeerAddr, value)
	case "sport":
		return c.LocalPort == value
	case "dport":
		return c.PeerPort == value
	case "state":
		return c.State == strings.ToUpper(value)
	case "proc":
		return c.Process != nil &&
			strings.Contains(strings.ToLower(*c.Process), strings.ToLower(value))
	case "pid":
		return c.PID != nil && strconv.Itoa(*c.PID) == value
	case "signal":
		want := strings.ToLower(value)
		for _, s := range c.Signals {
			if strings.ToLower(string(s.Type)) == want || strings.ToLower(s.Type.Label()) == want {
				return true
			}
		}
		return false
	case "":
		return matchBareword(value, c)
	}
	return false
}

// matchBareword matches a token with no "key=": a known state name filters by
// state, otherwise it's treated as a local-address substring.
func matchBareword(value string, c *model.Connection) bool {
	up := strings.ToUpper(value)
	for _, s := range knownStates {
		if up == s {
			return c.State == s
		}
	}
	return strings.Contains(c.LocalAddr, value)
}

// --- query parsing -------------------------------------------------------
//
// Grammar (lowest to highest precedence):
//
//	or   := and ( "or" and )*
//	and  := not ( "and"? not )*      // adjacent terms are implicitly AND-ed
//	not  := ("not" | "!") not | primary
//	primary := "(" or ")" | "key=value" | bareword

func parseFilter(s string) filterNode {
	p := &filterParser{toks: tokenizeFilter(s)}
	return p.parseOr()
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
	return makePred(t)
}

func makePred(tok string) filterNode {
	if i := strings.Index(tok, "="); i >= 0 {
		return predNode{key: strings.ToLower(tok[:i]), value: tok[i+1:]}
	}
	return predNode{value: tok}
}
