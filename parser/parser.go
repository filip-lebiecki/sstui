package parser

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"sstui/model"
)

// congAlgos are the congestion-control names ss prints as a bare token in the
// tcp_info section (e.g. "ts sack cubic wscale:7,7").
var congAlgos = map[string]bool{
	"cubic": true, "bbr": true, "reno": true, "vegas": true, "htcp": true,
	"cdg": true, "dctcp": true, "lp": true, "nv": true, "hybla": true,
	"illinois": true, "highspeed": true, "scalable": true, "westwood": true,
	"yeah": true, "bic": true,
}

func parseAddrPort(raw string) (addr, port string) {
	if raw == "*" {
		return "*", "*"
	}
	if strings.HasPrefix(raw, "[") {
		if end := strings.LastIndex(raw, "]:"); end > 0 && end+2 < len(raw) {
			return raw[1:end], raw[end+2:]
		}
	}
	if i := strings.LastIndexByte(raw, ':'); i >= 0 {
		return raw[:i], raw[i+1:]
	}
	return raw, "*"
}

// slab backs the numeric pointer fields of one Connection. The model uses
// pointers so "absent" (nil) is distinct from 0; allocating each value
// separately cost ~90 allocations per socket. Handing out pointers into one
// per-connection array makes it a single allocation, and since every pointer
// lives exactly as long as its Connection, nothing is retained longer.
type slab struct {
	ints   [56]int
	floats [16]float64
	ni, nf int
}

func (s *slab) int(v int) *int {
	if s.ni == len(s.ints) {
		p := new(int) // not &v: that would heap-allocate v on every call
		*p = v
		return p
	}
	p := &s.ints[s.ni]
	s.ni++
	*p = v
	return p
}

func (s *slab) float(v float64) *float64 {
	if s.nf == len(s.floats) {
		p := new(float64)
		*p = v
		return p
	}
	p := &s.floats[s.nf]
	s.nf++
	*p = v
	return p
}

// atoi parses a non-negative decimal integer without allocating.
func (s *slab) atoi(v string) *int {
	n, err := strconv.Atoi(v)
	if err != nil {
		return nil
	}
	return s.int(n)
}

func (s *slab) atof(v string) *float64 {
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return nil
	}
	return s.float(f)
}

// parseBPS parses an ss rate like "43415650bps" (also tolerating the
// human-readable "43.4Mbps" form ss prints without -n, and "123bps/456bps"
// where only the first value is the current rate).
func (s *slab) parseBPS(v string) *int {
	if i := strings.IndexByte(v, '/'); i >= 0 {
		v = v[:i]
	}
	v, ok := strings.CutSuffix(v, "bps")
	if !ok || v == "" {
		return nil
	}
	mult := 1.0
	switch v[len(v)-1] {
	case 'K', 'k':
		mult, v = 1e3, v[:len(v)-1]
	case 'M':
		mult, v = 1e6, v[:len(v)-1]
	case 'G':
		mult, v = 1e9, v[:len(v)-1]
	}
	if mult == 1 {
		return s.atoi(v)
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return nil
	}
	return s.int(int(f * mult))
}

// parseMS parses "500ms" or "1800ms(45.0%)" into milliseconds.
func (s *slab) parseMS(v string) *float64 {
	if i := strings.IndexByte(v, 'm'); i >= 0 && strings.HasPrefix(v[i:], "ms") {
		return s.atof(v[:i])
	}
	return nil
}

// strPtr returns a pointer to a copy of s. Taking &v of a loop or case-local
// variable directly makes the compiler heap-allocate it on every iteration,
// even on paths that never take its address.
func strPtr(s string) *string { return &s }

// splitPair splits "a/b" or "a,b".
func splitPair(v string, sep byte) (string, string, bool) {
	i := strings.IndexByte(v, sep)
	if i < 0 {
		return "", "", false
	}
	return v[:i], v[i+1:], true
}

// nextField returns the next whitespace-delimited field of s starting at i, and
// the index just past it. tok is "" at end of input.
func nextField(s string, i int) (tok string, next int) {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	j := i
	for j < len(s) && s[j] != ' ' && s[j] != '\t' {
		j++
	}
	return s[i:j], j
}

// usersEnd returns the index just past the users:((...)) block starting at i.
// Process names are quoted and may contain spaces or parentheses, so the
// closing "))" is searched for outside quotes.
func usersEnd(s string, i int) int {
	inQuote := false
	for j := i; j < len(s); j++ {
		switch s[j] {
		case '"':
			inQuote = !inQuote
		case ')':
			if !inQuote && j+1 < len(s) && s[j+1] == ')' {
				return j + 2
			}
		}
	}
	return len(s)
}

// parseUsers extracts the first process name and pid from a users:((...))
// block, e.g. users:(("nginx",pid=12,fd=6),("nginx",pid=13,fd=6)).
func parseUsers(c *model.Connection, sl *slab, block string) {
	if i := strings.IndexByte(block, '"'); i >= 0 {
		if j := strings.IndexByte(block[i+1:], '"'); j >= 0 {
			c.Process = strPtr(block[i+1 : i+1+j])
			block = block[i+2+j:]
		}
	}
	if i := strings.Index(block, "pid="); i >= 0 {
		v := block[i+4:]
		j := 0
		for j < len(v) && v[j] >= '0' && v[j] <= '9' {
			j++
		}
		c.PID = sl.atoi(v[:j])
	}
}

// parseSkmem parses skmem:(r0,rb131072,t0,tb87040,f0,w0,o0,bl0,d0).
func parseSkmem(c *model.Connection, sl *slab, v string) {
	v = strings.TrimSuffix(strings.TrimPrefix(v, "("), ")")
	for len(v) > 0 {
		var item string
		item, v, _ = strings.Cut(v, ",")
		j := 0
		for j < len(item) && (item[j] < '0' || item[j] > '9') {
			j++
		}
		n := sl.atoi(item[j:])
		switch item[:j] {
		case "r":
			c.SkmemR = n
		case "rb":
			c.SkmemRB = n
		case "t":
			c.SkmemT = n
		case "tb":
			c.SkmemTB = n
		case "f":
			c.SkmemF = n
		case "w":
			c.SkmemW = n
		case "o":
			c.SkmemO = n
		case "bl":
			c.SkmemBL = n
		case "d":
			c.SkmemD = n
		}
	}
}

// parseBBR parses bbr:(bw:123bps,mrtt:1.2,pacing_gain:2.88,cwnd_gain:2.88).
func parseBBR(c *model.Connection, sl *slab, v string) {
	v = strings.TrimSuffix(strings.TrimPrefix(v, "("), ")")
	for len(v) > 0 {
		var item string
		item, v, _ = strings.Cut(v, ",")
		k, val, _ := strings.Cut(item, ":")
		switch k {
		case "bw":
			c.BBRBW = sl.parseBPS(val)
		case "mrtt":
			c.BBRMRTT = sl.atof(val)
		case "pacing_gain":
			c.BBRPacingGain = sl.atof(val)
		case "cwnd_gain":
			c.BBRCWndGain = sl.atof(val)
		}
	}
}

// ParseLine parses a single ss record (without the Netid column) into a
// Connection. It is a single left-to-right pass over the fields: identity
// columns first, then "key:value" tokens dispatched on the key. A few metrics
// are printed as two tokens ("send 123bps", "pacing_rate 123bps"); for those
// the key is remembered and applied to the next token.
func ParseLine(line string) (*model.Connection, error) {
	return parseRecord(line, time.Now())
}

func parseRecord(line string, ts time.Time) (*model.Connection, error) {
	var cols [5]string
	i := 0
	for n := range cols {
		cols[n], i = nextField(line, i)
		if cols[n] == "" {
			return nil, nil
		}
	}

	sl := new(slab)
	c := &model.Connection{
		Timestamp: ts,
		State:     cols[0],
		RecvQ:     sl.atoi(cols[1]),
		SendQ:     sl.atoi(cols[2]),
	}
	c.LocalAddr, c.LocalPort = parseAddrPort(cols[3])
	c.PeerAddr, c.PeerPort = parseAddrPort(cols[4])

	pending := "" // two-token metric awaiting its value
	for {
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		if i >= len(line) {
			break
		}
		if strings.HasPrefix(line[i:], "users:(") {
			end := usersEnd(line, i)
			parseUsers(c, sl, line[i:end])
			i = end
			continue
		}
		var tok string
		tok, i = nextField(line, i)

		if pending != "" {
			switch pending {
			case "send":
				c.SendBPS = sl.parseBPS(tok)
			case "pacing_rate":
				c.PacingRate = sl.parseBPS(tok)
			case "delivery_rate":
				c.DeliveryRate = sl.parseBPS(tok)
			}
			pending = ""
			continue
		}

		key, val, hasVal := strings.Cut(tok, ":")
		if !hasVal {
			switch {
			case tok == "send" || tok == "pacing_rate" || tok == "delivery_rate":
				pending = tok
			case tok == "app_limited":
				c.AppLimited = 1
			case tok == "ts":
				c.Timestamps = true
			case congAlgos[tok]:
				c.CongAlgo = strPtr(tok)
			}
			continue
		}

		switch key {
		case "uid":
			c.UID = sl.atoi(val)
		case "ino":
			c.Inode = strPtr(val)
		case "cgroup":
			c.Cgroup = strPtr(val)
		case "skmem":
			parseSkmem(c, sl, val)
		case "timer":
			// timer:(keepalive,50sec,0)
			inner := strings.TrimSuffix(strings.TrimPrefix(val, "("), ")")
			if typ, rest, ok := strings.Cut(inner, ","); ok {
				if dur, n, ok := strings.Cut(rest, ","); ok {
					c.TimerType = strPtr(typ)
					c.TimerDur = strPtr(dur)
					c.TimerRetrans = sl.atoi(n)
				}
			}
		case "wscale":
			if a, b, ok := splitPair(val, ','); ok {
				c.WscaleSnd, c.WscaleRcv = sl.atoi(a), sl.atoi(b)
			}
		case "rto":
			c.RTO = sl.atof(val)
		case "rtt":
			if a, b, ok := splitPair(val, '/'); ok {
				c.RTT, c.RTTVar = sl.atof(a), sl.atof(b)
			}
		case "ato":
			c.ATO = sl.atof(val)
		case "mss":
			c.MSS = sl.atoi(val)
		case "pmtu":
			c.PMTU = sl.atoi(val)
		case "rcvmss":
			c.RcvMSS = sl.atoi(val)
		case "advmss":
			c.AdvMSS = sl.atoi(val)
		case "cwnd":
			c.CWnd = sl.atoi(val)
		case "ssthresh":
			c.SSThresh = sl.atoi(val)
		case "bytes_sent":
			c.BytesSent = sl.atoi(val)
		case "bytes_retrans":
			c.BytesRetrans = sl.atoi(val)
		case "bytes_acked":
			c.BytesAcked = sl.atoi(val)
		case "bytes_received":
			c.BytesReceived = sl.atoi(val)
		case "segs_out":
			c.SegsOut = sl.atoi(val)
		case "segs_in":
			c.SegsIn = sl.atoi(val)
		case "data_segs_out":
			c.DataSegsOut = sl.atoi(val)
		case "data_segs_in":
			c.DataSegsIn = sl.atoi(val)
		case "bbr":
			parseBBR(c, sl, val)
		case "lastsnd":
			c.LastSnd = sl.atoi(val)
		case "lastrcv":
			c.LastRcv = sl.atoi(val)
		case "lastack":
			c.LastAck = sl.atoi(val)
		case "delivered":
			c.Delivered = sl.atoi(val)
		case "delivered_ce":
			c.DeliveredCE = sl.atoi(val)
		case "busy":
			c.BusyMS = sl.parseMS(val)
		case "rwnd_limited":
			c.RwndLimitedMS = sl.parseMS(val)
		case "sndbuf_limited":
			c.SndbufLimitedMS = sl.parseMS(val)
		case "unacked":
			c.Unacked = sl.atoi(val)
		case "retrans":
			if a, b, ok := splitPair(val, '/'); ok {
				c.RetransNow, c.Retrans = sl.atoi(a), sl.atoi(b)
			}
		case "lost":
			c.Lost = sl.atoi(val)
		case "reordering":
			c.Reordering = sl.atoi(val)
		case "reord_seen":
			c.ReordSeen = sl.atoi(val)
		case "dsack_dups":
			c.DSACKDups = sl.atoi(val)
		case "rcv_rtt":
			c.RcvRTT = sl.atof(val)
		case "rcv_space":
			c.RcvSpace = sl.atoi(val)
		case "rcv_ssthresh":
			c.RcvSSThresh = sl.atoi(val)
		case "minrtt":
			c.MinRTT = sl.atof(val)
		case "rcv_ooopack":
			c.RcvOOOPack = sl.atoi(val)
		case "snd_wnd":
			c.SndWnd = sl.atoi(val)
		case "rcv_wnd":
			c.RcvWnd = sl.atoi(val)
		}
	}
	return c, nil
}

// ssFlags queries TCP and UDP in one ss invocation. With both -t and -u, ss
// prefixes each record with a Netid column ("tcp"/"udp"). One call instead of
// two halves the cost of -p, which makes ss walk every /proc/<pid>/fd.
const ssFlags = "-atunpeimOH"

// SSFilter is a filter expression handed to ss itself (its STATE-FILTER and
// EXPRESSION arguments, see ss(8)), so non-matching sockets are never
// collected — unlike the UI filter, which hides sockets after collection.
// The zero value means "no filter".
type SSFilter struct {
	expr string
	args []string // the expression split into ss argv words
	// impliedState is set when the filter selects exactly one TCP state:
	// ss then omits the State column, so the parser fills it in. It's only a
	// label: whether the column is missing is detected per record.
	impliedState string
}

// ssStateNames maps ss filter state keywords to the State-column names ss
// prints. Group keywords (all, connected, synchronized, bucket, big) select
// several states, in which case ss keeps the column.
var ssStateNames = map[string]string{
	"established": "ESTAB", "syn-sent": "SYN-SENT", "syn-recv": "SYN-RECV",
	"fin-wait-1": "FIN-WAIT-1", "fin-wait-2": "FIN-WAIT-2", "time-wait": "TIME-WAIT",
	"closed": "UNCONN", "close-wait": "CLOSE-WAIT", "last-ack": "LAST-ACK",
	"listening": "LISTEN", "closing": "CLOSING",
}

// ParseSSFilter prepares a user-supplied ss filter, e.g.
//
//	dport = :443 or sport = :22
//	state established ( dst 10.0.0.0/8 )
//
// The expression is split into words (parentheses become their own words,
// which ss requires). Words starting with "-" are rejected: they'd reach ss
// as options, and some are destructive (-K kills the matching sockets).
func ParseSSFilter(expr string) (SSFilter, error) {
	f := SSFilter{expr: strings.TrimSpace(expr)}
	if f.expr == "" {
		return SSFilter{}, nil
	}
	f.args = strings.Fields(strings.NewReplacer("(", " ( ", ")", " ) ").Replace(f.expr))
	states, multi := []string{}, false
	for i, w := range f.args {
		if strings.HasPrefix(w, "-") {
			return SSFilter{}, fmt.Errorf("ss filter: %q looks like an option; only filter expressions are allowed", w)
		}
		switch strings.ToLower(w) {
		case "state":
			if i+1 < len(f.args) {
				states = append(states, strings.ToLower(f.args[i+1]))
			}
		case "exclude", "excl":
			multi = true
		}
	}
	if len(states) == 1 && !multi {
		f.impliedState = ssStateNames[states[0]]
	}
	return f, nil
}

// String returns the filter as the user wrote it.
func (f SSFilter) String() string { return f.expr }

// Active reports whether a filter is set.
func (f SSFilter) Active() bool { return len(f.args) > 0 }

// CheckSSFilter runs ss once with the filter (cheaply: no process or TCP
// info) so a malformed expression fails at startup with ss's own message.
func CheckSSFilter(f SSFilter) error {
	if !f.Active() {
		return nil
	}
	// Only ss's verdict matters: discard the (possibly huge) socket listing
	// and keep stderr for the error message.
	cmd := exec.Command("ss", append([]string{"-atunH"}, f.args...)...)
	var stderr strings.Builder
	cmd.Stdout, cmd.Stderr = io.Discard, &stderr
	if err := cmd.Run(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return errSSNotFound
		}
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("invalid ss filter %q: %s", f.expr, firstLine(msg))
	}
	return nil
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

// RunSS runs ss for TCP and UDP (restricted to f when set) and returns the
// connections plus the number of record lines that could not be parsed (so
// the UI can surface a silent parse failure rather than dropping sockets
// invisibly).
func RunSS(f SSFilter) ([]*model.Connection, int, error) {
	conns, drops, err := runSS(ssFlags, "", f)
	if err != nil && !errors.Is(err, errSSNotFound) {
		// The combined query can fail when one protocol's socket diagnostics
		// are unavailable (restricted netlink, missing diag module). Fall
		// back to per-protocol queries so the one that works is still shown.
		tcp, tcpDrops, tcpErr := runSS("-atnpeimOH", "tcp", f)
		udp, udpDrops, udpErr := runSS("-aunpeimOH", "udp", f)
		conns, err = mergeResults(tcp, tcpErr, udp, udpErr)
		drops = tcpDrops + udpDrops
	}
	if conns == nil {
		return nil, 0, err
	}
	postProcess(conns)
	return conns, drops, err
}

// mergeResults combines per-protocol fallback results. When both queries fail
// it returns a nil slice and an error (the caller keeps the last good
// snapshot). When only one fails it returns the protocol that succeeded plus
// an error describing the partial result, so the UI can flag it rather than
// silently dropping a whole protocol.
func mergeResults(tcpConns []*model.Connection, tcpErr error, udpConns []*model.Connection, udpErr error) ([]*model.Connection, error) {
	switch {
	case tcpErr != nil && udpErr != nil:
		return nil, fmt.Errorf("tcp: %v; udp: %v", tcpErr, udpErr)
	case tcpErr != nil:
		return udpConns, fmt.Errorf("tcp query failed (showing UDP only): %v", tcpErr)
	case udpErr != nil:
		return tcpConns, fmt.Errorf("udp query failed (showing TCP only): %v", udpErr)
	}
	return append(tcpConns, udpConns...), nil
}

// postProcess applies the cross-record fixups: synthetic UDP states and
// zero-filling counters ss omits while they are 0.
func postProcess(conns []*model.Connection) {
	for _, c := range conns {
		if c.Protocol == "udp" {
			applyUDPState(c)
		}
	}
	fillOmittedZeros(conns)
}

var errSSNotFound = errors.New("ss not found in PATH; install iproute2")

// parseProtoRecord parses one record. With protocol "" the record starts with
// ss's Netid column (combined -t -u output), which is split off and used as
// the protocol; otherwise the record has no Netid column and protocol is
// applied. skip is true for protocols sstui doesn't track (not a drop).
func parseProtoRecord(line, protocol, impliedState string, ts time.Time) (c *model.Connection, skip bool) {
	netid, i := protocol, 0
	if protocol == "" {
		netid, i = nextField(line, 0)
		if netid != "tcp" && netid != "udp" {
			return nil, true
		}
	}
	rec := line[i:]
	// ss omits the State column when its filter selects a single state. That
	// is detected from the record itself — the first field is then Recv-Q (a
	// number), and a state name never starts with a digit — rather than
	// predicted from the filter text, so an unmodeled keyword can't shift
	// every column. The filter only supplies the label.
	if first, _ := nextField(rec, 0); first != "" && first[0] >= '0' && first[0] <= '9' {
		state := impliedState
		if state == "" {
			state = "UNKNOWN"
		}
		rec = state + " " + rec
	}
	c, err := parseRecord(rec, ts)
	if err != nil || c == nil {
		return nil, false
	}
	c.Protocol = netid
	return c, false
}

// omittedGroup is a set of tcp_info counters that ss prints only when they're
// non-zero, all introduced to the kernel's tcp_info together. The sentinel is a
// member that is almost always non-zero on a live socket, so seeing it on any
// socket proves the running kernel reports the whole group.
type omittedGroup struct {
	sentinel func(*model.Connection) bool
	fields   func(*model.Connection) []**int
	floats   func(*model.Connection) []**float64
}

var omittedGroups = []omittedGroup{
	{ // Linux 4.1/4.2: bytes_acked, bytes_received, segs_out, segs_in
		sentinel: func(c *model.Connection) bool { return c.SegsOut != nil },
		fields: func(c *model.Connection) []**int {
			return []**int{&c.BytesAcked, &c.BytesReceived, &c.SegsOut, &c.SegsIn}
		},
	},
	{ // unacked is printed only when non-zero (it's in every tcp_info version)
		sentinel: func(c *model.Connection) bool { return true },
		fields: func(c *model.Connection) []**int {
			return []**int{&c.Unacked}
		},
	},
	{ // Linux 4.10: busy, rwnd_limited, sndbuf_limited
		sentinel: func(c *model.Connection) bool { return c.BusyMS != nil },
		floats: func(c *model.Connection) []**float64 {
			return []**float64{&c.BusyMS, &c.RwndLimitedMS, &c.SndbufLimitedMS}
		},
	},
	{ // Linux 4.6: data_segs_out, data_segs_in
		sentinel: func(c *model.Connection) bool { return c.DataSegsOut != nil || c.DataSegsIn != nil },
		fields: func(c *model.Connection) []**int {
			return []**int{&c.DataSegsOut, &c.DataSegsIn}
		},
	},
	{ // Linux 4.19: bytes_sent, bytes_retrans, dsack_dups, reord_seen
		sentinel: func(c *model.Connection) bool { return c.BytesSent != nil },
		fields: func(c *model.Connection) []**int {
			return []**int{&c.BytesSent, &c.BytesRetrans, &c.DSACKDups, &c.ReordSeen}
		},
	},
	{ // Linux 4.18: delivered, delivered_ce
		sentinel: func(c *model.Connection) bool { return c.Delivered != nil },
		fields: func(c *model.Connection) []**int {
			return []**int{&c.Delivered, &c.DeliveredCE}
		},
	},
	{ // Linux 5.4: snd_wnd (sentinel, ~never 0 unless zero-window), rcv_ooopack
		sentinel: func(c *model.Connection) bool { return c.SndWnd != nil },
		fields: func(c *model.Connection) []**int {
			return []**int{&c.RcvOOOPack}
		},
	},
}

// hasTCPInfo reports whether ss printed a tcp_info block for this socket.
// cwnd is always non-zero on a socket that has tcp_info, so its presence is a
// reliable marker; TIME-WAIT and other info-less sockets lack it.
func hasTCPInfo(c *model.Connection) bool {
	return c.Protocol == "tcp" && c.CWnd != nil
}

// fillOmittedZeros sets zero-omitted tcp_info counters to 0 on sockets that
// have tcp_info but didn't print them. ss skips counters like bytes_retrans
// and dsack_dups while they're 0, so absent means 0 — not unknown — and
// leaving them nil makes the first poll in which a counter moves off zero
// (a clean connection's first loss burst) produce no delta. A group is only
// filled when some socket in this poll shows its sentinel, so on an older
// kernel that doesn't report the group at all the fields stay nil ("-")
// instead of turning into a misleading 0.
func fillOmittedZeros(conns []*model.Connection) {
	for _, g := range omittedGroups {
		supported := false
		for _, c := range conns {
			if hasTCPInfo(c) && g.sentinel(c) {
				supported = true
				break
			}
		}
		if !supported {
			continue
		}
		for _, c := range conns {
			if !hasTCPInfo(c) {
				continue
			}
			if g.fields != nil {
				for _, f := range g.fields(c) {
					if *f == nil {
						*f = new(int)
					}
				}
			}
			if g.floats != nil {
				for _, f := range g.floats(c) {
					if *f == nil {
						*f = new(float64)
					}
				}
			}
		}
	}
}

// applyUDPState maps raw ss UDP state into the app's synthetic states.
func applyUDPState(c *model.Connection) {
	hasQ := (c.RecvQ != nil && *c.RecvQ > 0) || (c.SendQ != nil && *c.SendQ > 0)
	switch {
	case c.State == "ESTAB":
		c.State = "UDP_ESTAB"
	case hasQ:
		c.State = "UDP_ACTIVE"
	default:
		c.State = "UDP_IDLE"
	}
}

func runSS(flags, protocol string, f SSFilter) ([]*model.Connection, int, error) {
	cmd := exec.Command("ss", append([]string{flags}, f.args...)...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, 0, fmt.Errorf("ss: %w", err)
	}
	if err := cmd.Start(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, 0, errSSNotFound
		}
		return nil, 0, fmt.Errorf("ss: %w", err)
	}

	conns, drops, scanErr := scanRecords(stdout, protocol, f.impliedState, time.Now())
	if err := cmd.Wait(); err != nil {
		// Include what ss said; "exit status 1" alone is undiagnosable.
		if msg := firstLine(strings.TrimSpace(stderr.String())); msg != "" {
			return nil, 0, fmt.Errorf("ss: %s (%w)", msg, err)
		}
		return nil, 0, fmt.Errorf("ss: %w", err)
	}
	if scanErr != nil {
		return nil, 0, fmt.Errorf("ss scan: %w", scanErr)
	}
	return conns, drops, nil
}

// scanRecords reads ss records from r (Netid-prefixed when protocol is "", see
// parseProtoRecord). Split out from runSS so it can be fed captured ss output
// in tests.
func scanRecords(r io.Reader, protocol, impliedState string, ts time.Time) ([]*model.Connection, int, error) {
	var conns []*model.Connection
	var drops int // record lines that looked like sockets but didn't parse
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var pending string
	flush := func() {
		if pending == "" {
			return
		}
		// ss is run with -H, so every non-continuation line is a socket record.
		// A nil result means a record we couldn't parse — count it rather than
		// discarding it silently.
		if c, skip := parseProtoRecord(pending, protocol, impliedState, ts); c != nil {
			conns = append(conns, c)
		} else if !skip {
			drops++
		}
		pending = ""
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		// Without -O (or on old ss), TCP info is printed on a continuation line
		// that starts with whitespace. Append it to the previous record so all
		// fields land in one parse.
		if line[0] == ' ' || line[0] == '\t' {
			if pending != "" {
				pending += " " + strings.TrimSpace(line)
			}
			continue
		}
		flush()
		pending = line
	}
	flush()
	return conns, drops, scanner.Err()
}
