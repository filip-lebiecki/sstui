package parser

import (
	"bufio"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"sstui/model"
)

var (
	reProcess       = regexp.MustCompile(`users:\(\("([^"]+)"`)
	rePID           = regexp.MustCompile(`pid=(\d+)`)
	reUID           = regexp.MustCompile(`uid:(\d+)`)
	reInode         = regexp.MustCompile(`ino:(\d+)`)
	reCgroup        = regexp.MustCompile(`cgroup:(\S+)`)
	reSkmem         = regexp.MustCompile(`skmem:\(r(\d+),rb(\d+),t(\d+),tb(\d+),f(\d+),w(\d+),o(\d+),bl(\d+),d(\d+)\)`)
	reTimer         = regexp.MustCompile(`timer:\(([\w-]+),([^,)]+),(\d+)\)`)
	reWscale        = regexp.MustCompile(`wscale:(\d+),(\d+)`)
	reDelivered     = regexp.MustCompile(`\bdelivered:(\d+)`)
	reSendBPS       = regexp.MustCompile(`\bsend (\d+)bps`)
	reRTO           = regexp.MustCompile(`rto:(\d+\.?\d*)`)
	reRTT           = regexp.MustCompile(`\brtt:(\d+\.?\d*)/(\d+\.?\d*)`)
	reATO           = regexp.MustCompile(`\bato:(\d+\.?\d*)`)
	reMSS           = regexp.MustCompile(`\bmss:(\d+)`)
	reCWnd          = regexp.MustCompile(`\bcwnd:(\d+)`)
	reBytesSent     = regexp.MustCompile(`bytes_sent:(\d+)`)
	reBytesRecv     = regexp.MustCompile(`bytes_received:(\d+)`)
	reBytesAcked    = regexp.MustCompile(`bytes_acked:(\d+)`)
	reSegsOut       = regexp.MustCompile(`\bsegs_out:(\d+)`)
	reSegsIn        = regexp.MustCompile(`\bsegs_in:(\d+)`)
	reMinRTT        = regexp.MustCompile(`minrtt:(\d+\.?\d*)`)
	rePacingRate    = regexp.MustCompile(`pacing_rate\s+(\d+)bps`)
	reDeliveryRate  = regexp.MustCompile(`delivery_rate\s+(\d+)bps`)
	reRetrans       = regexp.MustCompile(`\bretrans:(\d+)/(\d+)`)
	reSndWnd        = regexp.MustCompile(`snd_wnd:(\d+)`)
	reSSThresh      = regexp.MustCompile(`\bssthresh:(\d+)`)
	reRcvSpace      = regexp.MustCompile(`rcv_space:(\d+)`)
	reRcvSSThresh   = regexp.MustCompile(`rcv_ssthresh:(\d+)`)
	reBusy          = regexp.MustCompile(`busy:(\d+\.?\d*)ms`)
	reRwndLimited   = regexp.MustCompile(`rwnd_limited:(\d+\.?\d*)ms`)
	reSndbufLimited = regexp.MustCompile(`sndbuf_limited:(\d+\.?\d*)ms`)
	reLost          = regexp.MustCompile(`\blost:(\d+)`)
	reUnacked       = regexp.MustCompile(`\bunacked:(\d+)`)
	reDataSegsOut   = regexp.MustCompile(`\bdata_segs_out:(\d+)`)
	reDataSegsIn    = regexp.MustCompile(`\bdata_segs_in:(\d+)`)
	reBytesRetrans  = regexp.MustCompile(`bytes_retrans:(\d+)`)
	rePMTU          = regexp.MustCompile(`\bpmtu:(\d+)`)
	reAdvMSS        = regexp.MustCompile(`\badvmss:(\d+)`)
	reRcvMSS        = regexp.MustCompile(`\brcvmss:(\d+)`)
	reLastSnd       = regexp.MustCompile(`\blastsnd:(\d+)`)
	reLastRcv       = regexp.MustCompile(`\blastrcv:(\d+)`)
	reLastAck       = regexp.MustCompile(`\blastack:(\d+)`)
	reDSACKDups     = regexp.MustCompile(`\bdsack_dups:(\d+)`)
	reBBR           = regexp.MustCompile(`bbr:\(bw:(\d+)bps,mrtt:(\d+\.?\d*),pacing_gain:(\d+\.?\d*),cwnd_gain:(\d+\.?\d*)\)`)
	reIPv6Bracket   = regexp.MustCompile(`\[(.+)\]:(\S+)`)
	reAppLimited    = regexp.MustCompile(`\bapp_limited\b`)
	reRcvRTT        = regexp.MustCompile(`\brcv_rtt:(\d+\.?\d*)`)
	reRcvWnd        = regexp.MustCompile(`\brcv_wnd:(\d+)`)
	reReordering    = regexp.MustCompile(`\breordering:(\d+)`)
	reReordSeen     = regexp.MustCompile(`\breord_seen:(\d+)`)
	reRcvOOOPack    = regexp.MustCompile(`\brcv_ooopack:(\d+)`)
)

// congAlgos are the congestion-control names ss prints as a bare token in the
// tcp_info section (e.g. "ts sack cubic wscale:7,7").
var congAlgos = map[string]bool{
	"cubic": true, "bbr": true, "reno": true, "vegas": true, "htcp": true,
	"cdg": true, "dctcp": true, "lp": true, "nv": true, "hybla": true,
	"illinois": true, "highspeed": true, "scalable": true, "westwood": true,
	"yeah": true, "bic": true,
}

// tcpInfoSection returns the part of an ss record that holds kernel-reported
// socket metrics. Everything before skmem:( is identity — users:((...)) with
// free-form process names and the cgroup path — which must not be searched for
// bare-word tokens like congestion-control names: a process named "reno" or a
// cgroup like "/cups-lp.service" would otherwise be mistaken for one.
func tcpInfoSection(rest string) string {
	if i := strings.Index(rest, "skmem:("); i >= 0 {
		return rest[i:]
	}
	// No skmem (ss run without -m): skip past the identity fields instead.
	if i := strings.LastIndex(rest, "))"); i >= 0 && strings.HasPrefix(rest, "users:") {
		rest = rest[i+2:]
	}
	if i := strings.Index(rest, "cgroup:"); i >= 0 {
		if j := strings.IndexByte(rest[i:], ' '); j >= 0 {
			return rest[i+j:]
		}
		return ""
	}
	return rest
}

// findCongAlgo returns the congestion-control token in the tcp_info section.
func findCongAlgo(info string) *string {
	for _, tok := range strings.Fields(info) {
		if congAlgos[tok] {
			return &tok
		}
	}
	return nil
}

func mustInt(s string) *int {
	v, err := strconv.Atoi(s)
	if err != nil {
		return nil
	}
	return &v
}

func mustFloat(s string) *float64 {
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil
	}
	return &v
}

func parseAddrPort(raw string) (addr, port string) {
	if raw == "*" {
		return "*", "*"
	}
	if strings.HasPrefix(raw, "[") {
		matched := reIPv6Bracket.FindStringSubmatch(raw)
		if len(matched) == 3 {
			return matched[1], matched[2]
		}
	}
	parts := strings.Split(raw, ":")
	if len(parts) >= 2 {
		return strings.Join(parts[:len(parts)-1], ":"), parts[len(parts)-1]
	}
	return raw, "*"
}

// ParseLine parses a single line of ss output into a Connection.
func ParseLine(line string) (*model.Connection, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, nil
	}

	parts := strings.Fields(line)
	if len(parts) < 5 {
		return nil, nil
	}

	c := &model.Connection{
		Timestamp: time.Now(),
		State:     parts[0],
		RecvQ:     mustInt(parts[1]),
		SendQ:     mustInt(parts[2]),
	}
	c.LocalAddr, c.LocalPort = parseAddrPort(parts[3])
	c.PeerAddr, c.PeerPort = parseAddrPort(parts[4])

	rest := strings.Join(parts[5:], " ")

	if m := reProcess.FindStringSubmatch(rest); len(m) == 2 {
		c.Process = &m[1]
	}
	if m := rePID.FindStringSubmatch(rest); len(m) == 2 {
		c.PID = mustInt(m[1])
	}
	if m := reUID.FindStringSubmatch(rest); len(m) == 2 {
		c.UID = mustInt(m[1])
	}
	if m := reInode.FindStringSubmatch(rest); len(m) == 2 {
		c.Inode = &m[1]
	}
	if m := reCgroup.FindStringSubmatch(rest); len(m) == 2 {
		c.Cgroup = &m[1]
	}

	if m := reSkmem.FindStringSubmatch(rest); len(m) == 10 {
		c.SkmemR = mustInt(m[1])
		c.SkmemRB = mustInt(m[2])
		c.SkmemT = mustInt(m[3])
		c.SkmemTB = mustInt(m[4])
		c.SkmemF = mustInt(m[5])
		c.SkmemW = mustInt(m[6])
		c.SkmemO = mustInt(m[7])
		c.SkmemBL = mustInt(m[8])
		c.SkmemD = mustInt(m[9])
	}

	if m := reTimer.FindStringSubmatch(rest); len(m) == 4 {
		c.TimerType = &m[1]
		c.TimerDur = &m[2]
		c.TimerRetrans = mustInt(m[3])
	}

	if m := reWscale.FindStringSubmatch(rest); len(m) == 3 {
		c.WscaleSnd = mustInt(m[1])
		c.WscaleRcv = mustInt(m[2])
	}

	if m := reDelivered.FindStringSubmatch(rest); len(m) == 2 {
		c.Delivered = mustInt(m[1])
	}

	info := tcpInfoSection(rest)

	if reAppLimited.MatchString(info) {
		c.AppLimited = 1
	}

	if m := reSendBPS.FindStringSubmatch(rest); len(m) == 2 {
		c.SendBPS = mustInt(m[1])
	}

	if m := reRTO.FindStringSubmatch(rest); len(m) == 2 {
		c.RTO = mustFloat(m[1])
	}

	if m := reRTT.FindStringSubmatch(rest); len(m) == 3 {
		c.RTT = mustFloat(m[1])
		c.RTTVar = mustFloat(m[2])
	}

	if m := reATO.FindStringSubmatch(rest); len(m) == 2 {
		c.ATO = mustFloat(m[1])
	}

	if m := reMSS.FindStringSubmatch(rest); len(m) == 2 {
		c.MSS = mustInt(m[1])
	}

	if m := reCWnd.FindStringSubmatch(rest); len(m) == 2 {
		c.CWnd = mustInt(m[1])
	}

	if m := reBytesSent.FindStringSubmatch(rest); len(m) == 2 {
		c.BytesSent = mustInt(m[1])
	}
	if m := reBytesRecv.FindStringSubmatch(rest); len(m) == 2 {
		c.BytesReceived = mustInt(m[1])
	}
	if m := reBytesAcked.FindStringSubmatch(rest); len(m) == 2 {
		c.BytesAcked = mustInt(m[1])
	}

	if m := reSegsOut.FindStringSubmatch(rest); len(m) == 2 {
		c.SegsOut = mustInt(m[1])
	}
	if m := reSegsIn.FindStringSubmatch(rest); len(m) == 2 {
		c.SegsIn = mustInt(m[1])
	}

	if m := reMinRTT.FindStringSubmatch(rest); len(m) == 2 {
		c.MinRTT = mustFloat(m[1])
	}

	if m := rePacingRate.FindStringSubmatch(rest); len(m) == 2 {
		c.PacingRate = mustInt(m[1])
	}
	if m := reDeliveryRate.FindStringSubmatch(rest); len(m) == 2 {
		c.DeliveryRate = mustInt(m[1])
	}

	if m := reRetrans.FindStringSubmatch(rest); len(m) == 3 {
		c.RetransNow = mustInt(m[1])
		c.Retrans = mustInt(m[2])
	}

	if m := reSndWnd.FindStringSubmatch(rest); len(m) == 2 {
		c.SndWnd = mustInt(m[1])
	}
	if m := reSSThresh.FindStringSubmatch(rest); len(m) == 2 {
		c.SSThresh = mustInt(m[1])
	}
	if m := reRcvSpace.FindStringSubmatch(rest); len(m) == 2 {
		c.RcvSpace = mustInt(m[1])
	}
	if m := reRcvSSThresh.FindStringSubmatch(rest); len(m) == 2 {
		c.RcvSSThresh = mustInt(m[1])
	}

	if m := reBusy.FindStringSubmatch(rest); len(m) == 2 {
		c.BusyMS = mustFloat(m[1])
	}
	if m := reRwndLimited.FindStringSubmatch(rest); len(m) == 2 {
		c.RwndLimitedMS = mustFloat(m[1])
	}
	if m := reSndbufLimited.FindStringSubmatch(rest); len(m) == 2 {
		c.SndbufLimitedMS = mustFloat(m[1])
	}
	if m := reLost.FindStringSubmatch(rest); len(m) == 2 {
		c.Lost = mustInt(m[1])
	}
	if m := reUnacked.FindStringSubmatch(rest); len(m) == 2 {
		c.Unacked = mustInt(m[1])
	}

	if m := reDataSegsOut.FindStringSubmatch(rest); len(m) == 2 {
		c.DataSegsOut = mustInt(m[1])
	}
	if m := reDataSegsIn.FindStringSubmatch(rest); len(m) == 2 {
		c.DataSegsIn = mustInt(m[1])
	}

	if m := reBytesRetrans.FindStringSubmatch(rest); len(m) == 2 {
		c.BytesRetrans = mustInt(m[1])
	}

	if m := rePMTU.FindStringSubmatch(rest); len(m) == 2 {
		c.PMTU = mustInt(m[1])
	}
	if m := reAdvMSS.FindStringSubmatch(rest); len(m) == 2 {
		c.AdvMSS = mustInt(m[1])
	}
	if m := reRcvMSS.FindStringSubmatch(rest); len(m) == 2 {
		c.RcvMSS = mustInt(m[1])
	}

	if m := reLastSnd.FindStringSubmatch(rest); len(m) == 2 {
		c.LastSnd = mustInt(m[1])
	}
	if m := reLastRcv.FindStringSubmatch(rest); len(m) == 2 {
		c.LastRcv = mustInt(m[1])
	}
	if m := reLastAck.FindStringSubmatch(rest); len(m) == 2 {
		c.LastAck = mustInt(m[1])
	}

	if m := reDSACKDups.FindStringSubmatch(rest); len(m) == 2 {
		c.DSACKDups = mustInt(m[1])
	}

	if m := reBBR.FindStringSubmatch(rest); len(m) == 5 {
		c.BBRBW = mustInt(m[1])
		c.BBRMRTT = mustFloat(m[2])
		c.BBRPacingGain = mustFloat(m[3])
		c.BBRCWndGain = mustFloat(m[4])
	}

	if m := reRcvRTT.FindStringSubmatch(rest); len(m) == 2 {
		c.RcvRTT = mustFloat(m[1])
	}
	if m := reRcvWnd.FindStringSubmatch(rest); len(m) == 2 {
		c.RcvWnd = mustInt(m[1])
	}
	c.CongAlgo = findCongAlgo(info)
	if m := reReordering.FindStringSubmatch(rest); len(m) == 2 {
		c.Reordering = mustInt(m[1])
	}
	if m := reReordSeen.FindStringSubmatch(rest); len(m) == 2 {
		c.ReordSeen = mustInt(m[1])
	}
	if m := reRcvOOOPack.FindStringSubmatch(rest); len(m) == 2 {
		c.RcvOOOPack = mustInt(m[1])
	}

	return c, nil
}

// RunSS runs ss for both TCP and UDP and returns merged connections plus the
// number of record lines that could not be parsed (so the UI can surface a
// silent parse failure rather than dropping sockets invisibly).
func RunSS() ([]*model.Connection, int, error) {
	tcpConns, tcpDrops, tcpErr := runSS("-atnpeimOH", "tcp")
	udpConns, udpDrops, udpErr := runSS("-aunpeimOH", "udp")
	conns, err := mergeResults(tcpConns, tcpErr, udpConns, udpErr)
	return conns, tcpDrops + udpDrops, err
}

// mergeResults combines the per-protocol ss results into a single list and a
// single error. Split out from RunSS so the success / partial / total-failure
// branches are testable without invoking the real ss binary.
//
// When both queries fail it returns a nil slice and an error (the caller keeps
// the last good snapshot). When only one fails it returns the protocol that
// succeeded together with a non-nil error describing the partial result, so
// the caller can ingest what it got while still flagging the failure rather
// than silently dropping a whole protocol.
func mergeResults(tcpConns []*model.Connection, tcpErr error, udpConns []*model.Connection, udpErr error) ([]*model.Connection, error) {
	if tcpErr != nil && udpErr != nil {
		return nil, fmt.Errorf("tcp: %v; udp: %v", tcpErr, udpErr)
	}
	conns := append(tcpConns, udpConns...)
	for _, c := range conns {
		if c.Protocol == "udp" {
			applyUDPState(c)
		}
	}
	fillOmittedZeros(conns)
	switch {
	case tcpErr != nil:
		return conns, fmt.Errorf("tcp query failed (showing UDP only): %v", tcpErr)
	case udpErr != nil:
		return conns, fmt.Errorf("udp query failed (showing TCP only): %v", udpErr)
	}
	return conns, nil
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
	{ // Linux 4.1/4.2: bytes_received, segs_out, segs_in
		sentinel: func(c *model.Connection) bool { return c.SegsOut != nil },
		fields: func(c *model.Connection) []**int {
			return []**int{&c.BytesReceived, &c.SegsOut, &c.SegsIn}
		},
	},
	{ // Linux 4.10: busy, rwnd_limited, sndbuf_limited
		sentinel: func(c *model.Connection) bool { return c.BusyMS != nil },
		floats: func(c *model.Connection) []**float64 {
			return []**float64{&c.BusyMS, &c.RwndLimitedMS, &c.SndbufLimitedMS}
		},
	},
	{ // Linux 4.19: bytes_sent, bytes_retrans, dsack_dups, reord_seen
		sentinel: func(c *model.Connection) bool { return c.BytesSent != nil },
		fields: func(c *model.Connection) []**int {
			return []**int{&c.BytesSent, &c.BytesRetrans, &c.DSACKDups, &c.ReordSeen}
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

func runSS(flags, protocol string) ([]*model.Connection, int, error) {
	cmd := exec.Command("ss", flags)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, 0, fmt.Errorf("ss: %w", err)
	}
	if err := cmd.Start(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, 0, fmt.Errorf("ss not found in PATH; install iproute2")
		}
		return nil, 0, fmt.Errorf("ss: %w", err)
	}

	var conns []*model.Connection
	var drops int // record lines that looked like sockets but didn't parse
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var pending string
	flush := func() {
		if pending == "" {
			return
		}
		// ss is run with -H, so every non-continuation line is a socket record.
		// A nil/error result means a record we couldn't parse — count it rather
		// than discarding it silently.
		if c, err := ParseLine(pending); err == nil && c != nil {
			c.Protocol = protocol
			conns = append(conns, c)
		} else {
			drops++
		}
		pending = ""
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		// ss prints TCP info on a continuation line that starts with whitespace.
		// Append it to the previous record so all fields land in one ParseLine call.
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
	scanErr := scanner.Err()
	if err := cmd.Wait(); err != nil {
		return nil, 0, fmt.Errorf("ss: %w", err)
	}
	if scanErr != nil {
		return nil, 0, fmt.Errorf("ss scan: %w", scanErr)
	}
	return conns, drops, nil
}
