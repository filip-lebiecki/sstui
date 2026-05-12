package parser

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"ss-stats-tui/model"
)

var (
	reProcess     = regexp.MustCompile(`users:\(\("([^"]+)"`)
	rePID         = regexp.MustCompile(`pid=(\d+)`)
	reUID         = regexp.MustCompile(`uid:(\d+)`)
	reInode       = regexp.MustCompile(`ino:(\d+)`)
	reCgroup      = regexp.MustCompile(`cgroup:(\S+)`)
	reSkmem       = regexp.MustCompile(`skmem:\(r(\d+),rb(\d+),t(\d+),tb(\d+),f(\d+),w(\d+),o(\d+),bl(\d+),d(\d+)\)`)
	reTimer       = regexp.MustCompile(`timer:\(([\w-]+),([^,)]+),(\d+)\)`)
	reWscale      = regexp.MustCompile(`wscale:(\d+),(\d+)`)
	reDelivered   = regexp.MustCompile(`\bdelivered:(\d+)`)
	reSendBPS     = regexp.MustCompile(`\bsend (\d+)bps`)
	reRTO         = regexp.MustCompile(`rto:(\d+\.?\d*)`)
	reRTT         = regexp.MustCompile(`\brtt:(\d+\.?\d*)/(\d+\.?\d*)`)
	reATO         = regexp.MustCompile(`\bato:(\d+\.?\d*)`)
	reMSS         = regexp.MustCompile(`\bmss:(\d+)`)
	reCWnd        = regexp.MustCompile(`\bcwnd:(\d+)`)
	reBytesSent   = regexp.MustCompile(`bytes_sent:(\d+)`)
	reBytesRecv   = regexp.MustCompile(`bytes_received:(\d+)`)
	reBytesAcked  = regexp.MustCompile(`bytes_acked:(\d+)`)
	reSegsOut     = regexp.MustCompile(`segs_out:(\d+)`)
	reSegsIn      = regexp.MustCompile(`segs_in:(\d+)`)
	reMinRTT      = regexp.MustCompile(`minrtt:(\d+\.?\d*)`)
	rePacingRate  = regexp.MustCompile(`pacing_rate\s+(\d+)bps`)
	reDeliveryRate = regexp.MustCompile(`delivery_rate\s+(\d+)bps`)
	reRetrans     = regexp.MustCompile(`\bretrans:(\d+)/(\d+)`)
	reSndWnd      = regexp.MustCompile(`snd_wnd:(\d+)`)
	reSSThresh    = regexp.MustCompile(`\bssthresh:(\d+)`)
	reRcvSpace    = regexp.MustCompile(`rcv_space:(\d+)`)
	reRcvSSThresh = regexp.MustCompile(`rcv_ssthresh:(\d+)`)
	reBusy        = regexp.MustCompile(`busy:(\d+\.?\d*)ms`)
	reLost        = regexp.MustCompile(`\blost:(\d+)`)
	reUnacked     = regexp.MustCompile(`\bunacked:(\d+)`)
	reDataSegsOut = regexp.MustCompile(`\bdata_segs_out:(\d+)`)
	reDataSegsIn  = regexp.MustCompile(`\bdata_segs_in:(\d+)`)
	reBytesRetrans = regexp.MustCompile(`bytes_retrans:(\d+)`)
	rePMTU        = regexp.MustCompile(`\bpmtu:(\d+)`)
	reAdvMSS      = regexp.MustCompile(`\badvmss:(\d+)`)
	reRcvMSS      = regexp.MustCompile(`\brcvmss:(\d+)`)
	reLastSnd     = regexp.MustCompile(`\blastsnd:(\d+)`)
	reLastRcv     = regexp.MustCompile(`\blastrcv:(\d+)`)
	reLastAck     = regexp.MustCompile(`\blastack:(\d+)`)
	reDSACKDups   = regexp.MustCompile(`\bdsack_dups:(\d+)`)
	reBBR         = regexp.MustCompile(`bbr:\(bw:(\d+)bps,mrtt:(\d+\.?\d*),pacing_gain:(\d+\.?\d*),cwnd_gain:(\d+\.?\d*)\)`)
	reIPv6Bracket = regexp.MustCompile(`\[(.+)\]:(\S+)`)
	reAppLimited  = regexp.MustCompile(`\bapp_limited\b`)
)

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

	if reAppLimited.MatchString(rest) {
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

	return c, nil
}

// RunSS executes ss -atnpeimOH and returns parsed connections.
func RunSS() ([]*model.Connection, error) {
	cmd := exec.Command("ss", "-atnpeimOH")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("ss: %w", err)
	}

	var conns []*model.Connection
	for _, line := range strings.Split(string(out), "\n") {
		c, err := ParseLine(line)
		if err != nil {
			continue
		}
		if c != nil {
			conns = append(conns, c)
		}
	}
	return conns, nil
}
