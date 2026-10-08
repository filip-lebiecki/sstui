package findings

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"sstui/classifier"
	"sstui/model"
	"sstui/poller"
)

// rules run in order; host-counter rules come after the per-socket ones so
// they can fold their evidence into an existing finding instead of
// duplicating it.
var rules = []func(*analysis){
	ruleZeroWindow,
	ruleRecvBacklog,
	ruleListenQueue,
	ruleSynStall,
	rulePMTUBlackHole,
	rulePathLoss,
	ruleInboundLoss,
	ruleReordering,
	rulePMTU,
	ruleRTTInflation,
	ruleRwndLimited,
	ruleSndbufLimited,
	ruleRcvbufLimited,
	ruleCloseWaitLeak,
	ruleTimeWaitStorm,
	ruleEphemeralPorts,
	ruleListenOverflowHost,
	ruleSynBacklog,
	ruleUDPRcvbufHost,
	ruleRetransHost,
	ruleRcvMemPressure,
}

// ---- per-socket rules ---------------------------------------------------

// ruleZeroWindow: peers that stopped reading, grouped by our process and the
// peer endpoint. When the receiver is on this host, name it.
func ruleZeroWindow(a *analysis) {
	key := func(c *model.Connection) string { return procKey(c) + "|" + endpoint(c.PeerAddr, c.PeerPort) }
	for _, g := range a.groupBySignal(key, model.SignalZeroWindow) {
		c0 := g.conns[0]
		peer := endpoint(c0.PeerAddr, c0.PeerPort)
		queued := 0
		for _, c := range g.conns {
			queued += deref(c.SendQ)
		}
		f := Finding{
			ID:       "zero_window|" + g.key,
			Severity: 2,
			Title:    fmt.Sprintf("%s → %s: %s stalled — peer not reading (zero window)", a.procLabel(c0), peer, plural(len(g.conns), "connection")),
			Detail:   "The receiver's buffer is full because its application stopped reading, so it advertises a zero window and our data piles up unsent.",
			Evidence: []string{fmt.Sprintf("%s · %s waiting in Send-Q", plural(len(g.conns), "socket"), humanBytes(float64(queued)))},
			Filter:   filterJoin("signal=ZERO_WIN", procFilter(c0), "peer=="+c0.PeerAddr, "dport="+c0.PeerPort),
			Count:    len(g.conns),
		}
		if s, ok := signalOf(c0, model.SignalZeroWindow); ok && s.Value != nil {
			f.Evidence = append(f.Evidence, fmt.Sprint(s.Value))
		}
		if rcv := a.localPeer(c0); rcv != nil {
			f.Evidence = append(f.Evidence, fmt.Sprintf("receiver is %s on this host (Recv-Q %s)", a.procLabel(rcv), humanBytes(float64(deref(rcv.RecvQ)))))
			f.Actions = append(f.Actions, Action{Text: fmt.Sprintf("Find out why %s stopped reading: a blocked or deadlocked thread, a GC pause, or CPU starvation", a.procLabel(rcv))})
			if rcv.PID != nil {
				f.Actions = append(f.Actions, Action{Text: "See what its threads are doing", Command: fmt.Sprintf("top -H -p %d", *rcv.PID)})
			}
		} else {
			f.Actions = append(f.Actions, Action{Text: fmt.Sprintf("The application at %s is blocked or overloaded and not draining its socket — investigate it, not the network", peer)})
		}
		f.Actions = append(f.Actions, Action{Text: "Watch the stalled sockets", Command: "ss -tnoi dst " + peer})
		a.add(f)
	}
}

// ruleRecvBacklog: a local process not keeping up with its sockets — full
// receive queues (RCV_Q) and kernel drops (DROPS), grouped by process.
func ruleRecvBacklog(a *analysis) {
	// Drops that come with inbound gaps and an unpressured receive queue are
	// out-of-order data discarded during recovery, not a slow reader: the
	// classifier makes those info, so they don't group here, and
	// ruleInboundLoss mentions them. A listener's drops are connection
	// attempts it turned away, which ruleListenQueue reports.
	key := func(c *model.Connection) string {
		if c.State == "LISTEN" {
			return ""
		}
		return procKey(c)
	}
	for _, g := range a.groupBySignal(key, model.SignalRecvBufferPressure, model.SignalSocketDrops) {
		c0 := g.conns[0]
		var queued, drops, udp int
		for _, c := range g.conns {
			queued += deref(c.RecvQ)
			drops += deref(c.DeltaSkmemD)
			if c.Protocol == "udp" {
				udp++
			}
		}
		f := Finding{
			ID:       "recv_backlog|" + g.key,
			Severity: g.sev,
			Title:    fmt.Sprintf("%s isn't reading fast enough: %s backed up", a.procLabel(c0), plural(len(g.conns), "socket")),
			Detail:   "Data arrives faster than the application reads it; once a socket's receive buffer fills, the kernel drops (UDP) or throttles (TCP) the sender.",
			Evidence: []string{fmt.Sprintf("%s waiting in Recv-Q", humanBytes(float64(queued)))},
			// Same as the grouping: loss-recovery discards are info DROPS.
			Filter: filterJoin(procFilter(c0), "not state=LISTEN", "(signal=RCV_Q or signal=DROPS:warn)"),
			Count:  len(g.conns),
		}
		if udp > 0 {
			a.udpBacklog[f.ID] = true
		}
		if drops > 0 {
			f.Severity = 2
			f.Evidence = append(f.Evidence, fmt.Sprintf("%d packets dropped at these sockets in the last poll", drops))
		}
		// Link the two ends of a local stall: senders on this host that see
		// a zero window from these sockets.
		stalled := 0
		for _, c := range g.conns {
			if snd := a.localPeer(c); snd != nil {
				if _, ok := signalOf(snd, model.SignalZeroWindow); ok {
					stalled++
				}
			}
		}
		if stalled > 0 {
			f.Evidence = append(f.Evidence, fmt.Sprintf("this is stalling %s on this host (they see a zero window)", plural(stalled, "local sender")))
		}
		if c0.PID != nil {
			f.Actions = append(f.Actions, Action{Text: "The fix is a faster reader — check whether it's CPU-bound or blocked", Command: fmt.Sprintf("top -H -p %d", *c0.PID)})
		}
		if udp > 0 {
			rmemMax, _ := a.in.Sysctl.Int("net.core.rmem_max")
			target := roundUpMB(max(float64(rmemMax)*4, 8<<20))
			f.Actions = append(f.Actions, Action{
				Text:    fmt.Sprintf("Bigger buffers absorb bursts. UDP doesn't autotune: raise net.core.rmem_max (now %s) and the app's SO_RCVBUF", humanBytes(float64(rmemMax))),
				Command: fmt.Sprintf("sysctl -w net.core.rmem_max=%d", target),
			})
		}
		// A bigger TCP limit only matters once autotuning has hit it; a slow
		// reader's buffer usually never grows that far.
		atCap := func(v []int) bool {
			return slices.ContainsFunc(g.conns, func(c *model.Connection) bool {
				return c.Protocol == "tcp" && c.SkmemRB != nil && *c.SkmemRB >= v[2]
			})
		}
		if udp < len(g.conns) {
			if v := a.in.Sysctl.Ints("net.ipv4.tcp_rmem"); len(v) == 3 && atCap(v) {
				f.Actions = append(f.Actions, Action{
					Text:    fmt.Sprintf("For TCP, a larger buffer only helps with bursts; it has reached tcp_rmem max (%s)", humanBytes(float64(v[2]))),
					Command: fmt.Sprintf(`sysctl -w net.ipv4.tcp_rmem="%d %d %d"`, v[0], v[1], roundUpMB(float64(v[2])*2)),
				})
			}
		}
		a.add(f)
	}
}

// ruleListenQueue: full or overflowing accept queues, per listener: a queue
// full right now (LISTEN_Q), or drops at the listener since the last poll
// (DROPS on a listening socket), which catches bursts that overflow the queue
// between polls. A listener's drop counter counts every handshake it turns
// away, but also stray handshake segments it discards (a duplicate or
// out-of-window ACK when packets are lost); only refusals also count in the
// host's TcpExt:ListenDrops (and accept-queue overflows in ListenOverflows),
// so drops without either are left alone. Tells apart a backlog capped by
// somaxconn from one the application chose itself.
func ruleListenQueue(a *analysis) {
	key := func(c *model.Connection) string {
		if c.State != "LISTEN" {
			return "" // other sockets' drops are ruleRecvBacklog's
		}
		return endpoint(c.LocalAddr, c.LocalPort)
	}
	overflows, _ := a.rate("TcpExt:ListenOverflows")
	refused, _ := a.rate("TcpExt:ListenDrops")
	for _, g := range a.groupBySignal(key, model.SignalListenQueueFull, model.SignalSocketDrops) {
		// SO_REUSEPORT listeners share an endpoint: describe a full one if
		// any is full.
		c0, full := g.conns[0], false
		drops := 0
		for _, c := range g.conns {
			drops += deref(c.DeltaSkmemD)
			if _, ok := signalOf(c, model.SignalListenQueueFull); ok && !full {
				c0, full = c, true
			}
		}
		if !full && overflows <= 0 && refused <= 0 {
			continue // stray segments discarded, no connection refused
		}
		rq, sq := deref(c0.RecvQ), deref(c0.SendQ)
		var title, detail string
		switch {
		case full:
			title = fmt.Sprintf("Accept queue full on :%s (%s) — new connections are being dropped", c0.LocalPort, a.procLabel(c0))
			detail = "Clients complete the handshake but the application isn't calling accept() fast enough, so the kernel drops new SYNs or ACKs once the queue is full."
		case overflows > 0:
			title = fmt.Sprintf("Accept queue on :%s (%s) overflowed — connections were dropped", c0.LocalPort, a.procLabel(c0))
			detail = "The queue isn't full right now, but the listener turned connection attempts away since the last poll and the kernel counted accept-queue overflows: bursts fill it faster than the application accept()s."
		default:
			// The listener's drop counter also counts SYN-queue drops and
			// other refusals; without overflows, don't blame accept().
			title = fmt.Sprintf("Listener :%s (%s) is dropping connection attempts", c0.LocalPort, a.procLabel(c0))
			detail = "The listener turned connection attempts away since the last poll (the kernel counted ListenDrops), but no accept-queue overflows: a full SYN queue (a SYN flood without syncookies), or a socket filter or other policy refusing them."
		}
		f := Finding{
			ID:         "listen_queue|" + g.key,
			Severity:   g.sev,
			Title:      title,
			Detail:     detail,
			Evidence:   []string{fmt.Sprintf("queue %d / %d", rq, sq)},
			Filter:     filterJoin("state=LISTEN", "sport="+c0.LocalPort),
			ShowListen: true,
			Count:      len(g.conns),
		}
		if drops > 0 {
			f.Severity = 2
			f.Evidence = append(f.Evidence, fmt.Sprintf("%s dropped at this listener in the last poll", plural(drops, "connection attempt")))
		}
		if overflows > 0 {
			f.Evidence = append(f.Evidence, fmt.Sprintf("kernel: ListenOverflows +%.1f/s", overflows))
		}
		somax, ok := a.in.Sysctl.Int("net.core.somaxconn")
		switch {
		case ok && sq >= somax:
			f.Evidence = append(f.Evidence, fmt.Sprintf("backlog is capped by net.core.somaxconn = %d", somax))
			f.Actions = append(f.Actions, Action{
				Text:    "Raise the system cap (and the app's listen backlog with it)",
				Command: fmt.Sprintf("sysctl -w net.core.somaxconn=%d", max(4096, somax*2)),
			})
		case ok:
			f.Evidence = append(f.Evidence, fmt.Sprintf("the app asked for a backlog of %d (somaxconn %d isn't the limit)", sq, somax))
			f.Actions = append(f.Actions, Action{Text: fmt.Sprintf("Raise the backlog in %s's config — e.g. nginx `listen … backlog=4096`, or the listen() argument", a.procLabel(c0))})
		}
		f.Actions = append(f.Actions, Action{Text: "A longer queue only buys time: the real fix is accepting faster (more workers, a non-blocking accept loop)"})
		if c0.PID != nil {
			f.Actions = append(f.Actions, Action{Text: "Check whether the accepting threads are busy", Command: fmt.Sprintf("top -H -p %d", *c0.PID)})
		}
		a.add(f)
	}
}

// ruleSynStall: outbound connections that can't complete a handshake,
// grouped by destination.
func ruleSynStall(a *analysis) {
	key := func(c *model.Connection) string { return endpoint(c.PeerAddr, c.PeerPort) }
	for _, g := range a.groupBySignal(key, model.SignalSynStall) {
		c0 := g.conns[0]
		maxTries := 0
		procs := map[string]int{}
		for _, c := range g.conns {
			maxTries = max(maxTries, deref(c.TimerRetrans))
			procs[a.procLabel(c)]++
		}
		a.add(Finding{
			ID:       "syn_stall|" + g.key,
			Severity: g.sev,
			Title:    fmt.Sprintf("Can't connect to %s: %s retrying", g.key, plural(len(g.conns), "handshake")),
			Detail:   "SYNs go out but nothing comes back — the destination is down, unreachable, or a firewall is silently dropping the traffic.",
			Evidence: []string{
				fmt.Sprintf("up to %d SYN retransmits", maxTries),
				"from " + strings.Join(topBy(procs, 3), ", "),
			},
			Actions: []Action{
				{Text: "Test reachability directly", Command: fmt.Sprintf("nc -vz -w3 %s %s", c0.PeerAddr, c0.PeerPort)},
				{Text: "Check the route this host would use", Command: "ip route get " + c0.PeerAddr},
				{Text: "Check firewalls / security groups on the path, and that DNS isn't returning a stale address"},
			},
			Filter: filterJoin("state=SYN-SENT", "peer=="+c0.PeerAddr, "dport="+c0.PeerPort),
			Count:  len(g.conns),
		})
	}
}

// lossSignals mean the path to a peer is losing packets: steady loss that a
// full queue doesn't explain (PATH_LOSS), or connections stalled on lost
// packets (RTO, NO_ACK). The per-poll retransmit signals (RETRANS, LOSS,
// HI_RETRANS) don't count: TCP loses packets in bursts while it fills a link,
// and the scenario lab showed them firing on healthy traffic.
var lossSignals = []model.SignalType{model.SignalPathLoss, model.SignalRTOFiring, model.SignalPeerNoAck}

// rulePathLoss: packet loss on the path. Loss toward one peer points at that
// peer or its path; loss toward many peers at once points at this host.
func rulePathLoss(a *analysis) {
	key := func(c *model.Connection) string {
		if classifier.HungAfterHandshake(c) {
			return "" // rulePMTUBlackHole's
		}
		return c.PeerAddr
	}
	groups := a.groupBySignal(key, lossSignals...)
	if len(groups) == 0 {
		return
	}
	if a.manyPeers(len(groups)) {
		var conns []*model.Connection
		sev := 0
		for _, g := range groups {
			conns = append(conns, g.conns...)
			sev = max(sev, g.sev)
		}
		f := Finding{
			ID:       "loss_local",
			Severity: sev,
			Title:    fmt.Sprintf("Packet loss toward %d different peers — likely a problem on this host", len(groups)),
			Detail:   "When many unrelated destinations lose packets at once, the common factor is the local NIC, driver, uplink, or a CPU too busy to service the network.",
			Evidence: append([]string{lossEvidence(conns)}, retransRateEvidence(a)...),
			Actions:  localLossActions(),
			Filter:   sigFilter(lossSignals...),
			Count:    len(conns),
		}
		a.add(f)
		return
	}
	for _, g := range groups {
		detail := "Connections to this destination are stalling on lost packets."
		if anySignal(g.conns, model.SignalPathLoss) {
			detail = "Data to this destination is retransmitted steadily without a queue building up, so it isn't the loss TCP causes while filling a link: a lossy link or device on the path, or a bottleneck with a very small buffer."
		}
		a.add(Finding{
			ID:       "loss|" + g.key,
			Severity: g.sev,
			Title:    fmt.Sprintf("Packet loss toward %s: %s affected", g.key, plural(len(g.conns), "connection")),
			Detail:   detail + " Only this destination is affected, so the loss is on its side or somewhere along the path to it.",
			Evidence: []string{lossEvidence(g.conns)},
			Actions: []Action{
				{Text: "Find the lossy hop", Command: "mtr -rwzbc 100 " + g.key},
				{Text: "If loss starts at the first hop, check this host's link instead", Command: "ip -s link"},
			},
			Filter: filterJoin("peer=="+g.key, sigFilter(lossSignals...)),
			Count:  len(g.conns),
		})
	}
}

// rulePMTUBlackHole: connections stalled on their very first data. The
// handshake's small packets got through and every full-sized segment since
// vanished, the signature of a path MTU black hole. Many peers at once point
// at this host's own MTU (a VPN, tunnel or container interface).
func rulePMTUBlackHole(a *analysis) {
	key := func(c *model.Connection) string {
		if !classifier.HungAfterHandshake(c) {
			return ""
		}
		return c.PeerAddr
	}
	groups := a.groupBySignal(key, model.SignalRTOFiring, model.SignalPeerNoAck)
	if len(groups) == 0 {
		return
	}
	detail := "The handshake's small packets got through, but not one full-sized data segment has been acknowledged since. That is the signature of a path MTU black hole: a link on the path (a tunnel, VPN or overlay) carries smaller packets, and the ICMP \"fragmentation needed\" that would tell this host is filtered. Less likely: the peer went away right after accepting."
	var fixes []Action
	if v, ok := a.in.Sysctl.Int("net.ipv4.tcp_mtu_probing"); ok && v == 0 {
		fixes = append(fixes, Action{Text: "Let TCP find a packet size that gets through by itself", Command: "sysctl -w net.ipv4.tcp_mtu_probing=1"})
	}
	fixes = append(fixes, Action{Text: "Fix it at the source: allow ICMP \"fragmentation needed\" (ICMPv6 \"packet too big\") through the firewalls, or clamp the MSS on the tunnel or VPN"})
	if a.manyPeers(len(groups)) {
		var conns []*model.Connection
		sev := 0
		for _, g := range groups {
			conns = append(conns, g.conns...)
			sev = max(sev, g.sev)
		}
		a.add(Finding{
			ID:       "pmtu_blackhole_local",
			Severity: sev,
			Title:    fmt.Sprintf("Connections to %d different peers hang right after the handshake — likely this host's MTU", len(groups)),
			Detail:   detail + " With this many unrelated peers, suspect this host: an interface (VPN, tunnel, container network) whose MTU is larger than what its path carries.",
			Evidence: []string{blackHoleEvidence(conns)},
			Actions: append([]Action{{
				Text:    "Compare the interfaces' MTUs with what the network under them carries, and lower the one that's too large (ip link set dev IFACE mtu N); a mismatch on one link drops oversized frames without any ICMP",
				Command: "ip link",
			}}, fixes...),
			Filter: sigFilter(model.SignalRTOFiring, model.SignalPeerNoAck),
			Count:  len(conns),
		})
		return
	}
	for _, g := range groups {
		a.add(Finding{
			ID:       "pmtu_blackhole|" + g.key,
			Severity: g.sev,
			Title:    fmt.Sprintf("Connections to %s hang right after the handshake — likely a path MTU black hole", g.key),
			Detail:   detail,
			Evidence: []string{blackHoleEvidence(g.conns)},
			Actions: append([]Action{{
				Text:    "Check whether full-sized packets get through (unfragmented; payload = path MTU minus headers)",
				Command: pingDF(g.key, g.conns[0]),
			}}, fixes...),
			Filter: filterJoin("peer=="+g.key, sigFilter(model.SignalRTOFiring, model.SignalPeerNoAck)),
			Count:  len(g.conns),
		})
	}
}

// blackHoleEvidence describes connections hung after their handshake.
func blackHoleEvidence(conns []*model.Connection) string {
	mss, retries := 0, 0
	for _, c := range conns {
		mss = max(mss, deref(c.MSS))
		retries = max(retries, deref(c.TimerRetrans))
	}
	return fmt.Sprintf("%s: handshake done, nothing acknowledged since; %d-byte segments retransmitted %s", plural(len(conns), "connection"), mss, plural(retries, "time"))
}

// pingDF is a ping of full-sized packets that mustn't be fragmented, sized to
// the connection's path MTU (1500 when unknown) minus the IP and ICMP headers.
func pingDF(peer string, c *model.Connection) string {
	mtu := 1500
	if c.PMTU != nil && *c.PMTU > 0 {
		mtu = *c.PMTU
	}
	if strings.Contains(peer, ":") {
		return fmt.Sprintf("ping -6 -M do -c 3 -s %d %s", mtu-48, peer)
	}
	return fmt.Sprintf("ping -M do -c 3 -s %d %s", mtu-28, peer)
}

// manyPeers reports whether a problem seen toward n distinct peers is
// widespread enough to blame this host rather than each peer's path: at least
// five peers, and at least a third of all established peers.
func (a *analysis) manyPeers(n int) bool {
	peers := map[string]bool{}
	for _, c := range a.in.Conns {
		if c.State == "ESTAB" {
			peers[c.PeerAddr] = true
		}
	}
	return n >= 5 && n*3 >= len(peers)
}

// lossEvidence summarizes which loss signals fired and the retransmit rate
// across conns over the window PATH_LOSS judges.
func lossEvidence(conns []*model.Connection) string {
	counts := map[string]int{}
	var sent, retr int
	var from, to time.Time
	for _, c := range conns {
		for _, s := range c.Signals {
			if slices.Contains(lossSignals, s.Type) {
				counts[s.Type.Label()]++
			}
		}
		for _, s := range c.SendSlots {
			sent += s.Sent
			retr += s.Retrans
			if from.IsZero() || s.Start.Before(from) {
				from = s.Start
			}
			to = maxTime(to, s.End)
		}
	}
	ev := strings.Join(topBy(counts, len(counts)), " · ")
	if sent > 0 {
		ev += fmt.Sprintf(" · %.2f%% of bytes retransmitted over the last %s", float64(retr)/float64(sent)*100, to.Sub(from).Round(time.Second))
	}
	return ev
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// anySignal reports whether any of conns carries signal t.
func anySignal(conns []*model.Connection, t model.SignalType) bool {
	return slices.ContainsFunc(conns, func(c *model.Connection) bool {
		return slices.ContainsFunc(c.Signals, func(s model.Signal) bool { return s.Type == t })
	})
}

func retransRateEvidence(a *analysis) []string {
	out, ok := a.rate("Tcp:OutSegs")
	if !ok || out <= 0 {
		return nil
	}
	re, _ := a.rate("Tcp:RetransSegs")
	return []string{fmt.Sprintf("host-wide: %.1f%% of TCP segments retransmitted in the last poll (%.0f/s)", re/out*100, re)}
}

// windowRetransEvidence is the host-wide retransmit count behind
// ruleRetransHost's verdict, over the same window.
func windowRetransEvidence(a *analysis) []string {
	out, ok := a.in.Sys.Delta(a.in.SysWindow, "Tcp:OutSegs")
	if !ok || out <= 0 {
		return nil
	}
	re, _ := a.in.Sys.Delta(a.in.SysWindow, "Tcp:RetransSegs")
	return []string{fmt.Sprintf("host-wide: %d of %d TCP segments retransmitted over the last %s", re, out, poller.SlotWindow().Round(time.Second))}
}

func localLossActions() []Action {
	return []Action{
		{Text: "Look for RX/TX errors, drops and overruns on the interfaces", Command: "ip -s link"},
		{Text: "NIC-level counters (replace the interface name)", Command: "ethtool -S eth0 | grep -iE 'err|drop|miss'"},
		{Text: "Check for CPU / softirq saturation", Command: "mpstat -P ALL 1 5"},
	}
}

// ruleInboundLoss: segments from peers arriving after gaps (RX_LOSS) — loss
// on the inbound path, seen from the receiving side. Like outbound loss, one
// peer points at that peer's path; many peers at once point at this host's
// receive path (NIC drops, ring buffer overruns, softirq starvation).
func ruleInboundLoss(a *analysis) {
	groups := a.groupBySignal(func(c *model.Connection) string { return c.PeerAddr }, model.SignalInboundLoss)
	if len(groups) == 0 {
		return
	}
	// ratio returns the aggregate evidence line over the window RX_LOSS
	// judges (none when no data-segment counts are known, rather than an
	// empty bullet).
	ratio := func(conns []*model.Connection) []string {
		var ooo, in int
		var from, to time.Time
		for _, c := range conns {
			for _, s := range c.RecvSlots {
				ooo += s.OOO
				in += s.Segs
				if from.IsZero() || s.Start.Before(from) {
					from = s.Start
				}
				to = maxTime(to, s.End)
			}
		}
		if in == 0 {
			return nil
		}
		return []string{fmt.Sprintf("%.1f%% of %d data segments received over the last %s arrived after a gap", float64(ooo)/float64(in)*100, in, to.Sub(from).Round(time.Second))}
	}
	rxActions := []Action{
		{Text: "Check this host's receive path for drops and overruns", Command: "ip -s link"},
		{Text: "NIC-level RX drops / missed packets (replace the interface name)", Command: "ethtool -S eth0 | grep -iE 'rx.*(drop|miss|err)'"},
		{Text: "If the NIC ring overflows, a larger RX ring can help (compare current vs max)", Command: "ethtool -g eth0"},
	}
	if a.manyPeers(len(groups)) {
		var conns []*model.Connection
		sev := 0
		for _, g := range groups {
			conns = append(conns, g.conns...)
			sev = max(sev, g.sev)
		}
		ev := discardEvidence(conns)
		f := Finding{
			ID:       "rx_loss_local",
			Severity: sev,
			Title:    fmt.Sprintf("Inbound packet loss from %d different peers — likely this host's receive path", len(groups)),
			Detail:   "Data from many unrelated senders arrives with gaps at once, so the common factor is here: NIC or driver drops, a full RX ring, or a CPU too busy to service network interrupts.",
			Evidence: append(ratio(conns), ev...),
			Actions:  append(rxActions, Action{Text: "Check for softirq / CPU saturation", Command: "mpstat -P ALL 1 5"}),
			Filter:   "signal=RX_LOSS",
			Count:    len(conns),
		}
		if r, ok := a.rate("TcpExt:TCPOFOQueue"); ok && r > 0 {
			f.Evidence = append(f.Evidence, fmt.Sprintf("kernel: TCPOFOQueue +%.0f/s", r))
		}
		a.add(f)
		return
	}
	for _, g := range groups {
		ev := discardEvidence(g.conns)
		a.add(Finding{
			ID:       "rx_loss|" + g.key,
			Severity: g.sev,
			Title:    fmt.Sprintf("Inbound packet loss from %s: %s receiving data with gaps", g.key, plural(len(g.conns), "connection")),
			Detail:   "Segments sent by this peer go missing (or arrive reordered) on the way here; the sender retransmits, which costs throughput and latency. Its retransmit counters are on the other machine — this is the receiving side's view.",
			Evidence: append(ratio(g.conns), ev...),
			Actions: append([]Action{
				{Text: "Trace the path back toward the peer (ideally run mtr from the peer's side too, since loss is often asymmetric)", Command: "mtr -rwzbc 100 " + g.key},
			}, rxActions[0]),
			Filter: filterJoin("peer=="+g.key, "signal=RX_LOSS"),
			Count:  len(g.conns),
		})
	}
}

// discardEvidence describes kernel drops that inbound loss explains (see
// classifier.DropsExplainedByInboundLoss).
func discardEvidence(conns []*model.Connection) []string {
	drops := 0
	for _, c := range conns {
		if classifier.DropsExplainedByInboundLoss(c) {
			drops += deref(c.DeltaSkmemD)
		}
	}
	if drops == 0 {
		return nil
	}
	return []string{fmt.Sprintf("the kernel also discarded %s (receive memory full during loss recovery) — not a slow reader: the receive queue is empty", plural(drops, "out-of-order segment"))}
}

// ruleReordering: sender-detected reordering, grouped by peer.
func ruleReordering(a *analysis) {
	for _, g := range a.groupBySignal(func(c *model.Connection) string { return c.PeerAddr }, model.SignalReordering) {
		events, segs, lossy := 0, 0.0, 0
		var from, to time.Time
		for _, c := range g.conns {
			for _, s := range c.SendSlots {
				events += s.Reord
				if c.MSS != nil && *c.MSS > 0 {
					segs += float64(s.Sent) / float64(*c.MSS)
				}
				if from.IsZero() || s.Start.Before(from) {
					from = s.Start
				}
				to = maxTime(to, s.End)
			}
			// Steady loss or stalls, not a retransmit now and then: real
			// reordering itself causes the occasional one.
			if slices.ContainsFunc(c.Signals, func(s model.Signal) bool { return slices.Contains(lossSignals, s.Type) }) {
				lossy++
			}
		}
		ev := []string{fmt.Sprintf("the sender saw %d reordering events over the last %s", events, to.Sub(from).Round(time.Second))}
		if segs > 0 {
			ev[0] += fmt.Sprintf(" (%.2f%% of segments)", float64(events)/segs*100)
		}
		if lossy > 0 {
			// reord_seen also grows when ACKs are lost or retransmits turn
			// out spurious, so alongside loss it isn't proof of reordering.
			ev = append(ev, fmt.Sprintf("caution: %d of these connections also show packet loss — loss can inflate this counter, so treat the loss finding as primary", lossy))
		}
		a.add(Finding{
			ID:       "reorder|" + g.key,
			Severity: g.sev,
			// reord_seen is counted by the sender: it's our packets that are
			// reordered on the way to the peer.
			Title:    fmt.Sprintf("Packets to %s are being reordered (%s)", g.key, plural(len(g.conns), "connection")),
			Detail:   "Packets of one flow take different paths and overtake each other — typically ECMP or link-aggregation hashing, or multi-queue paths. It can trigger spurious retransmits.",
			Evidence: ev,
			Actions: []Action{
				{Text: "Linux tolerates moderate reordering; if throughput suffers, check LACP / ECMP hashing on the path (hash on the full 5-tuple)"},
				{Text: "See which hops are involved", Command: "tracepath -n " + g.key},
			},
			Filter: filterJoin("peer=="+g.key, "signal=REORDER"),
			Count:  len(g.conns),
		})
	}
}

// rulePMTU: path MTU smaller than the MSS we advertise, grouped by peer.
func rulePMTU(a *analysis) {
	for _, g := range a.groupBySignal(func(c *model.Connection) string { return c.PeerAddr }, model.SignalPMTUMismatch) {
		c0 := g.conns[0]
		f := Finding{
			ID:       "pmtu|" + g.key,
			Severity: g.sev,
			Title:    fmt.Sprintf("Path MTU toward %s is smaller than expected", g.key),
			Detail:   "Something on the path (a tunnel, VPN or overlay) has a smaller MTU. If ICMP \"fragmentation needed\" is blocked, large packets vanish and connections hang.",
			Evidence: []string{fmt.Sprintf("pmtu %d, advertised MSS %d", deref(c0.PMTU), deref(c0.AdvMSS))},
			Actions: []Action{
				{Text: "Find where the MTU drops", Command: "tracepath -n " + g.key},
				{Text: "Make sure ICMP type 3 code 4 isn't filtered; consider MSS clamping on the tunnel or VPN"},
			},
			Filter: filterJoin("peer=="+g.key, "signal=PMTU"),
			Count:  len(g.conns),
		}
		if v, ok := a.in.Sysctl.Int("net.ipv4.tcp_mtu_probing"); ok && v == 0 {
			f.Actions = append(f.Actions, Action{Text: "Let TCP recover from black-holed paths by probing", Command: "sysctl -w net.ipv4.tcp_mtu_probing=1"})
		}
		a.add(f)
	}
}

// ruleRTTInflation: queueing delay (bufferbloat) toward a peer.
func ruleRTTInflation(a *analysis) {
	for _, g := range a.groupBySignal(func(c *model.Connection) string { return c.PeerAddr }, model.SignalRTTSpike) {
		var worst *model.Connection
		for _, c := range g.conns {
			if worst == nil || (c.RTT != nil && worst.RTT != nil && *c.RTT > *worst.RTT) {
				worst = c
			}
		}
		f := Finding{
			ID:       "rtt|" + g.key,
			Severity: g.sev,
			Title:    fmt.Sprintf("Latency to %s is inflated (%s)", g.key, plural(len(g.conns), "connection")),
			Detail:   "Round-trip time is far above this path's minimum — packets are sitting in a queue somewhere (bufferbloat) or the path changed.",
			Filter:   filterJoin("peer=="+g.key, "signal=RTT_SPIKE"),
			Count:    len(g.conns),
		}
		if worst != nil && worst.RTT != nil && worst.MinRTT != nil {
			f.Evidence = append(f.Evidence, fmt.Sprintf("RTT %.1f ms vs %.1f ms minimum", *worst.RTT, *worst.MinRTT))
		}
		f.Actions = append(f.Actions,
			Action{Text: "If this host's own link is the bottleneck, look for a deep queue on its egress interface (backlog, drops)", Command: "tc -s qdisc show"},
			Action{Text: "Otherwise the queue is at the bottleneck on the path (often a router, modem or VPN gateway): fq_codel or cake there keeps it short; see where the RTT jumps", Command: "mtr -rwzbc 100 " + g.key})
		if q := a.in.Sysctl["net.core.default_qdisc"]; q != "" && q != "fq" && q != "fq_codel" && q != "cake" {
			f.Actions = append(f.Actions, Action{
				Text:    fmt.Sprintf("default_qdisc is %s; fq or fq_codel keep queues short", q),
				Command: "sysctl -w net.core.default_qdisc=fq",
			})
		}
		if cc := a.in.Sysctl["net.ipv4.tcp_congestion_control"]; cc != "bbr" &&
			slices.Contains(strings.Fields(a.in.Sysctl["net.ipv4.tcp_available_congestion_control"]), "bbr") {
			f.Actions = append(f.Actions, Action{
				Text:    fmt.Sprintf("BBR (available, current: %s) builds much smaller queues than loss-based congestion control", cc),
				Command: "sysctl -w net.ipv4.tcp_congestion_control=bbr",
			})
		}
		a.add(f)
	}
}

// ruleRwndLimited: throughput capped by the receiver's advertised window.
// From the sending end a receive buffer too small for the path and a slow
// reader (whose full buffer leaves little window) look the same, so the
// finding names both unless the receiver is on this host, where its Recv-Q
// tells. The delivery rate isn't evidence here: under a window limit it is
// the window divided by the RTT, whatever the path could carry.
func ruleRwndLimited(a *analysis) {
	key := func(c *model.Connection) string {
		if rcv := a.localPeer(c); rcv != nil {
			if _, ok := signalOf(rcv, model.SignalRcvbufLimited); ok {
				return "" // the receiver's own rcvbuf finding covers it
			}
		}
		return c.PeerAddr
	}
	for _, g := range a.groupBySignal(key, model.SignalRwndLimited) {
		c0 := g.conns[0]
		f := Finding{
			ID:       "rwnd|" + g.key,
			Severity: g.sev,
			Title:    fmt.Sprintf("Throughput to %s is limited by the receiver's window", g.key),
			Detail:   "We could send faster, but the receiver's advertised window holds us back: either its receive buffer is too small for this path, or the application there reads slowly and its buffer is full. From this end the two look the same.",
			Filter:   filterJoin("peer=="+g.key, "signal=RWND_LIM"),
			Count:    len(g.conns),
		}
		if s, ok := signalOf(c0, model.SignalRwndLimited); ok {
			f.Evidence = append(f.Evidence, fmt.Sprintf("blocked on the window %v", s.Value))
		}
		if c0.SndWnd != nil && c0.RTT != nil && *c0.RTT > 0 {
			f.Evidence = append(f.Evidence, fmt.Sprintf("the receiver advertises %s; at %.0f ms RTT that caps a connection at ≈%s/s",
				humanBytes(float64(*c0.SndWnd)), *c0.RTT, humanBytes(float64(*c0.SndWnd)/(*c0.RTT/1000))))
		}
		switch {
		case c0.WscaleSnd == nil:
			f.Evidence = append(f.Evidence, "window scaling wasn't negotiated — the window can't exceed 64 KB")
			if v, ok := a.in.Sysctl.Int("net.ipv4.tcp_window_scaling"); ok && v == 0 {
				f.Actions = append(f.Actions, Action{Text: "Window scaling is disabled on this host", Command: "sysctl -w net.ipv4.tcp_window_scaling=1"})
			} else {
				f.Actions = append(f.Actions, Action{Text: "Enable window scaling on the receiver, and check for a middlebox stripping the TCP option"})
			}
		case *c0.WscaleSnd == 0:
			f.Evidence = append(f.Evidence, "the receiver advertises window scale 0 — its window can't exceed 64 KB")
		}
		rcv := a.localPeer(c0)
		var slowReader bool
		if rcv != nil {
			_, slowReader = signalOf(rcv, model.SignalRecvBufferPressure)
		}
		switch {
		case slowReader:
			f.Detail = "We could send faster, but the receiver's advertised window holds us back. The receiver is on this host and its receive queue is full: the application reads slowly, and a bigger buffer wouldn't help."
			f.Evidence = append(f.Evidence, fmt.Sprintf("the receiving socket (%s) has %s waiting in Recv-Q", a.procLabel(rcv), humanBytes(float64(deref(rcv.RecvQ)))))
			if rcv.PID != nil {
				f.Actions = append(f.Actions, Action{Text: "Find out why the reader is slow — CPU-bound or blocked", Command: fmt.Sprintf("top -H -p %d", *rcv.PID)})
			}
		case rcv != nil:
			if v := a.in.Sysctl.Ints("net.ipv4.tcp_rmem"); len(v) == 3 {
				f.Actions = append(f.Actions, Action{
					Text:    fmt.Sprintf("The receiver is on this host and keeps up with its data, so its buffer is the cap; tcp_rmem max is %s", humanBytes(float64(v[2]))),
					Command: fmt.Sprintf(`sysctl -w net.ipv4.tcp_rmem="%d %d %d"`, v[0], v[1], roundUpMB(float64(v[2])*2)),
				})
			}
		default:
			var ports []string
			for _, c := range g.conns {
				if p := "sport = :" + c.PeerPort; !slices.Contains(ports, p) {
					ports = append(ports, p)
				}
			}
			slices.Sort(ports)
			f.Actions = append(f.Actions,
				Action{Text: fmt.Sprintf("On %s, look at the receiving sockets: a full Recv-Q means the application there reads slowly (fix the reader); a nearly empty one means its buffer is too small", g.key),
					Command: fmt.Sprintf("ss -tmn '%s'", strings.Join(ports, " or "))},
				Action{Text: "For a small buffer: raise its tcp_rmem max, or SO_RCVBUF if the app sets one (which also disables autotuning)"})
		}
		a.add(f)
	}
}

// ruleSndbufLimited: throughput capped by our own send buffer, per process.
// Autotuning grows a send buffer up to exactly tcp_wmem max, so a full one
// at any other size is held there: the application set SO_SNDBUF, which
// turns autotuning off (and can exceed tcp_wmem max). One at the max needs a
// higher max. (The delivery
// rate isn't evidence: under the cap it's the buffer divided by the RTT.)
func ruleSndbufLimited(a *analysis) {
	for _, g := range a.groupBySignal(procKey, model.SignalSndbufLimited) {
		c0 := g.conns[0]
		f := Finding{
			ID:       "sndbuf|" + g.key,
			Severity: g.sev,
			Title:    fmt.Sprintf("%s: throughput capped by the local send buffer", a.procLabel(c0)),
			Detail:   "The network could take more, but the socket's send buffer is too small to keep enough data in flight for this path.",
			Filter:   filterJoin(procFilter(c0), "signal=SNDBUF_LIM"),
			Count:    len(g.conns),
		}
		if s, ok := signalOf(c0, model.SignalSndbufLimited); ok {
			f.Evidence = append(f.Evidence, fmt.Sprintf("blocked on the send buffer: %v", s.Value))
		}
		if c0.SendQ != nil && c0.RTT != nil && *c0.RTT > 0 {
			flight := *c0.SendQ // the send queue holds what's in flight, plus anything unsent
			if c0.Unacked != nil && c0.MSS != nil {
				flight = min(flight, *c0.Unacked**c0.MSS)
			}
			f.Evidence = append(f.Evidence, fmt.Sprintf("≈%s in flight; at %.0f ms RTT that caps a connection at ≈%s/s",
				humanBytes(float64(flight)), *c0.RTT, humanBytes(float64(flight)/(*c0.RTT/1000))))
		}
		wmax, _ := a.in.Sysctl.Int("net.core.wmem_max")
		setByApp := fmt.Sprintf("If %s sets SO_SNDBUF itself, autotuning is off — remove it or raise it (also capped by net.core.wmem_max = %s)", a.procLabel(c0), humanBytes(float64(wmax)))
		v := a.in.Sysctl.Ints("net.ipv4.tcp_wmem")
		switch {
		case len(v) == 3 && c0.SkmemTB != nil && *c0.SkmemTB != v[2]:
			f.Evidence = append(f.Evidence, fmt.Sprintf("the buffer (%s) is full but not at tcp_wmem max (%s), where autotuning would take it", humanBytes(float64(*c0.SkmemTB)), humanBytes(float64(v[2]))))
			f.Actions = append(f.Actions, Action{Text: fmt.Sprintf("%s most likely sets SO_SNDBUF, which turns autotuning off — remove it or raise it (capped by net.core.wmem_max = %s)", a.procLabel(c0), humanBytes(float64(wmax)))})
		case len(v) == 3:
			f.Evidence = append(f.Evidence, fmt.Sprintf("the buffer has grown to tcp_wmem max (%s)", humanBytes(float64(v[2]))))
			f.Actions = append(f.Actions,
				Action{Text: "Let autotuning grow send buffers further", Command: fmt.Sprintf(`sysctl -w net.ipv4.tcp_wmem="%d %d %d"`, v[0], v[1], roundUpMB(float64(v[2])*2))},
				Action{Text: setByApp})
		default:
			f.Actions = append(f.Actions, Action{Text: setByApp})
		}
		a.add(f)
	}
}

// ruleRcvbufLimited: this host's receive buffers cap what peers send, per
// process: the receiving end's view of what the sender sees as RWND_LIM.
// Autotuning grows a receive buffer up to exactly tcp_rmem max, so one held
// at any other size was fixed by the application (SO_RCVBUF, which turns
// autotuning off); one at the max needs a higher max.
func ruleRcvbufLimited(a *analysis) {
	for _, g := range a.groupBySignal(procKey, model.SignalRcvbufLimited) {
		c0 := g.conns[0]
		f := Finding{
			ID:       "rcvbuf|" + g.key,
			Severity: g.sev,
			Title:    fmt.Sprintf("%s: receive buffer caps what peers can send (%s)", a.procLabel(c0), plural(len(g.conns), "connection")),
			Detail:   "The application reads everything that arrives, but the socket's receive buffer is too small for the path: the whole advertised window arrives every round trip, so the sender waits on it instead of using the link.",
			Filter:   filterJoin(procFilter(c0), "signal=RCVBUF_LIM"),
			Count:    len(g.conns),
		}
		if s, ok := signalOf(c0, model.SignalRcvbufLimited); ok {
			f.Evidence = append(f.Evidence, fmt.Sprint(s.Value))
		}
		if c0.RcvWnd != nil && c0.RcvRTT != nil && *c0.RcvRTT > 0 {
			f.Evidence = append(f.Evidence, fmt.Sprintf("at %.0f ms RTT a %s window caps a connection at ≈%s/s",
				*c0.RcvRTT, humanBytes(float64(*c0.RcvWnd)), humanBytes(float64(*c0.RcvWnd)/(*c0.RcvRTT/1000))))
		}
		rmax, _ := a.in.Sysctl.Int("net.core.rmem_max")
		setByApp := fmt.Sprintf("If %s sets SO_RCVBUF itself, autotuning is off — remove it or raise it (capped by net.core.rmem_max = %s)", a.procLabel(c0), humanBytes(float64(rmax)))
		v := a.in.Sysctl.Ints("net.ipv4.tcp_rmem")
		switch {
		case len(v) == 3 && c0.SkmemRB != nil && *c0.SkmemRB != v[2]:
			f.Evidence = append(f.Evidence, fmt.Sprintf("the buffer (%s) isn't at tcp_rmem max (%s), where autotuning would take it", humanBytes(float64(*c0.SkmemRB)), humanBytes(float64(v[2]))))
			f.Actions = append(f.Actions, Action{Text: fmt.Sprintf("%s most likely sets SO_RCVBUF, which turns autotuning off — remove it or raise it (capped by net.core.rmem_max = %s)", a.procLabel(c0), humanBytes(float64(rmax)))})
		case len(v) == 3:
			f.Evidence = append(f.Evidence, fmt.Sprintf("the buffer has grown to tcp_rmem max (%s)", humanBytes(float64(v[2]))))
			f.Actions = append(f.Actions,
				Action{Text: "Let autotuning grow receive buffers further", Command: fmt.Sprintf(`sysctl -w net.ipv4.tcp_rmem="%d %d %d"`, v[0], v[1], roundUpMB(float64(v[2])*2))},
				Action{Text: setByApp})
		default:
			f.Actions = append(f.Actions, Action{Text: setByApp})
		}
		a.add(f)
	}
}

// ruleCloseWaitLeak: a process sitting on CLOSE-WAIT sockets (fd leak). The
// classifier already aggregates this per PID.
func ruleCloseWaitLeak(a *analysis) {
	for _, g := range a.groupBySignal(procKey, model.SignalCloseWaitLeak) {
		c0 := g.conns[0]
		peers := map[string]int{}
		for _, c := range g.conns {
			peers[endpoint(c.PeerAddr, c.PeerPort)]++
		}
		f := Finding{
			ID:       "close_wait|" + g.key,
			Severity: g.sev,
			Title:    fmt.Sprintf("%s is leaking sockets: %d stuck in CLOSE-WAIT", a.procLabel(c0), len(g.conns)),
			Detail:   "The peers hung up, but the application never called close(). Each socket holds a file descriptor until the process runs out.",
			Evidence: []string{"peers: " + strings.Join(topBy(peers, 3), ", ")},
			Actions: []Action{
				{Text: "Find the code path that doesn't close a connection after the peer disconnects (missing close/defer, a connection-pool bug, an error path)"},
			},
			Filter: filterJoin("state=CLOSE-WAIT", procFilter(c0)),
			Count:  len(g.conns),
		}
		if c0.PID != nil {
			f.Actions = append(f.Actions,
				Action{Text: "Check how close it is to its file-descriptor limit", Command: fmt.Sprintf("ls /proc/%d/fd | wc -l; grep 'open files' /proc/%d/limits", *c0.PID, *c0.PID)})
		}
		f.Actions = append(f.Actions, Action{Text: "Restarting frees them for now, but they'll come back until the code is fixed"})
		a.add(f)
	}
}

// ruleTimeWaitStorm: connection churn toward one peer endpoint.
func ruleTimeWaitStorm(a *analysis) {
	key := func(c *model.Connection) string { return endpoint(c.PeerAddr, c.PeerPort) }
	for _, g := range a.groupBySignal(key, model.SignalTimeWaitStorm) {
		c0 := g.conns[0]
		f := Finding{
			ID:       "time_wait|" + g.key,
			Severity: g.sev,
			Title:    fmt.Sprintf("%d TIME-WAIT sockets toward %s — connections opened and closed too often", len(g.conns), g.key),
			Detail:   "Each closed connection holds its local port for ~60s. Opening a new connection per request to the same peer burns through the ephemeral port range.",
			Actions: []Action{
				{Text: "Reuse connections instead of opening one per request (HTTP keep-alive, a client connection pool)"},
			},
			Filter: filterJoin("state=TIME-WAIT", "peer=="+c0.PeerAddr, "dport="+c0.PeerPort),
			Count:  len(g.conns),
		}
		f.Actions = append(f.Actions, twReuseActions(a)...)
		a.add(f)
	}
}

// twReuseActions suggests enabling tcp_tw_reuse when it's not already on.
func twReuseActions(a *analysis) []Action {
	v, ok := a.in.Sysctl.Int("net.ipv4.tcp_tw_reuse")
	if !ok || v == 1 {
		return nil
	}
	note := ""
	if v == 2 {
		note = " (currently 2: loopback only)"
	}
	return []Action{{
		Text:    "Let new outgoing connections safely reuse TIME-WAIT ports" + note,
		Command: "sysctl -w net.ipv4.tcp_tw_reuse=1",
	}}
}

// PortRange returns the configured ephemeral port range (Linux default when
// unknown).
func PortRange(s map[string]string) (lo, hi int) {
	lo, hi = 32768, 60999
	if f := strings.Fields(s["net.ipv4.ip_local_port_range"]); len(f) == 2 {
		if v, err := strconv.Atoi(f[0]); err == nil {
			lo = v
		}
		if v, err := strconv.Atoi(f[1]); err == nil {
			hi = v
		}
	}
	return lo, hi
}

// PortsInUse counts distinct local ports inside [lo, hi] across conns. TCP
// and UDP allocate from the same range, so de-duping by number is the right
// measure of how close the host is to running out.
func PortsInUse(conns []*model.Connection, lo, hi int) int {
	used := make(map[int]bool)
	for _, c := range conns {
		if p, err := strconv.Atoi(c.LocalPort); err == nil && p >= lo && p <= hi {
			used[p] = true
		}
	}
	return len(used)
}

// ruleEphemeralPorts: host-wide ephemeral port exhaustion risk.
func ruleEphemeralPorts(a *analysis) {
	lo, hi := PortRange(a.in.Sysctl)
	if hi <= lo {
		return
	}
	size := hi - lo + 1
	used := PortsInUse(a.in.Conns, lo, hi)
	pct := float64(used) / float64(size) * 100
	sev := 0
	switch {
	case pct >= 90:
		sev = 2
	case pct >= 70:
		sev = 1
	}
	if sev == 0 {
		return
	}
	peers := map[string]int{}
	for _, c := range a.in.Conns {
		if p, err := strconv.Atoi(c.LocalPort); err == nil && p >= lo && p <= hi {
			peers[endpoint(c.PeerAddr, c.PeerPort)]++
		}
	}
	f := Finding{
		ID:       "ephemeral_ports",
		Severity: sev,
		Title:    fmt.Sprintf("Ephemeral ports %.0f%% used (%d of %d)", pct, used, size),
		Detail:   "When the range runs out, outgoing connect() calls fail with EADDRNOTAVAIL.",
		Evidence: []string{"most ports go to " + strings.Join(topBy(peers, 3), ", ")},
		Actions: []Action{
			{Text: "Reuse connections (keep-alive / pooling) toward the busiest peers"},
			{Text: fmt.Sprintf("Widen the range (now %d–%d)", lo, hi), Command: `sysctl -w net.ipv4.ip_local_port_range="1024 65535"`},
		},
		Count: used,
	}
	f.Actions = append(f.Actions, twReuseActions(a)...)
	a.add(f)
}

// ---- host-counter rules -------------------------------------------------

// findByPrefix returns the first existing finding whose ID starts with prefix.
func (a *analysis) findByPrefix(prefix string) *Finding {
	for i := range a.out {
		if strings.HasPrefix(a.out[i].ID, prefix) {
			return &a.out[i]
		}
	}
	return nil
}

// ruleListenOverflowHost: the kernel counted accept-queue overflows. If a
// listener is full right now, ruleListenQueue already covers it; otherwise
// queues are overflowing in bursts between polls.
func ruleListenOverflowHost(a *analysis) {
	over, _ := a.rate("TcpExt:ListenOverflows")
	drops, _ := a.rate("TcpExt:ListenDrops")
	if over <= 0 && drops <= 0 {
		return
	}
	if a.findByPrefix("listen_queue|") != nil {
		return
	}
	// Name the fullest listeners as likely culprits.
	type lq struct {
		c     *model.Connection
		ratio float64
	}
	var ls []lq
	for _, c := range a.in.Conns {
		if c.State == "LISTEN" && deref(c.SendQ) > 0 {
			ls = append(ls, lq{c, float64(deref(c.RecvQ)) / float64(deref(c.SendQ))})
		}
	}
	slices.SortFunc(ls, func(x, y lq) int {
		switch {
		case x.ratio > y.ratio:
			return -1
		case x.ratio < y.ratio:
			return 1
		}
		return 0
	})
	f := Finding{
		ID:       "listen_overflow_host",
		Severity: 2,
		Title:    "Accept queues are overflowing in bursts — connections are being dropped",
		Detail:   "No listener is full at this instant, but the kernel counted overflows since the last poll: bursts of connections fill a queue faster than the app accepts.",
		Evidence: []string{fmt.Sprintf("kernel: ListenOverflows +%.1f/s, ListenDrops +%.1f/s", over, drops)},
	}
	var names []string
	for i, l := range ls {
		if i == 3 {
			break
		}
		names = append(names, fmt.Sprintf(":%s %s (%d/%d)", l.c.LocalPort, a.procLabel(l.c), deref(l.c.RecvQ), deref(l.c.SendQ)))
	}
	if len(names) > 0 {
		f.Evidence = append(f.Evidence, "fullest listeners: "+strings.Join(names, ", "))
	}
	if somax, ok := a.in.Sysctl.Int("net.core.somaxconn"); ok {
		f.Actions = append(f.Actions, Action{
			Text:    fmt.Sprintf("Raise the accept-queue cap (somaxconn = %d) and the app's listen backlog", somax),
			Command: fmt.Sprintf("sysctl -w net.core.somaxconn=%d", max(4096, somax*2)),
		})
	}
	f.Actions = append(f.Actions, Action{Text: "Watch the counters", Command: "nstat -az TcpExtListenOverflows TcpExtListenDrops"})
	a.add(f)
}

// ruleSynBacklog: the kernel answered SYNs with syncookies because a
// listener's SYN queue was full. With syncookies on (the default) that queue
// is as long as the listener's backlog, the listen() argument capped by
// net.core.somaxconn; tcp_max_syn_backlog only applies with syncookies off,
// when no cookies are sent at all. So the listeners holding half-open
// connections, and their backlogs, are the evidence and the knob.
func ruleSynBacklog(a *analysis) {
	r, _ := a.rate("TcpExt:SyncookiesSent")
	if r <= 0 {
		return
	}
	synRecv := 0
	halfOpen := map[string]int{} // by local port
	for _, c := range a.in.Conns {
		if c.State == "SYN-RECV" {
			synRecv++
			halfOpen[c.LocalPort]++
		}
	}
	f := Finding{
		ID:       "syn_backlog",
		Severity: 1,
		Title:    "SYN backlog overflowing — the kernel is answering with syncookies",
		Detail:   "More half-open connections arrive than a listener's SYN queue holds: either a SYN flood, or legitimate load above the listener's backlog. With syncookies on, the SYN queue is as long as the backlog (the listen() argument, capped by net.core.somaxconn).",
		Evidence: []string{fmt.Sprintf("kernel: SyncookiesSent +%.1f/s · %d sockets in SYN-RECV", r, synRecv)},
		Actions: []Action{
			{Text: "See where the half-open connections come from", Command: `ss -tn state syn-recv | awk 'NR>1{sub(/:[0-9]+$/,"",$4); print $4}' | sort | uniq -c | sort -rn | head`},
		},
		Filter: "state=SYN-RECV",
	}
	// One line per port: SO_REUSEPORT groups and per-address listeners share
	// the port's half-open count, which can't be split between them.
	var listeners []*model.Connection
	sockets := map[string]int{}
	for _, c := range a.in.Conns {
		if c.State == "LISTEN" && halfOpen[c.LocalPort] > 0 {
			if sockets[c.LocalPort]++; sockets[c.LocalPort] == 1 {
				listeners = append(listeners, c)
			}
		}
	}
	slices.SortFunc(listeners, func(x, y *model.Connection) int { return halfOpen[y.LocalPort] - halfOpen[x.LocalPort] })
	for _, l := range listeners[:min(len(listeners), 3)] {
		ev := fmt.Sprintf("listener :%s (%s): %d half-open, backlog %d", l.LocalPort, a.procLabel(l), halfOpen[l.LocalPort], deref(l.SendQ))
		if n := sockets[l.LocalPort]; n > 1 {
			ev += fmt.Sprintf(" each across %d listening sockets", n)
		}
		f.Evidence = append(f.Evidence, ev)
	}
	somax, haveSomax := a.in.Sysctl.Int("net.core.somaxconn")
	switch {
	case len(listeners) > 0 && haveSomax && deref(listeners[0].SendQ) < somax:
		f.Actions = append(f.Actions, Action{Text: fmt.Sprintf("If the traffic is legitimate, raise the backlog in %s's config (the listen() argument); somaxconn = %d isn't the limit", a.procLabel(listeners[0]), somax)})
	case haveSomax:
		f.Actions = append(f.Actions, Action{
			Text:    fmt.Sprintf("If the traffic is legitimate, raise the cap on listen backlogs (somaxconn = %d) and the app's backlog with it", somax),
			Command: fmt.Sprintf("sysctl -w net.core.somaxconn=%d", max(4096, somax*2)),
		})
	}
	a.add(f)
}

// ruleUDPRcvbufHost: UDP datagrams dropped because receive buffers were full.
// Folds into the per-process finding when the dropping sockets are visible.
func ruleUDPRcvbufHost(a *analysis) {
	r, _ := a.rate("Udp:RcvbufErrors")
	if r <= 0 {
		return
	}
	ev := fmt.Sprintf("kernel: Udp RcvbufErrors +%.1f/s", r)
	folded := false
	for i := range a.out {
		if a.udpBacklog[a.out[i].ID] {
			a.out[i].Evidence = append(a.out[i].Evidence, ev)
			folded = true
		}
	}
	if folded {
		return
	}
	rmemMax, _ := a.in.Sysctl.Int("net.core.rmem_max")
	a.add(Finding{
		ID:       "udp_rcvbuf_host",
		Severity: 2,
		Title:    "UDP datagrams are being dropped: receive buffers full",
		Detail:   "Some UDP application isn't reading fast enough (or its buffer is too small for bursts), so the kernel discards incoming datagrams.",
		Evidence: []string{ev, fmt.Sprintf("net.core.rmem_max = %s", humanBytes(float64(rmemMax)))},
		Actions: []Action{
			{Text: "Find sockets with queued data", Command: "ss -uanpm | awk '$2 > 0'"},
			{Text: "Raise the cap, then the app's SO_RCVBUF (UDP doesn't autotune)", Command: fmt.Sprintf("sysctl -w net.core.rmem_max=%d", roundUpMB(max(float64(rmemMax)*4, 8<<20)))},
		},
		Filter: "proto=udp",
	})
}

// ruleRetransHost: high host-wide TCP retransmit rate, over the last
// poller.SlotWindow rather than one poll: a slow-start overshoot or a burst
// of requests can resend a large share of one poll's segments on a healthy
// host. Skipped only when the host-wide loss finding already covers it: a
// single lossy peer doesn't explain a high rate across the whole host.
func ruleRetransHost(a *analysis) {
	pct, ok := a.windowRetransPct()
	if !ok {
		return // too little history or traffic for a meaningful rate
	}
	sev := 0
	switch {
	case pct >= 10:
		sev = 2
	case pct >= 2:
		sev = 1
	}
	if sev == 0 || a.findByPrefix("loss_local") != nil {
		return
	}
	a.add(Finding{
		ID:       "retrans_host",
		Severity: sev,
		Title:    fmt.Sprintf("Host-wide TCP retransmit rate is %.1f%% over the last %s", pct, poller.SlotWindow().Round(time.Second)),
		Detail:   "A noticeable share of all outgoing TCP segments are resent. No single connection stands out, so look at the host's link and load.",
		Evidence: windowRetransEvidence(a),
		Actions:  localLossActions(),
	})
}

// ruleRcvMemPressure: the kernel pruned receive queues or dropped segments
// for lack of socket memory.
func ruleRcvMemPressure(a *analysis) {
	var parts []string
	for _, k := range []string{"TcpExt:PruneCalled", "TcpExt:RcvPruned", "TcpExt:OfoPruned", "TcpExt:TCPBacklogDrop"} {
		if r, _ := a.rate(k); r > 0 {
			parts = append(parts, fmt.Sprintf("%s +%.1f/s", strings.TrimPrefix(k, "TcpExt:"), r))
		}
	}
	if len(parts) == 0 {
		return
	}
	f := Finding{
		ID:       "rcv_mem_pressure",
		Severity: 1,
		Title:    "TCP is under receive-memory pressure — the kernel is pruning queues",
		Detail:   "Socket receive memory hit its limits, so the kernel collapsed or discarded queued data. Applications are reading too slowly or tcp_mem/tcp_rmem are too small for the load.",
		Evidence: []string{"kernel: " + strings.Join(parts, ", ")},
		Actions: []Action{
			{Text: "Compare current TCP memory with the tcp_mem limits (pages)", Command: "cat /proc/net/sockstat"},
		},
	}
	if v := a.in.Sysctl["net.ipv4.tcp_mem"]; v != "" {
		f.Evidence = append(f.Evidence, "net.ipv4.tcp_mem = "+v+" (pages)")
	}
	a.add(f)
}
