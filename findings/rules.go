package findings

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"sstui/classifier"
	"sstui/model"
)

// rules run in order; host-counter rules come after the per-socket ones so
// they can fold their evidence into an existing finding instead of
// duplicating it.
var rules = []func(*analysis){
	ruleZeroWindow,
	ruleRecvBacklog,
	ruleListenQueue,
	ruleSynStall,
	rulePathLoss,
	ruleInboundLoss,
	ruleReordering,
	rulePMTU,
	ruleRTTInflation,
	ruleRwndLimited,
	ruleSndbufLimited,
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
	// Drops that come with inbound loss and an unpressured receive queue are
	// out-of-order data discarded during recovery, not a slow reader;
	// ruleInboundLoss reports those.
	key := func(c *model.Connection) string {
		if classifier.DropsExplainedByInboundLoss(c.Signals) {
			return ""
		}
		return procKey(c)
	}
	for _, g := range a.groupBySignal(key, model.SignalRecvBufferPressure, model.SignalSocketDrops) {
		c0 := g.conns[0]
		var queued, drops, udp int
		listen := false // a listener with drops: Live must show LISTEN sockets
		for _, c := range g.conns {
			queued += deref(c.RecvQ)
			drops += deref(c.DeltaSkmemD)
			if c.Protocol == "udp" {
				udp++
			}
			listen = listen || c.State == "LISTEN"
		}
		f := Finding{
			ID:       "recv_backlog|" + g.key,
			Severity: g.sev,
			Title:    fmt.Sprintf("%s isn't reading fast enough: %s backed up", a.procLabel(c0), plural(len(g.conns), "socket")),
			Detail:   "Data arrives faster than the application reads it; once a socket's receive buffer fills, the kernel drops (UDP) or throttles (TCP) the sender.",
			Evidence: []string{fmt.Sprintf("%s waiting in Recv-Q", humanBytes(float64(queued)))},
			// Same exclusion as the grouping: DROPS counts here unless it
			// comes with RX_LOSS (and no RCV_Q, which the first term covers).
			Filter:     filterJoin(procFilter(c0), "(signal=RCV_Q or (signal=DROPS not signal=RX_LOSS))"),
			ShowListen: listen,
			Count:      len(g.conns),
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
		if udp < len(g.conns) {
			if v := a.in.Sysctl.Ints("net.ipv4.tcp_rmem"); len(v) == 3 {
				f.Actions = append(f.Actions, Action{
					Text:    fmt.Sprintf("For TCP, a larger buffer only helps with bursts (tcp_rmem max is %s)", humanBytes(float64(v[2]))),
					Command: fmt.Sprintf(`sysctl -w net.ipv4.tcp_rmem="%d %d %d"`, v[0], v[1], roundUpMB(float64(v[2])*2)),
				})
			}
		}
		a.add(f)
	}
}

// ruleListenQueue: full accept queues, per listener. Tells apart a backlog
// capped by somaxconn from one the application chose itself.
func ruleListenQueue(a *analysis) {
	key := func(c *model.Connection) string { return endpoint(c.LocalAddr, c.LocalPort) }
	for _, g := range a.groupBySignal(key, model.SignalListenQueueFull) {
		c0 := g.conns[0]
		rq, sq := deref(c0.RecvQ), deref(c0.SendQ)
		f := Finding{
			ID:         "listen_queue|" + g.key,
			Severity:   g.sev,
			Title:      fmt.Sprintf("Accept queue full on :%s (%s) — new connections are being dropped", c0.LocalPort, a.procLabel(c0)),
			Detail:     "Clients complete the handshake but the application isn't calling accept() fast enough, so the kernel drops new SYNs or ACKs once the queue is full.",
			Evidence:   []string{fmt.Sprintf("queue %d / %d", rq, sq)},
			Filter:     filterJoin("state=LISTEN", "sport="+c0.LocalPort),
			ShowListen: true,
			Count:      len(g.conns),
		}
		if s, ok := a.rate("TcpExt:ListenOverflows"); ok && s > 0 {
			f.Evidence = append(f.Evidence, fmt.Sprintf("kernel: ListenOverflows +%.1f/s", s))
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

var lossSignals = []model.SignalType{
	model.SignalRTOFiring, model.SignalPeerNoAck, model.SignalCongestionLoss,
	model.SignalHighRetransRate, model.SignalRetransInFlight,
}

// rulePathLoss: retransmission trouble. Loss toward one peer points at that
// peer or its path; loss toward many peers at once points at this host.
func rulePathLoss(a *analysis) {
	groups := a.groupBySignal(func(c *model.Connection) string { return c.PeerAddr }, lossSignals...)
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
		a.add(Finding{
			ID:       "loss|" + g.key,
			Severity: g.sev,
			Title:    fmt.Sprintf("Packet loss toward %s: %s retransmitting", g.key, plural(len(g.conns), "connection")),
			Detail:   "Only this destination is affected, so the loss is on its side or somewhere along the path to it.",
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

// lossEvidence summarizes which loss signals fired and the aggregate
// retransmit rate across conns.
func lossEvidence(conns []*model.Connection) string {
	counts := map[string]int{}
	var sent, retr int
	for _, c := range conns {
		for _, s := range c.Signals {
			if slices.Contains(lossSignals, s.Type) {
				counts[s.Type.Label()]++
			}
		}
		sent += deref(c.DeltaBytesSent)
		retr += deref(c.DeltaBytesRetrans)
	}
	ev := strings.Join(topBy(counts, len(counts)), " · ")
	if sent > 0 {
		ev += fmt.Sprintf(" · %.1f%% of bytes retransmitted this poll", float64(retr)/float64(sent)*100)
	}
	return ev
}

func retransRateEvidence(a *analysis) []string {
	out, ok := a.rate("Tcp:OutSegs")
	if !ok || out <= 0 {
		return nil
	}
	re, _ := a.rate("Tcp:RetransSegs")
	return []string{fmt.Sprintf("host-wide: %.1f%% of TCP segments retransmitted (%.0f/s)", re/out*100, re)}
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
	// ratio returns the aggregate evidence line (none when no data-segment
	// counts are known, rather than an empty bullet).
	ratio := func(conns []*model.Connection) []string {
		var ooo, in int
		for _, c := range conns {
			ooo += deref(c.DeltaRcvOOOPack)
			in += deref(c.DeltaDataSegsIn)
		}
		if in == 0 {
			return nil
		}
		return []string{fmt.Sprintf("%.1f%% of %d data segments received this poll arrived after a gap", float64(ooo)/float64(in)*100, in)}
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
		ev, dsev := discardEvidence(conns)
		f := Finding{
			ID:       "rx_loss_local",
			Severity: max(sev, dsev),
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
		ev, sev := discardEvidence(g.conns)
		a.add(Finding{
			ID:       "rx_loss|" + g.key,
			Severity: max(g.sev, sev),
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
// classifier.DropsExplainedByInboundLoss) and returns the severity they add:
// discarded out-of-order data forces extra retransmits, so it can raise the
// inbound-loss finding to the DROPS signal's severity.
func discardEvidence(conns []*model.Connection) ([]string, int) {
	drops, sev := 0, 0
	for _, c := range conns {
		if !classifier.DropsExplainedByInboundLoss(c.Signals) {
			continue
		}
		drops += deref(c.DeltaSkmemD)
		if s, ok := signalOf(c, model.SignalSocketDrops); ok {
			sev = max(sev, s.Severity)
		}
	}
	if drops == 0 {
		return nil, 0
	}
	return []string{fmt.Sprintf("the kernel also discarded %s (receive memory full during loss recovery) — not a slow reader: the receive queue is empty", plural(drops, "out-of-order segment"))}, sev
}

// ruleReordering: sender-detected reordering, grouped by peer.
func ruleReordering(a *analysis) {
	for _, g := range a.groupBySignal(func(c *model.Connection) string { return c.PeerAddr }, model.SignalReordering) {
		events, lossy := 0, 0
		for _, c := range g.conns {
			events += deref(c.DeltaReordSeen)
			for _, s := range c.Signals {
				if slices.Contains(lossSignals, s.Type) {
					lossy++
					break
				}
			}
		}
		ev := []string{fmt.Sprintf("the sender detected %d reordering events in the last poll", events)}
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
		f.Actions = append(f.Actions, Action{Text: "Check for a deep FIFO queue on the egress interface", Command: "tc -s qdisc show"})
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

// bdpBytes estimates a connection's bandwidth-delay product from its delivery
// rate and RTT: the in-flight data needed to keep the path full.
func bdpBytes(c *model.Connection) (float64, bool) {
	if c.DeliveryRate == nil || c.RTT == nil || *c.DeliveryRate <= 0 {
		return 0, false
	}
	return float64(*c.DeliveryRate) / 8 * *c.RTT / 1000, true
}

// ruleRwndLimited: throughput capped by the receiver's advertised window.
func ruleRwndLimited(a *analysis) {
	for _, g := range a.groupBySignal(func(c *model.Connection) string { return c.PeerAddr }, model.SignalRwndLimited) {
		c0 := g.conns[0]
		f := Finding{
			ID:       "rwnd|" + g.key,
			Severity: g.sev,
			Title:    fmt.Sprintf("Throughput to %s is limited by the receiver's window", g.key),
			Detail:   "We could send faster, but the receiver's advertised window is too small for this path — its buffer, not the network, is the bottleneck.",
			Filter:   filterJoin("peer=="+g.key, "signal=RWND_LIM"),
			Count:    len(g.conns),
		}
		if s, ok := signalOf(c0, model.SignalRwndLimited); ok {
			f.Evidence = append(f.Evidence, fmt.Sprintf("blocked on the window %v", s.Value))
		}
		bdp, haveBDP := bdpBytes(c0)
		if haveBDP {
			f.Evidence = append(f.Evidence, fmt.Sprintf("path needs ≈%s in flight (delivery rate × RTT)", humanBytes(bdp)))
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
		if a.localPeer(c0) != nil {
			if v := a.in.Sysctl.Ints("net.ipv4.tcp_rmem"); len(v) == 3 {
				target := float64(v[2]) * 2
				if haveBDP {
					target = max(target, bdp*2)
				}
				f.Actions = append(f.Actions, Action{
					Text:    fmt.Sprintf("The receiver is on this host; tcp_rmem max is %s", humanBytes(float64(v[2]))),
					Command: fmt.Sprintf(`sysctl -w net.ipv4.tcp_rmem="%d %d %d"`, v[0], v[1], roundUpMB(target)),
				})
			}
		} else {
			f.Actions = append(f.Actions, Action{Text: fmt.Sprintf("Raise the receive buffer on %s (its tcp_rmem max, or SO_RCVBUF if the app sets one — which also disables autotuning)", g.key)})
		}
		a.add(f)
	}
}

// ruleSndbufLimited: throughput capped by our own send buffer, per process.
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
		bdp, haveBDP := 0.0, false
		for _, c := range g.conns {
			if b, ok := bdpBytes(c); ok && b > bdp {
				bdp, haveBDP = b, true
			}
		}
		if haveBDP {
			f.Evidence = append(f.Evidence, fmt.Sprintf("path needs ≈%s in flight (delivery rate × RTT)", humanBytes(bdp)))
		}
		if v := a.in.Sysctl.Ints("net.ipv4.tcp_wmem"); len(v) == 3 {
			target := float64(v[2]) * 2
			if haveBDP {
				target = max(target, bdp*2)
			}
			f.Evidence = append(f.Evidence, fmt.Sprintf("tcp_wmem max is %s", humanBytes(float64(v[2]))))
			f.Actions = append(f.Actions, Action{
				Text:    "Let autotuning grow send buffers further",
				Command: fmt.Sprintf(`sysctl -w net.ipv4.tcp_wmem="%d %d %d"`, v[0], v[1], roundUpMB(target)),
			})
		}
		wmax, _ := a.in.Sysctl.Int("net.core.wmem_max")
		f.Actions = append(f.Actions, Action{Text: fmt.Sprintf("If %s sets SO_SNDBUF itself, autotuning is off — remove it or raise it (also capped by net.core.wmem_max = %s)", a.procLabel(c0), humanBytes(float64(wmax)))})
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

// ruleSynBacklog: the SYN queue overflowed and the kernel fell back to
// syncookies — a SYN flood or a SYN backlog too small for the load.
func ruleSynBacklog(a *analysis) {
	r, _ := a.rate("TcpExt:SyncookiesSent")
	if r <= 0 {
		return
	}
	synRecv := 0
	for _, c := range a.in.Conns {
		if c.State == "SYN-RECV" {
			synRecv++
		}
	}
	f := Finding{
		ID:       "syn_backlog",
		Severity: 1,
		Title:    "SYN backlog overflowing — the kernel is answering with syncookies",
		Detail:   "More half-open connections arrive than the SYN queue holds: either a SYN flood, or legitimate load above the configured backlog.",
		Evidence: []string{fmt.Sprintf("kernel: SyncookiesSent +%.1f/s · %d sockets in SYN-RECV", r, synRecv)},
		Actions: []Action{
			{Text: "See where the half-open connections come from", Command: `ss -tn state syn-recv | awk 'NR>1{split($4,a,":"); print a[1]}' | sort | uniq -c | sort -rn | head`},
		},
		Filter: "state=SYN-RECV",
	}
	if v, ok := a.in.Sysctl.Int("net.ipv4.tcp_max_syn_backlog"); ok {
		f.Actions = append(f.Actions, Action{
			Text:    fmt.Sprintf("If the traffic is legitimate, raise the SYN backlog (now %d)", v),
			Command: fmt.Sprintf("sysctl -w net.ipv4.tcp_max_syn_backlog=%d", v*2),
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

// ruleRetransHost: high host-wide TCP retransmit rate. Skipped only when the
// host-wide loss finding already covers it — a single lossy peer doesn't
// explain a high rate across the whole host.
func ruleRetransHost(a *analysis) {
	pct, ok := a.retransPct()
	if !ok {
		return // too little traffic for a meaningful rate
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
		Title:    fmt.Sprintf("Host-wide TCP retransmit rate is %.1f%%", pct),
		Detail:   "A noticeable share of all outgoing TCP segments are resent. No single connection stands out, so look at the host's link and load.",
		Evidence: retransRateEvidence(a),
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
