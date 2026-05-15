package classifier

import (
	"fmt"
	"ss-stats-tui/model"
)

// Classify analyzes a connection and returns detected signals.
func Classify(c *model.Connection) []model.Signal {
	var signals []model.Signal

	if c.Protocol == "udp" {
		if v := c.RecvQ; v != nil && *v > 0 {
			sev := 1
			if *v > 100 {
				sev = 2
			}
			signals = append(signals, model.Signal{Type: model.SignalRecvBufferPressure, Severity: sev, Value: *v})
		}
		if v := c.SendQ; v != nil && *v > 0 {
			sev := 1
			if *v > 100 {
				sev = 2
			}
			signals = append(signals, model.Signal{Type: model.SignalSendBufferPressure, Severity: sev, Value: *v})
		}
		if c.State == "UDP_IDLE" {
			signals = append(signals, model.Signal{Type: model.SignalIdle, Severity: 0})
		}
		return signals
	}

	if c.State == "LISTEN" {
		// For LISTEN sockets ss reports Recv-Q as the current accept-queue
		// depth and Send-Q as its maximum (somaxconn-capped backlog). A full
		// or nearly-full accept queue means new SYNs are getting dropped,
		// which is a distinct failure from generic buffer pressure.
		rq, sq := 0, 0
		if c.RecvQ != nil {
			rq = *c.RecvQ
		}
		if c.SendQ != nil {
			sq = *c.SendQ
		}
		if sq > 0 && rq > 0 {
			ratio := float64(rq) / float64(sq)
			if ratio > 0.8 {
				sev := 1
				if ratio >= 1.0 {
					sev = 2
				}
				signals = append(signals, model.Signal{Type: model.SignalListenQueueFull, Severity: sev,
					Value: fmt.Sprintf("%d/%d", rq, sq)})
			}
		} else if rq > 0 {
			// Backlog limit unknown — fall back to absolute threshold.
			sev := 1
			if rq > 100 {
				sev = 2
			}
			signals = append(signals, model.Signal{Type: model.SignalListenQueueFull, Severity: sev, Value: rq})
		}
		return signals
	}

	// SYN-SENT with the retransmission timer running and at least one retry
	// means the handshake is stalled — DNS/firewall/route problem.
	if c.State == "SYN-SENT" && c.TimerRetrans != nil && *c.TimerRetrans > 0 {
		sev := 1
		if *c.TimerRetrans >= 3 {
			sev = 2
		}
		signals = append(signals, model.Signal{Type: model.SignalSynStall, Severity: sev, Value: *c.TimerRetrans})
	}

	if v := c.RetransNow; v != nil && *v > 3 {
		sev := 1
		if *v > 10 {
			sev = 2
		}
		signals = append(signals, model.Signal{Type: model.SignalRetransInFlight, Severity: sev, Value: *v})
	}

	// app_limited is a state, not a fault — surface as info only.
	if c.AppLimited == 1 {
		signals = append(signals, model.Signal{Type: model.SignalAppLimited, Severity: 0})
	}

	// IDLE: ESTAB with no bytes moving this poll. Only fire when we actually
	// have deltas to compare against — on the very first snapshot of a new
	// connection both deltas are nil and we can't yet tell idle from active.
	if c.State == "ESTAB" && c.DeltaBytesSent != nil && c.DeltaBytesReceived != nil {
		if *c.DeltaBytesSent == 0 && *c.DeltaBytesReceived == 0 {
			signals = append(signals, model.Signal{Type: model.SignalIdle, Severity: 0})
		}
	}

	if v := c.SndWnd; v != nil && *v == 0 && c.State == "ESTAB" {
		signals = append(signals, model.Signal{Type: model.SignalZeroWindow, Severity: 2})
	}

	if v := c.Lost; v != nil && *v > 2 {
		sev := 1
		if *v > 10 {
			sev = 2
		}
		signals = append(signals, model.Signal{Type: model.SignalCongestionLoss, Severity: sev, Value: *v})
	}

	// Real PMTU problem: path MTU below our advertised MSS.
	if c.PMTU != nil && c.AdvMSS != nil && *c.PMTU > 0 && *c.AdvMSS > 0 {
		// PMTU includes IP+TCP headers (~40-60B). Compare with margin.
		if *c.PMTU < *c.AdvMSS+40 {
			signals = append(signals, model.Signal{Type: model.SignalPMTUMismatch, Severity: 1,
				Value: fmt.Sprintf("pmtu=%d advmss=%d", *c.PMTU, *c.AdvMSS)})
		}
	}

	if c.RTT != nil && c.MinRTT != nil && *c.MinRTT > 0 {
		ratio := *c.RTT / *c.MinRTT
		if ratio > 5 {
			sev := 1
			if ratio > 15 {
				sev = 2
			}
			signals = append(signals, model.Signal{Type: model.SignalRTTSpike, Severity: sev, Value: ratio})
		}
	}

	if v := c.SendQ; v != nil && *v > 0 {
		sev := 1
		if *v > 100 {
			sev = 2
		}
		signals = append(signals, model.Signal{Type: model.SignalSendBufferPressure, Severity: sev, Value: *v})
	}

	if v := c.RecvQ; v != nil && *v > 0 {
		sev := 1
		if *v > 100 {
			sev = 2
		}
		signals = append(signals, model.Signal{Type: model.SignalRecvBufferPressure, Severity: sev, Value: *v})
	}

	if c.DeltaBytesRetrans != nil && c.DeltaBytesSent != nil && *c.DeltaBytesSent > 0 {
		rate := float64(*c.DeltaBytesRetrans) / float64(*c.DeltaBytesSent)
		if rate > 0.05 {
			sev := 1
			if rate > 0.2 {
				sev = 2
			}
			signals = append(signals, model.Signal{Type: model.SignalHighRetransRate, Severity: sev, Value: rate})
		}
	}

	// Only flag delivery drop when the app is actually trying to send.
	if c.AppLimited == 0 && c.DeltaBytesSent != nil && *c.DeltaBytesSent > 0 &&
		c.DeliveryRate != nil && c.PacingRate != nil && *c.PacingRate > 0 {
		ratio := float64(*c.DeliveryRate) / float64(*c.PacingRate)
		if ratio < 0.5 {
			signals = append(signals, model.Signal{Type: model.SignalDeliveryDrop, Severity: 1, Value: ratio})
		}
	}

	// Unacked relative to cwnd: >80% of the congestion window in flight.
	if c.Unacked != nil && c.CWnd != nil && *c.CWnd > 0 && *c.Unacked > 0 {
		if float64(*c.Unacked) > 0.8*float64(*c.CWnd) && *c.Unacked > 10 {
			signals = append(signals, model.Signal{Type: model.SignalUnackedBuildup, Severity: 1, Value: *c.Unacked})
		}
	}

	// RTO firing: retransmission timer active and we've already retransmitted
	// at least twice — RTO is doubling. This catches escalating loss episodes
	// that the RETRANS-in-flight signal can miss when only one segment is
	// outstanding but it keeps timing out.
	if c.State == "ESTAB" && c.TimerType != nil && *c.TimerType == "on" &&
		c.TimerRetrans != nil && *c.TimerRetrans >= 2 {
		sev := 1
		if *c.TimerRetrans >= 4 {
			sev = 2
		}
		signals = append(signals, model.Signal{Type: model.SignalRTOFiring, Severity: sev, Value: *c.TimerRetrans})
	}

	// One-way stall: we are actively transferring in one direction but the
	// other direction has been silent for >30s. Classic symptom of a
	// half-closed peer or stuck application read/write.
	if c.State == "ESTAB" && c.LastSnd != nil && c.LastRcv != nil {
		sending := c.DeltaBytesSent != nil && *c.DeltaBytesSent > 0
		receiving := c.DeltaBytesReceived != nil && *c.DeltaBytesReceived > 0
		if sending && !receiving && *c.LastRcv > 30000 {
			signals = append(signals, model.Signal{Type: model.SignalOneWayStall, Severity: 1,
				Value: fmt.Sprintf("tx only, no rx for %ds", *c.LastRcv/1000)})
		} else if receiving && !sending && *c.LastSnd > 30000 {
			signals = append(signals, model.Signal{Type: model.SignalOneWayStall, Severity: 1,
				Value: fmt.Sprintf("rx only, no tx for %ds", *c.LastSnd/1000)})
		}
	}

	// CWnd collapse: congestion window dropped sharply between polls. Only
	// meaningful when the prior window was non-trivial; tiny windows
	// fluctuate naturally during slow start.
	if c.PrevCWnd != nil && c.CWnd != nil && *c.PrevCWnd >= 20 {
		ratio := float64(*c.CWnd) / float64(*c.PrevCWnd)
		if ratio < 0.5 {
			sev := 1
			if ratio < 0.25 {
				sev = 2
			}
			signals = append(signals, model.Signal{Type: model.SignalCWndCollapse, Severity: sev,
				Value: fmt.Sprintf("%d→%d", *c.PrevCWnd, *c.CWnd)})
		}
	}

	// DSACK growth: peer reported duplicate ACKs since last poll. Means our
	// RTO was too aggressive and we retransmitted unnecessarily.
	if c.DeltaDSACKDups != nil && *c.DeltaDSACKDups > 0 {
		sev := 1
		if *c.DeltaDSACKDups > 5 {
			sev = 2
		}
		signals = append(signals, model.Signal{Type: model.SignalDSACKSpurious, Severity: sev, Value: *c.DeltaDSACKDups})
	}

	// Reordering: receiver saw out-of-order packets this poll. Distinguishes
	// real packet reordering on the path from straight loss — both can
	// trigger spurious retransmits, but the fix is different (often a queue
	// or LACP issue, not congestion).
	if c.DeltaRcvOOOPack != nil && *c.DeltaRcvOOOPack > 0 {
		sev := 1
		if *c.DeltaRcvOOOPack > 50 {
			sev = 2
		}
		signals = append(signals, model.Signal{Type: model.SignalReordering, Severity: sev, Value: *c.DeltaRcvOOOPack})
	}

	// BBR delivering less than half its bandwidth estimate while actively
	// trying to send (and not app-limited). Surfaces BBR-specific
	// under-utilization that the generic DEL_DROP signal may miss when
	// pacing_rate is calibrated to the actual delivery rate.
	if c.BBRBW != nil && *c.BBRBW > 0 && c.DeliveryRate != nil &&
		c.AppLimited == 0 && c.DeltaBytesSent != nil && *c.DeltaBytesSent > 0 {
		ratio := float64(*c.DeliveryRate) / float64(*c.BBRBW)
		if ratio < 0.5 {
			signals = append(signals, model.Signal{Type: model.SignalBBRUnderutil, Severity: 1, Value: ratio})
		}
	}

	return signals
}
