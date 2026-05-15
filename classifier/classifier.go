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
		if v := c.RecvQ; v != nil && *v > 0 {
			sev := 1
			if *v > 100 {
				sev = 2
			}
			signals = append(signals, model.Signal{Type: model.SignalRecvBufferPressure, Severity: sev, Value: *v})
		}
		return signals
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

	// IDLE: ESTAB with no bytes moving this poll.
	if c.State == "ESTAB" {
		tx, rx := 0, 0
		if c.DeltaBytesSent != nil {
			tx = *c.DeltaBytesSent
		}
		if c.DeltaBytesReceived != nil {
			rx = *c.DeltaBytesReceived
		}
		if tx == 0 && rx == 0 {
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

	return signals
}
