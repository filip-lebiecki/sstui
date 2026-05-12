package classifier

import (
	"fmt"
	"ss-stats-tui/model"
)

// Classify analyzes a connection and returns detected signals.
func Classify(c *model.Connection) []model.Signal {
	var signals []model.Signal

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

	if v := c.RetransNow; v != nil && *v > 0 {
		sev := 1
		if *v > 3 {
			sev = 2
		}
		signals = append(signals, model.Signal{Type: model.SignalRetransInFlight, Severity: sev, Value: *v})
	}

	if c.AppLimited == 1 {
		signals = append(signals, model.Signal{Type: model.SignalAppLimited, Severity: 1})
	}

	if v := c.SndWnd; v != nil && *v == 0 && c.State == "ESTAB" {
		signals = append(signals, model.Signal{Type: model.SignalZeroWindow, Severity: 2})
	}

	if v := c.Lost; v != nil && *v > 0 {
		sev := 1
		if *v > 5 {
			sev = 2
		}
		signals = append(signals, model.Signal{Type: model.SignalCongestionLoss, Severity: sev, Value: *v})
	}

	if c.PMTU != nil && c.AdvMSS != nil && c.RcvMSS != nil {
		if *c.AdvMSS != *c.RcvMSS {
			signals = append(signals, model.Signal{Type: model.SignalPMTUMismatch, Severity: 1,
				Value: fmt.Sprintf("%d/%d", *c.AdvMSS, *c.RcvMSS)})
		}
	}

	if c.RTT != nil && c.MinRTT != nil && *c.MinRTT > 0 {
		ratio := *c.RTT / *c.MinRTT
		if ratio > 3 {
			sev := 1
			if ratio > 10 {
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

	if c.SSThresh != nil && c.CWnd != nil {
		if *c.SSThresh < *c.CWnd {
			signals = append(signals, model.Signal{Type: model.SignalCongestionReduce, Severity: 1})
		}
	}

	if c.CWnd != nil && c.MSS != nil && *c.MSS > 0 {
		if *c.CWnd <= 2*(*c.MSS) {
			signals = append(signals, model.Signal{Type: model.SignalSlowStart, Severity: 0})
		}
	}

	if c.SkmemT != nil && c.SkmemTB != nil && *c.SkmemT > *c.SkmemTB/2 {
		signals = append(signals, model.Signal{Type: model.SignalBufferBloat, Severity: 1})
	}

	if c.DeliveryRate != nil && c.PacingRate != nil && *c.PacingRate > 0 {
		ratio := float64(*c.DeliveryRate) / float64(*c.PacingRate)
		if ratio < 0.5 {
			signals = append(signals, model.Signal{Type: model.SignalDeliveryDrop, Severity: 1, Value: ratio})
		}
	}

	if v := c.Unacked; v != nil && *v > 10 {
		signals = append(signals, model.Signal{Type: model.SignalUnackedBuildup, Severity: 1, Value: *v})
	}

	if v := c.BusyMS; v != nil && *v > 100 {
		sev := 1
		if *v > 1000 {
			sev = 2
		}
		signals = append(signals, model.Signal{Type: model.SignalBusyTimeout, Severity: sev, Value: *v})
	}

	return signals
}
