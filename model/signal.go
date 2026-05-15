package model

// SignalType represents a detected anomaly on a connection.
type SignalType string

const (
	SignalRetransInFlight    SignalType = "retrans_in_flight"
	SignalAppLimited         SignalType = "app_limited"
	SignalIdle               SignalType = "idle"
	SignalZeroWindow         SignalType = "zero_window"
	SignalCongestionLoss     SignalType = "congestion_loss"
	SignalPMTUMismatch       SignalType = "pmtu_mismatch"
	SignalRTTSpike           SignalType = "rtt_spike"
	SignalSendBufferPressure SignalType = "send_buffer_pressure"
	SignalRecvBufferPressure SignalType = "recv_buffer_pressure"
	SignalHighRetransRate    SignalType = "high_retrans_rate"
	SignalDeliveryDrop       SignalType = "delivery_drop"
	SignalUnackedBuildup     SignalType = "unacked_buildup"
)

// SignalColor returns a display string for the signal.
func (s SignalType) Label() string {
	labels := map[SignalType]string{
		SignalRetransInFlight:    "RETRANS",
		SignalAppLimited:         "APP_LIM",
		SignalIdle:               "IDLE",
		SignalZeroWindow:         "ZERO_WIN",
		SignalCongestionLoss:     "LOSS",
		SignalPMTUMismatch:       "PMTU",
		SignalRTTSpike:           "RTT_SPIKE",
		SignalSendBufferPressure: "SEND_Q",
		SignalRecvBufferPressure: "RCV_Q",
		SignalHighRetransRate:    "HI_RETRANS",
		SignalDeliveryDrop:       "DEL_DROP",
		SignalUnackedBuildup:     "UNACKED",
	}
	if l, ok := labels[s]; ok {
		return l
	}
	return string(s)
}

// Signal holds a detected anomaly with its severity.
type Signal struct {
	Type     SignalType
	Severity int // 0=info, 1=warn, 2=critical
	Value    any
}
