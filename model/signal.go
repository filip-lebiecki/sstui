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
	SignalCwndLimited        SignalType = "cwnd_limited"
	SignalListenQueueFull    SignalType = "listen_queue_full"
	SignalRTOFiring          SignalType = "rto_firing"
	SignalSynStall           SignalType = "syn_stall"
	SignalPeerNoAck          SignalType = "peer_no_ack"
	SignalCWndCollapse       SignalType = "cwnd_collapse"
	SignalDSACKSpurious      SignalType = "dsack_spurious"
	SignalBBRUnderutil       SignalType = "bbr_underutil"
	SignalReordering         SignalType = "reordering"
	SignalSocketDrops        SignalType = "socket_drops"
	SignalRwndLimited        SignalType = "rwnd_limited"
	SignalSndbufLimited      SignalType = "sndbuf_limited"
	SignalCloseWaitLeak      SignalType = "close_wait_leak"
	SignalTimeWaitStorm      SignalType = "time_wait_storm"
	SignalInboundLoss        SignalType = "inbound_loss"
)

// signalLabels maps each signal type to its short display label. Built once;
// Label() is called in hot render and filter paths.
var signalLabels = map[SignalType]string{
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
	SignalCwndLimited:        "CWND_LIM",
	SignalListenQueueFull:    "LISTEN_Q",
	SignalRTOFiring:          "RTO",
	SignalSynStall:           "SYN_STALL",
	SignalPeerNoAck:          "NO_ACK",
	SignalCWndCollapse:       "CWND_DROP",
	SignalDSACKSpurious:      "DSACK",
	SignalBBRUnderutil:       "BBR_LOW",
	SignalReordering:         "REORDER",
	SignalSocketDrops:        "DROPS",
	SignalRwndLimited:        "RWND_LIM",
	SignalSndbufLimited:      "SNDBUF_LIM",
	SignalCloseWaitLeak:      "CW_LEAK",
	SignalTimeWaitStorm:      "TW_STORM",
	SignalInboundLoss:        "RX_LOSS",
}

// Label returns the short display label for the signal.
func (s SignalType) Label() string {
	if l, ok := signalLabels[s]; ok {
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
