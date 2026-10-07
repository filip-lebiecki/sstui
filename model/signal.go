package model

import (
	"slices"
	"strings"
)

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
	SignalCwndLimited        SignalType = "cwnd_limited"
	SignalListenQueueFull    SignalType = "listen_queue_full"
	SignalRTOFiring          SignalType = "rto_firing"
	SignalSynStall           SignalType = "syn_stall"
	SignalPeerNoAck          SignalType = "peer_no_ack"
	SignalCWndCollapse       SignalType = "cwnd_collapse"
	SignalDSACKSpurious      SignalType = "dsack_spurious"
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
	SignalCwndLimited:        "CWND_LIM",
	SignalListenQueueFull:    "LISTEN_Q",
	SignalRTOFiring:          "RTO",
	SignalSynStall:           "SYN_STALL",
	SignalPeerNoAck:          "NO_ACK",
	SignalCWndCollapse:       "CWND_DROP",
	SignalDSACKSpurious:      "DSACK",
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

// signalByName maps each lower-cased label and type name to its type.
var signalByName = func() map[string]SignalType {
	m := make(map[string]SignalType, 2*len(signalLabels))
	for t, l := range signalLabels {
		m[strings.ToLower(l)] = t
		m[string(t)] = t
	}
	return m
}()

// ParseSignalType resolves a signal by its label ("RETRANS") or type name
// ("retrans_in_flight"), ignoring case.
func ParseSignalType(name string) (SignalType, bool) {
	t, ok := signalByName[strings.ToLower(name)]
	return t, ok
}

// SignalLabels returns every signal label, sorted.
func SignalLabels() []string {
	ls := make([]string, 0, len(signalLabels))
	for _, l := range signalLabels {
		ls = append(ls, l)
	}
	slices.Sort(ls)
	return ls
}

// Signal holds a detected anomaly with its severity.
type Signal struct {
	Type     SignalType
	Severity int // 0=info, 1=warn, 2=critical
	Value    any
}
