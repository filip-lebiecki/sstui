package model

import "time"

// Connection holds all parsed fields from a single ss row.
type Connection struct {
	Timestamp time.Time

	Protocol  string // "tcp" or "udp"
	State     string
	RecvQ     *int
	SendQ     *int
	LocalAddr string
	LocalPort string
	PeerAddr  string
	PeerPort  string
	Process   *string
	PID       *int
	UID       *int
	Inode     *string
	Cgroup    *string

	// skmem
	SkmemR  *int
	SkmemRB *int
	SkmemT  *int
	SkmemTB *int
	SkmemF  *int
	SkmemW  *int
	SkmemO  *int
	SkmemBL *int
	SkmemD  *int

	// timer
	TimerType    *string
	TimerDur     *string
	TimerRetrans *int

	// wscale
	WscaleSnd *int
	WscaleRcv *int

	// throughput
	Delivered  *int
	AppLimited int
	SendBPS    *int

	// TCP metrics
	RTO      *float64
	RTT      *float64
	RTTVar   *float64
	ATO      *float64
	MSS      *int
	CWnd     *int
	SSThresh *int

	// bytes
	BytesSent     *int
	BytesReceived *int
	BytesAcked    *int
	BytesRetrans  *int

	// segments
	SegsOut     *int
	SegsIn      *int
	DataSegsOut *int
	DataSegsIn  *int

	MinRTT       *float64
	PacingRate   *int
	DeliveryRate *int

	// retrans
	RetransNow *int
	Retrans    *int

	Lost        *int
	Unacked     *int
	SndWnd      *int
	RcvWnd      *int
	RcvRTT      *float64
	RcvSpace    *int
	RcvSSThresh *int

	// Congestion control algorithm (cubic, bbr, reno, ...). Reported as a
	// bare token by ss; absent on non-TCP sockets.
	CongAlgo *string

	BusyMS     *float64
	PMTU       *int
	AdvMSS     *int
	RcvMSS     *int
	LastSnd    *int
	LastRcv    *int
	LastAck    *int
	DSACKDups  *int
	Reordering *int // reordering: kernel's reordering distance estimate
	ReordSeen  *int // reord_seen: cumulative reorder events observed
	RcvOOOPack *int // rcv_ooopack: cumulative out-of-order packets received

	// BBR
	BBRBW         *int
	BBRMRTT       *float64
	BBRPacingGain *float64
	BBRCWndGain   *float64

	// Computed deltas
	DeltaBytesSent     *int
	DeltaBytesReceived *int
	DeltaSegsOut       *int
	DeltaSegsIn        *int
	DeltaBytesRetrans  *int
	DeltaDSACKDups     *int
	DeltaRcvOOOPack    *int
	DeltaSkmemD        *int // new socket-buffer drops since the previous poll
	DeltaBusyMS        *float64

	// Previous values kept for non-monotonic signals (e.g. cwnd collapse) and
	// for queue-pressure persistence (a queue must stay full across two polls
	// before the signal fires, so normal transfer bursts don't trip it).
	PrevCWnd  *int
	PrevSendQ *int
	PrevRecvQ *int

	// Signals are populated by poller.AddSnapshot after deltas, so the
	// classifier runs once per poll rather than once per render frame.
	Signals []Signal
}

// ConnKey returns a stable identifier for this connection across polls.
//
// The 4-tuple alone is not unique: SO_REUSEPORT listeners share the same
// local addr:port with a wildcard peer, so several distinct sockets collapse
// to one key. When ss reports a socket inode (ino:), we fold it in to keep
// such sockets distinct. The inode is stable for a socket's lifetime, so the
// key stays consistent across snapshots. Inode "0" is the kernel's no-inode
// sentinel (TIME-WAIT/orphans) and is treated as absent.
func (c *Connection) ConnKey() string {
	key := c.Protocol + "|" + c.LocalAddr + ":" + c.LocalPort + "|" + c.PeerAddr + ":" + c.PeerPort
	if c.Inode != nil && *c.Inode != "" && *c.Inode != "0" {
		key += "|" + *c.Inode
	}
	return key
}
