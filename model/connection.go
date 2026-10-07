package model

import "time"

// SendSlotMin is the shortest span a SendSlot covers once complete.
const SendSlotMin = 2 * time.Second

// SendSlot summarizes at least SendSlotMin of a connection's sending: the
// polls in which it sent data, what was retransmitted or reordered, and the
// queueing delay each poll saw.
type SendSlot struct {
	Start, End time.Time
	Sent       int       // bytes sent
	Retrans    int       // bytes retransmitted
	Reord      int       // reordering events the sender detected (reord_seen)
	QueueMS    []float64 // rtt - minrtt at each of those polls
}

// Connection holds all parsed fields from a single ss row.
type Connection struct {
	Timestamp time.Time

	Protocol  string  `json:",omitempty"` // "tcp" or "udp"
	State     string  `json:",omitempty"`
	RecvQ     *int    `json:",omitempty"`
	SendQ     *int    `json:",omitempty"`
	LocalAddr string  `json:",omitempty"`
	LocalPort string  `json:",omitempty"`
	PeerAddr  string  `json:",omitempty"`
	PeerPort  string  `json:",omitempty"`
	Process   *string `json:",omitempty"`
	PID       *int    `json:",omitempty"`
	UID       *int    `json:",omitempty"`
	Inode     *string `json:",omitempty"`
	Cgroup    *string `json:",omitempty"`

	// skmem
	SkmemR  *int `json:",omitempty"`
	SkmemRB *int `json:",omitempty"`
	SkmemT  *int `json:",omitempty"`
	SkmemTB *int `json:",omitempty"`
	SkmemF  *int `json:",omitempty"`
	SkmemW  *int `json:",omitempty"`
	SkmemO  *int `json:",omitempty"`
	SkmemBL *int `json:",omitempty"`
	SkmemD  *int `json:",omitempty"`

	// timer
	TimerType    *string `json:",omitempty"`
	TimerDur     *string `json:",omitempty"`
	TimerRetrans *int    `json:",omitempty"`

	// wscale
	WscaleSnd *int `json:",omitempty"`
	WscaleRcv *int `json:",omitempty"`

	// throughput
	Delivered   *int `json:",omitempty"`
	DeliveredCE *int `json:",omitempty"` // delivered_ce: delivered packets whose ACKs echoed an ECN congestion mark
	AppLimited  int  `json:",omitempty"`
	SendBPS     *int `json:",omitempty"`

	// TCP metrics
	RTO      *float64 `json:",omitempty"`
	RTT      *float64 `json:",omitempty"`
	RTTVar   *float64 `json:",omitempty"`
	ATO      *float64 `json:",omitempty"`
	MSS      *int     `json:",omitempty"`
	CWnd     *int     `json:",omitempty"`
	SSThresh *int     `json:",omitempty"`

	// bytes
	BytesSent     *int `json:",omitempty"`
	BytesReceived *int `json:",omitempty"`
	BytesAcked    *int `json:",omitempty"`
	BytesRetrans  *int `json:",omitempty"`

	// segments
	SegsOut     *int `json:",omitempty"`
	SegsIn      *int `json:",omitempty"`
	DataSegsOut *int `json:",omitempty"`
	DataSegsIn  *int `json:",omitempty"`

	MinRTT       *float64 `json:",omitempty"`
	PacingRate   *int     `json:",omitempty"`
	DeliveryRate *int     `json:",omitempty"`

	// retrans
	RetransNow *int `json:",omitempty"`
	Retrans    *int `json:",omitempty"`

	Lost        *int     `json:",omitempty"`
	Unacked     *int     `json:",omitempty"`
	SndWnd      *int     `json:",omitempty"`
	RcvWnd      *int     `json:",omitempty"`
	RcvRTT      *float64 `json:",omitempty"`
	RcvSpace    *int     `json:",omitempty"`
	RcvSSThresh *int     `json:",omitempty"`

	// Congestion control algorithm (cubic, bbr, reno, ...). Reported as a
	// bare token by ss; absent on non-TCP sockets.
	CongAlgo *string `json:",omitempty"`

	BusyMS          *float64 `json:",omitempty"`
	RwndLimitedMS   *float64 `json:",omitempty"` // cumulative ms the sender was blocked on the peer's recv window
	SndbufLimitedMS *float64 `json:",omitempty"` // cumulative ms the sender was blocked on its own send buffer
	PMTU            *int     `json:",omitempty"`
	AdvMSS          *int     `json:",omitempty"`
	RcvMSS          *int     `json:",omitempty"`
	LastSnd         *int     `json:",omitempty"`
	LastRcv         *int     `json:",omitempty"`
	LastAck         *int     `json:",omitempty"`
	DSACKDups       *int     `json:",omitempty"`
	Reordering      *int     `json:",omitempty"` // reordering: kernel's reordering distance estimate
	ReordSeen       *int     `json:",omitempty"` // reord_seen: cumulative reorder events observed
	RcvOOOPack      *int     `json:",omitempty"` // rcv_ooopack: cumulative out-of-order packets received

	// BBR
	BBRBW         *int     `json:",omitempty"`
	BBRMRTT       *float64 `json:",omitempty"`
	BBRPacingGain *float64 `json:",omitempty"`
	BBRCWndGain   *float64 `json:",omitempty"`

	// Computed deltas
	DeltaBytesSent       *int     `json:",omitempty"`
	DeltaBytesReceived   *int     `json:",omitempty"`
	DeltaSegsOut         *int     `json:",omitempty"`
	DeltaSegsIn          *int     `json:",omitempty"`
	DeltaBytesRetrans    *int     `json:",omitempty"`
	DeltaDSACKDups       *int     `json:",omitempty"`
	DeltaRcvOOOPack      *int     `json:",omitempty"`
	DeltaDataSegsIn      *int     `json:",omitempty"` // data segments received this poll (OOO ratio denominator)
	DeltaReordSeen       *int     `json:",omitempty"` // reordering events the sender detected this poll
	DeltaBytesAcked      *int     `json:",omitempty"` // bytes newly acknowledged by the peer this poll
	DeltaDeliveredCE     *int     `json:",omitempty"` // packets delivered with an ECN congestion mark this poll
	DeltaSkmemD          *int     `json:",omitempty"` // new socket-buffer drops since the previous poll
	DeltaBusyMS          *float64 `json:",omitempty"`
	DeltaRwndLimitedMS   *float64 `json:",omitempty"` // ms blocked on the peer's recv window this poll
	DeltaSndbufLimitedMS *float64 `json:",omitempty"` // ms blocked on the local send buffer this poll

	// Previous values kept for non-monotonic signals (e.g. cwnd collapse) and
	// for queue-pressure persistence (a queue must stay full across two polls
	// before the signal fires, so normal transfer bursts don't trip it).
	PrevCWnd  *int `json:",omitempty"`
	PrevSendQ *int `json:",omitempty"`
	PrevRecvQ *int `json:",omitempty"`
	// PrevUnacked lets NO_ACK require data to stay outstanding across polls.
	PrevUnacked *int `json:",omitempty"`
	// SendSlots summarize the connection's recent sending, oldest first, so
	// PATH_LOSS and REORDER judge several seconds rather than one poll. The
	// poller carries them from poll to poll; they aren't recorded or
	// exported (replay rebuilds them).
	SendSlots []SendSlot `json:"-"`

	// Signals are populated by poller.AddSnapshot after deltas, so the
	// classifier runs once per poll rather than once per render frame.
	Signals []Signal `json:",omitempty"`

	// key caches ConnKey(). Set via SetKey before the connection is published
	// to readers; never written afterwards.
	key string
}

// SetKey caches the connection's key so ConnKey() doesn't rebuild the string
// on every call. Only call it before the connection is shared.
func (c *Connection) SetKey(k string) { c.key = k }

// ConnKey returns a stable identifier for this connection across polls.
//
// The 4-tuple alone is not unique: SO_REUSEPORT listeners share the same
// local addr:port with a wildcard peer, so several distinct sockets collapse
// to one key. When ss reports a socket inode (ino:), we fold it in to keep
// such sockets distinct. The inode is stable for a socket's lifetime, so the
// key stays consistent across snapshots. Inode "0" is the kernel's no-inode
// sentinel (TIME-WAIT/orphans) and is treated as absent.
func (c *Connection) ConnKey() string {
	if c.key != "" {
		return c.key
	}
	key := c.Protocol + "|" + c.LocalAddr + ":" + c.LocalPort + "|" + c.PeerAddr + ":" + c.PeerPort
	if c.Inode != nil && *c.Inode != "" && *c.Inode != "0" {
		key += "|" + *c.Inode
	}
	return key
}
