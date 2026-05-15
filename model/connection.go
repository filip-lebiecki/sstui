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
	RcvSpace    *int
	RcvSSThresh *int

	BusyMS    *float64
	PMTU      *int
	AdvMSS    *int
	RcvMSS    *int
	LastSnd   *int
	LastRcv   *int
	LastAck   *int
	DSACKDups *int

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

	// Signals are populated by poller.AddSnapshot after deltas, so the
	// classifier runs once per poll rather than once per render frame.
	Signals []Signal
}

// ConnKey returns a unique identifier for this connection.
func (c *Connection) ConnKey() string {
	return c.Protocol + "|" + c.LocalAddr + ":" + c.LocalPort + "|" + c.PeerAddr + ":" + c.PeerPort
}
