package poller

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"ss-stats-tui/model"
)

// ExportJSON writes the full ring buffer as a single JSON document.
// Returns the number of snapshots written and the absolute path.
func (b *Buffer) ExportJSON(path string) (int, error) {
	snaps := b.GetAll()
	payload := struct {
		ExportedAt time.Time     `json:"exported_at"`
		PollEvery  time.Duration `json:"poll_interval"`
		Snapshots  []*Snapshot   `json:"snapshots"`
	}{
		ExportedAt: time.Now(),
		PollEvery:  PollInterval,
		Snapshots:  snaps,
	}

	f, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(payload); err != nil {
		return 0, err
	}
	return len(snaps), nil
}

// ExportCSV writes the latest snapshot as a flat CSV (one row per connection).
// Signals are joined as "LABEL:sev;LABEL:sev". Returns row count and any error.
func (b *Buffer) ExportCSV(path string) (int, error) {
	snap := b.GetLatest()
	if snap == nil {
		return 0, fmt.Errorf("no snapshot to export")
	}

	f, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	header := []string{
		"timestamp", "proto", "state",
		"local_addr", "local_port", "peer_addr", "peer_port",
		"process", "pid",
		"rtt_ms", "min_rtt_ms", "rto_ms",
		"cwnd", "ssthresh", "mss", "snd_wnd",
		"send_q", "recv_q",
		"bytes_sent", "bytes_received", "bytes_retrans",
		"retrans_now", "retrans_total", "lost", "unacked",
		"delivery_rate_bps", "pacing_rate_bps",
		"signals",
	}
	if err := w.Write(header); err != nil {
		return 0, err
	}

	ts := snap.Timestamp.UTC().Format(time.RFC3339Nano)
	for _, c := range snap.Conns {
		row := []string{
			ts, c.Protocol, c.State,
			c.LocalAddr, c.LocalPort, c.PeerAddr, c.PeerPort,
			derefStr(c.Process), itoaPtr(c.PID),
			ftoaPtr(c.RTT), ftoaPtr(c.MinRTT), ftoaPtr(c.RTO),
			itoaPtr(c.CWnd), itoaPtr(c.SSThresh), itoaPtr(c.MSS), itoaPtr(c.SndWnd),
			itoaPtr(c.SendQ), itoaPtr(c.RecvQ),
			itoaPtr(c.BytesSent), itoaPtr(c.BytesReceived), itoaPtr(c.BytesRetrans),
			itoaPtr(c.RetransNow), itoaPtr(c.Retrans), itoaPtr(c.Lost), itoaPtr(c.Unacked),
			itoaPtr(c.DeliveryRate), itoaPtr(c.PacingRate),
			fmtSignals(c.Signals),
		}
		if err := w.Write(row); err != nil {
			return 0, err
		}
	}
	return len(snap.Conns), w.Error()
}

func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func itoaPtr(p *int) string {
	if p == nil {
		return ""
	}
	return strconv.Itoa(*p)
}

func ftoaPtr(p *float64) string {
	if p == nil {
		return ""
	}
	return strconv.FormatFloat(*p, 'f', -1, 64)
}

func fmtSignals(sigs []model.Signal) string {
	if len(sigs) == 0 {
		return ""
	}
	var b strings.Builder
	for i, s := range sigs {
		if i > 0 {
			b.WriteByte(';')
		}
		fmt.Fprintf(&b, "%s:%d", s.Type.Label(), s.Severity)
	}
	return b.String()
}
