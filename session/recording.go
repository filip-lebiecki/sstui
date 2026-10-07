package session

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"strings"
	"sync"
	"time"

	"sstui/model"
	"sstui/poller"
)

// A recording is a JSON-lines file, gzip-compressed when its name ends in
// .gz: a Header line, then one line per poll with the parsed sockets (before
// deltas and signals, which replay recomputes), the host counters, and the
// kernel settings whenever they change. Storing parsed sockets rather than
// raw ss text keeps a recording readable with jq.

// recordingFormat is bumped on incompatible changes to the line layout.
const recordingFormat = 1

// Header describes a recording.
type Header struct {
	Format       int           `json:"sstui_recording"`
	Version      string        `json:"version"` // sstui version that recorded it
	Host         string        `json:"host"`
	Kernel       string        `json:"kernel,omitempty"`
	Started      time.Time     `json:"started"`
	Interval     time.Duration `json:"interval_ns"`
	SSFilter     string        `json:"ss_filter,omitempty"`
	Unprivileged bool          `json:"unprivileged,omitempty"`
}

// NewHeader describes a recording of this host starting now.
func NewHeader(version, ssFilter string, unprivileged bool) Header {
	host, _ := os.Hostname()
	return Header{
		Format: recordingFormat, Version: version, Host: host, Kernel: KernelRelease(),
		Started: time.Now(), Interval: poller.PollInterval,
		SSFilter: ssFilter, Unprivileged: unprivileged,
	}
}

// KernelRelease returns the running kernel's release ("6.8.0-45-generic"),
// or "" when unreadable.
func KernelRelease() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

type pollLine struct {
	Time   time.Time           `json:"t"`
	Conns  []*model.Connection `json:"conns"`
	Drops  int                 `json:"drops,omitempty"`
	Err    string              `json:"err,omitempty"`
	Sys    map[string]int64    `json:"sys,omitempty"`
	Sysctl poller.Sysctls      `json:"sysctl,omitempty"`
}

// Recorder writes a recording. It is safe to call from several goroutines
// (the TUI writes from its poll goroutine and closes on exit).
type Recorder struct {
	mu         sync.Mutex
	closed     bool
	f          *os.File
	gz         *gzip.Writer // nil for plain JSON lines
	w          *bufio.Writer
	enc        *json.Encoder
	lastSysctl poller.Sysctls
}

// Create starts a recording at path, gzip-compressed if path ends in .gz.
// The file is readable only by its owner: it lists every socket's process,
// PID and peer, which ss hides from other unprivileged users.
func Create(path string, h Header) (*Recorder, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	r := &Recorder{f: f}
	var out io.Writer = f
	if strings.HasSuffix(path, ".gz") {
		r.gz = gzip.NewWriter(f)
		out = r.gz
	}
	r.w = bufio.NewWriterSize(out, 256<<10)
	r.enc = json.NewEncoder(r.w)
	if err := r.enc.Encode(h); err != nil {
		f.Close()
		return nil, err
	}
	return r, r.flush()
}

// Write appends a poll. Call it before Session.Ingest, which annotates the
// connections. Each poll is flushed through to the file, so a recording
// that is killed mid-way is still readable up to its last poll.
func (r *Recorder) Write(p *Poll) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errors.New("recording is closed")
	}
	line := pollLine{Time: p.Time, Conns: p.Conns, Drops: p.Drops}
	if p.Err != nil {
		line.Err = p.Err.Error()
	}
	if p.Sys != nil {
		line.Sys = p.Sys.Counters
	}
	if p.Sysctl != nil && !maps.Equal(p.Sysctl, r.lastSysctl) {
		line.Sysctl, r.lastSysctl = p.Sysctl, p.Sysctl
	}
	if err := r.enc.Encode(line); err != nil {
		return err
	}
	return r.flush()
}

func (r *Recorder) flush() error {
	if err := r.w.Flush(); err != nil {
		return err
	}
	if r.gz != nil {
		return r.gz.Flush()
	}
	return nil
}

// Close finishes the recording. Closing twice is harmless.
func (r *Recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	err := r.flush()
	if r.gz != nil {
		if cerr := r.gz.Close(); err == nil {
			err = cerr
		}
	}
	if cerr := r.f.Close(); err == nil {
		err = cerr
	}
	return err
}

// Reader reads a recording.
type Reader struct {
	Header Header
	// Unclosed is set once Next has reached an end that wasn't written
	// cleanly: the recorder was killed (kill -9, power loss) before closing
	// the file, so a gzip stream lacks its trailer or the last line is cut
	// off. Every complete poll before that point was still returned.
	Unclosed bool

	f   *os.File
	dec *json.Decoder
}

// Open opens a recording, detecting gzip from its content.
func Open(path string) (*Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	br := bufio.NewReaderSize(f, 256<<10)
	var in io.Reader = br
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		in = gz
	}
	r := &Reader{f: f, dec: json.NewDecoder(in)}
	if err := r.dec.Decode(&r.Header); err != nil || r.Header.Format == 0 {
		f.Close()
		return nil, fmt.Errorf("%s: not an sstui recording", path)
	}
	if r.Header.Format > recordingFormat {
		f.Close()
		return nil, fmt.Errorf("%s: recording format %d is newer than this sstui supports (%d); upgrade sstui", path, r.Header.Format, recordingFormat)
	}
	if r.Header.Interval <= 0 {
		f.Close()
		return nil, fmt.Errorf("%s: recording has no poll interval", path)
	}
	return r, nil
}

// Next returns the next poll, or io.EOF at the end of the recording.
func (r *Reader) Next() (*Poll, error) {
	var line pollLine
	if err := r.dec.Decode(&line); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			r.Unclosed = true
			return nil, io.EOF
		}
		return nil, err
	}
	p := &Poll{Time: line.Time, Conns: line.Conns, Drops: line.Drops, Sysctl: line.Sysctl}
	if line.Sys != nil {
		p.Sys = &poller.SysStat{Timestamp: line.Time, Counters: line.Sys}
	}
	if line.Err != "" {
		p.Err = errors.New(line.Err)
	}
	return p, nil
}

// Close closes the recording.
func (r *Reader) Close() error { return r.f.Close() }
