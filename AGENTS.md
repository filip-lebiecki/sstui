# ss-stats-tui

Terminal UI that polls `ss -atnpeimOH` every 2s to display live TCP connection stats.

## Commands

```
go build -o ss-stats-tui .   # build binary (gitignored)
./ss-stats-tui               # run (requires root or CAP_NET_ADMIN for full ss output)
```

No tests, linter, CI, or formatter configured. Standard `go fmt` applies.

## Architecture

Single binary, 5 packages:

| Package | Purpose |
|---------|---------|
| `main.go` | bubbletea event loop, tab navigation, key handling |
| `parser/` | parses `ss -atnpeimOH` output into `model.Connection` |
| `poller/` | ring buffer of 1500 snapshots, computes deltas between polls |
| `model/` | `Connection` struct (all fields `*T` — nil means ss didn't report it), `Signal` types |
| `classifier/` | rule-based anomaly detection on a single connection |
| `ui/` | rendering: table, detail, overview, top, header, footer |

## Key Gotchas

- **All `model.Connection` fields are pointers**. A `nil` field means `ss` didn't report it for that connection (e.g. LISTEN sockets have no RTT). Always nil-check before dereferencing.
- **Deltas are computed in poller, not parser**. `DeltaBytesSent`, `DeltaBytesReceived`, `DeltaSegsOut`, `DeltaSegsIn`, `DeltaBytesRetrans` are set by `poller.Buffer.computeDeltas()` comparing current vs previous snapshot. They're `nil` on first poll for a connection, and also nil when `sameConnection()` rejects the pair (inode changed → 4-tuple reuse).
- **`ss` command requires elevated privileges**. Without root/CAP_NET_ADMIN, fields like `users:`, `inode`, `cgroup`, and skmem won't be present. When `Inode` is missing the 4-tuple-reuse check falls back to the negative-delta guard alone.
- **Classifier runs once per poll**, not per frame. `poller.AddSnapshot` calls `classifier.Classify` and stashes the result on `Connection.Signals`; UI code reads `c.Signals` directly.
- **Detail view tracks connection by key**. The key is `LocalAddr:LocalPort|PeerAddr:PeerPort`. Lookup is O(1) via `Snapshot.Lookup` (a `byKey` map built in `AddSnapshot`).
- **Table sort cycle** (`[h]`) is in `ui/table.go:sortCycle` — state/local/peer/process (asc+desc) followed by rtt/cwnd/sq/rq/tx/rx/retrans (desc only).
- **Filter keywords are `local=`/`peer=`/`lport=`/`pport=`/`state=`**, matching the column headers. A bare token is matched against `LocalAddr` unless it's a known state name.
- **Rate display divides by `poller.PollInterval`** in `fmtRate` (`ui/format.go`) and `fmtBytesPerSec` (`ui/header.go`). Deltas stored on `Connection` are raw byte counts over one poll interval; the conversion to /s happens at format time only.
- **`fmtBytes` uses binary units** (1024-based) while `fmtRate` and `fmtNum` use decimal (1000-based).
- **`fmtBPS` keeps units in bits/sec** (`ui/format.go`). `ss` reports `pacing_rate`/`delivery_rate`/`bbr.bw` in bps; we display Mbps/Gbps unchanged.
- **Polling is async** via a `tea.Cmd` returning `pollResultMsg`; the next `tickCmd` is scheduled from `pollResultMsg` so a slow `ss` invocation can't freeze input.
