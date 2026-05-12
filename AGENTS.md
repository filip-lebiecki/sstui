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
- **Deltas are computed in poller, not parser**. `DeltaBytesSent`, `DeltaBytesReceived`, `DeltaSegsOut`, `DeltaSegsIn`, `DeltaBytesRetrans` are set by `poller.Buffer.computeDeltas()` comparing current vs previous snapshot. They're `nil` on first poll for a connection.
- **`ss` command requires elevated privileges**. Without root/CAP_NET_ADMIN, fields like `users:`, `inode`, `cgroup`, and skmem won't be present.
- **Classifier runs on every render frame** (`ui/table.go:39`, `ui/detail.go:40`), not just on poll ticks. bubbletea renders ~60fps, so `classifier.Classify()` runs many times per second on the same data. Same for sparkline rendering in `detail.go:199`.
- **Detail view tracks connection by key** (`main.go:302`). The key is `LocalAddr:LocalPort|PeerAddr:PeerPort`. If the connection disappears and reappears, it gets a new `Connection` object but the same key.
- **Table sort cycle** (`[h]`) is hardcoded in `ui/table.go:245` — state asc/desc, local asc/desc, peer asc/desc, process asc/desc.
- **`fmtBPS` divides by 8** (`ui/format.go:52`) — ss reports rates in bits/sec, display shows bytes/sec.
- **`fmtBytes` uses binary units** (1024-based) while `fmtRate` and `fmtNum` use decimal (1000-based).
