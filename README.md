# sstui

A terminal UI for `ss(8)` that watches every TCP and UDP socket on a Linux
host, works out what's going wrong, **tells you what to do about it**, and
keeps ~50 minutes of history so you can answer "what happened" instead of
just "what's happening now".

Built for triage: it opens on a ranked list of host-level problems
("postgres → 10.0.0.5:5432: 37 connections stalled — peer not reading"),
each with its evidence and copy-ready fix commands sized from this host's
kernel settings. Underneath, 26 per-socket signals like `ZERO_WIN`,
`NO_ACK`, `RX_LOSS`, `SYN_STALL` and `LISTEN_Q` light up automatically, and
every kernel metric is one key press away.

![tabs](https://img.shields.io/badge/tabs-9-blue) ![signals](https://img.shields.io/badge/signals-26-orange) ![ring%20buffer](https://img.shields.io/badge/history-50%20min-green)

---

## Contents

1. [What it does](#what-it-does)
2. [Proven on real failures](#proven-on-real-failures)
3. [Who it's for](#who-its-for)
4. [Why not just `ss` or `netstat`?](#why-not-just-ss-or-netstat)
5. [Install / build](#install--build)
6. [Permissions: what you see, and as whom](#permissions-what-you-see-and-as-whom)
7. [Quick tour](#quick-tour)
8. [Tabs](#tabs)
9. [Keybindings](#keybindings)
10. [Filtering](#filtering)
11. [Export](#export)
12. [Headless: check, record, replay, report](#headless-check-record-replay-report)
13. [Common workflows](#common-workflows)
14. [Signals reference](#signals-reference)
15. [Metrics reference](#metrics-reference)
16. [Performance footprint](#performance-footprint)
17. [Troubleshooting / FAQ](#troubleshooting--faq)
18. [Limitations](#limitations)
19. [Architecture](#architecture)
20. [Development](#development)
21. [License](#license)

---

## What it does

`sstui` runs `ss -atunpeimOH` (TCP and UDP in one call) every 2 seconds,
parses the output, computes per-poll deltas, runs a classifier over each
connection, and keeps the last **1500 snapshots** (≈50 min) in a ring buffer.
Everything you see on screen — the table, the bars, the events log, the
sparklines — is rendered from that buffer. Hit `Space` to freeze the Live
table and `[` / `]` to scrub back and forward through that history, so you
can replay exactly how a connection went bad instead of only seeing "now".

There's no agent, no daemon, no setuid binary. Just `ss`. Without root you
still see every socket, but only your own sockets show which process owns
them. **Run it with `sudo` to see process names for every socket** (see
[Permissions](#permissions-what-you-see-and-as-whom)).

What you get out of the box:

- **Findings home screen** — the first thing you see: a ranked list of
  host-level problems ("postgres → 10.0.0.5:5432: 37 connections stalled —
  peer not reading"), each with the evidence, what it means, and concrete
  next steps built from this host's own kernel settings (e.g. "backlog is
  capped by net.core.somaxconn = 4096 → `sysctl -w net.core.somaxconn=8192`").
  `Enter` jumps to exactly the affected sockets; `c` copies the command.
- **Live table** of every TCP/UDP socket on the host with sortable columns,
  state-coloured fields, and an at-a-glance signal indicator per row.
- **Automatic problem detection** through 26 named signals — retransmits,
  RTO storms, zero-window stalls, listen-queue overflow, ephemeral port
  exhaustion, packet reordering, CWnd collapse, and
  more. Each is tunable in one place (`classifier/classifier.go`).
- **50 minutes of history** in memory so you can see *when* something
  went wrong, not just that it's wrong now.
- **Drill-down detail** with two paired tabs: a network-level view (RTT,
  CWnd, congestion, retransmits, inbound out-of-order ratio) and a
  kernel-side view (queues, socket memory, BBR state) with per-connection
  bar-graph history of RTT, CWnd, TX, RX, queue depths, unacked, retrans.
- **Event log** that tells you the *moment* each signal started firing on
  each connection, scrollable and exportable to JSON/CSV.
- **Filter language** for narrowing by address, port, state, process
  name, protocol or signal — plus `--ss-filter` to filter inside `ss`
  itself so non-matching sockets are never collected.
- **Snapshot/buffer export** to JSON (history) and CSV (current snapshot)
  for offline analysis with jq, pandas, or a spreadsheet; runs in the
  background so the UI never freezes.
- **Headless mode** with the same analysis: `sstui check` for scripts and
  monitoring (Nagios-style exit codes, text or JSON), `sstui record` /
  `sstui replay` to capture a host and step through it later on another
  machine, and `sstui report` for a markdown incident summary to paste
  into a ticket.

---

## Proven on real failures

Every diagnosis below is checked against the real thing. The [scenario
lab](#scenario-lab) recreates each failure in network namespaces (real
kernel TCP, `tc netem` on the links), records it with `sstui record`, and
asserts on what `sstui check` says, often from both ends of the
connection. It also asserts what sstui must *not* say: loss must not be
called reordering, a full accept queue must not be blamed on a slow
reader. Healthy traffic must come out with no findings at all.

| Failure recreated | What sstui reports |
|---|---|
| Packet loss on the path: 0.1%, 1%, 3%; cubic and BBR; bulk and request/response | Loss toward the peer at the sender (critical at 3%); inbound loss at the receiver, which sees only the gaps (not for BBR, see [Limitations](#limitations)) |
| Reordering: light, heavy, request/response | Reordering, not loss |
| Loss on this host's own link, outbound or inbound | One local-link finding, not one per peer |
| Loss spread over many short connections | The host-wide retransmit rate |
| A path MTU smaller than the link's | A PMTU warning, not loss |
| A path MTU black hole (the ICMP is dropped): new connections, an established one, this host's own link | The black hole by name; an established connection is told apart as a stall while other connections to the same host get through |
| Bufferbloat: a deep queue at the bottleneck | Latency inflation, pointing along the path; its losses aren't called path loss |
| A server that never answers the SYN | SYN stall |
| A SYN flood | The SYN backlog, with the real limit named |
| A peer that stops reading | Zero-window stall |
| A full accept queue, steady or in bursts, also outside an `--ss-filter` | The listen-queue overflow (not a slow reader); the host's overflow counters when the listener is out of view |
| A CLOSE-WAIT leak | The leaking process |
| Ephemeral port exhaustion | The port range nearly used up, and the TIME-WAIT pile behind it |
| A slow reader | Its full receive queue, and the receiver's window at the sender |
| A small receive buffer, reader keeping up | The window at the sender, the capped buffer at the receiver; the reader isn't blamed |
| A small send buffer (app-set `SO_SNDBUF`) | The send buffer holding the sender back, which the kernel's own counter misses |
| UDP receive drops, also outside an `--ss-filter` | The dropping socket; the host's UDP drop counters when it's out of view |
| TCP short of memory host-wide (`tcp_mem` squeezed, on a disposable VM) | Memory pressure, seen from the host and from inside a network namespace (a container's view); the readers aren't blamed |
| One socket's queue outgrowing its own buffer | The kernel discarding data, not blamed on `tcp_mem` |
| Healthy: bulk (cubic, BBR), a congested slow link, a long path, bursty request/response, a connection joining a busy path, idle connections with keepalive probes | No findings at all, and no socket signal at warning or worse, on either end |

Where failures look alike from one host is under [Limitations](#limitations).

---

## Who it's for

- **SREs and on-call engineers** triaging a host: "is it the network or
  the app?" — sstui surfaces ZERO_WIN, RTO, SYN_STALL, NO_ACK,
  LISTEN_Q in seconds and points at the specific 4-tuple/process.
- **Performance engineers** chasing tail latency: the RTT-inflation
  view, RTT/MinRTT ratio per connection, and CWND_DROP/REORDER signals
  separate "the wire is slow" from "we're retransmitting" from "we're
  reordering".
- **Backend developers** debugging connection-pool / DB-client issues:
  filter by `proc=` to see only your service's sockets, watch SEND_Q,
  RCV_Q, CWND_LIM, IDLE patterns over time.
- **Network engineers** investigating reorder/MTU/path issues: PMTU,
  REORDER, RTT_SPIKE signals plus per-peer aggregates in the Top tab.
- **Anyone curious about a Linux box's network state** — sstui needs
  nothing more than `ss` and a terminal.

Not aimed at: production *monitoring* dashboards (sstui is on-host,
interactive, single-machine), packet-level analysis (use tcpdump /
Wireshark for that), or BPF tracing (use `bpftrace`, `bcc`, or
`bpftool`).

---

## Why not just `ss` or `netstat`?

`ss` itself is the data source — sstui is `ss` reimagined for
human-paced triage:

| Capability                                    | `ss` / `netstat` | `sstui`                       |
|-----------------------------------------------|------------------|-------------------------------|
| **Ranked findings with fix commands**         | ✗                | ✓ Findings tab                |
| Snapshot of current sockets                   | ✓                | ✓                             |
| Per-connection RTT, CWnd, retrans, BBR        | ✓ with `-i`      | ✓ parsed and labelled         |
| Refreshes automatically                       | `watch ss`       | Built-in, 2 s ticks            |
| **Per-poll deltas** (TX/RX rates, retrans rate, OOO growth) | ✗   | ✓ computed in poller          |
| **Anomaly classification** (named signals)    | ✗                | ✓ 26 rules                    |
| **History** for "when did this start?"        | ✗                | ✓ 50 min ring                 |
| **Time-series view** per connection           | ✗                | ✓ bar-graph sparklines        |
| **Event log** of signal onsets                | ✗                | ✓ Events tab                  |
| **Filter by signal / process / address**      | ✗                | ✓                             |
| **Export** for offline analysis               | redirect output  | ✓ JSON / CSV, record + replay |
| **Scriptable health check** (exit codes, JSON) | ✗               | ✓ `sstui check`               |
| **System-wide rollups** (`/proc/net` counters, overflows, port exhaustion) | ✗  | ✓ System tab                |

Compared to `iftop` / `nethogs` / `bmon`: those are byte-rate views.
sstui is a TCP-state and TCP-internals view — it tells you *why* a
connection is slow, not just *how much* it's moving.

Compared to `nettop` / `tcptrack`: similar surface area, but sstui's
signals and history buffer are the differentiator.

---

## Install / build

Prebuilt static binaries for Linux amd64 and arm64 are attached to each
[release](https://github.com/filip-lebiecki/sstui/releases):

```bash
curl -L -o sstui https://github.com/filip-lebiecki/sstui/releases/latest/download/sstui-linux-amd64
chmod +x sstui
sudo ./sstui
```

Verify downloads with `sha256sum -c SHA256SUMS` (also attached). Or build
from source:

```bash
git clone https://github.com/filip-lebiecki/sstui
cd sstui
go build -ldflags "-X main.version=$(git describe --tags)" .
sudo ./sstui
```

> **Run it with `sudo`.** It works as a normal user, but then `ss` can only
> name the process for sockets you own. Other users' sockets (nginx,
> postgres, …) show `-` in the Process column, and findings call the owner
> "unknown process". The Findings tab tells you how many sockets that hides.

Command-line flags:

| Flag             | Default | Description                                              |
|------------------|---------|----------------------------------------------------------|
| `--interval`     | `2s`    | Poll cadence (e.g. `1s`, `500ms`); minimum `100ms`. Rates and the ~50-min history window scale with it. |
| `--filter`       | (none)  | Start pre-filtered with a `/`-prompt expression, e.g. `--filter 'dport=443 not state=TIME-WAIT'`. |
| `--show-listen`  | off     | Show LISTEN sockets at startup (hidden by default).      |
| `--resolve`      | off     | Resolve peer/local addresses to hostnames (reverse DNS). |
| `--ss-filter`    | (none)  | Filter passed to `ss` itself, e.g. `--ss-filter 'dport = :443'`. Non-matching sockets are never collected — see [Filtering at the source](#filtering-at-the-source). |
| `--record FILE`  | (none)  | Also record every poll to `FILE` while you watch (gzip if it ends in `.gz`); open it later with `sstui replay FILE`. |
| `--version`      |         | Print version and exit.                                  |

```bash
./sstui --interval 1s --filter 'proc=nginx or dport=443' --show-listen
```

Without the TUI, `sstui check`, `record`, `replay` and `report` run the
same analysis from scripts — see
[Headless](#headless-check-record-replay-report).

Requirements:

- Linux with a recent iproute2 (the parser is `ss(8)`-specific and uses
  `ss -O`/`--oneline`, added in 2018).
- Go 1.26+ to build (see `go.mod`).
- A terminal that speaks 24-bit color and Unicode block glyphs (most do).

If `ss` isn't in `$PATH`, sstui exits with `ss not found in PATH;
install iproute2`. On Debian/Ubuntu: `apt install iproute2`; on
RHEL/Fedora: `dnf install iproute`.

---

## Permissions: what you see, and as whom

`ss` is the only privileged operation sstui performs, and sstui doesn't
elevate on its own.

- **Run as your user**: you see all sockets system-wide, with full TCP
  metrics, but the `users:(("process",pid=,fd=))` block (process name and
  PID) is only filled in for sockets your user owns. Other users' sockets
  show `Process: -` and no PID, findings name their owner as "unknown
  process (run with sudo to see it)", and the Findings tab shows a
  "not root: process names hidden for N sockets" note.
- **Run as root (`sudo sstui`)**: process names and PIDs are shown for
  every socket. This is the recommended way to run it.
- **No CAP_NET_ADMIN required.** sstui doesn't touch netlink directly,
  doesn't open raw sockets, doesn't load BPF.

Why root: `ss` finds a socket's process by reading every `/proc/<pid>/fd`
directory, and the kernel only lets you read another user's with
`CAP_SYS_PTRACE`. Giving `ss` that capability (`setcap`) would let any
local user inspect every process's open files, and a package update
silently removes it, so `sudo` is the better option.

---

## Quick tour

sstui opens on **Findings** (here: a real zero-window stall reproduced on
loopback):

```
 sstui  ✖ 1 crit · 1 warn   TOTAL 95   ESTAB 16   LISTEN 64   RTT 17.3ms   …
   Findings    Live    Detail    Socket    Overview    Top    Perf    Events    System

   Findings   ✖ 1 critical  ▲ 1 warning   95 sockets (16 established)

 ▶ ✖ CRIT  python3 (pid 2775135) → 127.0.0.1:47123: 1 connection stalled — peer not reading (zero window)   new
       The receiver's buffer is full because its application stopped reading, so it
       advertises a zero window and our data piles up unsent.
       • 1 socket · 1.7 MB waiting in Send-Q
       • receiver is python3 (pid 2775135) on this host (Recv-Q 4 KB)
       → See what its threads are doing
         $ top -H -p 2775135
       ⏎ show 1 affected socket in Live  (signal=ZERO_WIN pid=2775135 peer==127.0.0.1 dport=47123)

   ▲ WARN  python3 (pid 2775135) isn't reading fast enough: 1 socket backed up            new
   [j/k] select   [Enter] show affected sockets in Live   [c] copy command
```

Press `1`–`9` to switch tabs (`2` is the Live socket table), `Enter` to
drill in, `/` to filter, `?` for help.

---

## Tabs

### 1. Findings

The home screen. Every poll, sstui groups per-socket signals and host-wide
kernel counters into **findings** — one per underlying problem rather than
one per socket — and ranks them critical first, then by how many sockets
they affect. The selected finding expands to show:

- **what it means** in one sentence,
- **evidence** (socket counts, queued bytes, kernel counter rates, the
  relevant sysctl values, the local process at the other end of a loopback
  connection),
- **what to do**, with copy-ready commands sized from this host's settings
  (`somaxconn`, `tcp_rmem`/`tcp_wmem`, `ip_local_port_range`,
  `tcp_tw_reuse`, `default_qdisc`, congestion control, …).

`j`/`k` select, `Enter` opens the Live tab filtered to exactly the affected
sockets, `c` copies the suggested command to the clipboard (OSC 52 — works
over SSH and in tmux with clipboard passthrough). Each finding shows how
long it has been active. A pill in the header (`✖ 2 crit · 1 warn`) keeps
the count visible from every tab. While paused (`Space`, or scrubbing with
`[` `]`), Findings and the pill show that moment rather than the present,
so you can step back to see what was wrong when.

| Finding | Triggered by | Typical recommendation |
|---|---|---|
| Peer not reading | `ZERO_WIN`, grouped by process + peer | names the local receiver if it's on this host; investigate the app, not the network |
| App not reading fast enough | `RCV_Q` / `DROPS` on non-listening sockets, per process | find the slow reader; buffer sizes for bursts (UDP doesn't autotune) |
| Accept queue full or overflowing | `LISTEN_Q`, or `DROPS` on the listener (bursts that overflow between polls) when the host counted `ListenOverflows` / `ListenDrops` | names the listener; tells apart a `somaxconn` cap from the app's own backlog |
| Can't connect | `SYN_STALL`, per destination | `nc -vz`, `ip route get`, firewalls |
| Packet loss (per peer / host-wide) | `PATH_LOSS`, `RTO`, `NO_ACK` | `mtr` for one peer; NIC/CPU checks when many peers lose at once |
| Path MTU black hole | `RTO` / `NO_ACK` on connections with nothing acknowledged since the handshake, segments over 536 bytes | a ping of full-sized packets with DF set; `tcp_mtu_probing`; let ICMP "fragmentation needed" through or clamp the MSS |
| Selective stall (MTU black hole mid-connection, or one broken ECMP/LAG path) | connections stuck (3+ consecutive RTOs, nothing acked for 3 s) while another connection to the same peer gets data acknowledged | the DF ping, `tracepath`; `tcp_mtu_probing` |
| Inbound loss (per peer / host-wide) | `RX_LOSS` | path back toward the peer (loss is often asymmetric); RX drops / ring size when many peers are affected |
| Reordering, path MTU, latency inflation | `REORDER`, `PMTU`, `RTT_SPIKE` | ECMP/LACP hashing; ICMP/MSS clamping; qdisc / BBR |
| Window- or buffer-limited throughput | `RWND_LIM`, `SNDBUF_LIM`, `RCVBUF_LIM` | slow reader or small buffer at the receiver (its Recv-Q tells; named outright when the receiver is local), `tcp_rmem`, window scaling; for the send buffer, an app-set `SO_SNDBUF` (full but below `tcp_wmem` max) vs a `tcp_wmem` max that's too low |
| Socket leak | `CW_LEAK` | fd count vs limit; the code path missing `close()` |
| Connection churn / port exhaustion | `TW_STORM`, ephemeral range ≥70% used | pooling/keep-alive, `tcp_tw_reuse`, wider port range |
| SYN flood / backlog, UDP drops, memory pressure | `SyncookiesSent`, `Udp:RcvbufErrors`; TCP's memory (`/proc/net/sockstat`) against `tcp_mem`, sockets dropping data with empty buffers; prune/drop counters alone only say a receive queue outgrew its buffer, which one socket can do | sources of half-open connections and the listeners' backlogs (with syncookies on, the SYN queue is the backlog), `rmem_max`, `tcp_mem` |

The rules live in `findings/rules.go`; each is a small function over the
latest snapshot, the host counters and the sysctls.

### 2. Live

Sortable, filterable table of every open connection — protocol, state,
4-tuple, RTT, queue depths, TX/RX deltas, retransmits, keepalive, process.
The leftmost column is a single-glyph **signal indicator**:

| Glyph | Meaning                                          |
|-------|--------------------------------------------------|
| green `●`  | No warn/crit signals                         |
| yellow `●` | 1+ warn-level signals                        |
| orange `●` | ≥4 warn signals                              |
| red `●`    | 1+ crit-level signals                        |

`j`/`k` move the cursor; `Enter` opens **Detail** for that connection.
Below the table, signal badges show every signal firing on the highlighted
row.

### 3. Detail

Network-level deep dive for one connection: Identity, Performance,
Congestion, Throughput, Retransmit (what *we* send) and, for TCP,
**Inbound (receiver side)** — data segments received, out-of-order
arrivals and their ratio per poll and over the connection's life, the
receiving host's only view of loss on the peer → here path. Two-column
layout above 100 cols, single column otherwise. Signal badges sit at the
bottom. A **diagnosis banner** at the top synthesizes the active signals
into a one-line, plain-English verdict and a suggested next step — root
causes (zero window, SYN stall) win over downstream symptoms.

When you inspect a connection from an older snapshot (paused/scrubbed, or
one that has since closed), a note says so: history records summary fields
only (RTT, cwnd, queues, rates, signals), so the rest reads `-`.

### 4. Socket

Kernel-side view of the same connection: Queues (bytes + segs in/out),
Socket Memory (buffer usage with ratio bars, backlog, **drops**), BBR
state (when applicable), and **History sparklines** — bar graphs of
RTT, CWnd, TX, RX, queues, Unacked, Retrans across the full ring buffer.

### 5. Overview

Aggregate views over the whole buffer:

- **Connections over time** — total socket count history.
- **Avg RTT over time** — mean RTT across all sockets.
- **Throughput over time** — TX and RX bars.
- **State distribution** — current breakdown by TCP state.

### 6. Top

Rankings at the current snapshot:

- **Top Processes** by connection count, with avg RTT, TX/s, RX/s, and
  per-process signal counts.
- **Top Local Ports** with service names.
- **Top Peer Hosts** by connection count and bytes.
- **Top TX / RX** — per-connection bytes leaders.

### 7. Perf

Performance / anomaly view. Sections:

- **Health Summary** — total ESTAB / warn / crit counts, per-signal-type
  counts as colored chips, and a bar-graph history of warn+crit volume.
- **System** — TIME-WAIT growth (count, ~30s delta, sparkline) and
  **ephemeral port exhaustion** (used/total ports in
  `/proc/sys/net/ipv4/ip_local_port_range`).
- **RTT Inflation** — connections where `rtt/minrtt > 1.5` and RTT is
  at least 10 ms above the minimum (loopback/LAN jitter is ignored).
- **Slow Connections** — RTT > 50 ms.
- **Retransmit Rate** — current-poll retrans / sent ratio.
- **Cumulative Retransmits** — top 10 by total retrans.
- **Queue Pressure** — non-empty Send-Q / Recv-Q with usage bars vs the
  kernel buffer limits.
- **Zero Window** — sockets stalled by a peer that stopped reading
  (`ZERO_WIN`).
- **Send Backlog** — unacked / cwnd ratios.
- **Busiest Sockets** — per-poll busy ms and percentage.

### 8. Events

Signal-onset log. Every time a connection acquires a warn/crit signal it
didn't have the prior poll, that's an event. Reverse-chronological,
scrollable with `j`/`k`/`g`/`G`/`PgUp`/`PgDn`. `e` exports the events
list as JSON, `E` as CSV.

Info-level signals (`IDLE`, `APP_LIM`, `CWND_LIM`) are filtered out so
the log stays focused on real anomalies.

### 9. System

Host-wide networking counters from `/proc/net/snmp` and `/proc/net/netstat`,
each shown as a cumulative value plus its per-poll delta as a rate. This is
the one view that *isn't* per-socket: it catches things that never become
sockets or that the kernel only tallies globally — SYN floods and syncookies,
accept-queue overflows (`ListenOverflows`/`ListenDrops`), global retransmit
and timeout rates, receive-buffer pruning/OFO, and UDP `RcvbufErrors`/`NoPorts`.
Error/drop/overflow counters turn red the moment they move. Grouped into TCP,
Accept queue / SYN, Loss / retransmit, Buffer pressure / OFO, and UDP.

---

## Keybindings

| Key            | Action                                                     |
|----------------|------------------------------------------------------------|
| `1`–`9`        | Switch tabs (Findings, Live, Detail, Socket, Overview, Top, Perf, Events, System) |
| `Tab` / `S-Tab`| Next / previous tab                                        |
| `Space`        | Pause / resume — freeze the Live table and Findings for inspection |
| `[` / `]`      | Scrub back / forward one snapshot (auto-pauses)             |
| `{` / `}`      | Scrub back / forward ten snapshots                         |
| `j` / `↓`      | Next finding / row / scroll down (Events)                  |
| `k` / `↑`      | Previous finding / row / scroll up (Events)                |
| `g` / `G`      | First / last (or top / bottom on Events)                   |
| `PgUp`/`PgDn`  | Page scroll on Events                                      |
| `Enter`        | Open Detail for the highlighted row (Findings: show the affected sockets in Live) |
| `c`            | Copy the selected finding's suggested command (Findings)  |
| `Esc`          | Back to Live (clears selection) / close help / clear filter |
| `h`            | Cycle sort column / direction in Live                      |
| `L`            | Toggle hiding LISTEN sockets                               |
| `r`            | Toggle reverse DNS (peer/local hostnames; async, cached)   |
| `/`            | Open filter prompt                                         |
| `e`            | Export ring buffer to JSON (events list on Events tab)     |
| `E`            | Export latest snapshot to CSV (events list on Events tab)  |
| `?`            | Toggle help overlay                                        |
| `q` / `Ctrl-C` | Quit                                                       |

---

## Filtering

Press `/`, type one or more terms, hit `Enter`:

| Term                | Match                                                |
|---------------------|------------------------------------------------------|
| `local=<substr>`    | Substring match on local address                     |
| `peer=<substr>`     | Substring match on peer address                      |
| `peer==<addr>`      | Exact peer address (also `local==<addr>`)            |
| `sport=<port>`      | Exact source (local) port                            |
| `dport=<port>`      | Exact destination (peer) port                        |
| `state=<state>`     | Exact TCP state (`ESTAB`, `LISTEN`, `TIME-WAIT`, ...)|
| `proc=<substr>`     | Substring match on process name (case-insensitive)   |
| `pid=<pid>`         | Exact process ID                                     |
| `proto=<tcp\|udp>`  | Protocol                                             |
| `signal=<label>`    | Connection has this signal active (e.g. `RETRANS`, `cwnd_collapse`) |
| `signal=<label>:warn` | ... at warn or crit, not as info (also `:crit`)      |
| `signal=DROPS:mem`  | Drops the kernel refused memory for: the socket held almost none of its receive buffer (TCP short of memory host-wide) |
| bare `<state>`      | Shortcut for `state=…` if it matches a known state   |
| any other bare term | Substring match on local address, peer address or process name |

Terms can be combined with the boolean operators `and`, `or`, `not`, and
grouped with parentheses. A space between terms is an implicit `and`.

Examples:

```
/state=ESTAB peer=10.0    # all established connections to a /16
/proc=nginx signal=RETRANS # retransmitting nginx connections
/dport=443 sport=51234     # one specific socket pair
/(peer=10.0.0.1 or peer=10.1.0.1) and sport=1234
/proc=nginx not signal=RETRANS
/signal=DROPS:warn         # drops that are a fault, not loss-recovery discards
```

`Esc` clears the filter.

A term that can never match is rejected instead of quietly showing an empty
table: an unknown key (`sigal=RETRANS`) or signal name (`signal=RETRANZ`,
or the removed `DEL_DROP` / `BBR_LOW`). The prompt stays open with the
reason and the current filter stays in place; `--filter` exits with the
same message.

### Filtering at the source

The `/` filter hides sockets *after* sstui has collected them. On a host
with tens of thousands of sockets where you only care about a few, use
`--ss-filter` instead: the expression is handed to `ss` itself (its
`STATE-FILTER` and `EXPRESSION` syntax, see `ss(8)`), so everything else is
never collected, parsed or kept in history — less CPU and memory, and only
the sockets you asked about everywhere in the UI.

```bash
sstui --ss-filter 'dport = :443 or sport = :443'
sstui --ss-filter 'state established ( dst 10.0.0.0/8 )'
sstui --ss-filter 'sport = :5432'          # just the local Postgres
```

- The expression is validated at startup; a typo exits with `ss`'s own
  error message.
- Only filter expressions are accepted — words starting with `-` are
  rejected, so nothing can sneak an option like `-K` (kill sockets) into
  the `ss` command line.
- It's fixed for the session and shown in the footer. Both filters
  combine: `--ss-filter` decides what's collected, `/` narrows the view.
- Findings say when a filter is active: socket-count checks (ephemeral
  ports, TIME-WAIT storms, CLOSE-WAIT leaks) then only see the matching
  sockets, while the kernel counters (System tab, overflow/drop findings)
  stay host-wide.

---

## Export

Exports write to the current working directory with a timestamped name.
They run in the background (the status line says "exporting…" and then
confirms the path), so even a large ring buffer never freezes the UI.

| Tab + key        | Output                                                 |
|------------------|--------------------------------------------------------|
| any tab, `e`     | `./ss-stats-<ts>.json` — the whole ring buffer: every parsed field for the latest snapshot, the history fields (identity, state, RTT, cwnd, queues, rates, signals) for older ones; empty fields are omitted |
| any tab, `E`     | `./ss-stats-<ts>.csv` — current snapshot, flat (one row per connection) |
| Events tab, `e`  | `./ss-events-<ts>.json` — list of signal-onset events  |
| Events tab, `E`  | `./ss-events-<ts>.csv` — same, flat                    |

A green status line at the bottom confirms the path and row/snapshot count.

---

## Headless: check, record, replay, report

The same analysis runs without the TUI. Each command takes `-h`, and flags
can go before or after the file name.

```bash
sudo sstui check                      # watch 4s, print findings, exit 0/1/2/3
sudo sstui check --json --duration 10s
sudo sstui record -o web-1.jsonl.gz   # until Ctrl-C (or --duration 30m)
sstui replay web-1.jsonl.gz           # step through it in the TUI, anywhere
sstui report web-1.jsonl.gz -o incident.md
sudo sstui report --duration 1m       # watch live for a minute, then write the report
```

| Command | What it does |
|---|---|
| `check [FILE]` | Watches the host for `--duration` (default 4s, so there are deltas to compare), or analyses a recording, then prints each finding with its evidence and next steps. A finding counts if it showed up in any poll; each one says whether it was still active at the end. `--json` prints one JSON document instead. |
| `record` | Saves every poll to a file (default `sstui-HOST-TIME.jsonl.gz`) until Ctrl-C, SIGTERM, the SSH session dropping, or `--duration`. Prints findings as they appear and clear. `sstui --record FILE` records while you use the TUI. |
| `replay FILE` | Opens a recording in the TUI at its end. `[` `]` (or `{` `}` ×10) step through it, and every tab, Findings included, shows that moment. Keeps the last 1500 polls of a longer recording. |
| `report [FILE]` | Writes markdown: a summary table of every finding (first seen, last seen, how often, still active?), each finding in full with commands, the host counters that moved, the sockets at the end, and the kernel settings. Analyses a recording, or watches live for `--duration` (default 30s). `-o FILE` writes to a file. |

**Exit codes** (`check`) follow the Nagios plugin convention, so it drops
into monitoring agents and cron as is: `0` OK, `1` warning, `2` critical,
`3` unknown (bad arguments, `ss` failing, an unreadable recording). The
first line is a one-line verdict:

```
CRITICAL: 1 critical — web-1, 4s (3 polls), 812 sockets (640 established), host retransmits 0.12%

✖ CRIT  nginx (pid 812) → 10.0.0.5:5432: 37 connections stalled — peer not reading (zero window)
        active · seen in 3 of 3 polls, 14:02:07–14:02:11
        The receiver's buffer is full because its application stopped reading, …
        • 37 sockets · 41.2 MB waiting in Send-Q
        → See what its threads are doing
          $ top -H -p 812
        sockets: sstui --filter 'signal=ZERO_WIN pid=812 peer==10.0.0.5 dport=5432'
```

Colour is used only on a terminal, and text is wrapped only to a
terminal's width, so redirected output stays one line per item for
`grep` and logs.

**Recordings** are JSON lines: a header (host, kernel, sstui version, poll
interval, `--ss-filter`, whether it ran as root), then one line per poll
with the parsed sockets, the `/proc/net` counters, and the kernel settings
whenever they change. Deltas, signals and findings aren't stored; replay
recomputes them, so a newer sstui reads an old recording with its newer
rules. Names ending in `.gz` are gzip-compressed (roughly 100–200 KB per
1000 sockets per poll); either way `zcat | jq` works. Each poll is flushed
as it's written, so a recorder killed with `kill -9` still leaves every
complete poll readable (sstui notes that the file wasn't closed). Files
are created mode `0600`: a recording made with sudo names every socket's
process, which `ss` hides from other users.

A finding's "sockets" hint for a recording is a replay command
(`sstui replay --filter '…' FILE`), not the live TUI, which would show
the sockets of whatever machine you run it on.

---

## Common workflows

### "Something's wrong with this box — where do I start?"

1. Launch `sstui` (sudo for full process visibility). It opens on
   **Findings**.
2. Read the top finding: its title says what's wrong and where, the
   bullets say why sstui thinks so, the arrows say what to do.
3. `c` copies the suggested command; `Enter` shows the affected sockets in
   Live so you can drill into one (`Enter` again → Detail).
4. Nothing listed? The checks are summarized on the empty screen — move
   on to the per-socket views below.

### "The app is slow — is it the network?"

1. Launch `sstui` (sudo for full process visibility) and press `2` for Live.
2. `/proc=<your-service>` to scope the table.
3. Sort by RTT (`h` to cycle) — anything > 50 ms is yellow, > 200 ms
   orange.
4. Glance at the signal indicator column: a red `●` means a crit signal is
   active. `Enter` on a red row to open **Detail**.
5. On Detail, scan the Signals row at the bottom: `PATH_LOSS` means
   steady packet loss on the path (`RETRANS`, `LOSS` and `HI_RETRANS`
   alone are one poll's retransmits, normal while TCP fills a link); `RTT_SPIKE` alone means bufferbloat or path
   change; `ZERO_WIN` means the *peer* isn't reading; `RCV_Q` means
   *we* aren't reading.
6. `4` to switch to **Socket** — the History bar graph shows whether
   this is a momentary spike or a sustained problem.

### "Are we leaking ephemeral ports?"

1. Findings flags exhaustion at ≥70% on its own. For detail, `7` for **Perf**.
2. Scroll to the **System** section. The "Ephemeral ports" bar shows
   used/total ports inside the kernel's configured ephemeral range,
   coloured green/yellow/orange/red as utilization climbs through 40 /
   70 / 90 %.
3. If TIME-WAIT count is also climbing fast, that's where your
   ephemeral ports are going. The sparkline next to it shows the
   trajectory; growth in the last ~30 s is shown in parens.
4. `6` for **Top** → "Top Peer Hosts" / "Top Processes" to find the
   source of the churn.

### "Which connections retransmit the most?"

1. Filter to anomalies: `/signal=RETRANS` (or `signal=HI_RETRANS`).
2. Or `7` → Perf, scroll to **Cumulative Retransmits** and **Retransmit
   Rate** for current-poll ranking.
3. Drill into one with Enter → **Detail** → Retransmit section shows
   total retrans, in-flight retrans, bytes retrans, lost, DSACK dups,
   reorder counters.

### "Why is this BBR connection slow?"

1. Open the connection in Detail. Identity shows `Cong Ctrl: bbr` (green).
2. Tab to **Socket**, look at BBR: `BW` is its bottleneck-bandwidth
   estimate (the peak delivery rate over the last ~10 round trips, or the
   policed rate once BBR detects a token-bucket policer), `MRTT` its
   min-RTT estimate.
3. `Pacing Gain` / `CWnd Gain` show the phase: 2.89 / 2.89 is STARTUP,
   0.35 / 2.89 DRAIN, 1.25 → 0.75 → 1.0 / 2 PROBE_BW (steady state), and
   1 / 1 PROBE_RTT (cwnd cut to 4 packets for ~200 ms every ~10 s, by
   design).
4. A steady connection in PROBE_BW with `BW` well below the link is
   limited elsewhere: check for `RWND_LIM`, `SNDBUF_LIM`, `APP_LIM`, or
   loss (`PATH_LOSS`, `RTO`). The window signals fire
   only from 25% of a poll; Detail's **Rwnd Limited** / **Sndbuf
   Limited** rows show smaller shares that can still cap throughput.

### "Capture state for a bug report"

1. `sudo sstui record -o incident.jsonl.gz` on the server while the
   problem happens (or `sudo sstui --record incident.jsonl.gz` to watch at
   the same time). Ctrl-C when you have it.
2. `sstui report incident.jsonl.gz -o incident.md` and paste the markdown
   into the ticket; attach the recording.
3. Whoever picks it up runs `sstui replay incident.jsonl.gz` on their own
   machine and steps through the incident in the TUI.
4. For spreadsheets or pandas, `e` / `E` in the TUI still export the ring
   buffer as JSON or the current snapshot as CSV.

### "Alert me when this box has a network problem"

```bash
# cron, a monitoring agent, or a health check: exit 2 means critical
sudo sstui check --duration 10s || logger -t sstui "network check: exit $?"
sudo sstui check --json | jq '.findings[] | select(.active) | .title'
```

### "What happened on this host in the last hour?"

1. `8` for **Events**.
2. The list shows every signal onset since launch, newest first.
3. `G` to jump to the oldest events, `j`/`k` or `PgUp`/`PgDn` to walk
   through.
4. `e` exports the entire list as JSON with timestamps, 4-tuples,
   process names, signal labels, and values.

---

## Signals reference

There are **26 signal types**, each at one of three severities: `info`
(grey), `warn` (yellow/orange), `crit` (red). Severity is reflected in the
badge color and in the Live-tab indicator glyph.

| Label      | Type const           | Fires when                                                                 | Inputs (parsed?)                       | Severity | Color  |
|------------|----------------------|----------------------------------------------------------------------------|----------------------------------------|----------|--------|
| `RETRANS`  | `retrans_in_flight`  | `retrans_now > 3`                                                          | `retrans:N/M` ✓                        | 0 (info) | red    |
| `APP_LIM`  | `app_limited`        | `app_limited` flag set                                                      | `app_limited` ✓                        | 0 (info) | green  |
| `IDLE`     | `idle`               | ESTAB & no bytes moved this poll                                            | computed deltas ✓                      | 0 (info) | gray   |
| `ZERO_WIN` | `zero_window`        | ESTAB with the persist (zero-window probe) timer armed, or `snd_wnd:0`     | `timer:(persist,…)` ✓ (`ss` omits `snd_wnd` when 0) | 2 | red |
| `LOSS`     | `congestion_loss`    | `lost > 2`                                                                  | `lost:` ✓                              | 0 (info) | red    |
| `PMTU`     | `pmtu_mismatch`      | `pmtu < advmss+40`                                                          | `pmtu:` `advmss:` ✓                    | 1        | orange |
| `RTT_SPIKE`| `rtt_spike`          | `rtt/minrtt > 5` (crit >15) and `rtt − minrtt ≥ 10ms`                       | `rtt:` `minrtt:` ✓                     | 1–2      | orange |
| `SEND_Q`   | `send_buffer_pressure` | Send-Q ≥ 50% of send buffer (crit ≥80%), sustained 2 polls; 16K/64K abs fallback | column + `skmem` `tb` ✓        | UDP 1–2, TCP 0 (info) | yellow |
| `RCV_Q`    | `recv_buffer_pressure` | Recv-Q ≥ 50% of recv buffer (crit ≥80%), sustained 2 polls; for TCP of half the buffer, what it holds in data; 16K/64K abs fallback | column + `skmem` `rb` ✓        | 1–2      | yellow |
| `HI_RETRANS`| `high_retrans_rate` | `retrans/sent > 5%` this poll                                              | deltas of `bytes_sent`/`bytes_retrans` ✓ | 0 (info) | red  |
| `CWND_LIM` | `cwnd_limited`       | `unacked > 0.8·cwnd` && `> 10` (using its full window — healthy bulk transfer) | `unacked:` `cwnd:` ✓                | 0 (info) | gray   |
| `LISTEN_Q` | `listen_queue_full`  | LISTEN `RecvQ/SendQ > 0.8` (crit ≥1.0)                                      | `RecvQ/SendQ` column ✓                 | 1–2      | red    |
| `RTO`      | `rto_firing`         | ESTAB, timer on, `TimerRetrans ≥ 2` (crit ≥4)                               | `timer:` `TimerRetrans` ✓              | 1–2      | red    |
| `SYN_STALL`| `syn_stall`          | SYN-SENT, `TimerRetrans ≥ 2` (crit ≥3)                                      | `state`, `TimerRetrans` ✓              | 1–2      | orange |
| `NO_ACK`   | `peer_no_ack`        | data outstanding on two consecutive polls and nothing ACKed in between (crit if no ACK ≥10s) | `unacked:` `bytes_acked:` delta, `lastack:` ✓ | 1–2 | red |
| `CWND_DROP`| `cwnd_collapse`      | `CWnd < ⌊PrevCWnd/2⌋`, prev ≥ 20, with loss or ECN marks the same poll, not BBR ProbeRTT | `cwnd:` + prev poll `cwnd`, `bytes_retrans:` delta, `lost:`, `delivered_ce:` delta ✓ | 0 (info) | orange |
| `DSACK`    | `dsack_spurious`     | `Δdsack_dups > 0`                                                           | `dsack_dups:` delta ✓                  | info     | yellow |
| `REORDER`  | `reordering`         | over the last ~12 s: reordering events in at least half of the 2 s slots and ≥0.5% of segments (crit ≥5%), and ≥10 per retransmitted segment | `reord_seen:` `bytes_sent:` deltas, `mss:` ✓ | 1–2 | orange |
| `DROPS`    | `socket_drops`       | `Δskmem.d > 0` (crit >10) — kernel dropped data at this socket (info when segments arrived after a gap that poll and there's no `RCV_Q`: out-of-order data discarded during loss recovery; and on TCP when no data arrived that poll, or none of the host's buffer-drop counters moved: probes, PAWS, duplicates) | `skmem` `d` delta ✓ | 0–2 | red |
| `RWND_LIM` | `rwnd_limited`       | sending & `Δrwnd_limited ≥ 25%` of poll (crit ≥75%), this poll and the one before — blocked on peer window | `rwnd_limited:` delta ✓               | 1–2      | yellow |
| `SNDBUF_LIM`| `sndbuf_limited`    | sending & `Δsndbuf_limited ≥ 25%` of poll (crit ≥75%), this poll and the one before — blocked on send buffer; or (warn) the send buffer full (Send-Q ≥ 40% of `tb`) on both polls with all of it in flight and room in `cwnd` and the peer's window, which the kernel's timer misses | `sndbuf_limited:` delta, Send-Q, `skmem` `tb`, `unacked:` `cwnd:` `snd_wnd:` ✓ | 1–2      | yellow |
| `RCVBUF_LIM`| `rcvbuf_limited`    | receiving: data per round trip (Δbytes_received × `rcv_rtt`) ≥ 80% of `rcv_wnd` on this poll and the one before, Recv-Q < 25% of `rb` (needs TCP timestamps) — this socket's buffer caps the sender | `bytes_received:` delta, `rcv_rtt:` `rcv_wnd:` `ts`, Recv-Q, `skmem` `rb` ✓ | 1 | yellow |
| `CW_LEAK`  | `close_wait_leak`    | one process holds ≥20 CLOSE-WAIT sockets (crit ≥50) — fd leak              | per-process CLOSE-WAIT count ✓          | 1–2      | red    |
| `TW_STORM` | `time_wait_storm`    | ≥200 TIME-WAIT toward one peer endpoint (crit ≥2000) — port exhaustion risk | per-peer TIME-WAIT count ✓            | 1–2      | orange |
| `RX_LOSS`  | `inbound_loss`       | over the last ~12 s: ≥2% of data segments received arrived after a gap (crit ≥10%), in at least half of the 2 s slots, with `rcv_rtt` near min RTT in ¾ of receiving polls (needs TCP timestamps; the min is the lowest among connections to the same peer, since a receiver measures its own only on the handshake) — inbound loss seen at the receiver | `rcv_ooopack:` `data_segs_in:` deltas, `rcv_rtt:` `minrtt:` `ts` ✓ | 1–2 | red |
| `PATH_LOSS`| `path_loss`          | over the last ~12 s: ≥0.05% of bytes retransmitted (crit ≥1%), in at least half of the 2 s slots, with median RTT while sending near its minimum (BBR exempt) | `bytes_sent:` `bytes_retrans:` deltas, `rtt:` `minrtt:` ✓ | 1–2 | red |

### Connection-state signals

| Signal       | Fires when                                                                  | Severity   | What it means                                                          |
|--------------|------------------------------------------------------------------------------|------------|------------------------------------------------------------------------|
| `IDLE`       | ESTAB, no bytes moved either way this poll, nothing waiting in Send-Q        | info       | Connection is alive but quiet (a stalled send queue is not idle)       |
| `APP_LIM`    | `app_limited` flag set                                                       | info       | TCP could send more; the app isn't producing data fast enough          |
| `LISTEN_Q`   | LISTEN socket with `RecvQ/SendQ > 0.8` (or RecvQ > 100 when SendQ unknown)   | warn / crit (≥1.0) | Accept queue full — incoming SYNs are being dropped              |
| `SYN_STALL`  | `SYN-SENT` still retrying: `TimerRetrans ≥ 2` (~3 s without an answer)      | warn / crit (≥3) | Handshake stuck — DNS, firewall, or routing problem. One retry is a lost SYN or SYN-ACK on a lossy path, and the connection usually goes through |
| `NO_ACK`     | Data outstanding across a whole poll with no bytes ACKed                     | warn / crit (≥10s) | Peer hung, or the path / a middlebox is black-holing packets   |

### Loss & retransmission signals

| Signal        | Fires when                                                            | Severity                | What it means                                              |
|---------------|-----------------------------------------------------------------------|-------------------------|------------------------------------------------------------|
| `PATH_LOSS`   | Over the last ~12 s (or four polls if slower): ≥0.05% of bytes retransmitted, in at least half of the 2 s slots, and the median RTT while sending within max(4 ms, 10% of min RTT) of its minimum. BBR skips the RTT test | warn / crit (≥1%) | **Steady loss on the path**, not the loss TCP causes itself while filling a link: that comes in bursts (slow start, request bursts) or from a flow that fills the bottleneck queue (RTT climbs while it sends). Drives the loss finding. A bottleneck whose buffer is only a few ms deep drops before the queue shows, so several flows saturating one can look the same; the finding names both causes |
| `RETRANS`     | `retrans:N/M` first field > 3                                          | info                    | Segments being retransmitted right now. Context: normal for a moment while TCP fills a link; `PATH_LOSS` judges loss |
| `RTO`         | ESTAB, `timer:(on,…)` running, `TimerRetrans ≥ 2`                      | warn / crit (≥4)        | RTO timer doubling — single segment stuck retransmitting   |
| `LOSS`        | `lost:N > 2`                                                           | info                    | Segments the kernel currently considers lost. Context, like `RETRANS` |
| `HI_RETRANS`  | `Δbytes_retrans / Δbytes_sent > 5%`                                    | info                    | This poll's retransmit rate is high. Context only: a burst like this is normal during slow start, so findings rely on `PATH_LOSS` |
| `DSACK`       | `dsack_dups` grew this poll                                            | info                    | Spurious retransmits — the data had arrived (aggressive RTO, or reordering). Context: TCP undoes them itself, and healthy flows on a busy link have them now and then |
| `REORDER`     | Over the last ~12 s: `reord_seen` grew in at least half of the 2 s slots, by ≥0.5% of the segments sent, and at least 10 events per retransmitted segment | warn / crit (≥5%) | Our packets are reordered on the way to the peer (often ECMP / LACP / multi-queue hashing). The counter also ticks now and then on request bursts, and steadily during loss recovery (up to 5.5 events per retransmit in the lab, against 21+ for real reordering), so one-off events and lossy connections don't count |
| `DROPS`       | `skmem` drop counter (`d`) grew this poll                             | warn / crit (>10); info for loss-recovery discards and TCP's own discards | Kernel discarded data at the socket — buffer overran, receiver too slow. On a listening socket it counts refused connection attempts (accept or SYN queue overflow) or stray handshake segments instead; the accept-queue finding reports it when the host's `ListenOverflows` / `ListenDrops` counters say connections were refused. When segments arrived after a gap in the same poll and the receive queue is empty, it's out-of-order data discarded during loss recovery instead: info, and the inbound-loss finding mentions it. On a TCP socket that received no data that poll, it's segments TCP discards by design, mostly keepalive and zero-window probes (an idle connection with keepalive on drops one per probe): info. So are drops in a poll where none of the host's buffer-drop counters moved (`TCPRcvQDrop`, `TCPZeroWindowDrop`, `TCPOFODrop`, `RcvPruned`, `OfoPruned`, `TCPBacklogDrop`): segments TCP's own checks discard, PAWS timestamps failing on ACKs above all. On a TCP socket holding almost none of its receive buffer, the kernel refused it memory host-wide (`tcp_mem`): the memory-pressure finding reports it, not the reader |
| `RX_LOSS`     | Over the last ~12 s: ≥2% of data segments received arrived after a gap, in at least half of the 2 s slots, and `rcv_rtt` within max(4 ms, 10% of min RTT) of the minimum in at least ¾ of the receiving polls. The minimum is the lowest among connections to the same peer: a receiver measures its own only on the handshake, which may have waited in the queue. No verdict without TCP timestamps | warn / crit (≥10%) | **Inbound** loss (or reordering) on the peer → here path. The only loss signal available on the receiving side — the retransmit counters live on the sender. One lost segment makes everything behind it arrive out of order, so the ratio overstates the loss rate (in the lab 0.1% loss gave ~6%, 1% ~10%). A flow filling a bottleneck also arrives with gaps, but its data waits in the queue, which `rcv_rtt` includes. Blind to a BBR sender's loss (BBR keeps a standing queue); the sender's `PATH_LOSS` sees it |

### Congestion & flow control

| Signal        | Fires when                                                       | Severity         | What it means                                                       |
|---------------|------------------------------------------------------------------|------------------|---------------------------------------------------------------------|
| `ZERO_WIN`    | ESTAB, persist timer armed (or `snd_wnd:0`)                      | crit             | Peer's receive window is closed — peer not reading                  |
| `CWND_DROP`   | `CWnd` below half of `PrevCWnd`, rounded down (prev ≥ 20), with retransmits, lost packets or new ECN marks the same poll; not BBR ProbeRTT | info | Loss or ECN congestion marks cut the congestion window sharply. Context: slow start overshooting a link does this on healthy traffic. Cuts without them (restart after idle, an app-limited window trimmed) are ignored |
| `CWND_LIM`    | `unacked > 0.8 × cwnd` and `unacked > 10`                        | info             | Using its full congestion window — normal for a bulk transfer       |
| `PMTU`        | `pmtu < advmss + 40`                                             | warn             | Path MTU smaller than our advertised MSS                            |
| `RTT_SPIKE`   | `rtt / minrtt > 5` and ≥10ms above min                            | warn / crit (>15) | Latency spike vs the connection's baseline                         |

### Buffer pressure

| Signal      | Fires when                                          | Severity         | What it means                            |
|-------------|------------------------------------------------------|------------------|------------------------------------------|
| `SEND_Q`    | Send-Q ≥ 50% of the send buffer (crit ≥80%) on two consecutive polls; 16 KB / 64 KB when the buffer size is unknown | UDP warn / crit; TCP info | Data queued faster than it drains. For TCP that's an app writing faster than the path: normal for bulk transfers (a blocked sender shows as `ZERO_WIN`, `RWND_LIM`, `SNDBUF_LIM`). For UDP the host can't put packets out as fast as the app sends |
| `RCV_Q`     | Recv-Q ≥ 50% of the receive buffer (crit ≥80%) on two consecutive polls; same fallback. For TCP, of half the buffer: the rest of `rb` pays per-packet overhead, so a full TCP queue holds about half of it in data | warn / crit | The local app isn't reading fast enough |
| `RCVBUF_LIM` | Data arriving per round trip fills ≥ 80% of the advertised window on two consecutive polls while Recv-Q stays under a quarter of the buffer; needs TCP timestamps | warn | This socket's receive buffer caps the sender: the app keeps up, but the whole window arrives every round trip. The receiving end's view of the sender's `RWND_LIM` |

---

## Metrics reference

Everything `ss -atunpeimOH` produces, organized by what it tells you. `Δ` is
the per-poll delta (computed in the poller), `cum.` means cumulative since
socket creation.

### Identity

| Field           | ss source            | Notes                                                        |
|-----------------|----------------------|--------------------------------------------------------------|
| Protocol        | Netid column         | TCP and UDP come from one `ss -atun…` call (falls back to separate queries if that fails) |
| State           | first column         | UDP rewritten to `UDP_ESTAB` / `UDP_ACTIVE` / `UDP_IDLE`     |
| Local / Peer    | 4-tuple              | IPv6 bracketed; UDP uses `*:port` for unconnected sockets    |
| Process / PID / UID | `users:(("name",pid=,fd=))`, `uid:`         |                                                              |
| Inode           | `ino:`               | Used internally to detect 4-tuple reuse                      |
| Cgroup          | `cgroup:`            | Path of the owning cgroup                                    |
| CongAlgo        | bare token           | `cubic`, `bbr`, `reno`, `vegas`, `htcp`, `dctcp`, …          |
| Timer           | `timer:(type,dur,retr)` | Keepalive countdown shown as `15s` / `4m02s`              |

### Latency / RTT

| Field      | ss source       | Notes                                              |
|------------|------------------|---------------------------------------------------|
| RTT        | `rtt:X/Y`        | Smoothed round-trip time (ms)                     |
| RTT Var    | `rtt:X/Y`        | RTT variance                                      |
| Min RTT    | `minrtt:`        | Lowest RTT observed                               |
| Rcv RTT    | `rcv_rtt:`       | Receiver-side RTT estimate                        |
| RTO        | `rto:`           | Retransmission timeout (ms)                       |
| ATO        | `ato:`           | Delayed ACK timeout                               |

### Congestion control

| Field         | ss source       | Notes                                                          |
|---------------|------------------|---------------------------------------------------------------|
| CWnd          | `cwnd:`          | Congestion window in MSS-sized packets                        |
| ssthresh      | `ssthresh:`      | Slow-start threshold                                          |
| MSS / AdvMSS / RcvMSS | `mss:`/`advmss:`/`rcvmss:` | Negotiated / advertised / received segment sizes |
| PMTU          | `pmtu:`          | Path MTU                                                      |
| SndWnd        | `snd_wnd:`       | Peer's advertised receive window (bytes)                      |
| RcvWnd        | `rcv_wnd:`       | Our own receive window                                        |
| RcvSpace      | `rcv_space:`     | Auto-tuned receive buffer target                              |
| RcvSSThresh   | `rcv_ssthresh:`  | Receive-side ssthresh                                         |
| WScale        | `wscale:S,R`     | Window scale exponents                                        |
| PrevCWnd      | (computed)       | Last poll's CWnd — backs the `CWND_DROP` signal               |

### Throughput

| Field             | ss source            | Notes                                                  |
|-------------------|----------------------|--------------------------------------------------------|
| Bytes Sent / Recv / Acked / Retrans | `bytes_sent:` etc.   | cum.                                       |
| Δ Bytes Sent / Recv / Retrans       | (computed)           | Per-poll bytes — drives the table TX/RX columns and `HI_RETRANS` |
| Pacing Rate       | `pacing_rate Xbps`   | Target send rate                                       |
| Delivery Rate     | `delivery_rate Xbps` | Observed delivery rate                                 |
| Send (inst)       | `send Xbps`          | Instantaneous estimated send rate                      |
| Delivered         | `delivered:`         | cum. delivered packets                                 |
| Delivered CE      | `delivered_ce:`      | cum. delivered packets ACKed with an ECN congestion mark (shown when non-zero) |
| AppLimited        | `app_limited`        | TCP was waiting on the application this RTT            |
| Busy              | `busy:Xms`           | cum. ms doing TCP work; UI shows `ΔBusy / poll` ratio  |

### Segments

| Field                       | ss source           | Notes                                          |
|-----------------------------|---------------------|------------------------------------------------|
| Segs Out / In               | `segs_out:` / `segs_in:` | cum. total segments                       |
| Data Segs Out / In          | `data_segs_out:` / `data_segs_in:` | cum. data-carrying segments     |
| Δ Segs Out / In             | (computed)          | Per-poll segments                              |
| Δ Data Segs In              | (computed)          | Per-poll data segments received — the denominator of the inbound OOO ratio |

### Retransmits / loss / reordering

| Field          | ss source           | Notes                                                              |
|----------------|---------------------|--------------------------------------------------------------------|
| Retrans (flight) | `retrans:N/…`     | Segments currently being retransmitted                             |
| Retrans (total)  | `retrans:…/M`     | cum. retransmits                                                   |
| Lost           | `lost:`             | Kernel's estimate of currently-lost packets                        |
| Unacked        | `unacked:`          | Bytes / segs in flight                                             |
| DSACK Dups     | `dsack_dups:`       | cum. duplicate ACKs reported by peer                               |
| Δ DSACK Dups   | (computed)          | Drives the `DSACK` signal                                          |
| Reordering     | `reordering:`       | Kernel's reordering-distance estimate                              |
| Reord Seen     | `reord_seen:`       | cum. reorder events observed                                       |
| Rcv OOO        | `rcv_ooopack:`      | cum. out-of-order segments **received**: each one arrived after a gap, i.e. a segment from the peer was lost (or reordered) on its way here. When sstui runs on the receiving host this is the only visible trace of inbound loss — the sender's retransmit counters live on the other machine |
| OOO / data in  | (computed)          | `rcv_ooopack / data_segs_in`, per poll and over the connection's life (Detail → Inbound). Summed per receive slot, it drives the `RX_LOSS` signal |
| Δ Reord Seen   | (computed)          | Summed per send slot; drives the `REORDER` signal                  |

### Last-activity timestamps

| Field   | ss source     | Notes                                              |
|---------|---------------|----------------------------------------------------|
| LastSnd | `lastsnd:`    | ms since last send                                 |
| LastRcv | `lastrcv:`    | ms since last receive                              |
| LastAck | `lastack:`    | ms since last ACK                                  |

`lastack` sets the `NO_ACK` severity.

### BBR (when CongAlgo = bbr)

| Field           | ss source                                  | Notes                              |
|-----------------|--------------------------------------------|------------------------------------|
| BW              | `bbr:(bw:X…)`                              | BBR's bandwidth estimate           |
| MRTT            | `bbr:(…,mrtt:X…)`                          | BBR min RTT window                 |
| Pacing Gain     | `bbr:(…,pacing_gain:X…)`                   | Current pacing multiplier          |
| CWnd Gain       | `bbr:(…,cwnd_gain:X…)`                     | Current cwnd multiplier            |

Pacing gain > 1.5 = probing up; < 0.85 = draining.

### Socket memory (`skmem`)

ss reports `skmem:(r,rb,t,tb,f,w,o,bl,d)`:

| Field      | Meaning                                                            |
|------------|--------------------------------------------------------------------|
| rcv buf    | bytes used vs receive buffer limit (`r` / `rb`)                    |
| snd buf    | bytes queued vs send buffer limit: `w` / `tb` for TCP, `t` / `tb` for UDP (TCP's `t` is only what's been handed to the device) |
| fwd alloc  | forward-allocated memory (`f`)                                     |
| write alloc| write-queue allocated memory (`w`)                                 |
| optmem     | option memory (`o`)                                                |
| backlog    | backlog queue size (`bl`)                                          |
| drops      | **packets dropped from this socket** (`d`) — red when non-zero     |

### System-wide (Perf → System section)

| Metric                    | Source                                       | Notes                                          |
|---------------------------|----------------------------------------------|------------------------------------------------|
| TIME-WAIT count + growth  | counted from snapshots                       | Sparkline shows full history; +N is ~30 s delta |
| Ephemeral port usage      | `/proc/sys/net/ipv4/ip_local_port_range`     | Counts distinct local ports inside that range   |

---

## Architecture

```
                ┌─────────┐
ss -atunpeimOH ►│ parser  │──► []*model.Connection
                │         │
                └─────────┘
                     │
                     ▼
                ┌─────────┐       ┌─────────────┐
                │ poller  │──┐    │ classifier  │
                │ (ring   │  └───►│ (26 signals)│
                │  buffer)│       └─────────────┘
                └────┬────┘             │
                     │                  ▼
                     │            c.Signals
                     ▼
     1500 Snapshots: compact Samples (+ full Conns for the newest)
                     │
                     ├──────────────► findings ◄── /proc/net counters + sysctls
                     ▼                (18 rules, once per poll)
                ┌─────────┐                │
                │   ui    │◄───────────────┘
                └─────────┘  bubbletea TUI, 9 tabs
```

- **`parser/`** — runs one `ss` subprocess for TCP+UDP and tokenizes
  each record in a single left-to-right pass (`key:value` tokens
  dispatched on the key; no regexes), returning `[]*model.Connection`.
  Counters `ss` omits while zero are filled with 0 when the kernel is
  known to report them.
- **`poller/`** — `Buffer` is a ring of 1500 snapshots. `AddSnapshot` is
  three-phase: (1) read-lock to copy `prevMap` pointers, (2) compute
  deltas + classify **outside the lock**, (3) write-lock briefly to
  publish. Each snapshot stores compact `Sample`s (~100 B: interned
  identity, inline numbers) sorted by key for binary-search lookup, plus
  `stateCounts`. Only the newest snapshot keeps full-detail
  `Connection`s; older ones materialize slim connections on demand.
- **`classifier/`** — pure rules producing 26 signal types, run once per
  connection per poll (plus aggregate rules for CLOSE-WAIT leaks and
  TIME-WAIT storms).
  Severity is encoded as `0` (info) / `1` (warn) / `2` (crit). New
  signals are roughly one struct field, one parser case, and a 10-line
  rule here.
- **`findings/`** — turns signals, host counters and sysctls into ranked
  host-level findings with evidence and recommendations. Pure: input in,
  report out, once per poll; a tracker dates each finding.
- **`session/`** — the pipeline the TUI and the headless commands share:
  `Ingest` takes a poll (live, or read back from a recording), adds it to
  the ring buffer, rolls the host counters, runs the findings and keeps
  each snapshot's report so a paused view shows that moment. Also the
  recording format (`Recorder` / `Reader`) and the `Timeline` that
  summarises findings across a window for `check` and `report`.
- **`headless/`** — renders a timeline as text, JSON or markdown.
- **`ui/`** — pure bubbletea + lipgloss. One file per tab. Reads only
  from `poller.Buffer` and the findings report; never mutates state.

### Polling cadence

2 s by default, set with `--interval` (minimum 100 ms); the ring holds
`BufferSize = 1500` snapshots, so the history window is 1500 × interval
(50 minutes at 2 s). Rates, busy ratios and the window/buffer-limited
fractions all scale with the interval automatically.

### Coloring conventions

- TX direction → green, RX → magenta.
- Latency tiers: `≤50ms` green, `≤200ms` yellow, `>200ms` orange.
- Queue pressure (non-zero) → yellow.
- Retransmits / drops / zero-window → red.
- Dim grey = informational / context (no problem).

---

## Performance footprint

On a host with ~500 sockets:

- `ss -atunpeimOH` takes ~5–15 ms wall clock (dominated by `-p`
  walking `/proc/*/fd`).
- Parsing: ~2–3 µs per socket; delta computation + classification add
  well under a millisecond per snapshot.
- Memory: history costs ~110 B per socket per snapshot, so ~500
  long-lived sockets for the full 50 minutes ≈ **80 MB** (1000 ≈ 160
  MB). Real hosts churn through short-lived TIME-WAITs, so steady-state
  usage is usually lower.
- CPU at idle (no input, only ticks): single-digit % on one core.

If memory is a concern, drop `BufferSize` in `poller/poller.go`. Each
snapshot is independent, so shrinking the ring is safe.

---

## Troubleshooting / FAQ

**Q. Process names are missing for half my connections.**
You're not running as root, so `ss` can only name the process for your own
sockets. Run `sudo sstui` (see
[Permissions](#permissions-what-you-see-and-as-whom)). Some sockets
never have a process, even as root: TIME-WAIT, SYN-RECV, and connections
the app has already closed that the kernel is still finishing (FIN-WAIT,
LAST-ACK). sstui doesn't count those as hidden.

**Q. The footer shows `ss error: ... (data may be stale)` in red.**
`ss` failed this poll. The previous snapshot is still visible, but it's
not updating. Most common causes: `ss` was killed, the binary moved,
or the system is heavily resource-constrained. sstui keeps retrying
every 2 s.

**Q. I see `↓ N more line(s)` at the bottom of a tab.**
Content didn't fit in the viewport. Make the terminal taller, or switch
to a sibling tab (Detail ↔ Socket) which splits the same data across
two screens.

**Q. UDP connections show weird states like `UDP_ESTAB` / `UDP_IDLE`.**
`ss` doesn't give UDP sockets a meaningful state. sstui synthesises:
`UDP_ESTAB` (kernel reports ESTAB), `UDP_ACTIVE` (queues non-empty),
`UDP_IDLE` (default).

**Q. Why does IDLE fire on connections that are clearly active?**
It doesn't — on a connection's first snapshot, deltas are unknown, so
IDLE is suppressed until we have a prior poll to compare against, and a
connection with data stuck in its send queue is never IDLE. If you're
seeing it after the first poll, the connection genuinely moved zero bytes
in that interval.

**Q. `c` (copy command) doesn't put anything on my clipboard.**
It uses OSC 52, which the terminal has to support and allow (most modern
ones do; some need it enabled). In tmux, set `set -g set-clipboard on`
(and `allow-passthrough on` for nested sessions). It also works over SSH,
since the escape sequence travels with the terminal output.

**Q. The same key sometimes does different things.**
Some keys are tab-aware:
- `j`/`k`/`g`/`G` navigate the table on Live, scroll the list on
  Events.
- `e`/`E` export the ring buffer on most tabs; on Events they export
  the events list itself.
- `Enter` opens Detail on Live, and on Findings jumps to Live filtered to
  the finding's sockets. `c` copies a command only on Findings.

**Q. Can I run it remotely?**
Yes — over SSH like any TUI. Make sure your terminal forwards true
colors (`TERM=xterm-256color` or better; modern SSH clients usually do
this fine).

**Q. Can I record a session and replay it?**
Yes: `sudo sstui record -o FILE` (or `sstui --record FILE` while you
watch), then `sstui replay FILE` on any machine, or `sstui report FILE`
for a markdown summary. See [Headless](#headless-check-record-replay-report).

**Q. Replay says the recording "wasn't closed cleanly".**
The recorder was killed before it could finish the file (`kill -9`, OOM,
power loss). Ctrl-C, SIGTERM and a dropped SSH session all close it
properly. Every poll written before that point is still read.

**Q. How do I add a new signal?**
1. Add the constant + label to `model/signal.go`.
2. Add a color to `signalColors` in `ui/header.go`.
3. Add a classifier rule in `classifier/classifier.go`.
4. (Optional) Add a parser case / field to `parser/parser.go` and
   `model/connection.go` if you need new data, and a delta entry in
   `poller/poller.go` if it's a counter.

The classifier is intentionally a flat list of rules — no DSL — so
adding signals stays low-ceremony.

---

## Limitations

- **Linux-only.** macOS and BSDs ship different `netstat`/`ss`-likes
  with different output formats. A Darwin parser is possible but not
  written.
- **Polling, not streaming.** Anything finer-grained than 2 s
  (sub-RTT phenomena, SACK micro-events) is invisible.
- **No filter on number ranges** (e.g. "RTT > 100"). Add the term to
  `ui/filter.go` if you want it.
- **No scroll on Detail, Socket, Overview, Top or Perf.** Long content
  shows a `↓ N more line(s)` indicator but you can't scroll past it yet —
  make the terminal taller or switch to the paired tab. (Findings keeps the
  selected finding in view; Events scrolls.)
- **No persistence across restarts.** The ring buffer is in-memory.
  Use `e` to snapshot before quitting if you want to keep history.
- **Process names rely on `users:(...)` from `ss`.** Containerised
  workloads may show the runtime (e.g. `containerd-shim`) instead of
  the inner process unless you can see PID namespaces.
- **The signal classifier is heuristic.** Thresholds are tuned for
  general-purpose hosts; loud workloads (CDNs, proxies, databases)
  may need tweaks. Signal thresholds live in `classifier/classifier.go`,
  finding rules in `findings/rules.go`; both are one-line edits.
- **Some failures look alike from one host, and the lab confirms where.**
  A BBR sender's loss is invisible at the receiver: BBR keeps a standing
  queue, which the receiver can't tell from congestion, so check the
  sending end. A path that starts dropping everything right after the
  handshake looks like an MTU black hole. Inbound loss is measured
  against the lowest round trip seen on the path, so if every connection
  to a peer opened through an already-full queue, queueing delay can
  hide it.
- **`--ss-filter` narrows the socket-count checks.** With a filter
  active, findings like ephemeral-port exhaustion or TIME-WAIT storms see
  only the matching sockets (the Findings tab says so); kernel counters
  stay host-wide.

---

## Development

Layout:

```
classifier/   one-rule-per-block signal classifier
findings/     host-level findings + recommendations (Findings tab)
model/        Connection + Signal data types
parser/       ss(8) tokenizer and subprocess driver
poller/       ring buffer, delta computation, export (JSON/CSV)
session/      poll → buffer → findings pipeline, recordings, timelines
headless/     check / report output (text, JSON, markdown)
ui/           bubbletea views, one file per tab
main.go       AppModel: keybinds, scroll state, render dispatch
commands.go   check / record / replay / report subcommands
```

Build & run:

```bash
go build .
./sstui
```

Checks (run before committing):

```bash
scripts/check.sh
```

It runs gofmt, `go mod tidy`, `go vet`, staticcheck (pinned version,
fetched on first use) and `go test -race ./...`, and stops at the first
failure. There is no hosted CI; this script is the gate.

Tests cover the parser (against captured `ss` output), classifier rules,
findings rules (including that every finding's Live filter selects exactly
its sockets), the ring buffer and history samples, recordings (round trip,
files cut off mid-write), the check/report output, and the app's key flows
end to end, including replaying a recording. A few parser tests exercise
the real `ss` binary and skip when it isn't installed.

### Scenario lab

`scripts/lab.sh` recreates real failures and checks sstui diagnoses them:
each scenario builds a client and a server network namespace joined
through a router namespace, shapes the router's links with `tc netem`,
runs a small workload (a reader that stops reading, a server that never
accepts, packet loss, port exhaustion, a path MTU black hole, ...),
records the client, the server or both with `sstui record`, and asserts
on `sstui check --json`. Loss is checked from both ends: the sender sees
its retransmits, the receiver only the gaps in what arrives. Healthy
controls (bulk transfer, bursty request/response) must come out clean on
both ends, so a noisy rule fails the lab as surely as a missed diagnosis.

```bash
scripts/lab.sh                        # every scenario (about 7 minutes)
scripts/lab.sh -run ZeroWindow        # one of them
SSTUI_LAB_KEEP=out scripts/lab.sh     # keep each recording in out/
SSTUI_LAB_HOST=user@vm scripts/lab.sh # run them on another machine over ssh
SSTUI_LAB_HOSTWIDE=1 SSTUI_LAB_HOST=user@vm scripts/lab.sh
                                      # also scenarios that change host-wide
                                      # limits (tcp_mem): disposable machines only
```

It builds as you and runs the scenarios with sudo (on the other machine
with `SSTUI_LAB_HOST`, which needs passwordless sudo there); it needs
iproute2 (`ip`, `ss`) and `tc` with the netem qdisc. Host-wide scenarios
squeeze a kernel limit for a few seconds; a watchdog restores it within
90 s even if the run is killed. The scenarios live in
`lab/scenarios_test.go`; each one logs the findings and per-signal poll
counts it saw, so a failure shows its evidence.

Release binaries are built static with the version stamped in:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=v1.4.0" -o dist/sstui-linux-amd64 .
```

Coding conventions:

- One rule per signal, kept in `classifier/classifier.go`. Add the
  type + label in `model/signal.go`, the color in `ui/header.go`. If it
  describes a host-level problem, add a findings rule in
  `findings/rules.go` too.
- Renderers read from `*poller.Buffer` only; never mutate state.
- Cumulative counters get their delta in `poller.computeDeltas`.
  Non-monotonic values (e.g. `cwnd`) are stashed via `PrevX` fields.
- Colour palette is shared between tabs through `ui/table.go` and
  `ui/top.go`; latency tiers and direction colours are referenced by
  name (`colTX`, `colRX`, `colRTTOk` …).

Contributions especially welcome for:

- macOS / BSD parsers (different `netstat`/`ss`-likes).
- Numeric-range filters in `ui/filter.go`.
- Scrolling in Detail / Socket / Overview / Top / Perf.
- More golden-file parser tests against captured ss output from
  different iproute2 / kernel versions.

---

## License

MIT.
