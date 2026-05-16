# sstui

A terminal UI for `ss(8)` that watches every TCP and UDP socket on the
machine, classifies what's going wrong, and keeps ~50 minutes of history
so you can answer "what happened" instead of just "what's happening now".

Built for triage: tab through running connections, see signals like
`RETRANS`, `ZERO_WIN`, `RTO`, `SYN_STALL`, `REORDER` light up
automatically, and drill into the underlying kernel metrics on a single
key press.

![tabs](https://img.shields.io/badge/tabs-7-blue) ![signals](https://img.shields.io/badge/signals-20-orange) ![ring%20buffer](https://img.shields.io/badge/history-50%20min-green)

---

## Contents

1. [What it does](#what-it-does)
2. [Who it's for](#who-its-for)
3. [Why not just `ss` or `netstat`?](#why-not-just-ss-or-netstat)
4. [Install / build](#install--build)
5. [Permissions: what you see, and as whom](#permissions-what-you-see-and-as-whom)
6. [Quick tour](#quick-tour)
7. [Tabs](#tabs)
8. [Keybindings](#keybindings)
9. [Filtering](#filtering)
10. [Export](#export)
11. [Common workflows](#common-workflows)
12. [Signals reference](#signals-reference)
13. [Metrics reference](#metrics-reference)
14. [Performance footprint](#performance-footprint)
15. [Troubleshooting / FAQ](#troubleshooting--faq)
16. [Limitations](#limitations)
17. [Architecture](#architecture)
18. [Development](#development)
19. [License](#license)

---

## What it does

`sstui` runs `ss -atnpeimOH` (TCP) and `ss -aunpeimOH` (UDP) every 2 seconds,
parses the output, computes per-poll deltas, runs a classifier over each
connection, and keeps the last **1500 snapshots** (≈50 min) in a ring buffer.
Everything you see on screen — the table, the bars, the events log, the
sparklines — is rendered from that buffer.

There's no agent, no daemon, no setuid binary. Just `ss`. Run it as the
user whose connections you want to see, or with sudo to see everyone's.

What you get out of the box:

- **Live table** of every TCP/UDP socket on the host with sortable columns,
  state-coloured fields, and an at-a-glance signal indicator per row.
- **Automatic problem detection** through 20 named signals — retransmits,
  RTO storms, zero-window stalls, listen-queue overflow, ephemeral port
  exhaustion, packet reordering, CWnd collapse, BBR underutilization, and
  more. Each is tunable in one place (`classifier/classifier.go`).
- **50 minutes of history** in memory so you can see *when* something
  went wrong, not just that it's wrong now.
- **Drill-down detail** with two paired tabs: a network-level view (RTT,
  CWnd, congestion, retransmits) and a kernel-side view (queues, socket
  memory, BBR state) with per-connection bar-graph history of RTT, CWnd,
  TX, RX, queue depths, unacked, retrans.
- **Event log** that tells you the *moment* each signal started firing on
  each connection, scrollable and exportable to JSON/CSV.
- **Filter language** for narrowing by address, port, state, process
  name, or signal.
- **Snapshot/buffer export** to JSON (full history) and CSV (current
  snapshot) for offline analysis with jq, pandas, or a spreadsheet.

---

## Who it's for

- **SREs and on-call engineers** triaging a host: "is it the network or
  the app?" — sstui surfaces ZERO_WIN, RTO, SYN_STALL, ONE_WAY,
  LISTEN_Q in seconds and points at the specific 4-tuple/process.
- **Performance engineers** chasing tail latency: the RTT-inflation
  view, RTT/MinRTT ratio per connection, and CWND_DROP/REORDER signals
  separate "the wire is slow" from "we're retransmitting" from "we're
  reordering".
- **Backend developers** debugging connection-pool / DB-client issues:
  filter by `proc=` to see only your service's sockets, watch SEND_Q,
  RCV_Q, UNACKED, IDLE patterns over time.
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
| Snapshot of current sockets                   | ✓                | ✓                             |
| Per-connection RTT, CWnd, retrans, BBR        | ✓ with `-i`      | ✓ parsed and labelled         |
| Refreshes automatically                       | `watch ss`       | Built-in, 2 s ticks            |
| **Per-poll deltas** (TX/RX rates, retrans rate, OOO growth) | ✗   | ✓ computed in poller          |
| **Anomaly classification** (named signals)    | ✗                | ✓ 20 rules                    |
| **History** for "when did this start?"        | ✗                | ✓ 50 min ring                 |
| **Time-series view** per connection           | ✗                | ✓ bar-graph sparklines        |
| **Event log** of signal onsets                | ✗                | ✓ Events tab                  |
| **Filter by signal / process / address**      | ✗                | ✓                             |
| **Export** for offline analysis               | redirect output  | ✓ JSON / CSV                  |
| **System-wide rollups** (TIME-WAIT growth, port exhaustion) | ✗  | ✓ Perf tab                    |

Compared to `iftop` / `nethogs` / `bmon`: those are byte-rate views.
sstui is a TCP-state and TCP-internals view — it tells you *why* a
connection is slow, not just *how much* it's moving.

Compared to `nettop` / `tcptrack`: similar surface area, but sstui's
signals and history buffer are the differentiator.

---

## Install / build

```bash
git clone https://github.com/filip-lebiecki/sstui
cd sstui
go build .
./sstui
```

Requirements:

- Linux (the parser is `ss(8)`-specific — iproute2 ≥ 4.4 recommended).
- Go 1.22+ (uses generics-free stdlib only).
- A terminal that speaks 24-bit color and Unicode block glyphs (most do).

If `ss` isn't in `$PATH`, sstui exits with `ss not found in PATH;
install iproute2`. On Debian/Ubuntu: `apt install iproute2`; on
RHEL/Fedora: `dnf install iproute`.

---

## Permissions: what you see, and as whom

`ss` is the only privileged operation sstui performs, and sstui doesn't
elevate on its own.

- **Run as your user**: you see all sockets system-wide, but the
  `users:(("process",pid=,fd=))` block — process name and PID — is
  only populated for sockets your user owns. Other users' sockets show
  `Process: -` and no PID.
- **Run as root (or via `sudo sstui`)**: process names and PIDs are
  shown for every socket. Inode-based connection tracking is also more
  reliable, which improves the 4-tuple-reuse detection.
- **No CAP_NET_ADMIN required.** sstui doesn't touch netlink directly,
  doesn't open raw sockets, doesn't load BPF.

If you can't or don't want to run as root, an alternative is granting
`ss` the `cap_net_admin` file capability:

```bash
sudo setcap cap_net_admin+ep /usr/sbin/ss
```

…which makes process info visible without sudo. Verify with `getcap`.

---

## Quick tour

```
┌─ sstui ────────────────────── ESTAB 245   LISTEN 38   TIME-WAIT 12 ─┐
│ Live  Detail  Socket  Overview  Top  Perf  Events                    │
│                                                                       │
│ 🔴 TCP  ESTAB     10.0.0.1:443   …  17.2ms  ↑  120 KB/s   chrome  …  │
│ 🟡 TCP  ESTAB     10.0.0.5:5432  …   1.1ms  ↓   55 KB/s   psql    …  │
│ ...                                                                   │
│                                                                       │
│  RETRANS  RTO  CWND_DROP  ← signal badges for the selected row       │
│  245 conns | snapshots: 312 | updated: just now                       │
└──────────────────────────────────────────────────────────────────────┘
```

Press `1`–`7` to switch tabs, `Enter` on a row to drill in, `/` to filter,
`?` for the help overlay.

---

## Tabs

### 1. Live

Sortable, filterable table of every open connection — protocol, state,
4-tuple, RTT, queue depths, TX/RX deltas, retransmits, keepalive, process.
The leftmost column is a single-glyph **signal indicator**:

| Glyph | Meaning                                          |
|-------|--------------------------------------------------|
| 🟢    | No warn/crit signals                             |
| 🟡    | 1+ warn-level signals                            |
| 🟠    | ≥4 warn signals                                  |
| 🔴    | 1+ crit-level signals                            |

`j`/`k` move the cursor; `Enter` opens **Detail** for that connection.
Below the table, signal badges show every signal firing on the highlighted
row.

### 2. Detail

Network-level deep dive for one connection: Identity, Performance,
Congestion, Throughput, Retransmit. Two-column layout above 100 cols,
single column otherwise. Signal badges sit at the bottom.

### 3. Socket

Kernel-side view of the same connection: Queues (bytes + segs in/out),
Socket Memory (buffer usage with ratio bars, backlog, **drops**), BBR
state (when applicable), and **History sparklines** — bar graphs of
RTT, CWnd, TX, RX, queues, Unacked, Retrans across the full ring buffer.

### 4. Overview

Aggregate views over the whole buffer:

- **Connections over time** — total socket count history.
- **Avg RTT over time** — mean RTT across all sockets.
- **Throughput over time** — TX and RX bars.
- **State distribution** — current breakdown by TCP state.

### 5. Top

Rankings at the current snapshot:

- **Top Processes** by connection count, with avg RTT, TX/s, RX/s, and
  per-process signal counts.
- **Top Local Ports** with service names.
- **Top Peer Hosts** by connection count and bytes.
- **Top TX / RX** — per-connection bytes leaders.

### 6. Perf

Performance / anomaly view. Sections:

- **Health Summary** — total ESTAB / warn / crit counts, per-signal-type
  counts as colored chips, and a bar-graph history of warn+crit volume.
- **System** — TIME-WAIT growth (count, ~30s delta, sparkline) and
  **ephemeral port exhaustion** (used/total ports in
  `/proc/sys/net/ipv4/ip_local_port_range`).
- **RTT Inflation** — connections where `rtt/minrtt > 1.5`.
- **Slow Connections** — RTT > 50 ms.
- **Retransmit Rate** — current-poll retrans / sent ratio.
- **Cumulative Retransmits** — top 10 by total retrans.
- **Queue Pressure** — non-empty Send-Q / Recv-Q with usage bars vs the
  kernel buffer limits.
- **Zero Window** — sockets with `snd_wnd == 0` in ESTAB.
- **Send Backlog** — unacked / cwnd ratios.
- **Busiest Sockets** — per-poll busy ms and percentage.

### 7. Events

Signal-onset log. Every time a connection acquires a warn/crit signal it
didn't have the prior poll, that's an event. Reverse-chronological,
scrollable with `j`/`k`/`g`/`G`/`PgUp`/`PgDn`. `e` exports the events
list as JSON, `E` as CSV.

Info-level signals (`IDLE`, `APP_LIM`) are filtered out so the log stays
focused on real anomalies.

---

## Keybindings

| Key            | Action                                                     |
|----------------|------------------------------------------------------------|
| `1`–`7`        | Switch tabs (Live, Detail, Socket, Overview, Top, Perf, Events) |
| `Tab` / `S-Tab`| Next / previous tab                                        |
| `j` / `↓`      | Next row (Live) / scroll down (Events)                     |
| `k` / `↑`      | Previous row (Live) / scroll up (Events)                   |
| `g` / `G`      | First / last (or top / bottom on Events)                   |
| `PgUp`/`PgDn`  | Page scroll on Events                                      |
| `Enter`        | Open Detail for the highlighted row                        |
| `Esc`          | Back to Live (clears selection) / close help / clear filter |
| `h`            | Cycle sort column / direction in Live                      |
| `L`            | Toggle hiding LISTEN sockets                               |
| `/`            | Open filter prompt                                         |
| `e`            | Export ring buffer to JSON (events list on Events tab)     |
| `E`            | Export latest snapshot to CSV (events list on Events tab)  |
| `?`            | Toggle help overlay                                        |
| `q` / `Ctrl-C` | Quit                                                       |

---

## Filtering

Press `/`, type one or more space-separated terms, hit `Enter`:

| Term                | Match                                                |
|---------------------|------------------------------------------------------|
| `local=<substr>`    | Substring match on local address                     |
| `peer=<substr>`     | Substring match on peer address                      |
| `lport=<port>`      | Exact local port                                     |
| `pport=<port>`      | Exact peer port                                      |
| `state=<state>`     | Exact TCP state (`ESTAB`, `LISTEN`, `TIME-WAIT`, ...)|
| `proc=<substr>`     | Substring match on process name (case-insensitive)   |
| `signal=<label>`    | Connection has this signal active (e.g. `RETRANS`, `cwnd_collapse`) |
| bare `<state>`      | Shortcut for `state=…` if it matches a known state   |
| any other bare term | Treated as `local=<term>`                            |

Examples:

```
/state=ESTAB peer=10.0    # all established connections to a /16
/proc=nginx signal=RETRANS # retransmitting nginx connections
/pport=443 lport=51234     # one specific socket pair
```

`Esc` clears the filter.

---

## Export

Both modes write to the current working directory with a timestamped name.

| Tab + key        | Output                                                 |
|------------------|--------------------------------------------------------|
| any tab, `e`     | `./ss-stats-<ts>.json` — entire ring buffer, every field on every connection across every snapshot |
| any tab, `E`     | `./ss-stats-<ts>.csv` — current snapshot, flat (one row per connection) |
| Events tab, `e`  | `./ss-events-<ts>.json` — list of signal-onset events  |
| Events tab, `E`  | `./ss-events-<ts>.csv` — same, flat                    |

A green status line at the bottom confirms the path and row/snapshot count.

---

## Common workflows

### "The app is slow — is it the network?"

1. Launch `sstui` (sudo for full process visibility).
2. `/proc=<your-service>` to scope the table.
3. Sort by RTT (`h` to cycle) — anything > 50 ms is yellow, > 200 ms
   orange.
4. Glance at the signal indicator column: 🔴 means a crit signal is
   active. `Enter` on a red row to open **Detail**.
5. On Detail, scan the Signals row at the bottom: `RETRANS` + `LOSS`
   means real packet loss; `RTT_SPIKE` alone means bufferbloat or path
   change; `ZERO_WIN` means the *peer* isn't reading; `RCV_Q` means
   *we* aren't reading.
6. `3` to switch to **Socket** — the History bar graph shows whether
   this is a momentary spike or a sustained problem.

### "Are we leaking ephemeral ports?"

1. `6` for **Perf**.
2. Scroll to the **System** section. The "Ephemeral ports" bar shows
   used/total ports inside the kernel's configured ephemeral range,
   coloured green/yellow/orange/red as utilization climbs through 40 /
   70 / 90 %.
3. If TIME-WAIT count is also climbing fast, that's where your
   ephemeral ports are going. The sparkline next to it shows the
   trajectory; growth in the last ~30 s is shown in parens.
4. `4` for **Top** → "Top Peer Hosts" / "Top Processes" to find the
   source of the churn.

### "Which connections retransmit the most?"

1. Filter to anomalies: `/signal=RETRANS` (or `signal=HI_RETRANS`).
2. Or `6` → Perf, scroll to **Cumulative Retransmits** and **Retransmit
   Rate** for current-poll ranking.
3. Drill into one with Enter → **Detail** → Retransmit section shows
   total retrans, in-flight retrans, bytes retrans, lost, DSACK dups,
   reorder counters.

### "Why is this BBR connection underutilizing?"

1. Open the connection in Detail. Identity shows `Cong Ctrl: bbr` (green).
2. Tab to **Socket**, look at BBR: `BW`, `MRTT`, `Pacing Gain`, `CWnd Gain`.
3. `BBR_LOW` fires when delivery_rate < 0.5 × bw with non-app-limited
   active sends; cross-check with `Pacing Gain` to see if BBR is in a
   probe-down phase.

### "Capture state for a bug report"

1. Get to the right state in the UI.
2. Press `e` — writes `./ss-stats-<ts>.json` with the full ring buffer.
3. Or `E` for a CSV of the current snapshot.
4. Attach to the ticket; analyze offline with `jq` / `pandas` /
   `csvkit`. The exported JSON has every parsed field on every
   connection in every snapshot — it's roundtrip-able to the same
   classifier.

### "What happened on this host in the last hour?"

1. `7` for **Events**.
2. The list shows every signal onset since launch, newest first.
3. `G` to jump to the oldest events, `j`/`k` or `PgUp`/`PgDn` to walk
   through.
4. `e` exports the entire list as JSON with timestamps, 4-tuples,
   process names, signal labels, and values.

---

## Signals reference

There are **20 signal types**, each at one of three severities: `info`
(grey), `warn` (yellow/orange), `crit` (red). Severity is reflected in the
badge color and in the Live-tab indicator glyph.

```
┌────────────┬──────────────────────┬───────────────────────────────────────────────────┬──────────────────────────────────────┬──────────┬────────┐
│   Label    │      Type const      │                    Fires when                     │           Inputs (parsed?)           │ Severity │ Color  │
├────────────┼──────────────────────┼───────────────────────────────────────────────────┼──────────────────────────────────────┼──────────┼────────┤
│ RETRANS    │ retrans_in_flight    │ retrans_now > 3 (crit >10)                        │ retrans:N/M ✓                        │ 1–2      │ red    │
├────────────┼──────────────────────┼───────────────────────────────────────────────────┼──────────────────────────────────────┼──────────┼────────┤
│ APP_LIM    │ app_limited          │ app_limited flag set                              │ app_limited ✓                        │ 0 (info) │ green  │
├────────────┼──────────────────────┼───────────────────────────────────────────────────┼──────────────────────────────────────┼──────────┼────────┤
│ IDLE       │ idle                 │ ESTAB & no bytes moved this poll                  │ computed deltas ✓                    │ 0 (info) │ gray   │
├────────────┼──────────────────────┼───────────────────────────────────────────────────┼──────────────────────────────────────┼──────────┼────────┤
│ ZERO_WIN   │ zero_window          │ snd_wnd == 0 on ESTAB                             │ snd_wnd: ✓                           │ 2        │ red    │
├────────────┼──────────────────────┼───────────────────────────────────────────────────┼──────────────────────────────────────┼──────────┼────────┤
│ LOSS       │ congestion_loss      │ lost > 2 (crit >10)                               │ lost: ✓                              │ 1–2      │ red    │
├────────────┼──────────────────────┼───────────────────────────────────────────────────┼──────────────────────────────────────┼──────────┼────────┤
│ PMTU       │ pmtu_mismatch        │ pmtu < advmss+40                                  │ pmtu: advmss: ✓                      │ 1        │ orange │
├────────────┼──────────────────────┼───────────────────────────────────────────────────┼──────────────────────────────────────┼──────────┼────────┤
│ RTT_SPIKE  │ rtt_spike            │ rtt/minrtt > 5 (crit >15)                         │ rtt: minrtt: ✓                       │ 1–2      │ orange │
├────────────┼──────────────────────┼───────────────────────────────────────────────────┼──────────────────────────────────────┼──────────┼────────┤
│ SEND_Q     │ send_buffer_pressure │ Send-Q > 0 (crit >100)                            │ column ✓                             │ 1–2      │ yellow │
├────────────┼──────────────────────┼───────────────────────────────────────────────────┼──────────────────────────────────────┼──────────┼────────┤
│ RCV_Q      │ recv_buffer_pressure │ Recv-Q > 0 (crit >100)                            │ column ✓                             │ 1–2      │ yellow │
├────────────┼──────────────────────┼───────────────────────────────────────────────────┼──────────────────────────────────────┼──────────┼────────┤
│ HI_RETRANS │ high_retrans_rate    │ retrans/sent > 5% (crit >20%)                     │ deltas of bytes_sent/bytes_retrans ✓ │ 1–2      │ red    │
├────────────┼──────────────────────┼───────────────────────────────────────────────────┼──────────────────────────────────────┼──────────┼────────┤
│ DEL_DROP   │ delivery_drop        │ not app-limited & sending & delivery/pacing < 0.5 │ delivery_rate pacing_rate ✓          │ 1        │ orange │
├────────────┼──────────────────────┼───────────────────────────────────────────────────┼──────────────────────────────────────┼──────────┼────────┤
│ UNACKED    │ unacked_buildup      │ unacked > 0.8·cwnd && > 10                        │ unacked: cwnd: ✓                     │ 1        │ yellow │
├────────────┼──────────────────────┼───────────────────────────────────────────────────┼──────────────────────────────────────┼──────────┼────────┤
│ LISTEN_Q   │ listen_queue_full    │ LISTEN RecvQ/SendQ > 0.8 (crit ≥1.0)              │ RecvQ/SendQ column ✓                 │ 1–2      │ red    │
├────────────┼──────────────────────┼───────────────────────────────────────────────────┼──────────────────────────────────────┼──────────┼────────┤
│ RTO        │ rto_firing           │ ESTAB, timer on, TimerRetrans ≥ 2 (crit ≥4)       │ timer: TimerRetrans ✓                │ 1–2      │ red    │
├────────────┼──────────────────────┼───────────────────────────────────────────────────┼──────────────────────────────────────┼──────────┼────────┤
│ SYN_STALL  │ syn_stall            │ SYN-SENT, TimerRetrans > 0 (crit ≥3)              │ state, TimerRetrans ✓                │ 1–2      │ orange │
├────────────┼──────────────────────┼───────────────────────────────────────────────────┼──────────────────────────────────────┼──────────┼────────┤
│ ONE_WAY    │ one_way_stall        │ ESTAB, sending but no recv >30s (or symmetric)    │ lastsnd: lastrcv: computed deltas ✓  │ 1        │ yellow │
├────────────┼──────────────────────┼───────────────────────────────────────────────────┼──────────────────────────────────────┼──────────┼────────┤
│ CWND_DROP  │ cwnd_collapse        │ CWnd/PrevCWnd < 0.5 (crit <0.25), prev ≥ 20      │ cwnd: + prev poll cwnd ✓             │ 1–2      │ orange │
├────────────┼──────────────────────┼───────────────────────────────────────────────────┼──────────────────────────────────────┼──────────┼────────┤
│ DSACK      │ dsack_spurious       │ Δdsack_dups > 0 (crit >5)                         │ dsack_dups: delta ✓                  │ 1–2      │ yellow │
├────────────┼──────────────────────┼───────────────────────────────────────────────────┼──────────────────────────────────────┼──────────┼────────┤
│ BBR_LOW    │ bbr_underutil        │ BBR active, not app-limited, sending, delivery < 0.5×BBR_BW │ bbr:BW delivery_rate ✓   │ 1        │ orange │
├────────────┼──────────────────────┼───────────────────────────────────────────────────┼──────────────────────────────────────┼──────────┼────────┤
│ REORDER    │ reordering           │ Δrcv_ooopack > 0 (crit >50)                       │ rcv_ooopack: delta ✓                 │ 1–2      │ orange │
└────────────┴──────────────────────┴───────────────────────────────────────────────────┴──────────────────────────────────────┴──────────┴────────┘
```

### Connection-state signals

| Signal       | Fires when                                                                  | Severity   | What it means                                                          |
|--------------|------------------------------------------------------------------------------|------------|------------------------------------------------------------------------|
| `IDLE`       | ESTAB, both delta byte counters present, both equal to 0                     | info       | Connection is alive but no bytes moved this poll                       |
| `APP_LIM`    | `app_limited` flag set                                                       | info       | TCP could send more; the app isn't producing data fast enough          |
| `LISTEN_Q`   | LISTEN socket with `RecvQ/SendQ > 0.8` (or RecvQ > 100 when SendQ unknown)   | warn / crit (≥1.0) | Accept queue full — incoming SYNs are being dropped              |
| `SYN_STALL`  | `SYN-SENT` state with retransmit timer active (`TimerRetrans > 0`)           | warn / crit (≥3) | Handshake stuck — DNS, firewall, or routing problem              |
| `ONE_WAY`    | ESTAB sending bytes but no recv for >30 s (or symmetric)                     | warn       | Half-closed peer or stuck application read/write                       |

### Loss & retransmission signals

| Signal        | Fires when                                                            | Severity                | What it means                                              |
|---------------|-----------------------------------------------------------------------|-------------------------|------------------------------------------------------------|
| `RETRANS`     | `retrans:N/M` first field > 3                                          | warn / crit (>10)       | Segments currently being retransmitted in flight           |
| `RTO`         | ESTAB, `timer:(on,…)` running, `TimerRetrans ≥ 2`                      | warn / crit (≥4)        | RTO timer doubling — single segment stuck retransmitting   |
| `LOSS`        | `lost:N > 2`                                                           | warn / crit (>10)       | Kernel-detected packet loss                                |
| `HI_RETRANS`  | `Δbytes_retrans / Δbytes_sent > 5%`                                    | warn / crit (>20%)      | Current-poll retransmit rate is bad                        |
| `DSACK`       | `dsack_dups` grew this poll                                            | warn / crit (>5)        | Spurious retransmits — RTO too aggressive                  |
| `REORDER`     | `rcv_ooopack` grew this poll                                           | warn / crit (>50)       | Path is reordering packets (often LACP / multipath / queue issue)|

### Congestion & flow control

| Signal        | Fires when                                                       | Severity         | What it means                                                       |
|---------------|------------------------------------------------------------------|------------------|---------------------------------------------------------------------|
| `ZERO_WIN`    | ESTAB, `snd_wnd == 0`                                            | crit             | Peer's receive window is closed — peer not reading                  |
| `CWND_DROP`   | `CWnd / PrevCWnd < 0.5` (with prev ≥ 20)                         | warn / crit (<0.25) | Congestion window collapsed between polls — loss event             |
| `UNACKED`     | `unacked > 0.8 × cwnd` and `unacked > 10`                        | warn             | Most of cwnd is in flight, waiting for ACKs                         |
| `DEL_DROP`    | not app-limited, sending, `delivery_rate / pacing_rate < 0.5`    | warn             | Kernel can't reach its own pacing target                            |
| `BBR_LOW`     | BBR active, sending, not app-limited, `delivery_rate < 0.5 × BBR_BW` | warn         | BBR underutilizing its bandwidth estimate                           |
| `PMTU`        | `pmtu < advmss + 40`                                             | warn             | Path MTU smaller than our advertised MSS                            |
| `RTT_SPIKE`   | `rtt / minrtt > 5`                                               | warn / crit (>15) | Latency spike vs the connection's baseline                         |

### Buffer pressure

| Signal      | Fires when                                          | Severity         | What it means                            |
|-------------|------------------------------------------------------|------------------|------------------------------------------|
| `SEND_Q`    | non-LISTEN, `Send-Q > 0`                             | warn / crit (>100) | Bytes queued for transmission           |
| `RCV_Q`    | non-LISTEN, `Recv-Q > 0`                             | warn / crit (>100) | Bytes queued for the app to read        |

---

## Metrics reference

Everything `ss -atnpeimOH` produces, organized by what it tells you. `Δ` is
the per-poll delta (computed in the poller), `cum.` means cumulative since
socket creation.

### Identity

| Field           | ss source            | Notes                                                        |
|-----------------|----------------------|--------------------------------------------------------------|
| Protocol        | `tcp` / `udp`        | TCP and UDP polled separately, merged                        |
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
| AppLimited        | `app_limited`        | TCP was waiting on the application this RTT            |
| Busy              | `busy:Xms`           | cum. ms doing TCP work; UI shows `ΔBusy / poll` ratio  |

### Segments

| Field                       | ss source           | Notes                                          |
|-----------------------------|---------------------|------------------------------------------------|
| Segs Out / In               | `segs_out:` / `segs_in:` | cum. total segments                       |
| Data Segs Out / In          | `data_segs_out:` / `data_segs_in:` | cum. data-carrying segments     |
| Δ Segs Out / In             | (computed)          | Per-poll segments                              |

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
| Rcv OOO        | `rcv_ooopack:`      | cum. out-of-order packets received                                 |
| Δ Rcv OOO      | (computed)          | Drives the `REORDER` signal                                        |

### Last-activity timestamps

| Field   | ss source     | Notes                                              |
|---------|---------------|----------------------------------------------------|
| LastSnd | `lastsnd:`    | ms since last send                                 |
| LastRcv | `lastrcv:`    | ms since last receive                              |
| LastAck | `lastack:`    | ms since last ACK                                  |

Used by the `ONE_WAY` signal.

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
| snd buf    | bytes used vs send buffer limit (`t` / `tb`)                       |
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
ss -atnpeimOH ─►│ parser  │──► []*model.Connection
ss -aunpeimOH ─►│         │
                └─────────┘
                     │
                     ▼
                ┌─────────┐       ┌─────────────┐
                │ poller  │──┐    │ classifier  │
                │ (ring   │  └───►│ (20 rules)  │
                │  buffer)│       └─────────────┘
                └────┬────┘             │
                     │                  ▼
                     │            c.Signals
                     ▼
               1500 Snapshots, byKey index, stateCounts
                     │
                     ▼
                ┌─────────┐
                │   ui    │── bubbletea TUI, 7 tabs
                └─────────┘
```

- **`parser/`** — runs `ss` as a subprocess, regex-parses each line plus
  any whitespace-prefixed continuation lines, returns
  `[]*model.Connection`. ~50 regexes; one pass per line.
- **`poller/`** — `Buffer` is a ring of 1500 snapshots. `AddSnapshot` is
  three-phase: (1) read-lock to copy `prevMap` pointers, (2) compute
  deltas + classify **outside the lock**, (3) write-lock briefly to
  publish. Each snapshot carries `byKey` for O(1) lookup and
  `stateCounts` for O(1) state-distribution queries.
- **`classifier/`** — 20 pure rules, run once per connection per poll.
  Severity is encoded as `0` (info) / `1` (warn) / `2` (crit). New
  signals are roughly one struct field, one regex, and a 10-line rule
  here.
- **`ui/`** — pure bubbletea + lipgloss. One file per tab. Reads only
  from `poller.Buffer`; never mutates state.

### Polling cadence

Hardcoded at `PollInterval = 2 * time.Second`, ring at `BufferSize =
1500`. That gives 50 minutes of history. Changing the constant in
`poller/poller.go` adjusts both retention and the busy-ratio
denominator automatically.

### Coloring conventions

- TX direction → green, RX → magenta.
- Latency tiers: `≤50ms` green, `≤200ms` yellow, `>200ms` orange.
- Queue pressure (non-zero) → yellow.
- Retransmits / drops / zero-window → red.
- Dim grey = informational / context (no problem).

---

## Performance footprint

On a host with ~500 sockets:

- `ss -atnpeimOH` takes ~5–15 ms wall clock; UDP one is similar.
- Parsing + delta computation + classification: a few ms per snapshot.
- Memory: ~1500 snapshots × ~500 conns × ~800 B per Connection struct
  ≈ **500 MB worst-case** if every socket persists for the full 50
  minutes and every field is populated. Real hosts churn through
  short-lived TIME-WAITs, so steady-state RSS is typically 50–200 MB.
- CPU at idle (no input, only ticks): single-digit % on one core.

If memory is a concern, drop `BufferSize` in `poller/poller.go`. Each
snapshot is independent, so shrinking the ring is safe.

---

## Troubleshooting / FAQ

**Q. Process names are missing for half my connections.**
Run as root (or `sudo sstui`), or grant `ss` `cap_net_admin` (see
[Permissions](#permissions-what-you-see-and-as-whom)).

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
IDLE is suppressed until we have a prior poll to compare against. If
you're seeing it after the first poll, the connection genuinely moved
zero bytes that 2 s window.

**Q. The same key sometimes does different things.**
Some keys are tab-aware:
- `j`/`k`/`g`/`G` navigate the table on Live, scroll the list on
  Events.
- `e`/`E` export the ring buffer on most tabs; on Events they export
  the events list itself.
- `Enter` only acts on Live (opens Detail).

**Q. Can I run it remotely?**
Yes — over SSH like any TUI. Make sure your terminal forwards true
colors (`TERM=xterm-256color` or better; modern SSH clients usually do
this fine).

**Q. Can I record a session and replay it?**
Press `e` to dump the entire ring buffer as JSON. There's no replay UI
yet, but the JSON has every field — feeding it back into a future
replay mode is straightforward (the classifier is deterministic).

**Q. How do I add a new signal?**
1. Add the constant + label to `model/signal.go`.
2. Add a color to `signalColors` in `ui/header.go`.
3. Add a classifier rule in `classifier/classifier.go`.
4. (Optional) Add a regex / field to `parser/parser.go` and
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
- **No scroll on tabs other than Events.** Long Detail/Socket content
  shows a `↓ N more line(s)` indicator but you can't scroll past it
  yet — make the terminal taller or switch to the paired tab.
- **No persistence across restarts.** The ring buffer is in-memory.
  Use `e` to snapshot before quitting if you want to keep history.
- **Process names rely on `users:(...)` from `ss`.** Containerised
  workloads may show the runtime (e.g. `containerd-shim`) instead of
  the inner process unless you can see PID namespaces.
- **The signal classifier is heuristic.** Thresholds are tuned for
  general-purpose hosts; loud workloads (CDNs, proxies, databases)
  may need tweaks. All thresholds live in
  `classifier/classifier.go` and are one-line edits.

---

## Development

Layout:

```
classifier/   one-rule-per-block signal classifier
model/        Connection + Signal data types
parser/       ss(8) regex parser and subprocess driver
poller/       ring buffer, delta computation, export (JSON/CSV)
ui/           bubbletea views, one file per tab
main.go       AppModel: keybinds, scroll state, render dispatch
```

Build & run:

```bash
go build .
./sstui
```

Vet / test (no tests yet — contributions welcome):

```bash
go vet ./...
go build ./...
```

Coding conventions:

- One rule per signal, kept in `classifier/classifier.go`. Add the
  type + label in `model/signal.go`, the color in `ui/header.go`.
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
- Tests for the parser regexes (golden-file based against captured ss
  output).
- A replay mode that takes the exported JSON and feeds it through the
  classifier.

---

## License

MIT.
