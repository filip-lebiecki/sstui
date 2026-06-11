# sstui — Code Review Issues

## Bugs

### 1. Filter mode doesn't preserve previous tab (`main.go:168-172`)

Pressing `/` from any tab (e.g., Events, Perf) switches to `ViewFilter`. Pressing Esc in `handleFilterInput` always returns to `ViewLive`, losing the user's prior tab. Should stash `m.tab` on entry and restore it on cancel.

### 2. Esc while `m.tab == ViewFilter` and `m.filterMode == false` is a dead end (`main.go:180-189`)

If the filter mode flag is somehow false but the tab is still `ViewFilter`, the top-level `esc` handler hits the `m.filter.IsActive()` branch, resets the filter, but never switches `m.tab` back. The user gets stuck on the filter view with a blank query.

### 3. `compact` produces sparse `Conns` slices (`poller/poller.go:88-91`)

When `c == nil`, the loop `continue`s but `conns[i]` remains `nil`. Downstream code iterating `snap.Conns` (e.g., `RenderOverview`, `RenderTop`) may panic on nil dereference. Either pre-filter nils or shrink the slice.

### 4. Integration test skips on zero sockets (`parser/parser_test.go:65-66`)

`TestRunSSIntegration` skips when `len(conns) == 0`, so it passes in restricted environments (containers, CI) without actually validating the parser. Should either require root or use a fixture.

---

## Performance

### 5. `renderSparklines` is uncached O(n×m) per render (`ui/detail.go:417-485`)

Unlike events (which has `collectEventsCached`), sparklines walk all snapshots × all connections on every frame. With 1500 snapshots and many connections, j/k navigation on the Socket tab can stutter. Should cache on `buf.LastUpdate()`.

---

## Correctness / Robustness

### 6. `shortenAddrPort` uses `utf8.RuneCountInString` for display width (`ui/table.go:700-725`)

This counts runes, not display cells. Wide characters (CJK, emoji) are 1 rune but 2+ cells, causing misalignment. Should use `ansi.StringWidth` (already imported).

### 7. `truncate` is not ANSI-aware (`ui/table.go:775-784`)

If it ever receives styled text, it can split escape sequences. Currently only reached from `shortenAddrPort` with plain text, but it shares the `truncate` name with `ansi.Truncate` used elsewhere, inviting misuse. Consider removing or renaming.

### 8. Race on global cache state in tests (`ui/events_test.go:14`)

`evCacheValid = false` mutates package-level state without locking. If tests ever run with `-parallel`, this races with `collectEventsCached`. Should use a per-test buffer or lock the mutex.

---

## Minor

### 9. Redundant `min` function (`ui/detail.go:487-491`)

Go 1.21+ (your `go.mod` specifies 1.26.3) has `min` as a built-in. The local definition shadows it unnecessarily.

### 10. `compact` drops `UID` and `Cgroup` (`poller/poller.go:60-98`)

Slimmed historical connections lose these fields. If a future feature reads them from historical data, they'll silently be nil. Document the omission or include them.

### 11. Parse errors are silently dropped (`parser/parser.go:388-392`)

`runSS` discards connections that fail `ParseLine` with no logging. A malformed `ss` output line is silently invisible. A debug log or counter would help troubleshooting.

### 12. `renderSendBacklog` includes non-TCP connections (`perf.go:633-678`)

The section title says "Unacked / CWnd" but UDP connections can have `Unacked > 0` (from the raw `ss` field). `CWnd` will be nil for them, showing `X/0` with no bar. Filter to TCP only.
