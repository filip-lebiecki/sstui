package ui

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

// resolver does best-effort reverse DNS for display. Lookups are asynchronous
// and cached: display() never blocks — it returns the raw address immediately
// and kicks off a background PTR query whose result shows up on a later frame
// (the next poll re-renders within the poll interval). Disabled by default so
// sstui sends no DNS traffic unless the user opts in with `r`.
type resolver struct {
	mu       sync.Mutex
	enabled  bool
	cache    map[string]string // ip -> hostname, or ip itself when there's no PTR
	inflight map[string]bool
}

// maxDNSCache bounds the reverse-DNS cache so a long session on a host with high
// connection churn (many distinct peers) can't grow it without limit. On
// overflow the cache is cleared wholesale — crude but O(1) and self-healing:
// still-relevant names simply get re-resolved on the next render.
const maxDNSCache = 8192

var dnsResolver = &resolver{
	cache:    make(map[string]string),
	inflight: make(map[string]bool),
}

// lookupAddr is indirected so tests can stub the network call.
var lookupAddr = func(ctx context.Context, ip string) ([]string, error) {
	return net.DefaultResolver.LookupAddr(ctx, ip)
}

// ToggleResolveDNS flips reverse-DNS display and returns the new state.
func ToggleResolveDNS() bool { return dnsResolver.toggle() }

// SetResolveDNS sets reverse-DNS display on or off (used by the --resolve flag).
func SetResolveDNS(on bool) {
	dnsResolver.mu.Lock()
	dnsResolver.enabled = on
	dnsResolver.mu.Unlock()
}

// ResolveDNSEnabled reports whether reverse-DNS display is currently on.
func ResolveDNSEnabled() bool {
	dnsResolver.mu.Lock()
	defer dnsResolver.mu.Unlock()
	return dnsResolver.enabled
}

func (r *resolver) toggle() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enabled = !r.enabled
	return r.enabled
}

// display returns the name to show for addr: the cached hostname when resolution
// has succeeded, otherwise the address itself. Unspecified/wildcard addresses
// and non-IP strings are returned as-is and never queried.
func (r *resolver) display(addr string) string {
	switch addr {
	case "", "*", "0.0.0.0", "::":
		return addr
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.enabled {
		return addr
	}
	if name, ok := r.cache[addr]; ok {
		return name
	}
	if net.ParseIP(addr) == nil {
		// Already a hostname (or unparseable) — don't try to resolve it.
		r.cache[addr] = addr
		return addr
	}
	if !r.inflight[addr] {
		r.inflight[addr] = true
		go r.resolve(addr)
	}
	return addr
}

func (r *resolver) resolve(ip string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	name := ip // negative cache: fall back to the IP when there's no PTR
	if names, err := lookupAddr(ctx, ip); err == nil && len(names) > 0 {
		name = strings.TrimSuffix(names[0], ".")
	}

	r.mu.Lock()
	if len(r.cache) >= maxDNSCache {
		r.cache = make(map[string]string)
	}
	r.cache[ip] = name
	delete(r.inflight, ip)
	r.mu.Unlock()
}

// displayAddr is the package-level entry point used by the table and detail
// views to render an address with optional reverse-DNS substitution.
func displayAddr(addr string) string { return dnsResolver.display(addr) }
