package ui

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestResolverDisplay drives the async resolver with a stubbed lookup and
// verifies: disabled is a passthrough, wildcards are never resolved, a hit
// substitutes the hostname, and failures fall back to the raw IP.
func TestResolverDisplay(t *testing.T) {
	r := &resolver{cache: map[string]string{}, inflight: map[string]bool{}}

	var mu sync.Mutex
	done := make(chan struct{}, 1)
	stub := func(ip string) ([]string, error) {
		mu.Lock()
		defer mu.Unlock()
		if ip == "1.2.3.4" {
			return []string{"host.example.com."}, nil
		}
		return nil, context.DeadlineExceeded
	}

	origLookup := lookupAddr
	lookupAddr = func(_ context.Context, ip string) ([]string, error) {
		res, err := stub(ip)
		select {
		case done <- struct{}{}:
		default:
		}
		return res, err
	}
	defer func() { lookupAddr = origLookup }()

	// Disabled: passthrough, no lookups.
	if got := r.display("1.2.3.4"); got != "1.2.3.4" {
		t.Errorf("disabled resolver should pass through, got %q", got)
	}

	r.enabled = true

	// Wildcards/unspecified are never resolved.
	for _, w := range []string{"*", "0.0.0.0", "::", ""} {
		if got := r.display(w); got != w {
			t.Errorf("wildcard %q should pass through, got %q", w, got)
		}
	}

	// First call returns the IP and kicks off the async lookup.
	if got := r.display("1.2.3.4"); got != "1.2.3.4" {
		t.Errorf("first call should return the IP while resolving, got %q", got)
	}
	waitResolved(t, r, "1.2.3.4")
	if got := r.display("1.2.3.4"); got != "host.example.com" {
		t.Errorf("resolved display = %q, want host.example.com", got)
	}

	// A failing lookup negative-caches the IP itself.
	r.display("9.9.9.9")
	waitResolved(t, r, "9.9.9.9")
	if got := r.display("9.9.9.9"); got != "9.9.9.9" {
		t.Errorf("failed lookup should fall back to the IP, got %q", got)
	}
}

func waitResolved(t *testing.T, r *resolver, ip string) {
	t.Helper()
	for i := 0; i < 200; i++ {
		r.mu.Lock()
		_, ok := r.cache[ip]
		r.mu.Unlock()
		if ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s to resolve", ip)
}
