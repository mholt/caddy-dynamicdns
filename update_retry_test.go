package dynamicdns

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/libdns/libdns"
	"go.uber.org/zap"
)

// flakySetter is a libdns.RecordSetter whose SetRecords fails while fail is set.
type flakySetter struct {
	fail  bool
	calls int
}

func (f *flakySetter) SetRecords(_ context.Context, _ string, recs []libdns.Record) ([]libdns.Record, error) {
	f.calls++
	if f.fail {
		return nil, errors.New("provider unavailable")
	}
	return recs, nil
}

// TestUpdateProviderDNSRetriesFailedUpdate verifies that a record whose update
// failed is not remembered as current, so the next check sends it again; once
// an update succeeds, an unchanged IP is not sent again.
func TestUpdateProviderDNSRetriesFailedUpdate(t *testing.T) {
	lastIPsMu.Lock()
	defer lastIPsMu.Unlock()
	lastIPs = nil
	seededNames = make(map[string]bool)
	t.Cleanup(func() {
		lastIPs = nil
		seededNames = make(map[string]bool)
	})

	setter := &flakySetter{fail: true}
	app := App{ctx: caddy.Context{}, logger: zap.NewNop()}
	p := &Provider{
		Domains:     map[string][]string{"example.com.": {"sub"}},
		dnsProvider: setter,
	}
	ip := []netip.Addr{netip.MustParseAddr("192.0.2.1")}

	if n := app.updateProviderDNS(p, ip); n != 1 { // fails
		t.Fatalf("a failed update should be reported: %d failed zone(s), want 1", n)
	}
	app.updateProviderDNS(p, ip) // must retry
	if setter.calls != 2 {
		t.Fatalf("after a failed update the next check should retry: %d SetRecords calls, want 2", setter.calls)
	}

	setter.fail = false
	if n := app.updateProviderDNS(p, ip); n != 0 { // succeeds
		t.Fatalf("a successful update should not be reported as failed: %d", n)
	}
	app.updateProviderDNS(p, ip) // IP unchanged: nothing to send
	if setter.calls != 3 {
		t.Fatalf("after a successful update an unchanged IP should not be sent again: %d SetRecords calls, want 3", setter.calls)
	}
}

// fixedSource is an IPSource that always returns one address.
type fixedSource struct{ ip netip.Addr }

func (fixedSource) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "dynamic_dns.ip_sources.fixed", New: func() caddy.Module { return new(fixedSource) }}
}

func (f fixedSource) GetIPs(context.Context, IPSettings) ([]netip.Addr, error) {
	return []netip.Addr{f.ip}, nil
}

// TestCheckIPAndUpdateDNSReportsFailedUpdate verifies that a failed DNS update
// makes the check return an error, so the initial check is retried with
// backoff instead of waiting for the next interval.
func TestCheckIPAndUpdateDNSReportsFailedUpdate(t *testing.T) {
	lastIPsMu.Lock()
	lastIPs = nil
	seededNames = make(map[string]bool)
	lastIPsMu.Unlock()
	t.Cleanup(func() {
		lastIPs = nil
		seededNames = make(map[string]bool)
	})

	setter := &flakySetter{fail: true}
	app := App{
		ctx:       caddy.Context{},
		logger:    zap.NewNop(),
		ipSources: []IPSource{fixedSource{netip.MustParseAddr("192.0.2.1")}},
		Providers: []Provider{{
			Domains:     map[string][]string{"example.com.": {"sub"}},
			dnsProvider: setter,
		}},
	}
	if err := app.checkIPAndUpdateDNS(); err == nil {
		t.Fatal("a failed DNS update should make the check return an error")
	}
	setter.fail = false
	if err := app.checkIPAndUpdateDNS(); err != nil {
		t.Fatalf("after a successful retry the check should succeed: %v", err)
	}
}
