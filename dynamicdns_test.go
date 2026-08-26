// Copyright 2020 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dynamicdns

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/libdns/libdns"
	"go.uber.org/zap"
)

func Test_NormalizeProviders(t *testing.T) {
	provider1 := json.RawMessage(`{"name":"test_dummy","arg":"one"}`)
	provider2 := json.RawMessage(`{"name":"test_dummy","arg":"two"}`)
	domains1 := map[string][]string{"example.com": {"@"}}
	domains2 := map[string][]string{"example.org": {"@", "www"}}

	tests := []struct {
		name    string
		app     App
		want    []Provider
		wantErr bool
	}{
		{
			name: "legacy: top-level provider and domains",
			app: App{
				DNSProviderRaw: provider1,
				Domains:        domains1,
			},
			want: []Provider{
				{DNSProviderRaw: provider1, Domains: domains1},
			},
		},
		{
			name: "legacy top-level provider combined with providers list",
			app: App{
				DNSProviderRaw: provider1,
				Domains:        domains1,
				Providers: []Provider{
					{DNSProviderRaw: provider2, Domains: domains2},
				},
			},
			want: []Provider{
				{DNSProviderRaw: provider1, Domains: domains1},
				{DNSProviderRaw: provider2, Domains: domains2},
			},
		},
		{
			name: "top-level domains fold into a sole provider without domains",
			app: App{
				Domains: domains1,
				Providers: []Provider{
					{DNSProviderRaw: provider1},
				},
			},
			want: []Provider{
				{DNSProviderRaw: provider1, Domains: domains1},
			},
		},
		{
			name: "providers list only",
			app: App{
				Providers: []Provider{
					{DNSProviderRaw: provider1, Domains: domains1},
					{DNSProviderRaw: provider2, Domains: domains2},
				},
			},
			want: []Provider{
				{DNSProviderRaw: provider1, Domains: domains1},
				{DNSProviderRaw: provider2, Domains: domains2},
			},
		},
		{
			name: "top-level domains conflict with per-provider domains",
			app: App{
				Domains: domains1,
				Providers: []Provider{
					{DNSProviderRaw: provider1, Domains: domains2},
				},
			},
			wantErr: true,
		},
		{
			name: "top-level domains with multiple providers",
			app: App{
				Domains: domains1,
				Providers: []Provider{
					{DNSProviderRaw: provider1},
					{DNSProviderRaw: provider2},
				},
			},
			wantErr: true,
		},
		{
			name:    "no provider",
			app:     App{Domains: domains1},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.app.normalizeProviders()
			if err != nil {
				if !tt.wantErr {
					t.Errorf("normalizeProviders() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("normalizeProviders() expected error, got none")
			}
			if diff := cmp.Diff(tt.app.Providers, tt.want, cmp.AllowUnexported(Provider{})); diff != "" {
				t.Errorf("normalizeProviders() diff(-got +want):\n%s", diff)
			}
		})
	}
}

// recordSetterGetter is a minimal DNS provider that replaces a record set
// wholesale, the way real providers (e.g. Route 53) do.
type recordSetterGetter struct {
	records  []libdns.Record
	setCalls [][]libdns.Record
}

func (m *recordSetterGetter) GetRecords(_ context.Context, _ string) ([]libdns.Record, error) {
	return m.records, nil
}

func (m *recordSetterGetter) SetRecords(_ context.Context, _ string, recs []libdns.Record) ([]libdns.Record, error) {
	m.setCalls = append(m.setCalls, recs)
	m.records = recs

	return recs, nil
}

// Two same-type IPs must be published as one record set and then left alone:
// publishing only the IP that differs makes the set flip-flop every check.
func Test_MultipleIPsOfSameTypeArePublishedTogether(t *testing.T) {
	lastIPs = nil
	seededNames = make(map[string]bool)

	ipA := netip.MustParseAddr("203.0.113.10")
	ipB := netip.MustParseAddr("198.51.100.20")

	// DNS already holds one of the two addresses
	prov := &recordSetterGetter{records: []libdns.Record{libdns.Address{Name: "www", IP: ipA}}}
	app := App{
		Providers: []Provider{{
			Domains:     map[string][]string{"example.com": {"www"}},
			dnsProvider: prov,
		}},
		ipSources: []IPSource{Static{IPs: []netip.Addr{ipA, ipB}}},
		logger:    zap.NewNop(),
	}

	if err := app.checkIPAndUpdateDNS(); err != nil {
		t.Fatalf("first check: %v", err)
	}
	if len(prov.setCalls) != 1 {
		t.Fatalf("first check: got %d SetRecords calls, want 1", len(prov.setCalls))
	}
	got := recordIPs(t, prov.setCalls[0], "www")
	if diff := cmp.Diff(got, []string{ipB.String(), ipA.String()}, cmpopts.SortSlices(func(a, b string) bool { return a < b })); diff != "" {
		t.Errorf("first check record set diff(-got +want):\n%s", diff)
	}

	if err := app.checkIPAndUpdateDNS(); err != nil {
		t.Fatalf("second check: %v", err)
	}
	if len(prov.setCalls) != 1 {
		t.Errorf("second check: got %d SetRecords calls, want no further update", len(prov.setCalls))
	}
}

// recordIPs returns the IPs of recs, asserting they are all A records for name.
func recordIPs(t *testing.T, recs []libdns.Record, name string) []string {
	t.Helper()
	ips := make([]string, 0, len(recs))
	for _, r := range recs {
		addr, ok := r.(libdns.Address)
		if !ok {
			t.Fatalf("got %T, want libdns.Address", r)
		}
		if addr.Name != name {
			t.Errorf("got record name %q, want %q", addr.Name, name)
		}
		if recordType(addr.IP) != recordTypeA {
			t.Errorf("got record type %s for %s, want A", recordType(addr.IP), addr.IP)
		}
		ips = append(ips, addr.IP.String())
	}

	return ips
}
