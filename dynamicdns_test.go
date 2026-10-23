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

	"github.com/caddyserver/caddy/v2"
	"github.com/google/go-cmp/cmp"
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

// mockDNSProvider implements libdns.RecordSetter and libdns.RecordGetter for testing.
type mockDNSProvider struct {
	records map[string][]libdns.Record
}

func (m *mockDNSProvider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return recs, nil
}

func (m *mockDNSProvider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	return m.records[zone], nil
}

// TestLookupCurrentIPsFromDNS_OnlyIPv6Enabled verifies that with only IPv6
// enabled, A records are not looked up from DNS. This is a regression test
// for issue #89: caddy-dynamicdns logged "domain not found in DNS" for A
// records even though only `versions ipv6` was configured, because it always
// looked up both record types regardless of the enabled versions.
func TestLookupCurrentIPsFromDNS_OnlyIPv6Enabled(t *testing.T) {
	falseBool := false
	trueBool := true
	provider := &mockDNSProvider{
		records: map[string][]libdns.Record{
			"example.com.": {
				libdns.Address{Name: "sub", IP: netip.MustParseAddr("2001:db8::1")},
			},
		},
	}
	app := App{
		Versions:    IPVersions{IPv4: &falseBool, IPv6: &trueBool},
		ctx:      caddy.Context{},
		logger:   zap.NewNop(),
	}

	ips, err := app.lookupCurrentIPsFromDNS(&Provider{dnsProvider: provider}, map[string][]string{
		"example.com.": {"sub"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	absName := libdns.AbsoluteName("sub", "example.com.")

	aaaa, ok := ips[absName]["AAAA"]
	if !ok {
		t.Fatal("expected AAAA record to be looked up with IPv6 enabled")
	}
	if len(aaaa) != 1 || aaaa[0] != netip.MustParseAddr("2001:db8::1") {
		t.Errorf("expected AAAA record 2001:db8::1, got %v", aaaa)
	}

	if _, ok := ips[absName]["A"]; ok {
		t.Error("expected no A record lookup when only IPv6 is enabled (issue #89)")
	}
}

// TestLookupCurrentIPsFromDNS_OnlyIPv4Enabled verifies the inverse of issue
// #89: with only IPv4 enabled, AAAA records are not looked up from DNS.
func TestLookupCurrentIPsFromDNS_OnlyIPv4Enabled(t *testing.T) {
	falseBool := false
	trueBool := true
	provider := &mockDNSProvider{
		records: map[string][]libdns.Record{
			"example.com.": {
				libdns.Address{Name: "sub", IP: netip.MustParseAddr("192.0.2.1")},
			},
		},
	}
	app := App{
		Versions:    IPVersions{IPv4: &trueBool, IPv6: &falseBool},
		ctx:      caddy.Context{},
		logger:   zap.NewNop(),
	}

	ips, err := app.lookupCurrentIPsFromDNS(&Provider{dnsProvider: provider}, map[string][]string{
		"example.com.": {"sub"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	absName := libdns.AbsoluteName("sub", "example.com.")

	a, ok := ips[absName]["A"]
	if !ok {
		t.Fatal("expected A record to be looked up with IPv4 enabled")
	}
	if len(a) != 1 || a[0] != netip.MustParseAddr("192.0.2.1") {
		t.Errorf("expected A record 192.0.2.1, got %v", a)
	}

	if _, ok := ips[absName]["AAAA"]; ok {
		t.Error("expected no AAAA record lookup when only IPv4 is enabled")
	}
}

// TestLookupCurrentIPs_Default verifies that by default (both IPv4
// and IPv6 nil), both A and AAAA records are looked up.
func TestLookupCurrentIPs_Default(t *testing.T) {
	provider := &mockDNSProvider{
		records: map[string][]libdns.Record{
			"example.com.": {
				libdns.Address{Name: "sub", IP: netip.MustParseAddr("192.0.2.1")},
				libdns.Address{Name: "sub", IP: netip.MustParseAddr("2001:db8::1")},
			},
		},
	}
	app := App{
		Versions: IPVersions{},
		ctx:      caddy.Context{},
		logger:   zap.NewNop(),
	}

	ips, err := app.lookupCurrentIPsFromDNS(&Provider{dnsProvider: provider}, map[string][]string{
		"example.com.": {"sub"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	absName := libdns.AbsoluteName("sub", "example.com.")

	a, ok := ips[absName]["A"]
	if !ok {
		t.Fatal("expected A record lookup with default versions")
	}
	if len(a) != 1 || a[0] != netip.MustParseAddr("192.0.2.1") {
		t.Errorf("expected A record 192.0.2.1, got %v", a)
	}

	aaaa, ok := ips[absName]["AAAA"]
	if !ok {
		t.Fatal("expected AAAA record lookup with default versions")
	}
	if len(aaaa) != 1 || aaaa[0] != netip.MustParseAddr("2001:db8::1") {
		t.Errorf("expected AAAA record 2001:db8::1, got %v", aaaa)
	}
}
