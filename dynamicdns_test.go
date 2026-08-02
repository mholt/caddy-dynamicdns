// Copyright 2026 Nils Stein
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
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	"github.com/libdns/libdns"
	"go.uber.org/zap"
)

// Mock Storage

// mockStorage implements certmagic.Storage for testing
type mockStorage struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMockStorage() *mockStorage {
	return &mockStorage{
		data: make(map[string][]byte),
	}
}

func (m *mockStorage) Lock(ctx context.Context, key string) error {
	return nil
}

func (m *mockStorage) Unlock(ctx context.Context, key string) error {
	return nil
}

func (m *mockStorage) Store(ctx context.Context, key string, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = value
	return nil
}

func (m *mockStorage) Load(ctx context.Context, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if data, ok := m.data[key]; ok {
		return data, nil
	}
	return nil, &mockNotExistError{key: key}
}

func (m *mockStorage) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

func (m *mockStorage) Exists(ctx context.Context, key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.data[key]
	return ok
}

func (m *mockStorage) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	return nil, nil
}

func (m *mockStorage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	return certmagic.KeyInfo{}, nil
}

type mockNotExistError struct {
	key string
}

func (e *mockNotExistError) Error() string {
	return "key not found: " + e.key
}

// Mock DNS Provider

// mockDNSProvider implements libdns.RecordSetter, libdns.RecordGetter
// and libdns.RecordDeleter for testing
type mockDNSProvider struct {
	deletedRecords []deletedRecord
	deleteError    error
	records        map[string][]libdns.Record
}

type deletedRecord struct {
	zone    string
	records []libdns.Record
}

func (m *mockDNSProvider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return recs, nil
}

func (m *mockDNSProvider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	return m.records[zone], nil
}

func (m *mockDNSProvider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	if m.deleteError != nil {
		return nil, m.deleteError
	}
	m.deletedRecords = append(m.deletedRecords, deletedRecord{zone: zone, records: recs})
	return recs, nil
}

// mockDNSProviderNoDelete implements only libdns.RecordSetter (no delete support)
type mockDNSProviderNoDelete struct{}

func (m *mockDNSProviderNoDelete) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return recs, nil
}

// Storage Tests

func TestSaveManagedDomainsState(t *testing.T) {
	storage := newMockStorage()
	logger := zap.NewNop()
	ctx := context.Background()

	domains := make(domainTypeIPs)
	domains["example.com."] = map[string][]netip.Addr{
		"A":    {netip.MustParseAddr("192.0.2.1")},
		"AAAA": {netip.MustParseAddr("2001:db8::1")},
	}
	domains["sub.example.com."] = map[string][]netip.Addr{
		"A": {netip.MustParseAddr("192.0.2.2")},
	}

	saveManagedDomainsState(ctx, storage, domains, logger)

	// Verify data was stored
	if !storage.Exists(ctx, managedDomainsStorageKey) {
		t.Fatal("expected state to be stored")
	}

	// Verify the stored JSON structure
	data, err := storage.Load(ctx, managedDomainsStorageKey)
	if err != nil {
		t.Fatalf("failed to load stored data: %v", err)
	}

	var state managedDomainsState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("failed to unmarshal stored data: %v", err)
	}

	// Check timestamp is recent
	if time.Since(state.LastUpdated) > time.Minute {
		t.Errorf("LastUpdated timestamp is too old: %v", state.LastUpdated)
	}

	// Check domains
	if len(state.Domains) != 2 {
		t.Errorf("expected 2 domains, got %d", len(state.Domains))
	}

	if ips, ok := state.Domains["example.com."]; !ok {
		t.Error("expected example.com. in domains")
	} else {
		if len(ips["A"]) != 1 || ips["A"][0] != "192.0.2.1" {
			t.Errorf("unexpected A record for example.com.: %v", ips["A"])
		}
		if len(ips["AAAA"]) != 1 || ips["AAAA"][0] != "2001:db8::1" {
			t.Errorf("unexpected AAAA record for example.com.: %v", ips["AAAA"])
		}
	}
}

func TestSaveManagedDomainsState_NilDomains(t *testing.T) {
	storage := newMockStorage()
	logger := zap.NewNop()
	ctx := context.Background()

	// Should not panic or store anything with nil domains
	saveManagedDomainsState(ctx, storage, nil, logger)

	if storage.Exists(ctx, managedDomainsStorageKey) {
		t.Error("expected no state to be stored for nil domains")
	}
}

func TestSaveManagedDomainsState_SkipsInvalidIPs(t *testing.T) {
	storage := newMockStorage()
	logger := zap.NewNop()
	ctx := context.Background()

	domains := make(domainTypeIPs)
	domains["example.com."] = map[string][]netip.Addr{
		"A": {
			netip.MustParseAddr("192.0.2.1"),
			netip.Addr{}, // Invalid/zero IP
		},
	}

	saveManagedDomainsState(ctx, storage, domains, logger)

	data, _ := storage.Load(ctx, managedDomainsStorageKey)
	var state managedDomainsState
	json.Unmarshal(data, &state)

	// Should only have the valid IP
	if len(state.Domains["example.com."]["A"]) != 1 {
		t.Errorf("expected 1 IP (invalid filtered), got %d", len(state.Domains["example.com."]["A"]))
	}
}

func TestLoadManagedDomainsState(t *testing.T) {
	storage := newMockStorage()
	logger := zap.NewNop()
	ctx := context.Background()

	// Pre-populate storage with test data
	state := managedDomainsState{
		LastUpdated: time.Now().UTC(),
		Domains: map[string]map[string][]string{
			"example.com.": {
				"A":    {"192.0.2.1"},
				"AAAA": {"2001:db8::1"},
			},
			"sub.example.com.": {
				"A": {"192.0.2.2"},
			},
		},
	}
	data, _ := json.Marshal(state)
	storage.Store(ctx, managedDomainsStorageKey, data)

	// Load and verify
	result := loadManagedDomainsState(ctx, storage, logger)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if len(result) != 2 {
		t.Errorf("expected 2 domains, got %d", len(result))
	}

	// Verify example.com
	if ips, ok := result["example.com."]; !ok {
		t.Error("expected example.com. in result")
	} else {
		if len(ips["A"]) != 1 || ips["A"][0] != netip.MustParseAddr("192.0.2.1") {
			t.Errorf("unexpected A record: %v", ips["A"])
		}
		if len(ips["AAAA"]) != 1 || ips["AAAA"][0] != netip.MustParseAddr("2001:db8::1") {
			t.Errorf("unexpected AAAA record: %v", ips["AAAA"])
		}
	}

	// Verify sub.example.com
	if ips, ok := result["sub.example.com."]; !ok {
		t.Error("expected sub.example.com. in result")
	} else {
		if len(ips["A"]) != 1 || ips["A"][0] != netip.MustParseAddr("192.0.2.2") {
			t.Errorf("unexpected A record: %v", ips["A"])
		}
	}
}

func TestLoadManagedDomainsState_NoFile(t *testing.T) {
	storage := newMockStorage()
	logger := zap.NewNop()
	ctx := context.Background()

	// Load from empty storage - should return nil without error
	result := loadManagedDomainsState(ctx, storage, logger)

	if result != nil {
		t.Errorf("expected nil result for missing file, got %v", result)
	}
}

func TestLoadManagedDomainsState_InvalidJSON(t *testing.T) {
	storage := newMockStorage()
	logger := zap.NewNop()
	ctx := context.Background()

	// Store invalid JSON
	storage.Store(ctx, managedDomainsStorageKey, []byte("not valid json"))

	// Should return nil on parse error
	result := loadManagedDomainsState(ctx, storage, logger)

	if result != nil {
		t.Errorf("expected nil result for invalid JSON, got %v", result)
	}
}

func TestLoadManagedDomainsState_InvalidIP(t *testing.T) {
	storage := newMockStorage()
	logger := zap.NewNop()
	ctx := context.Background()

	// Store data with an invalid IP
	state := managedDomainsState{
		LastUpdated: time.Now().UTC(),
		Domains: map[string]map[string][]string{
			"example.com.": {
				"A": {"192.0.2.1", "not-an-ip", "192.0.2.2"},
			},
		},
	}
	data, _ := json.Marshal(state)
	storage.Store(ctx, managedDomainsStorageKey, data)

	result := loadManagedDomainsState(ctx, storage, logger)

	// Should only have the valid IPs
	if len(result["example.com."]["A"]) != 2 {
		t.Errorf("expected 2 valid IPs, got %d", len(result["example.com."]["A"]))
	}
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	storage := newMockStorage()
	logger := zap.NewNop()
	ctx := context.Background()

	// Create test data
	original := make(domainTypeIPs)
	original["example.com."] = map[string][]netip.Addr{
		"A":    {netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")},
		"AAAA": {netip.MustParseAddr("2001:db8::1")},
	}
	original["test.example.com."] = map[string][]netip.Addr{
		"A": {netip.MustParseAddr("192.0.2.100")},
	}

	// Save
	saveManagedDomainsState(ctx, storage, original, logger)

	// Load
	loaded := loadManagedDomainsState(ctx, storage, logger)

	// Verify round-trip
	if len(loaded) != len(original) {
		t.Fatalf("domain count mismatch: got %d, want %d", len(loaded), len(original))
	}

	for domain, origTypes := range original {
		loadedTypes, ok := loaded[domain]
		if !ok {
			t.Errorf("missing domain after round-trip: %s", domain)
			continue
		}

		for recType, origIPs := range origTypes {
			loadedIPs, ok := loadedTypes[recType]
			if !ok {
				t.Errorf("missing record type %s for domain %s", recType, domain)
				continue
			}

			if len(loadedIPs) != len(origIPs) {
				t.Errorf("IP count mismatch for %s %s: got %d, want %d",
					domain, recType, len(loadedIPs), len(origIPs))
			}
		}
	}
}

// Delete Orphaned Records Tests

func TestDeleteOrphanedRecords_Disabled(t *testing.T) {
	app := App{
		DeleteOrphans: false,
		logger:        zap.NewNop(),
	}

	// Set up lastIPs
	lastIPs = make(domainTypeIPs)
	lastIPs["orphan.example.com."] = map[string][]netip.Addr{
		"A": {netip.MustParseAddr("192.0.2.1")},
	}
	defer func() { lastIPs = nil }()

	allDomains := map[string][]string{
		"example.com.": {"@"},
	}

	result := app.deleteOrphanedRecords(context.Background(), allDomains)

	if result {
		t.Error("expected false when DeleteOrphans is disabled")
	}
}

func TestDeleteOrphanedRecords_NilLastIPs(t *testing.T) {
	app := App{
		DeleteOrphans: true,
		logger:        zap.NewNop(),
	}

	lastIPs = nil

	allDomains := map[string][]string{
		"example.com.": {"@"},
	}

	result := app.deleteOrphanedRecords(context.Background(), allDomains)

	if result {
		t.Error("expected false when lastIPs is nil")
	}
}

func TestDeleteOrphanedRecords_ProviderNoDeleteSupport(t *testing.T) {
	app := App{
		DeleteOrphans: true,
		dnsProvider:   &mockDNSProviderNoDelete{},
		logger:        zap.NewNop(),
	}

	lastIPs = make(domainTypeIPs)
	lastIPs["orphan.example.com."] = map[string][]netip.Addr{
		"A": {netip.MustParseAddr("192.0.2.1")},
	}
	defer func() { lastIPs = nil }()

	allDomains := map[string][]string{
		"example.com.": {"@"},
	}

	result := app.deleteOrphanedRecords(context.Background(), allDomains)

	if result {
		t.Error("expected false when provider doesn't support RecordDeleter")
	}
}

func TestDeleteOrphanedRecords_DomainStillInConfig(t *testing.T) {
	provider := &mockDNSProvider{}
	app := App{
		DeleteOrphans: true,
		dnsProvider:   provider,
		logger:        zap.NewNop(),
	}

	lastIPs = make(domainTypeIPs)
	lastIPs["sub.example.com."] = map[string][]netip.Addr{
		"A": {netip.MustParseAddr("192.0.2.1")},
	}
	defer func() { lastIPs = nil }()

	// Domain is still in config
	allDomains := map[string][]string{
		"example.com.": {"sub"},
	}

	result := app.deleteOrphanedRecords(context.Background(), allDomains)

	if result {
		t.Error("expected false when domain is still in config")
	}
	if len(provider.deletedRecords) > 0 {
		t.Error("expected no records to be deleted")
	}
}

func TestDeleteOrphanedRecords_DeletesOrphan(t *testing.T) {
	provider := &mockDNSProvider{}
	app := App{
		DeleteOrphans: true,
		dnsProvider:   provider,
		logger:        zap.NewNop(),
	}

	lastIPs = make(domainTypeIPs)
	lastIPs["orphan.example.com."] = map[string][]netip.Addr{
		"A": {netip.MustParseAddr("192.0.2.1")},
	}
	defer func() { lastIPs = nil }()

	// orphan.example.com is NOT in allDomains
	allDomains := map[string][]string{
		"example.com.": {"@"},
	}

	result := app.deleteOrphanedRecords(context.Background(), allDomains)

	if !result {
		t.Error("expected true when orphan is deleted")
	}
	if len(provider.deletedRecords) != 1 {
		t.Fatalf("expected 1 delete call, got %d", len(provider.deletedRecords))
	}
	if provider.deletedRecords[0].zone != "example.com." {
		t.Errorf("expected zone example.com., got %s", provider.deletedRecords[0].zone)
	}
}

func TestDeleteOrphanedRecords_DeleteError(t *testing.T) {
	provider := &mockDNSProvider{
		deleteError: errors.New("delete failed"),
	}
	app := App{
		DeleteOrphans: true,
		dnsProvider:   provider,
		logger:        zap.NewNop(),
	}

	lastIPs = make(domainTypeIPs)
	lastIPs["orphan.example.com."] = map[string][]netip.Addr{
		"A": {netip.MustParseAddr("192.0.2.1")},
	}
	defer func() { lastIPs = nil }()

	allDomains := map[string][]string{
		"example.com.": {"@"},
	}

	result := app.deleteOrphanedRecords(context.Background(), allDomains)

	// Should return false because delete failed
	if result {
		t.Error("expected false when delete fails")
	}
	// But orphan should still be removed from lastIPs
	if _, exists := lastIPs["orphan.example.com."]; exists {
		t.Error("expected orphan to be removed from lastIPs even on delete error")
	}
}

func TestDeleteOrphanedRecords_MultipleOrphans(t *testing.T) {
	provider := &mockDNSProvider{}
	app := App{
		DeleteOrphans: true,
		dnsProvider:   provider,
		logger:        zap.NewNop(),
	}

	lastIPs = make(domainTypeIPs)
	lastIPs["orphan1.example.com."] = map[string][]netip.Addr{
		"A": {netip.MustParseAddr("192.0.2.1")},
	}
	lastIPs["orphan2.example.com."] = map[string][]netip.Addr{
		"A":    {netip.MustParseAddr("192.0.2.2")},
		"AAAA": {netip.MustParseAddr("2001:db8::1")},
	}
	lastIPs["keep.example.com."] = map[string][]netip.Addr{
		"A": {netip.MustParseAddr("192.0.2.3")},
	}
	defer func() { lastIPs = nil }()

	// Only keep.example.com is in config
	allDomains := map[string][]string{
		"example.com.": {"keep"},
	}

	result := app.deleteOrphanedRecords(context.Background(), allDomains)

	if !result {
		t.Error("expected true when orphans are deleted")
	}
	if len(provider.deletedRecords) != 2 {
		t.Errorf("expected 2 delete calls, got %d", len(provider.deletedRecords))
	}
	// keep.example.com should still be in lastIPs
	if _, exists := lastIPs["keep.example.com."]; !exists {
		t.Error("expected keep.example.com. to remain in lastIPs")
	}
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
		dnsProvider: provider,
		ctx:         caddy.Context{},
		logger:      zap.NewNop(),
	}

	ips, err := app.lookupCurrentIPsFromDNS(map[string][]string{
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
		dnsProvider: provider,
		ctx:         caddy.Context{},
		logger:      zap.NewNop(),
	}

	ips, err := app.lookupCurrentIPsFromDNS(map[string][]string{
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
