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
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/libdns/libdns"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(App{})
}

// App is a Caddy app that keeps your DNS records updated with the public
// IP address of your instance. It updates A and AAAA records.
type App struct {
	// The sources from which to get the server's public IP address.
	// Multiple sources can be specified for redundancy.
	// Default: simple_http
	IPSourcesRaw []json.RawMessage `json:"ip_sources,omitempty" caddy:"namespace=dynamic_dns.ip_sources inline_key=source"`

	// The configuration for the DNS provider with which the DNS
	// records will be updated.
	DNSProviderRaw json.RawMessage `json:"dns_provider,omitempty" caddy:"namespace=dns.providers inline_key=name"`

	// The record names, keyed by DNS zone, for which to update the A/AAAA records.
	// Record names are relative to the zone. The zone is usually your registered
	// domain name. To refer to the zone itself, use the record name of "@".
	//
	// For example, assuming your zone is example.com, and you want to update A/AAAA
	// records for "example.com" and "www.example.com" so that they resolve to this
	// Caddy instance, configure like so: `"example.com": ["@", "www"]`
	Domains map[string][]string `json:"domains,omitempty"`

	// If enabled, no new DNS records will be created. Only existing records will be updated.
	// This means that the A or AAAA records need to be created manually ahead of time.
	UpdateOnly bool `json:"update_only,omitempty"`

	// If enabled, the "http" app's config will be scanned to assemble the list
	// of domains for which to enable dynamic DNS updates.
	DynamicDomains bool `json:"dynamic_domains,omitempty"`

	// The IP versions to enable. By default, both "ipv4" and "ipv6" will be enabled.
	// To disable IPv6, specify {"ipv6": false}.
	Versions IPVersions `json:"versions,omitempty"`

	// The IP ranges to include and exclude
	*IPRanges `json:",omitempty"`

	// How frequently to check the public IP address. Default: 30m
	CheckInterval caddy.Duration `json:"check_interval,omitempty"`

	// The TTL to set on DNS records.
	TTL caddy.Duration `json:"ttl,omitempty"`

	ipSources   []IPSource
	dnsProvider libdns.RecordSetter

	ctx    caddy.Context
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dynamic_dns",
		New: func() caddy.Module { return new(App) },
	}
}

// Provision sets up the app module.
func (a *App) Provision(ctx caddy.Context) error {
	a.ctx = ctx
	a.logger = ctx.Logger(a)

	// set up the DNS provider module
	if len(a.DNSProviderRaw) == 0 {
		return fmt.Errorf("a DNS provider is required")
	}
	val, err := ctx.LoadModule(a, "DNSProviderRaw")
	if err != nil {
		return fmt.Errorf("loading DNS provider module: %v", err)
	}
	a.dnsProvider = val.(libdns.RecordSetter)

	// set up the IP source module or use a default
	if a.IPSourcesRaw != nil {
		vals, err := ctx.LoadModule(a, "IPSourcesRaw")
		if err != nil {
			return fmt.Errorf("loading IP source module: %v", err)
		}
		for _, val := range vals.([]any) {
			a.ipSources = append(a.ipSources, val.(IPSource))
		}
	}
	if len(a.ipSources) == 0 {
		var sh SimpleHTTP
		if err = sh.Provision(ctx); err != nil {
			return err
		}
		a.ipSources = []IPSource{sh}
	}

	// make sure a check interval is set
	if a.CheckInterval == 0 {
		a.CheckInterval = caddy.Duration(defaultCheckInterval)
	}
	if time.Duration(a.CheckInterval) < time.Second {
		return fmt.Errorf("check interval must be at least 1 second")
	}

	return nil
}

// Start starts the app module.
func (a App) Start() error {
	go a.checkerLoop()
	return nil
}

// Stop stops the app module.
func (a App) Stop() error {
	return nil
}

// checkerLoop checks the public IP address at every check
// interval. It stops when a.ctx is cancelled.
func (a App) checkerLoop() {
	ticker := time.NewTicker(time.Duration(a.CheckInterval))
	defer ticker.Stop()

	a.checkIPAndUpdateDNS()

	for {
		select {
		case <-ticker.C:
			a.checkIPAndUpdateDNS()
		case <-a.ctx.Done():
			return
		}
	}
}

// checkIPAndUpdateDNS checks public IP addresses and, for any IP addresses
// that are different from before, it updates DNS records accordingly.
func (a App) checkIPAndUpdateDNS() {
	a.logger.Debug("beginning IP address check")

	lastIPsMu.Lock()
	defer lastIPsMu.Unlock()

	var err error

	allDomains := a.allDomains()

	// if we don't know current IPs, look them up from DNS
	if lastIPs == nil {
		lastIPs, err = a.lookupCurrentIPsFromDNS(allDomains)
		if err != nil {
			// not the end of the world, but might be an extra initial API hit with the DNS provider
			a.logger.Error("unable to lookup current IPs from DNS records", zap.Error(err))
		}
		a.logger.Debug("looked up current IPs from DNS", zap.Any("lastIPs", lastIPs))
	}

	// Lookup current address(es) from first successful IP source
	var currentIPs []netip.Addr
	for _, ipSrc := range a.ipSources {
		ipSettings := struct {
			*IPRanges
			IPVersions
		}{a.IPRanges, a.Versions}
		currentIPs, err = ipSrc.GetIPs(a.ctx, ipSettings)
		if len(currentIPs) == 0 {
			err = fmt.Errorf("no IP addresses returned")
		}
		if err == nil {
			break
		}
		a.logger.Error("looking up IP address",
			zap.String("ip_source", ipSrc.(caddy.Module).CaddyModule().ID.Name()),
			zap.Error(err))
	}

	// make sure the source returns tidy info; duplicates are wasteful
	currentIPs = removeDuplicateIPs(currentIPs)

	// do a diff of current and previous IPs to make DNS records to update
	updatedRecsByZone := make(map[string][]libdns.Address)
	for _, ip := range currentIPs {
		for zone, domains := range allDomains {
			for _, domain := range domains {
				oldIps, found := lastIPs[libdns.AbsoluteName(domain, zone)][recordType(ip)]
				if !found && a.UpdateOnly {
					a.logger.Debug("record doesn't exist; skipping update",
						zap.String("zone", zone),
						zap.String("name", domain),
					)
					continue
				}

				if found && ipListContains(oldIps, ip) {
					// IP is not different and no new domains to manage; no update needed
					continue
				}

				updatedRecsByZone[zone] = append(updatedRecsByZone[zone], libdns.Address{
					Name: domain,
					TTL:  time.Duration(a.TTL),
					IP:   ip,
				})
			}
		}
	}

	if len(updatedRecsByZone) == 0 {
		a.logger.Debug("no IP address change; no update needed")
		return
	}

	for zone, addresses := range updatedRecsByZone {
		records := make([]libdns.Record, len(addresses))
		for i, rec := range addresses {
			a.logger.Info("updating DNS record",
				zap.String("zone", zone),
				zap.String("type", recordType(rec.IP)),
				zap.String("name", rec.Name),
				zap.String("ip", rec.IP.String()),
				zap.Duration("ttl", rec.TTL),
			)
			records[i] = rec
		}
		if _, err = a.dnsProvider.SetRecords(a.ctx, zone, records); err != nil {
			a.logger.Error("failed setting DNS record(s) with new IP address(es)",
				zap.String("zone", zone),
				zap.Error(err),
			)
		}
		for _, rec := range addresses {
			name := libdns.AbsoluteName(rec.Name, zone)
			if lastIPs == nil {
				lastIPs = make(domainTypeIPs)
			}
			if lastIPs[name] == nil {
				lastIPs[name] = make(map[string][]netip.Addr)
			}
			lastIPs[name][recordType(rec.IP)] = []netip.Addr{rec.IP}
		}
	}

	currentIPStrings := make([]string, len(currentIPs))
	for i, val := range currentIPs {
		currentIPStrings[i] = val.String()
	}
	a.logger.Info("finished updating DNS",
		zap.Strings("current_ips", currentIPStrings))
}

// lookupCurrentIPsFromDNS looks up the current IP addresses
// from DNS records.
func (a App) lookupCurrentIPsFromDNS(domains map[string][]string) (domainTypeIPs, error) {
	// avoid duplicates
	currentIPs := make(domainTypeIPs)

	if recordGetter, ok := a.dnsProvider.(libdns.RecordGetter); ok {
		for zone, names := range domains {
			recs, err := recordGetter.GetRecords(a.ctx, zone)
			if err != nil {
				return nil, err
			}

			recMap := make(map[string]map[string]netip.Addr)
			for _, r := range recs {
				ar, ok := r.(libdns.Address)
				if !ok {
					continue
				}
				recType := recordType(ar.IP)
				a.logger.Debug("found DNS record", zap.String("type", recType), zap.String("name", ar.Name), zap.String("zone", zone), zap.String("value", ar.IP.String()))
				name := libdns.AbsoluteName(ar.Name, zone)
				if _, ok := recMap[name]; !ok {
					recMap[name] = make(map[string]netip.Addr)
				}
				recMap[name][recType] = ar.IP
			}
			for _, n := range names {
				name := libdns.AbsoluteName(n, zone)
				ips := make(map[string][]netip.Addr)
				for _, t := range []string{recordTypeA, recordTypeAAAA} {
					if ip, ok := recMap[name][t]; ok {
						ips[t] = []netip.Addr{ip}
					} else {
						a.logger.Info("domain not found in DNS", zap.String("domain", name), zap.String("type", t))
						ips[t] = []netip.Addr{nilIP}
					}
				}
				currentIPs[name] = ips
			}
		}
	}

	return currentIPs, nil
}

func (a App) lookupManagedDomains() ([]string, error) {
	cai, err := a.ctx.App("http")
	if err != nil {
		return nil, err
	}
	var hosts []string
	ca := cai.(*caddyhttp.App)
	for _, s := range ca.Servers {
		for _, r := range s.Routes {
			for _, ms := range r.MatcherSets {
				for _, rm := range ms {
					if hs, ok := rm.(caddyhttp.MatchHost); ok {
						for _, h := range hs {
							hosts = append(hosts, h)
						}
					}
				}
			}
		}
	}
	return hosts, nil
}

func (a App) allDomains() map[string][]string {
	if !a.DynamicDomains {
		return a.Domains
	}

	// Read hosts from config.
	m, err := a.lookupManagedDomains()
	if err != nil {
		return a.Domains
	}

	a.logger.Info("Loaded dynamic domains", zap.Strings("domains", m))
	d := make(map[string][]string)
	for zone, domains := range a.Domains {
		d[zone] = domains
		for _, h := range m {
			name, ok := func() (string, bool) {
				if h == zone {
					return "@", true
				}
				suffix := "." + zone
				if n := strings.TrimSuffix(h, suffix); n != h {
					return n, true
				}
				return "", false
			}()
			if !ok {
				// Not in this zone.
				continue
			}
			a.logger.Info("Adding dynamic domain", zap.String("domain", name))
			d[zone] = append(d[zone], name)
		}
	}
	return d
}

// recordType returns the DNS record type associated with the version of ip.
func recordType(addr netip.Addr) string {
	if addr.Is4() {
		return recordTypeA
	}
	return recordTypeAAAA
}

// removeDuplicateIPs returns ips without duplicates.
func removeDuplicateIPs(ips []netip.Addr) []netip.Addr {
	uniqueIPs := make(map[string]netip.Addr)
	for _, ip := range ips {
		uniqueIPs[ip.String()] = ip
	}
	clean := make([]netip.Addr, 0, len(uniqueIPs))
	for _, ip := range uniqueIPs {
		clean = append(clean, ip)
	}
	return clean
}

// ipListContains returns true if list contains ip; false otherwise.
func ipListContains(list []netip.Addr, ip netip.Addr) bool {
	for _, ipInList := range list {
		if ipInList.Compare(ip) == 0 {
			return true
		}
	}
	return false
}

// IPRanges is the set of IP ranges to include and exclude for dynamic
// DNS, where the most specific match "wins".
// If no ranges are configured then the default behaviour is to include
// global unicast ranges and exclude private ranges.
type IPRanges struct {
	Includes Subnets `json:"includes,omitempty"`
	Excludes Subnets `json:"excludes,omitempty"`
}

func (r *IPRanges) Contains(ip netip.Addr) bool {
	if r == nil {
		return !ip.IsPrivate() && ip.IsGlobalUnicast()
	}
	includeSize := r.Includes.largestContainingMaskSize(ip)
	excludeSize := r.Excludes.largestContainingMaskSize(ip)
	return (includeSize > excludeSize) || (excludeSize == -1 && len(r.Includes) == 0)
}

// A list of IP ranges.
type Subnets []netip.Prefix

// Get the size of the subnet with the largest mask which contains the IP.
func (r Subnets) largestContainingMaskSize(ip netip.Addr) int {
	matchSize := -1
	for _, subet := range r {
		size := subet.Bits()
		if size >= matchSize && subet.Contains(ip) {
			matchSize = size
		}
	}
	return matchSize
}

// Unmarshal from a list of CIDR strings.
func (r *Subnets) UnmarshalJSON(data []byte) error {
	var cidrRanges []string
	json.Unmarshal(data, &cidrRanges)

	for _, cidrRange := range cidrRanges {
		prefix, err := netip.ParsePrefix(cidrRange)
		if err != nil {
			return err
		}
		*r = append(*r, prefix)
	}
	return nil
}

// Marshal to a list of CIDR strings.
func (r *Subnets) MarshalJSON() ([]byte, error) {
	var strings []string
	for _, ipRange := range *r {
		strings = append(strings, ipRange.String())
	}
	return json.Marshal(strings)
}

// IPVersions is the IP versions to enable for dynamic DNS.
// Versions are enabled if true or nil, set to false to disable.
type IPVersions struct {
	IPv4 *bool `json:"ipv4,omitempty"`
	IPv6 *bool `json:"ipv6,omitempty"`
}

// V4Enabled returns true if IPv4 is enabled.
func (ip IPVersions) V4Enabled() bool {
	return ip.IPv4 == nil || *ip.IPv4
}

// V6Enabled returns true if IPv6 is enabled.
func (ip IPVersions) V6Enabled() bool {
	return ip.IPv6 == nil || *ip.IPv6
}

type domainTypeIPs map[string]map[string][]netip.Addr

// Remember what the last IPs are so that we
// don't try to update DNS records every
// time a new config is loaded; the IPs are
// unlikely to change very often.
var (
	lastIPs   domainTypeIPs
	lastIPsMu sync.Mutex

	// Special value indicate there is a new domain to manage.
	nilIP netip.Addr
)

const (
	recordTypeA    = "A"
	recordTypeAAAA = "AAAA"
)

const defaultCheckInterval = 30 * time.Minute

// Interface guards
var (
	_ caddy.Provisioner = (*App)(nil)
	_ caddy.App         = (*App)(nil)
)
