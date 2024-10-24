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
	"net"
	"strings"
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

	// How frequently to check the public IP address. Default: 30m
	CheckInterval caddy.Duration `json:"check_interval,omitempty"`

	// The TTL to set on DNS records.
	TTL caddy.Duration `json:"ttl,omitempty"`

	ipSources   []IPSource
	dnsProvider interface {
		libdns.RecordGetter
		libdns.RecordSetter
		libdns.RecordAppender
	}

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
	a.dnsProvider = val.(interface {
		libdns.RecordGetter
		libdns.RecordSetter
		libdns.RecordAppender
	})

	// set up the IP source module or use a default
	if a.IPSourcesRaw != nil {
		vals, err := ctx.LoadModule(a, "IPSourcesRaw")
		if err != nil {
			return fmt.Errorf("loading IP source module: %v", err)
		}
		for _, val := range vals.([]interface{}) {
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

	var err error

	allDomains := a.allDomains()

	// look up current address(es) from first successful IP source
	var currentIPs []net.IP
	for _, ipSrc := range a.ipSources {
		currentIPs, err = ipSrc.GetIPs(a.ctx, a.Versions)
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
	for _, ip := range currentIPs {
		for zone, domains := range allDomains {
			// find all records for the zone
			recs, err := a.dnsProvider.GetRecords(a.ctx, zone)
			if err != nil {
				a.logger.Error("failed to get all records for zone", zap.String("zone", zone), zap.Error(err))
				continue
			}

			needAppendRecords := make(map[string][]libdns.Record)
			needUpdateRecords := make(map[string][]libdns.Record)

			for _, domain := range domains {
				var record libdns.Record
				for _, rec := range recs {
					if rec.Name == domain && rec.Type == recordType(ip) {
						record = rec
						break
					}
				}

				if record.Name == "" {
					if a.UpdateOnly {
						a.logger.Error("record doesn't exist; skipping update",
							zap.String("zone", zone),
							zap.String("name", domain),
							zap.String("type", recordType(ip)),
						)
						continue
					}

					needAppendRecords[zone] = append(needAppendRecords[zone], libdns.Record{
						Type:  recordType(ip),
						Name:  domain,
						Value: ip.String(),
						TTL:   time.Duration(a.TTL),
					})
					continue
				}

				if record.Value == ip.String() {
					// IP is not different and no new domains to manage; no update needed
					continue
				}

				needUpdateRecords[zone] = append(needUpdateRecords[zone], libdns.Record{
					ID:    record.ID,
					Type:  record.Type,
					Name:  record.Name,
					Value: ip.String(),
					TTL:   time.Duration(a.TTL),
				})
			}

			if len(needAppendRecords) > 0 {
				for _, rec := range needAppendRecords[zone] {
					a.logger.Info("appending DNS record",
						zap.String("zone", zone),
						zap.String("name", rec.Name),
						zap.String("type", rec.Type),
						zap.String("value", rec.Value),
					)
				}
				_, err = a.dnsProvider.AppendRecords(a.ctx, zone, needAppendRecords[zone])
				if err != nil {
					a.logger.Error("failed to append DNS record(s)", zap.String("zone", zone), zap.Error(err))
				}
			}

			if len(needUpdateRecords) > 0 {
				for _, rec := range needUpdateRecords[zone] {
					a.logger.Info("updating DNS record",
						zap.String("id", rec.ID),
						zap.String("zone", zone),
						zap.String("name", rec.Name),
						zap.String("type", rec.Type),
						zap.String("value", rec.Value),
					)
				}
				_, err = a.dnsProvider.SetRecords(a.ctx, zone, needUpdateRecords[zone])
				if err != nil {
					a.logger.Error("failed to update DNS record(s)", zap.String("zone", zone), zap.Error(err))
				}
			}
		}
	}

	currentIPStrings := make([]string, len(currentIPs))
	for i, val := range currentIPs {
		currentIPStrings[i] = val.String()
	}
	a.logger.Info("finished updating DNS", zap.Strings("current_ips", currentIPStrings))
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
func recordType(ip net.IP) string {
	if ip.To4() == nil {
		return recordTypeAAAA
	}
	return recordTypeA
}

// removeDuplicateIPs returns ips without duplicates.
func removeDuplicateIPs(ips []net.IP) []net.IP {
	uniqueIPs := make(map[string]net.IP)
	for _, ip := range ips {
		uniqueIPs[ip.String()] = ip
	}
	clean := make([]net.IP, 0, len(uniqueIPs))
	for _, ip := range uniqueIPs {
		clean = append(clean, ip)
	}
	return clean
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
