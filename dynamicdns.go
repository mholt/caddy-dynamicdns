package dynamicdns

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
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

	// How frequently to check the public IP address. Default: 30m
	CheckInterval caddy.Duration `json:"check_interval,omitempty"`

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

	lastIPsMu.Lock()
	defer lastIPsMu.Unlock()

	var err error

	// if we don't know current IPs for this domain, look them up from DNS
	if lastIPs == nil {
		lastIPs, err = a.lookupCurrentIPsFromDNS()
		if err != nil {
			// not the end of the world, but might be an extra initial API hit with the DNS provider
			a.logger.Error("unable to lookup current IPs from DNS records", zap.Error(err))
		}
	}

	// look up current address(es) from first successful IP source
	var currentIPs []net.IP
	for _, ipSrc := range a.ipSources {
		currentIPs, err = ipSrc.GetIPs(a.ctx)
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

	// do a simple diff of current and previous IPs to make DNS records to update
	updatedRecsByZone := make(map[string][]libdns.Record)
	for _, ip := range currentIPs {
		if ipListContains(lastIPs, ip) {
			continue // IP is not different; no update needed
		}

		a.logger.Info("different IP address", zap.String("new_ip", ip.String()))

		for zone, domains := range a.Domains {
			for _, domain := range domains {
				updatedRecsByZone[zone] = append(updatedRecsByZone[zone], libdns.Record{
					Type:  recordType(ip),
					Name:  domain,
					Value: ip.String(),
					TTL:   time.Duration(a.CheckInterval),
				})
			}
		}
	}

	if len(updatedRecsByZone) == 0 {
		a.logger.Debug("no IP address change; no update needed")
		return
	}

	for zone, records := range updatedRecsByZone {
		for _, rec := range records {
			a.logger.Info("updating DNS record",
				zap.String("zone", zone),
				zap.String("type", rec.Type),
				zap.String("name", rec.Name),
				zap.String("value", rec.Value),
				zap.Duration("ttl", rec.TTL),
			)
		}
		_, err = a.dnsProvider.SetRecords(a.ctx, zone, records)
		if err != nil {
			a.logger.Error("failed setting DNS record(s) with new IP address(es)",
				zap.String("zone", zone),
				zap.Error(err),
			)
		}
	}

	a.logger.Info("finished updating DNS")

	lastIPs = currentIPs
}

// lookupCurrentIPsFromDNS looks up the current IP addresses
// from DNS records.
func (a App) lookupCurrentIPsFromDNS() ([]net.IP, error) {
	// avoid duplicates
	currentIPs := make(map[string]net.IP)

	if recordGetter, ok := a.dnsProvider.(libdns.RecordGetter); ok {
		for zone, names := range a.Domains {
			recs, err := recordGetter.GetRecords(a.ctx, zone)
			if err == nil {
				for _, r := range recs {
					if r.Type != recordTypeA && r.Type != recordTypeAAAA {
						continue
					}
					if !stringListContains(names, r.Name) {
						continue
					}
					ip := net.ParseIP(r.Value)
					if ip != nil {
						currentIPs[ip.String()] = ip
					} else {
						a.logger.Error("invalid IP address found in current DNS record", zap.String("A", r.Value))
					}
				}
			} else {
				return nil, err
			}
		}
	}

	// convert into a slice
	ips := make([]net.IP, 0, len(currentIPs))
	for _, ip := range currentIPs {
		ips = append(ips, ip)
	}

	return ips, nil
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
	var clean []net.IP
	for _, ip := range ips {
		if !ipListContains(clean, ip) {
			clean = append(clean, ip)
		}
	}
	return clean
}

// ipListContains returns true if list contains ip; false otherwise.
func ipListContains(list []net.IP, ip net.IP) bool {
	for _, ipInList := range list {
		if ipInList.Equal(ip) {
			return true
		}
	}
	return false
}

func stringListContains(list []string, s string) bool {
	for _, val := range list {
		if val == s {
			return true
		}
	}
	return false
}

// Remember what the last IPs are so that we
// don't try to update DNS records every
// time a new config is loaded; the IPs are
// unlikely to change very often.
var (
	lastIPs   []net.IP
	lastIPsMu sync.Mutex
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
