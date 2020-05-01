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
	"golang.org/x/net/publicsuffix"
)

func init() {
	caddy.RegisterModule(App{})
}

// App is a Caddy app that keeps your DNS records updated.
type App struct {
	// The source from which to get the server's public IP address.
	IPSourceRaw json.RawMessage `json:"ip_source,omitempty" caddy:"namespace=dynamic_dns.ip_sources inline_key=source"`

	// The configuration for the DNS provider with which the DNS
	// records will be updated.
	DNSProviderRaw json.RawMessage `json:"dns_provider,omitempty" caddy:"namespace=dns.providers inline_key=name"`

	// The domain name for which to update DNS records.
	Domain string `json:"domain,omitempty"`

	// How frequently to check the public IP address. Default: 10m
	CheckInterval caddy.Duration `json:"check_interval,omitempty"`

	ipSource    IPSource
	dnsProvider libdns.RecordSetter
	eTLDplus1   string // TODO: a better way to get the zone from the domain - recursive DNS lookups until SOA record, like lego does maybe?

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

	// parse the domain name
	if a.Domain == "" {
		return fmt.Errorf("domain is required")
	}
	eTLDplus1, err := publicsuffix.EffectiveTLDPlusOne(a.Domain)
	if err != nil {
		return err
	}
	a.eTLDplus1 = eTLDplus1

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
	if a.IPSourceRaw != nil {
		val, err := ctx.LoadModule(a, "IPSourceRaw")
		if err != nil {
			return fmt.Errorf("loading IP source module: %v", err)
		}
		a.ipSource = val.(IPSource)
	}
	if a.ipSource == nil {
		a.ipSource = Ipify{}
	}

	// make sure a check interval is set
	if a.CheckInterval == 0 {
		a.CheckInterval = caddy.Duration(10 * time.Minute)
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

// checkIPAndUpdateDNS checks the public IP address and,
// if it is different from the last IP, it updates DNS
// records accordingly.
func (a App) checkIPAndUpdateDNS() {
	lastIPMu.Lock()
	defer lastIPMu.Unlock()

	// if we don't know the current IP for this domain, try to get it
	if lastIP == nil {
		if recordGetter, ok := a.dnsProvider.(libdns.RecordGetter); ok {
			recs, err := recordGetter.GetRecords(a.ctx, a.eTLDplus1)
			if err == nil {
				for _, r := range recs {
					if r.Type == "A" && r.Name == a.Domain {
						lastIP = net.ParseIP(r.Value)
						break
					}
				}
			} else {
				a.logger.Error("unable to get current records", zap.Error(err))
			}
		}
	}

	ip, err := a.ipSource.GetIPv4()
	if err != nil {
		a.logger.Error("checking IP address", zap.Error(err))
		return
	}
	if ip.Equal(lastIP) {
		return
	}

	a.logger.Info("IP address changed",
		zap.String("last_ip", lastIP.String()),
		zap.String("new_ip", ip.String()),
	)
	err = a.updateDNS(ip)
	if err != nil {
		a.logger.Error("updating DNS record(s) with new IP address", zap.Error(err))
		return
	}

	lastIP = ip
}

func (a App) updateDNS(ipv4 net.IP) error {
	recordA := libdns.Record{
		Type:  "A",
		Name:  a.Domain,
		Value: ipv4.String(),
		TTL:   time.Duration(a.CheckInterval),
	}

	a.logger.Info("updating DNS record",
		zap.String("type", recordA.Type),
		zap.String("name", recordA.Name),
		zap.String("value", recordA.Value),
		zap.Duration("ttl", recordA.TTL),
	)

	_, err := a.dnsProvider.SetRecords(a.ctx, a.eTLDplus1, []libdns.Record{recordA})
	if err != nil {
		return err
	}

	a.logger.Info("finished updating DNS")

	return nil
}

// Remember what the last IP is so that we
// don't try to update DNS records every
// time a new config is loaded; the IP is
// unlikely to change that often.
var (
	lastIP   net.IP
	lastIPMu sync.Mutex
)

// Interface guards
var (
	_ caddy.Provisioner = (*App)(nil)
	_ caddy.App         = (*App)(nil)
)
