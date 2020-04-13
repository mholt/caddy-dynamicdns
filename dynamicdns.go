package dynamicdns

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/StackExchange/dnscontrol/v2/models"
	"github.com/StackExchange/dnscontrol/v2/providers"
	"github.com/caddyserver/caddy/v2"
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
	DNSProviderRaw json.RawMessage `json:"dns_provider,omitempty" caddy:"namespace=dynamic_dns.providers inline_key=provider"`

	// The domain name for which to update DNS records.
	Domain string `json:"domain,omitempty"`

	// How frequently to check the public IP address. Default: 10m
	CheckInterval caddy.Duration `json:"check_interval,omitempty"`

	ipSource      IPSource
	dnsProvider   providers.DNSServiceProvider
	eTLDplus1     string
	remainingZone string

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
	a.remainingZone = strings.Trim(strings.TrimSuffix(a.Domain, eTLDplus1), ".")

	// set up the DNS provider module
	if len(a.DNSProviderRaw) == 0 {
		return fmt.Errorf("a DNS provider is required")
	}
	val, err := ctx.LoadModule(a, "DNSProviderRaw")
	if err != nil {
		return fmt.Errorf("loading DNS provider module: %v", err)
	}
	a.dnsProvider = val.(providers.DNSServiceProvider)

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
	// configure the DNS 'A' record
	recordA := &models.RecordConfig{
		Type: "A",
		TTL:  uint32(time.Duration(a.CheckInterval) / time.Second),
	}
	recordA.SetLabel(a.remainingZone, a.eTLDplus1)
	recordA.SetTargetIP(ipv4)

	// configure the domain/zone
	domain := &models.DomainConfig{
		Name:        a.eTLDplus1,
		Records:     models.Records{recordA},
		KeepUnknown: true, // very important to not delete other records!!
	}

	// figure out which corrections need to be made
	corrections, err := a.dnsProvider.GetDomainCorrections(domain)
	if err != nil {
		return err
	}

	// make each correction to the DNS records
	for _, corr := range corrections {
		a.logger.Info("updating DNS", zap.String("change", corr.Msg))
		if err := corr.F(); err != nil {
			return err
		}
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
