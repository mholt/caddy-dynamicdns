package dynamicdns

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	upnp "github.com/NebulousLabs/go-upnp"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(SimpleHTTP{})
	caddy.RegisterModule(UPnP{})
}

// IPSource is a type that can get IP addresses.
type IPSource interface {
	GetIPs(context.Context) ([]net.IP, error)
}

// SimpleHTTP is an IP source that looks up the public IP addresses by
// making HTTP(S) requests to the specified endpoints; it will try each
// endpoint with IPv4 and IPv6 until at least one returns a valid value.
// It is OK if an endpoint doesn't support both IP versions; returning
// a single valid IP address is sufficient.
//
// The endpoints must return HTTP status 200 and the response body must
// contain only the IP address in plain text.
type SimpleHTTP struct {
	// The list of endpoints to query. If empty, a default list will
	// be used:
	//
	// - https://api.ipify.org
	// - https://myip.addr.space
	// - https://ifconfig.me
	// - https://icanhazip.com
	// - https://ident.me
	// - https://bot.whatismyipaddress.com
	// - https://ipecho.net/plain
	Endpoints []string `json:"endpoints,omitempty"`

	// Source of this ip_source, only valid value is "simple_http"
	Source string `json:"source,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (SimpleHTTP) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dynamic_dns.ip_sources.simple_http",
		New: func() caddy.Module { return new(SimpleHTTP) },
	}
}

func (sh *SimpleHTTP) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	var (
		unused   string
		endpoint string
	)
	if !d.AllArgs(&unused, &endpoint) {
		return d.ArgErr()
	}
	sh.Source = "simple_http"
	sh.Endpoints = append(sh.Endpoints, endpoint)
	return nil
}

// Provision sets up the module.
func (sh *SimpleHTTP) Provision(ctx caddy.Context) error {
	sh.logger = ctx.Logger(sh)
	if len(sh.Endpoints) == 0 {
		sh.Endpoints = defaultHTTPIPServices
	}
	return nil
}

// GetIPs gets the public addresses of this machine.
func (sh SimpleHTTP) GetIPs(ctx context.Context) ([]net.IP, error) {
	ipv4Client := sh.makeClient("tcp4")
	ipv6Client := sh.makeClient("tcp6")

	var ips []net.IP
	for _, endpoint := range sh.Endpoints {
		ipv4, err := sh.lookupIP(ctx, ipv4Client, endpoint)
		if err != nil {
			sh.logger.Warn("IPv4 lookup failed",
				zap.String("endpoint", endpoint),
				zap.Error(err))
		} else if !ipListContains(ips, ipv4) {
			ips = append(ips, ipv4)
		}

		ipv6, err := sh.lookupIP(ctx, ipv6Client, endpoint)
		if err != nil {
			sh.logger.Warn("IPv6 lookup failed",
				zap.String("endpoint", endpoint),
				zap.Error(err))
		} else if !ipListContains(ips, ipv6) {
			ips = append(ips, ipv6)
		}

		// use first successful service
		if len(ips) > 0 {
			break
		}
	}

	return ips, nil
}

// makeClient makes an HTTP client that forces use of the specified network type (e.g. "tcp6").
func (SimpleHTTP) makeClient(network string) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, address)
			},
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

func (SimpleHTTP) lookupIP(ctx context.Context, client *http.Client, endpoint string) (net.IP, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s: server response was: %d %s", endpoint, resp.StatusCode, resp.Status)
	}

	ipASCII, err := ioutil.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return nil, err
	}
	ipStr := strings.TrimSpace(string(ipASCII))

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("%s: invalid IP address: %s", endpoint, ipStr)
	}

	return ip, nil
}

var defaultHTTPIPServices = []string{
	"https://api.ipify.org",
	"https://myip.addr.space",
	"https://ifconfig.me",
	"https://icanhazip.com",
	"https://ident.me",
	"https://bot.whatismyipaddress.com",
	"https://ipecho.net/plain",
}

// UPnP gets the IP address from UPnP device.
type UPnP struct {
	// Source of this ip_source, only valid value is "upnp"
	Source string `json:"source,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (UPnP) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dynamic_dns.ip_sources.upnp",
		New: func() caddy.Module { return new(UPnP) },
	}
}

func (u *UPnP) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	u.Source = "upnp"
	return nil
}

// GetIPs gets the public address(es) of this machine.
func (UPnP) GetIPs(ctx context.Context) ([]net.IP, error) {
	d, err := upnp.DiscoverCtx(ctx)
	if err != nil {
		return nil, err
	}

	ipStr, err := d.ExternalIP()
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP: %s", ipStr)
	}

	return []net.IP{ip}, nil
}

// Interface guards
var (
	_ IPSource              = (*SimpleHTTP)(nil)
	_ caddy.Provisioner     = (*SimpleHTTP)(nil)
	_ caddyfile.Unmarshaler = (*SimpleHTTP)(nil)
	_ caddyfile.Unmarshaler = (*UPnP)(nil)

	_ IPSource = (*UPnP)(nil)
)
