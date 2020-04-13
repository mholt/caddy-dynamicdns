package dynamicdns

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(Ipify{})
}

// IPSource is a type that can get IP addresses.
// TODO: IPv6?
type IPSource interface {
	GetIPv4() (net.IP, error)
}

// Ipify gets IP addresses from ipify.org.
// (TODO: api6.ipify.org for IPv6)
type Ipify struct{}

// CaddyModule returns the Caddy module information.
func (Ipify) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dynamic_dns.ip_sources.ipify",
		New: func() caddy.Module { return new(Ipify) },
	}
}

// GetIPv4 gets the public IPv4 address of this machine.
func (Ipify) GetIPv4() (net.IP, error) {
	resp, err := http.Get("https://api.ipify.org")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("server response was: %d %s", resp.StatusCode, resp.Status)
	}

	ipASCII, err := ioutil.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return nil, err
	}
	ipStr := strings.TrimSpace(string(ipASCII))

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	return ip, nil
}

// Interface guard
var _ IPSource = (*Ipify)(nil)
