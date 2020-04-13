package dynamicdns

import (
	"github.com/StackExchange/dnscontrol/v2/providers"
	"github.com/StackExchange/dnscontrol/v2/providers/cloudflare"
	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(Cloudflare{})
}

// Cloudflare integrates Cloudflare DNS.
type Cloudflare struct {
	// TODO: these fields are deprecated, but still required by dnscontrol lib...
	APIUser string `json:"api_user,omitempty"`
	APIKey  string `json:"api_key,omitempty"`

	cloudflare.CloudflareApi `json:"-"`
}

// CaddyModule returns the Caddy module information.
func (Cloudflare) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dynamic_dns.providers.cloudflare",
		New: func() caddy.Module { return new(Cloudflare) },
	}
}

// Provision sets up the module.
func (cf *Cloudflare) Provision(_ caddy.Context) error {
	cf.CloudflareApi.ApiUser = cf.APIUser
	cf.CloudflareApi.ApiKey = cf.APIKey
	return nil
}

// Interface guards
var (
	_ providers.DNSServiceProvider = (*Cloudflare)(nil)
)
