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
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/google/go-cmp/cmp"
)

func init() {
	caddy.RegisterModule(dummyProvider{})
}

// dummyProvider is a stand-in DNS provider module so that tests can
// exercise the provider directive without depending on a real DNS
// provider module. Like real providers, it accepts an inline argument
// or a config block, and it errors on unrecognized subdirectives —
// which proves that tokens reserved by this app never leak through
// to the provider module.
type dummyProvider struct {
	Arg    string `json:"arg,omitempty"`
	APIKey string `json:"api_key,omitempty"`
}

func (dummyProvider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.test_dummy",
		New: func() caddy.Module { return new(dummyProvider) },
	}
}

func (p *dummyProvider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			p.Arg = d.Val()
		}
		if d.NextArg() {
			return d.ArgErr()
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "api_key":
				if !d.NextArg() {
					return d.ArgErr()
				}
				p.APIKey = d.Val()
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}
	return nil
}

func Test_ParseApp(t *testing.T) {
	tests := []struct {
		name    string
		d       *caddyfile.Dispenser
		want    string
		wantErr bool
	}{
		{
			name: "ip_source: upnp",
			d: caddyfile.NewTestDispenser(`
			dynamic_dns {
				ip_source upnp
			}`),
			want: ` {
				"ip_sources": [
					{
						"source": "upnp"
					}
				],
				"versions": {}
			}`,
		},
		{
			name: "ip_source: simple http endpoints",
			d: caddyfile.NewTestDispenser(`
			dynamic_dns {
				ip_source simple_http http://1.com
				ip_source simple_http http://2.com
			}`),
			want: ` {
				"ip_sources": [
					{
						"source": "simple_http",
						"endpoints": ["http://1.com"]
					},
					{
						"source": "simple_http",
						"endpoints": ["http://2.com"]
					}
				],
				"versions": {}
			}`,
		},
		{
			name: "ip_source: endpoints then upnp then endpoints",
			d: caddyfile.NewTestDispenser(`
			dynamic_dns {
				ip_source simple_http http://1.com
				ip_source upnp
				ip_source simple_http http://2.com
			}`),
			want: ` {
				"ip_sources": [
					{
						"source": "simple_http",
						"endpoints": ["http://1.com"]
					},
					{
						"source": "upnp"
					},
					{
						"source": "simple_http",
						"endpoints": ["http://2.com"]
					}
				],
				"versions": {}
			}`,
		},
		{
			name: "ip_source: interface",
			d: caddyfile.NewTestDispenser(`
			dynamic_dns {
				ip_source interface eth0
			}`),
			want: ` {
				"ip_sources": [
					{
						"name": "eth0",
						"source": "interface"
					}
				],
				"versions": {}
			}`,
		},
		{
			name: "ip versions",
			d: caddyfile.NewTestDispenser(`
			dynamic_dns {
				versions ipv4
			}`),
			want: ` {
				"versions": {
					"ipv4": true,
					"ipv6": false
				}
			}`,
		},
		{
			name: "ip versions: invalid version",
			d: caddyfile.NewTestDispenser(`
			dynamic_dns {
				versions ipv5
			}`),
			wantErr: true,
		},
		{
			name: "domains: zones get merged",
			d: caddyfile.NewTestDispenser(`
				dynamic_dns {
					domains {
						example @
						example test
						sub.example @
					}
				}
			`),
			want: `{
				"domains": {
					"example": [
						"@",
						"test"
					],
					"sub.example": [
						"@"
					]
				},
				"versions": {}
 			}`,
		},
		{
			name: "ip ranges",
			d: caddyfile.NewTestDispenser(`
				dynamic_dns {
					include "192.168.0.0/16" "2001:0db8:85a3::/48"
					exclude "192.168.10.0/24" "2001:0db8:85a3:1234::/64"
				}
			`),
			want: `{
				"include": [
					"192.168.0.0/16",
					"2001:db8:85a3::/48"
				],
				"exclude": [
					"192.168.10.0/24",
					"2001:db8:85a3:1234::/64"
				],
				"versions": {}
			}`,
		},
		{
			name: "ip ranges: include",
			d: caddyfile.NewTestDispenser(`
				dynamic_dns {
					include "192.168.0.0/16"
				}
			`),
			want: `{
				"include": [ "192.168.0.0/16" ],
				"versions": {}
			}`,
		},
		{
			name: "ip ranges: exclude",
			d: caddyfile.NewTestDispenser(`
				dynamic_dns {
					exclude "192.168.0.0/16"
				}
			`),
			want: `{
				"exclude": [ "192.168.0.0/16" ],
				"versions": {}
			}`,
		},
		{
			name: "provider: legacy single provider with top-level domains",
			d: caddyfile.NewTestDispenser(`
				dynamic_dns {
					provider test_dummy abc123
					domains {
						example.com @
					}
				}
			`),
			want: `{
				"dns_provider": {
					"name": "test_dummy",
					"arg": "abc123"
				},
				"domains": {
					"example.com": ["@"]
				},
				"versions": {}
			}`,
		},
		{
			name: "provider: legacy single provider with config block",
			d: caddyfile.NewTestDispenser(`
				dynamic_dns {
					provider test_dummy {
						api_key secret
					}
					domains {
						example.com @
					}
				}
			`),
			want: `{
				"dns_provider": {
					"name": "test_dummy",
					"api_key": "secret"
				},
				"domains": {
					"example.com": ["@"]
				},
				"versions": {}
			}`,
		},
		{
			name: "provider: multiple providers with nested domains",
			d: caddyfile.NewTestDispenser(`
				dynamic_dns {
					provider test_dummy one {
						domains {
							example.com @
							example.net www
						}
					}
					provider test_dummy two {
						domains {
							example.org @
						}
					}
				}
			`),
			want: `{
				"providers": [
					{
						"dns_provider": {
							"name": "test_dummy",
							"arg": "one"
						},
						"domains": {
							"example.com": ["@"],
							"example.net": ["www"]
						}
					},
					{
						"dns_provider": {
							"name": "test_dummy",
							"arg": "two"
						},
						"domains": {
							"example.org": ["@"]
						}
					}
				],
				"versions": {}
			}`,
		},
		{
			name: "provider: nested domains after module config",
			d: caddyfile.NewTestDispenser(`
				dynamic_dns {
					provider test_dummy {
						api_key secret1
						domains {
							example.com @ www
						}
					}
				}
			`),
			want: `{
				"providers": [
					{
						"dns_provider": {
							"name": "test_dummy",
							"api_key": "secret1"
						},
						"domains": {
							"example.com": ["@", "www"]
						}
					}
				],
				"versions": {}
			}`,
		},
		{
			name: "provider: nested domains before module config",
			d: caddyfile.NewTestDispenser(`
				dynamic_dns {
					provider test_dummy {
						domains {
							example.com @
						}
						api_key secret1
					}
				}
			`),
			want: `{
				"providers": [
					{
						"dns_provider": {
							"name": "test_dummy",
							"api_key": "secret1"
						},
						"domains": {
							"example.com": ["@"]
						}
					}
				],
				"versions": {}
			}`,
		},
		{
			name: "provider: unrecognized module subdirective",
			d: caddyfile.NewTestDispenser(`
				dynamic_dns {
					provider test_dummy {
						bogus
					}
				}
			`),
			wantErr: true,
		},
		{
			name: "ip ranges: invalid range",
			d: caddyfile.NewTestDispenser(`
				dynamic_dns {
					include "192.168.10.0/100",
					"versions": {}
				}
			`),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseApp(tt.d, nil)
			if err != nil {
				if !tt.wantErr {
					t.Errorf("parseApp() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}
			gotJSON := string(got.(httpcaddyfile.App).Value)
			if diff := equivalentJSON(gotJSON, tt.want, t); diff != "" {
				t.Errorf("parseApp() diff(-got +want):\n%s", diff)
			}
		})
	}
}

func equivalentJSON(s1, s2 string, t *testing.T) string {
	var v1, v2 map[string]interface{}
	if err := json.Unmarshal([]byte(s1), &v1); err != nil {
		t.Error(err)
	}
	if err := json.Unmarshal([]byte(s2), &v2); err != nil {
		t.Error(err)
	}

	return cmp.Diff(v1, v2)
}
