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

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/google/go-cmp/cmp"
)

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
			want: ` {
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
