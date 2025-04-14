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
	"net"
	"regexp"
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

func extractLastValidIP(body []byte, isIPv4 bool) (net.IP, error) {
	var regex string
	if isIPv4 {
		regex = `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`
	} else {
		regex = `\b2[0-9a-fA-F]{3}(?::[0-9a-fA-F]{0,4}){0,7}\b`
	}

	re := regexp.MustCompile(regex)
	matches := re.FindAllString(string(body), -1)

	var selectedIP net.IP
	var maxIPv6Length int

	for i := 0; i < len(matches); i++ {
		ipStr := matches[i]
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}

		if isIPv4 {
			if ip.To4() != nil && !ip.IsPrivate() && ip.IsGlobalUnicast() {
				selectedIP = ip // Always select the last valid IPv4
			}
		} else {
			if ip.To16() != nil && !ip.IsPrivate() && ip.IsGlobalUnicast() {
				length := len(ipStr) // Compare IPv6 string length, looking for the longest IPv6
				if length > maxIPv6Length {
					selectedIP = ip
					maxIPv6Length = length
				} else if length == maxIPv6Length {
					selectedIP = ip // Select the last IPv6 if lengths are equal
				}
			}
		}
	}
	if selectedIP != nil {
		return selectedIP, nil
	}
	return nil, nil
}

func Test_ExtractLastValidIP(t *testing.T) {
	tests := []struct {
		name    string
		isIPv4  bool
		body    string
		want    net.IP
		wantErr bool
	}{
		// IPv4 case
		{
			name:   "Valid IPv4 addresses, returns last valid",
			isIPv4: true,
			body: `title>complex html<title>哈哈
				host=1.0.0.1
				<p>Invalid IP: 999.999.999.999</p>
				ip:4.4.4.4,"ip":"8.8.8.88"
				<p>Another valid IP: 18.8.8.8</p>
				8.8.8.88alsoVlidIP=8.8.8.8口<css>
				<p>Private IP: 192.168.1.1</p>
				<p>Invalid IP: 999.999.999.999</p>
				`,
			want:    net.ParseIP("8.8.8.8"),
			wantErr: false,
		},
		{
			name:   "No valid IPv4 addresses",
			isIPv4: false,
			body: `
				<p>1.1.1.256</p>
				<p>192.168.1.1</p>
				<p>10.10.8.4</p>
				<p>256.10.8.4</p>
				<p>1.256.8.4</p>
				<p>1.10.256.4</p>
				<p>127.16.10.1</p>
				255.255.255.255
				999.999.999.999
				255.0.0.0
				169.254.06.1
				240.0.5.5
				233.233.2.2
				`,
			want:    nil,
			wantErr: false,
		},
		// IPv6 case
		{
			name:   "Valid IPv6 addresses, returns last valid",
			isIPv4: false,
			body: `title>complex html<title>哈哈
				host=2001:db8:::1234
		        <a>aaaaValidIP=2001:4860:4860::8888<css>
				<p>Private IP: 192.168.1.1</p>
				<p>Invalid IP: 999.999.999.999</p>
				<p>Another valid IPv6: 2001:0d0d:0c0c:0000:0000:1234:5678:2333口</p>
				badip 2001:db8:85a3::8a2e::0370
				fakeip 2001:db8:85a3:0000:0000:8a2e:0370
				`,
			want:    net.ParseIP("2001:0d0d:0c0c:0000:0000:1234:5678:2333"),
			wantErr: false,
		},
		{
			name:   "No valid IPv6 addresses",
			isIPv4: false,
			body: `
				<p>Invalid IPv6: 2001:db8:::1234</p>
				<p>Testing content: ::g123</p>
				2008:1,29992001:1
				fc00::1
				fd00::1
				fe80::1
				2001:db8:::1234
				2001:db8:::1234
				2001:db8:::1234
				2001:gggg:85a3::8a2e:0370:7334
				2001:db8:85a3:0000:0000:8a2e:0370:xyz
				2001:db8:85a3::8a2e::0370
				2001:db8:85a3::8a2e:370:733o4
				2001:db8:85a3:0000:0000:8a2e:03o70:7334
				2001:db8::8a2e:o0370:7334
				::ffff:192.168.1.1
				fe80::a2e:0370:7334:abcd
				fe80::a2e:0370:7334::1
				ff00::1234
				::ff00:1234
				fe80::/10
				::/0
				::ffff:256.256.256.256
				::ffff:999.999.999.999
				::192.168.1.1
				::10.0.0.1
				fe80::a2e:0370:7334:1234::abcd
				2001:db8::1234:5678:90ab::cdef
				2001:db8:aaaa::bbbb::cccc
				ff02::c0a8:1
				::zxy::abcd
				2001:db8::8a2e:0370::7334
				2001:db8::ffff::8888
				2001:db8::/48
				::a2e:0370:7334
				::zxy::a2e:0370:7334
`,
			want:    nil,
			wantErr: false,
		},
		// Compare IPv6 string length case
		{
			name:   "IPv6 string length Cases",
			isIPv4: false,
			body: `240e::1:2222
				   2001::gggg:1234
				   2001::
				   240e::1:1:122  // Select the last IPv6 if lengths are equal
				   240e::1:1:123  // Select the last IPv6 if lengths are equal
				   Gateway: 240e::1:123
				   240e::1:1:12
				   2001::gggg:1234
				   DNS: 240e::1:2  // IPv6 lengths too short
				`,
			want:    net.ParseIP("240e::1:1:123"),
			wantErr: false,
		},
		// Mixed IPv4 and IPv6 case
		{
			name:   "Mixed IPv4 and IPv6 addresses,want IPv6",
			isIPv4: false,
			body: `
				<p>Invalid IPv4: 256.256.256.256</p>
				<p>Invalid IPv6: 2G08::12345</p>
				<p>IPv4: 8.8.8.8</p>
				<p>IPv6: 2001:4567:4567::8888</p>
				<p>Invalid IPv4: 256.256.256.256</p>
				<p>Invalid IPv6: 2G08::12345</p>`,
			want:    net.ParseIP("2001:4567:4567::8888"),
			wantErr: false,
		},
		{
			name:   "Mixed IPv4 and IPv6 addresses,want IPv4",
			isIPv4: true,
			body: `
				<p>Invalid IPv4: 256.256.256.256</p>
				<p>Invalid IPv6: 2G08::12345</p>
				<p>IPv4: 8.8.8.4</p>
				<p>IPv6: 2001:6789:6789::8888</p>
				<p>Invalid IPv4: 256.256.256.256</p>
				<p>Invalid IPv6: 2G08::12345</p>`,
			want:    net.ParseIP("8.8.8.4"),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractLastValidIP([]byte(tt.body), tt.isIPv4)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractLastValidIP() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != nil && !got.Equal(tt.want) {
				t.Errorf("extractLastValidIP() = %v, want %v", got, tt.want)
			}
			if got == nil && tt.want != nil {
				t.Errorf("extractLastValidIP() = nil, want %v", tt.want)
			}
		})
	}
}
