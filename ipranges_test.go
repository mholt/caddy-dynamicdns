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
	"net/netip"
	"testing"
)

func TestIPRangesContains(t *testing.T) {
	prefixes := func(cidrs ...string) Subnets {
		var out Subnets
		for _, c := range cidrs {
			out = append(out, netip.MustParsePrefix(c))
		}
		return out
	}
	tests := []struct {
		name   string
		ranges IPRanges
		ip     string
		want   bool
	}{
		// No ranges configured: only global, non-private unicast addresses.
		{"default public v4", IPRanges{}, "203.0.114.1", true},
		{"default private v4", IPRanges{}, "192.168.1.10", false},
		{"default loopback v4", IPRanges{}, "127.0.0.1", false},
		{"default link-local v4", IPRanges{}, "169.254.1.1", false},
		{"default public v6", IPRanges{}, "2001:4860::1", true},
		{"default ULA v6", IPRanges{}, "fd00::1", false},
		{"default link-local v6", IPRanges{}, "fe80::1", false},

		// Configured ranges: the most specific match wins.
		{"include only, inside", IPRanges{Include: prefixes("192.168.0.0/16")}, "192.168.1.10", true},
		{"include only, outside", IPRanges{Include: prefixes("192.168.0.0/16")}, "203.0.114.1", false},
		{"exclude only, outside", IPRanges{Exclude: prefixes("192.168.0.0/16")}, "10.0.0.1", true},
		{"exclude only, inside", IPRanges{Exclude: prefixes("192.168.0.0/16")}, "192.168.1.10", false},
		{"more specific exclude", IPRanges{Include: prefixes("192.168.0.0/16"), Exclude: prefixes("192.168.10.0/24")}, "192.168.10.5", false},
		{"more specific include", IPRanges{Include: prefixes("192.168.10.0/24"), Exclude: prefixes("192.168.0.0/16")}, "192.168.10.5", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Call through IPSettings, the way the IP sources do.
			settings := IPSettings{IPRanges: tt.ranges}
			if got := settings.Contains(netip.MustParseAddr(tt.ip)); got != tt.want {
				t.Errorf("Contains(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}
