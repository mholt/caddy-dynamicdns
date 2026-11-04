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
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"

	"go.uber.org/zap"
)

func TestSimpleHTTPAddressFamily(t *testing.T) {
	trueBool, falseBool := true, false
	v4Only := IPVersions{IPv4: &trueBool, IPv6: &falseBool}
	v6Only := IPVersions{IPv4: &falseBool, IPv6: &trueBool}
	// Accept every address, so only the family check decides.
	all := IPRanges{Include: Subnets{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}}

	// serve starts an endpoint on the given loopback address that answers
	// with body.
	serve := func(t *testing.T, listen, body string) string {
		t.Helper()
		l, err := net.Listen("tcp", listen)
		if err != nil {
			t.Skipf("cannot listen on %s: %v", listen, err)
		}
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, body)
		}))
		srv.Listener.Close()
		srv.Listener = l
		srv.Start()
		t.Cleanup(srv.Close)
		return srv.URL
	}

	tests := []struct {
		name     string
		versions IPVersions
		listen   string
		bodies   []string
		want     []netip.Addr
	}{
		{"v4 lookup, v4 answer", v4Only, "127.0.0.1:0", []string{"203.0.113.7"}, []netip.Addr{netip.MustParseAddr("203.0.113.7")}},
		{"v4 lookup, v4-mapped answer", v4Only, "127.0.0.1:0", []string{"::ffff:203.0.113.7"}, []netip.Addr{netip.MustParseAddr("203.0.113.7")}},
		{"v4 lookup, v6 answer", v4Only, "127.0.0.1:0", []string{"2001:db8::7"}, nil},
		{"v4 lookup, v6 then v4 endpoint", v4Only, "127.0.0.1:0", []string{"2001:db8::7", "203.0.113.7"}, []netip.Addr{netip.MustParseAddr("203.0.113.7")}},
		{"v6 lookup, v6 answer", v6Only, "[::1]:0", []string{"2001:db8::7"}, []netip.Addr{netip.MustParseAddr("2001:db8::7")}},
		{"v6 lookup, v4 answer", v6Only, "[::1]:0", []string{"203.0.113.7"}, nil},
		{"v6 lookup, v4-mapped answer", v6Only, "[::1]:0", []string{"::ffff:203.0.113.7"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sh := SimpleHTTP{logger: zap.NewNop()}
			for _, body := range tt.bodies {
				sh.Endpoints = append(sh.Endpoints, serve(t, tt.listen, body))
			}
			got, err := sh.GetIPs(context.Background(), IPSettings{IPRanges: all, IPVersions: tt.versions})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
