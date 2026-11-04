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
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestSimpleHTTPRedirects(t *testing.T) {
	ipHandler := func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "203.0.113.7") }

	plain := httptest.NewServer(http.HandlerFunc(ipHandler))
	defer plain.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/ip", ipHandler)
	mux.HandleFunc("/to-https", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ip", http.StatusFound)
	})
	mux.HandleFunc("/to-http", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/", http.StatusFound)
	})
	mux.HandleFunc("/to-https-then-http", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/to-http", http.StatusFound)
	})
	mux.HandleFunc("/loop", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop", http.StatusFound)
	})
	secure := httptest.NewTLSServer(mux)
	defer secure.Close()

	plainRedirect := httptest.NewServer(http.RedirectHandler(plain.URL+"/", http.StatusFound))
	defer plainRedirect.Close()

	var sh SimpleHTTP
	client := sh.makeClient("tcp4")
	// Trust the test server's certificate, keep everything else of makeClient.
	client.Transport.(*http.Transport).TLSClientConfig = secure.Client().Transport.(*http.Transport).TLSClientConfig

	tests := []struct {
		name     string
		endpoint string
		wantErr  string
	}{
		{"https to https", secure.URL + "/to-https", ""},
		{"https to http", secure.URL + "/to-http", "refusing redirect"},
		{"https to https to http", secure.URL + "/to-https-then-http", "refusing redirect"},
		{"http to http", plainRedirect.URL, ""},
		{"too many redirects", secure.URL + "/loop", "stopped after 10 redirects"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := sh.lookupIP(context.Background(), client, tt.endpoint)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("got %s, %v; want an error containing %q", addr, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if want := netip.MustParseAddr("203.0.113.7"); addr != want {
				t.Errorf("got %s, want %s", addr, want)
			}
		})
	}
}
