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

	"github.com/google/go-cmp/cmp"
)

func Test_NormalizeProviders(t *testing.T) {
	provider1 := json.RawMessage(`{"name":"test_dummy","arg":"one"}`)
	provider2 := json.RawMessage(`{"name":"test_dummy","arg":"two"}`)
	domains1 := map[string][]string{"example.com": {"@"}}
	domains2 := map[string][]string{"example.org": {"@", "www"}}

	tests := []struct {
		name    string
		app     App
		want    []Provider
		wantErr bool
	}{
		{
			name: "legacy: top-level provider and domains",
			app: App{
				DNSProviderRaw: provider1,
				Domains:        domains1,
			},
			want: []Provider{
				{DNSProviderRaw: provider1, Domains: domains1},
			},
		},
		{
			name: "legacy top-level provider combined with providers list",
			app: App{
				DNSProviderRaw: provider1,
				Domains:        domains1,
				Providers: []Provider{
					{DNSProviderRaw: provider2, Domains: domains2},
				},
			},
			want: []Provider{
				{DNSProviderRaw: provider1, Domains: domains1},
				{DNSProviderRaw: provider2, Domains: domains2},
			},
		},
		{
			name: "top-level domains fold into a sole provider without domains",
			app: App{
				Domains: domains1,
				Providers: []Provider{
					{DNSProviderRaw: provider1},
				},
			},
			want: []Provider{
				{DNSProviderRaw: provider1, Domains: domains1},
			},
		},
		{
			name: "providers list only",
			app: App{
				Providers: []Provider{
					{DNSProviderRaw: provider1, Domains: domains1},
					{DNSProviderRaw: provider2, Domains: domains2},
				},
			},
			want: []Provider{
				{DNSProviderRaw: provider1, Domains: domains1},
				{DNSProviderRaw: provider2, Domains: domains2},
			},
		},
		{
			name: "top-level domains conflict with per-provider domains",
			app: App{
				Domains: domains1,
				Providers: []Provider{
					{DNSProviderRaw: provider1, Domains: domains2},
				},
			},
			wantErr: true,
		},
		{
			name: "top-level domains with multiple providers",
			app: App{
				Domains: domains1,
				Providers: []Provider{
					{DNSProviderRaw: provider1},
					{DNSProviderRaw: provider2},
				},
			},
			wantErr: true,
		},
		{
			name: "no provider",
			app:  App{Domains: domains1},
			want: []Provider{
				{Domains: domains1},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.app.normalizeProviders()
			if err != nil {
				if !tt.wantErr {
					t.Errorf("normalizeProviders() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("normalizeProviders() expected error, got none")
			}
			if diff := cmp.Diff(tt.app.Providers, tt.want, cmp.AllowUnexported(Provider{})); diff != "" {
				t.Errorf("normalizeProviders() diff(-got +want):\n%s", diff)
			}
		})
	}
}
