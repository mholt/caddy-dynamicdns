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
				]
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
				]
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
				]
			}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseApp(tt.d, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseApp() error = %v, wantErr %v", err, tt.wantErr)
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
