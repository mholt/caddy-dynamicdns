package dynamicdns

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"go.uber.org/zap"
)

// fakeSource is an IPSource that returns fixed addresses, or fails.
type fakeSource struct {
	ips   []string
	fail  bool
	calls *int
}

func (fakeSource) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "dynamic_dns.ip_sources.fake", New: func() caddy.Module { return new(fakeSource) }}
}

func (f fakeSource) GetIPs(context.Context, IPSettings) ([]netip.Addr, error) {
	if f.calls != nil {
		*f.calls++
	}
	if f.fail {
		return nil, errors.New("source down")
	}
	var out []netip.Addr
	for _, s := range f.ips {
		out = append(out, netip.MustParseAddr(s))
	}
	return out, nil
}

func answers(ips ...string) IPSource { return fakeSource{ips: ips} }

var downSource IPSource = fakeSource{fail: true}

func TestLookupPublicIPsQuorum(t *testing.T) {
	const right, wrong, other = "198.51.100.7", "203.0.113.9", "192.0.2.44"
	for _, tc := range []struct {
		name    string
		sources []IPSource
		quorum  int
		want    []string // nil: an error is expected
	}{
		{"all agree", []IPSource{answers(right), answers(right), answers(right)}, 2, []string{right}},
		{"one source down", []IPSource{answers(right), downSource, answers(right)}, 2, []string{right}},
		{"one source wrong is outvoted", []IPSource{answers(wrong), answers(right), answers(right)}, 2, []string{right}},
		{"two sources down", []IPSource{downSource, answers(right), downSource}, 2, nil},
		{"no two agree", []IPSource{answers(right), answers(wrong), answers(other)}, 2, nil},
		{"two agreeing wrong sources win", []IPSource{answers(wrong), answers(wrong), answers(right)}, 2, []string{wrong}},
		{"quorum 3 needs all three", []IPSource{answers(right), answers(right), downSource}, 3, nil},
		{"a source counts once per address", []IPSource{answers(wrong, wrong), answers(right)}, 2, nil},
		{"a source counts once per address, also mapped", []IPSource{answers(wrong, "::ffff:"+wrong), answers(right)}, 2, nil},
		{"an IPv4-mapped address counts as IPv4", []IPSource{answers("::ffff:" + right), answers(right)}, 2, []string{right}},
		{"IPv4 agreed, IPv6 not", []IPSource{answers(right, "2001:db8::1"), answers(right, "2001:db8::2")}, 2, []string{right}},
		{"both versions agreed", []IPSource{answers(right, "2001:db8::1"), answers(right, "2001:db8::1")}, 2, []string{right, "2001:db8::1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := App{IPSourceQuorum: tc.quorum, ipSources: tc.sources, logger: zap.NewNop()}
			got, err := a.lookupPublicIPs()
			if tc.want == nil {
				if err == nil {
					t.Fatalf("want an error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			var gotS []string
			for _, ip := range got {
				gotS = append(gotS, ip.String())
			}
			want := slices.Clone(tc.want)
			slices.Sort(gotS)
			slices.Sort(want)
			if !slices.Equal(gotS, want) {
				t.Errorf("got %v, want %v", gotS, want)
			}
		})
	}
}

// Without a quorum the first source that answers is used and the rest are
// not asked, as before.
func TestLookupPublicIPsDefaultFirstSource(t *testing.T) {
	var first, second, third int
	a := App{logger: zap.NewNop(), ipSources: []IPSource{
		fakeSource{fail: true, calls: &first},
		fakeSource{ips: []string{"198.51.100.7"}, calls: &second},
		fakeSource{ips: []string{"203.0.113.9"}, calls: &third},
	}}
	got, err := a.lookupPublicIPs()
	if err != nil || len(got) != 1 || got[0].String() != "198.51.100.7" {
		t.Fatalf("got %v, %v; want the second source's address", got, err)
	}
	if first != 1 || second != 1 || third != 0 {
		t.Errorf("calls %d/%d/%d, want 1/1/0", first, second, third)
	}

	a.ipSources = []IPSource{downSource, downSource}
	if _, err := a.lookupPublicIPs(); err == nil || !strings.Contains(err.Error(), "all IP sources failed") {
		t.Errorf("all sources down: got %v, want the old error", err)
	}
}

func TestCheckQuorum(t *testing.T) {
	two := []IPSource{answers("198.51.100.7"), answers("198.51.100.7")}
	for _, tc := range []struct {
		quorum  int
		wantErr bool
	}{{0, false}, {1, false}, {2, false}, {3, true}, {-1, true}} {
		err := App{IPSourceQuorum: tc.quorum, ipSources: two}.checkQuorum()
		if (err != nil) != tc.wantErr {
			t.Errorf("quorum %d with 2 sources: err %v, wantErr %v", tc.quorum, err, tc.wantErr)
		}
	}
}

func TestParseIPSourceQuorum(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "ip_source_quorum 2", want: `"ip_source_quorum":2`},
		{in: "ip_source_quorum", wantErr: true},
		{in: "ip_source_quorum 0", wantErr: true},
		{in: "ip_source_quorum two", wantErr: true},
		{in: "ip_source_quorum 2 3", wantErr: true},
	} {
		got, err := parseApp(caddyfile.NewTestDispenser("dynamic_dns {\n"+tc.in+"\n}"), nil)
		if tc.wantErr {
			if err == nil {
				t.Errorf("%q: want an error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%q: %v", tc.in, err)
		}
		if js := string(got.(httpcaddyfile.App).Value); !strings.Contains(js, tc.want) {
			t.Errorf("%q: JSON %s lacks %s", tc.in, js, tc.want)
		}
	}
}
