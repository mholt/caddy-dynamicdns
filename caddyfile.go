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

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

func init() {
	httpcaddyfile.RegisterGlobalOption("dynamic_dns", parseApp)
}

// parseApp configures the "dynamic_dns" global option from Caddyfile.
// Syntax:
//
//	dynamic_dns {
//		domains {
//			<zone> <names...>
//		}
//		check_interval <duration>
//		provider <name> ...
//		ip_source upnp|simple_http <endpoint>
//		includes <CIDRs ...>
//		excludes <CIDRs ...>
//		update_only
//		dynamic_domains
//		versions ipv4|ipv6
//		ttl <duration>
//	}
//
// If <names...> are omitted after <zone>, then "@" will be assumed.
func parseApp(d *caddyfile.Dispenser, _ any) (any, error) {
	app := new(App)

	// consume the option name
	if !d.Next() {
		return nil, d.ArgErr()
	}

	// handle the block
	for d.NextBlock(0) {
		switch d.Val() {
		case "domains":
			for nesting := d.Nesting(); d.NextBlock(nesting); {
				zone := d.Val()
				if zone == "" {
					return nil, d.ArgErr()
				}
				names := d.RemainingArgs()
				if len(names) == 0 {
					names = []string{"@"}
				}
				if app.Domains == nil {
					app.Domains = make(map[string][]string)
				}
				app.Domains[zone] = append(app.Domains[zone], names...)
			}

		case "update_only":
			if d.NextArg() {
				return nil, d.ArgErr()
			}
			app.UpdateOnly = true

		case "dynamic_domains":
			if d.NextArg() {
				return nil, d.ArgErr()
			}
			app.DynamicDomains = true

		case "check_interval":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return nil, err
			}
			app.CheckInterval = caddy.Duration(dur)

		case "provider":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			provName := d.Val()
			modID := "dns.providers." + provName
			unm, err := caddyfile.UnmarshalModule(d, modID)
			if err != nil {
				return nil, err
			}
			app.DNSProviderRaw = caddyconfig.JSONModuleObject(unm, "name", provName, nil)

		case "ip_source":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			sourceType := d.Val()
			modID := "dynamic_dns.ip_sources." + sourceType
			unm, err := caddyfile.UnmarshalModule(d, modID)
			if err != nil {
				return nil, err
			}
			app.IPSourcesRaw = append(app.IPSourcesRaw, caddyconfig.JSONModuleObject(unm, "source", sourceType, nil))

		case "versions":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return nil, d.Errf("Must specify at least one version")
			}

			// Set up defaults; if versions are specified,
			// both versions start as false, then flipped
			// to true otherwise.
			falseBool := false
			app.Versions = IPVersions{
				IPv4: &falseBool,
				IPv6: &falseBool,
			}

			trueBool := true
			for _, arg := range args {
				switch arg {
				case "ipv4":
					app.Versions.IPv4 = &trueBool
				case "ipv6":
					app.Versions.IPv6 = &trueBool
				default:
					return nil, d.Errf("Unsupported version: '%s'", arg)
				}
			}

		case "includes":
			ranges, err := parseRanges(app, d)
			if err != nil {
				return nil, err
			}
			app.Includes = append(app.Includes, ranges...)

		case "excludes":
			ranges, err := parseRanges(app, d)
			if err != nil {
				return nil, err
			}
			app.Excludes = append(app.Excludes, ranges...)

		case "ttl":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return nil, err
			}
			app.TTL = caddy.Duration(dur)
		default:
			return nil, d.ArgErr()
		}
	}

	return httpcaddyfile.App{
		Name:  "dynamic_dns",
		Value: caddyconfig.JSON(app, nil),
	}, nil
}

// Parse a list of CIDR ranges from the remaining args.
func parseRanges(app *App, d *caddyfile.Dispenser) ([]netip.Prefix, error) {
	if app.IPRanges == nil {
		app.IPRanges = new(IPRanges)
	}
	var ranges []netip.Prefix
	rangeStrings := d.RemainingArgs()
	for _, rangeString := range rangeStrings {
		net, err := netip.ParsePrefix(rangeString)
		if err != nil {
			return nil, err
		}
		ranges = append(ranges, net)
	}
	return ranges, nil
}
