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
//		provider <name> ... {
//			...
//			domains {
//				<zone> <names...>
//			}
//		}
//		ip_source upnp|simple_http <endpoint>
//		include <CIDRs ...>
//		exclude <CIDRs ...>
//		update_only
//		dynamic_domains
//		versions ipv4|ipv6
//		ttl <duration>
//	}
//
// If <names...> are omitted after <zone>, then "@" will be assumed.
//
// The provider directive may be repeated to update domains across multiple
// DNS providers, or multiple accounts of the same provider. In that case,
// each provider's domains are configured with a domains block inside the
// provider's block; the name "domains" is reserved there, and everything
// else in the block belongs to the DNS provider module as usual.
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
			if err := parseDomains(d, &app.Domains); err != nil {
				return nil, err
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
			providerName := d.Val()
			modID := "dns.providers." + providerName

			// the provider's block may contain a domains block reserved
			// for this app; split it out and give the DNS provider module
			// only its own tokens
			var prov Provider
			unm, err := unmarshalModule(d, modID, func(value string) (bool, error) {
				if value != "domains" {
					return false, nil
				}
				if err := parseDomains(d, &prov.Domains); err != nil {
					return false, err
				}
				return true, nil
			})
			if err != nil {
				return nil, err
			}
			prov.DNSProviderRaw = caddyconfig.JSONModuleObject(unm, "name", providerName, nil)
			app.Providers = append(app.Providers, prov)

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

		case "include":
			ranges, err := parseRanges(d)
			if err != nil {
				return nil, err
			}
			app.Include = append(app.Include, ranges...)

		case "exclude":
			ranges, err := parseRanges(d)
			if err != nil {
				return nil, err
			}
			app.Exclude = append(app.Exclude, ranges...)

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

	// a single provider with no domains of its own is equivalent to the
	// legacy single-provider config; keep the original config shape
	if len(app.Providers) == 1 && app.Providers[0].Domains == nil {
		app.DNSProviderRaw = app.Providers[0].DNSProviderRaw
		app.Providers = nil
	}

	return httpcaddyfile.App{
		Name:  "dynamic_dns",
		Value: caddyconfig.JSON(app, nil),
	}, nil
}

// parseDomains parses a domains block into the given map. The dispenser
// must be positioned on the "domains" token.
func parseDomains(d *caddyfile.Dispenser, domains *map[string][]string) error {
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		zone := d.Val()
		if zone == "" {
			return d.ArgErr()
		}
		names := d.RemainingArgs()
		if *domains == nil {
			*domains = make(map[string][]string)
		}
		(*domains)[zone] = append((*domains)[zone], names...)
	}
	return nil
}

// Similar to the (caddyfile.Dispenser).NextSegment(),
// but allows other functions to consume intermediate blocks.
// Since the boundaries are handled by internal functions, NewDispenser is not needed here.
//
//	consumer - Currently, used to handle domains
func nextSegment(d *caddyfile.Dispenser, consumer func(value string) (bool, error)) (caddyfile.Segment, error) {
	tkns := caddyfile.Segment{d.Token()}
	for d.NextArg() {
		tkns = append(tkns, d.Token())
	}
	var openedBlock bool
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		if !openedBlock {
			// because NextBlock() consumes the initial open
			// curly brace, we rewind here to append it, since
			// our case is special in that we want the new
			// dispenser to have all the tokens including
			// surrounding curly braces
			d.Prev()
			tkns = append(tkns, d.Token())
			d.Next()
			openedBlock = true
		}

		ok, err := consumer(d.Val())
		if err != nil {
			return nil, err
		}
		if ok {
			continue
		}

		tkns = append(tkns, d.Token())
	}
	if openedBlock {
		// include closing brace
		tkns = append(tkns, d.Token())

		// do not consume the closing curly brace; the
		// next iteration of the enclosing loop will
		// call Next() and consume it
	}
	return tkns, nil
}

// Similar to caddyfile.UnmarshalModule(), with consumer
func unmarshalModule(d *caddyfile.Dispenser, moduleID string, consumer func(value string) (bool, error)) (caddyfile.Unmarshaler, error) {
	mod, err := caddy.GetModule(moduleID)
	if err != nil {
		return nil, d.Errf("getting module named '%s': %v", moduleID, err)
	}
	inst := mod.New()
	unm, ok := inst.(caddyfile.Unmarshaler)
	if !ok {
		return nil, d.Errf("module %s is not a Caddyfile unmarshaler; is %T", mod.ID, inst)
	}
	seg, err := nextSegment(d, consumer)
	if err != nil {
		return nil, err
	}
	err = unm.UnmarshalCaddyfile(caddyfile.NewDispenser(seg))
	if err != nil {
		return nil, err
	}
	return unm, nil
}

// Parse a list of CIDR ranges from the remaining args.
func parseRanges(d *caddyfile.Dispenser) ([]netip.Prefix, error) {
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
