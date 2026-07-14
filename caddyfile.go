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
			provName := d.Val()
			modID := "dns.providers." + provName

			// the provider's block may contain a domains block reserved
			// for this app; split it out and give the DNS provider module
			// only its own tokens
			var prov Provider
			moduleTokens, err := splitProviderSegment(d.NextSegment(), &prov)
			if err != nil {
				return nil, err
			}
			unm, err := unmarshalModuleTokens(d, modID, moduleTokens)
			if err != nil {
				return nil, err
			}
			prov.DNSProviderRaw = caddyconfig.JSONModuleObject(unm, "name", provName, nil)
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

// splitProviderSegment partitions the tokens of a provider directive's
// segment (the provider module name through the end of its block) into
// the tokens destined for the DNS provider module and the domains blocks
// reserved by this app, which are parsed into prov. The returned tokens
// are what remains for the DNS provider module to unmarshal.
func splitProviderSegment(seg caddyfile.Segment, prov *Provider) ([]caddyfile.Token, error) {
	d := caddyfile.NewDispenser(seg)

	// the provider module name and its inline arguments
	d.Next()
	moduleTokens := []caddyfile.Token{d.Token()}
	for d.NextArg() {
		moduleTokens = append(moduleTokens, d.Token())
	}

	var blockTokens []caddyfile.Token
	var openBrace, closeBrace caddyfile.Token
	inBlock := false
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		if !inBlock {
			// NextBlock() consumed the open curly brace; rewind to
			// capture it, so that the module's block can be rebuilt
			// with its surrounding braces
			d.Prev()
			openBrace = d.Token()
			d.Next()
			inBlock = true
		}
		// the cursor is on a subdirective name; consume its whole
		// segment so nested tokens are never mistaken for a
		// subdirective of the provider block
		if d.Val() == "domains" {
			// reserved for this app
			sub := caddyfile.NewDispenser(d.NextSegment())
			sub.Next() // consume "domains"
			if err := parseDomains(sub, &prov.Domains); err != nil {
				return nil, err
			}
			continue
		}
		// everything else belongs to the DNS provider module
		blockTokens = append(blockTokens, d.NextSegment()...)
	}
	if inBlock {
		closeBrace = d.Token()
		// if the block contained only domains, leave the braces off
		// so the module sees the same tokens as without a block
		if len(blockTokens) > 0 {
			moduleTokens = append(moduleTokens, openBrace)
			moduleTokens = append(moduleTokens, blockTokens...)
			moduleTokens = append(moduleTokens, closeBrace)
		}
	}
	return moduleTokens, nil
}

// unmarshalModuleTokens is like caddyfile.UnmarshalModule, except that it
// unmarshals the module from an explicit list of tokens instead of from
// the dispenser's next segment.
func unmarshalModuleTokens(d *caddyfile.Dispenser, moduleID string, tokens []caddyfile.Token) (caddyfile.Unmarshaler, error) {
	mod, err := caddy.GetModule(moduleID)
	if err != nil {
		return nil, d.Errf("getting module named '%s': %v", moduleID, err)
	}
	inst := mod.New()
	unm, ok := inst.(caddyfile.Unmarshaler)
	if !ok {
		return nil, d.Errf("module %s is not a Caddyfile unmarshaler; is %T", mod.ID, inst)
	}
	err = unm.UnmarshalCaddyfile(caddyfile.NewDispenser(tokens))
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
