package dynamicdns

import (
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
//     dynamic_dns {
//         domains {
//             <zone> <names...>
//         }
//         check_interval <duration>
//         provider <name> ...
//         ip_source upnp|simple_http <endpoint>
//         versions ipv4|ipv6
//     }
//
// If <names...> are omitted after <zone>, then "@" will be assumed.
func parseApp(d *caddyfile.Dispenser, _ interface{}) (interface{}, error) {
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
				app.Domains[zone] = names
			}

		case "dynamic_domains":
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
			app.Versions = &IPVersions{
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

		default:
			return nil, d.ArgErr()
		}
	}

	return httpcaddyfile.App{
		Name:  "dynamic_dns",
		Value: caddyconfig.JSON(app, nil),
	}, nil
}
