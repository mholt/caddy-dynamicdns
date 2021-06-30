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
//         ip_source upnp
//         ip_source endpoint https://icanhazip.com
//     }
//
// If <names...> are omitted after <zone>, then "@" will be assumed.
func parseApp(d *caddyfile.Dispenser, _ interface{}) (interface{}, error) {
	app := new(App)

	// consume the option name
	if !d.Next() {
		return nil, d.ArgErr()
	}

	// Collects all seen endpoints, to be made into one simple http ip source at the end.
	var endpoints []string
	flushSimpleHTTPEndpoints := func() {
		if len(endpoints) > 0 {
			app.IPSourcesRaw = append(app.IPSourcesRaw, caddyconfig.JSON(map[string]interface{}{
				"source":    "simple_http",
				"endpoints": endpoints,
			}, nil))
		}
		endpoints = nil
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
			switch d.Val() {
			case "upnp":
				if d.NextArg() {
					// Expecting upnp as the last arg on the line.
					return nil, d.ArgErr()
				}
				flushSimpleHTTPEndpoints()
				app.IPSourcesRaw = append(app.IPSourcesRaw, upnpJSONValue)

			case "endpoint":
				if !d.NextArg() {
					// Expecting the value of an endpoint.
					return nil, d.ArgErr()
				}
				endpoints = append(endpoints, d.Val())

			default:
				return nil, d.ArgErr()
			}

		default:
			return nil, d.ArgErr()
		}
	}

	flushSimpleHTTPEndpoints()

	return httpcaddyfile.App{
		Name:  "dynamic_dns",
		Value: caddyconfig.JSON(app, nil),
	}, nil
}

var upnpJSONValue = caddyconfig.JSON(map[string]string{"source": "upnp"}, nil)
