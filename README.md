Dynamic DNS app for Caddy
=========================

This is a Caddy app that keeps your DNS pointed at your machine — useful when the address is not static. It periodically queries one or more **IP sources** for your public IP address(es) and, on change, updates A/AAAA records through a [caddy-dns](https://github.com/caddy-dns) provider module.

This repository is a fork of [mholt/caddy-dynamicdns](https://github.com/mholt/caddy-dynamicdns) with an optional **IP updater** hook: the same address change that updates DNS can also drive side effects (currently a ZTE home-gateway IPv6 firewall pinhole). Without `ip_updater`, behaviour matches upstream (IPv4/IPv6, multiple sources, include/exclude, `dynamic_domains`, `update_only`, TTL, intervals, …).

> [!NOTE]
> This is not an official repository of the [Caddy Web Server](https://github.com/caddyserver) organization.

Build example (replace the module path with your fork if needed; the Go module path remains `github.com/mholt/caddy-dynamicdns` for drop-in `--with` replace):

```bash
xcaddy build \
  --with github.com/caddy-dns/cloudflare \
  --with github.com/mholt/caddy-dynamicdns=github.com/<you>/caddy-dynamicdns@main
```

### Sample configurations

<details>
<summary>Minimal example config</summary>

Caddyfile config ([global options](https://caddyserver.com/docs/caddyfile/options)):

```
{
	dynamic_dns {
		provider cloudflare {env.CLOUDFLARE_API_TOKEN}
		domains {
			example.com @
		}
	}
}
```

(For subdomains, see the next example.)

Equivalent JSON config:

```json
{
	"apps": {
		"dynamic_dns": {
			"domains": {
				"example.com": ["@"]
			},
			"dns_provider": {
				"name": "cloudflare",
				"api_token": "{env.CLOUDFLARE_API_TOKEN}"
			}
		}
	}
}
```

This updates DNS records for `example.com` via Cloudflare's API. (Notice how the DNS zone is separate from record names/subdomains.)
</details>


<details>
<summary>Complex example config</summary>

Here's a more filled-out config, with all the options used.

This config prefers to get the IP address locally via UPnP (if edge router has UPnP enabled, of course), but if that fails, will fall back to querying `icanhazip.com` for the IP address. If those fail, it will try to find the IP address from the eth0 interface. It then updates records for `example.com`, `www.example.com`, and `subdomain.example.net`. Notice how the zones and subdomains are separate; this eliminates ambiguity since we don't have to try to be clever and figure out the zone via recursive, authoritative DNS lookups. We also check every 5 minutes instead of 30 minutes (default), and set a TTL of 1 hour for the records.

The interface option will return at most 1 IPv4 and 1 IPv6 address. It will only return addresses that are not [private according to RFC 1918 (IPv4) and RFC 4193 (IPv6)](https://pkg.go.dev/net#IP.IsPrivate), and is a [global unicast address according to RFC 1122, RFC 4632, and RFC 4291 with the exception of IPv4 directed broadcast addresses](https://pkg.go.dev/net#IP.IsGlobalUnicast).

Note that it's redundant to specify both IP versions in the config, since the default is to enable both IPv4 and IPv6. Its purpose is to allow disabling one or the other if your server is only reachable via one of the versions. It's included in this config example for posterity.

Caddyfile config ([global options](https://caddyserver.com/docs/caddyfile/options)):

```
{
	dynamic_dns {
		provider cloudflare {env.CLOUDFLARE_API_TOKEN}
		domains {
			example.com @ www
			example.net subdomain
		}
		ip_source upnp
		ip_source simple_http https://icanhazip.com
		ip_source simple_http https://api64.ipify.org
		ip_source interface eth0
		check_interval 5m
		versions ipv4 ipv6
		ttl 1h
	}
}
```

Equivalent JSON config:

```json
{
	"apps": {
		"dynamic_dns": {
			"dns_provider": {
				"name": "cloudflare",
				"api_token": "{env.CLOUDFLARE_API_TOKEN}"
			},
			"domains": {
				"example.com": ["@", "www"],
				"example.net": ["subdomain"]
			},
			"ip_sources": [
				{
					"source": "upnp"
				},
				{
					"source": "simple_http",
					"endpoints": ["https://icanhazip.com", "https://api64.ipify.org"]
				},
				{
					"source": "interface",
					"name": "eth0"
				}
			],
			"check_interval": "5m",
			"versions": {
				"ipv4": true,
				"ipv6": true
			},
			"ttl": "1h",
			"dynamic_domains": false
		}
	}
}
```
</details>

<details>
<summary>Disabling IPv4</summary>

To disable IPv4 lookups and use your unique global unicast IPv6 address, specify only IPv6 as the version you want enabled and use your machine interface to get the IP address:

Caddyfile config:

```
{
	dynamic_dns {
		provider cloudflare {env.CLOUDFLARE_API_TOKEN}
		domains {
			example.com @
		}
		versions ipv6
		ip_source interface eth0
	}
}
```

Equivalent JSON config; you may omit the other version you want to keep enabled (omission is assumed to mean enabled):

```json
{
	"apps": {
		"dynamic_dns": {
			"domains": {
				"example.com": ["@"]
			},
			"dns_provider": {
				"name": "cloudflare",
				"api_token": "{env.CLOUDFLARE_API_TOKEN}"
			},
			"ip_sources": [
				{
					"source": "interface",
					"name": "eth0"
				}
			],
			"versions": {
				"ipv4": false
			}
		}
	}
}
```
</details>


<details>
<summary>Disabling IPv6</summary>

To disable IPv6 lookups, specify only IPv4 as the version you want enabled:

Caddyfile config:

```
{
	dynamic_dns {
		provider cloudflare {env.CLOUDFLARE_API_TOKEN}
		domains {
			example.com @
		}
		versions ipv4
	}
}
```

Equivalent JSON config; you may omit the other version you want to keep enabled (omission is assumed to mean enabled):

```json
{
	"apps": {
		"dynamic_dns": {
			"domains": {
				"example.com": ["@"]
			},
			"dns_provider": {
				"name": "cloudflare",
				"api_token": "{env.CLOUDFLARE_API_TOKEN}"
			},
			"versions": {
				"ipv6": false
			}
		}
	}
}
```
</details>

<details>
<summary>Dynamic Domains</summary>

There are two ways of telling this app which domains to manage. One is static, via the `domains` config, as shown above. The other is dynamic: set `dynamic_domains` and the app will read hostnames from the HTTP app's site config (the `host` matcher). This is useful with plugins that create sites on the fly (for example [caddy-docker-proxy](https://github.com/lucaslorentz/caddy-docker-proxy)).

Caddyfile:

```
{
	dynamic_dns {
		provider cloudflare {env.CLOUDFLARE_API_TOKEN}
		domains {
			example.com @
		}
		dynamic_domains
	}
}

cool.example.com {
	respond "hi"
}
```
</details>

<details>
<summary>IP updaters (ZTE IPv6 firewall)</summary>

On some ZTE home gateways the IPv6 port-open rule is bound to a full `/128` address. When the ISP prefix changes, DNS may update while the router rule goes stale.

Optional `ip_updater` modules run on the **same trigger as DNS** (public IP set changed), not on every idle poll. Failures are logged and retried on the next interval; they do not block DNS. Omit `ip_updater` for upstream-only behaviour.

| Directive | Required | Description |
|-----------|----------|-------------|
| `router` | yes | Admin UI base URL, e.g. `http://192.168.1.1` |
| `password` | yes | Admin password (`{env.*}` / `{file.*}` recommended) |
| `name` | yes | Firewall rule name (same name → update in place) |
| `port` | yes | Single port (`MinPort` = `MaxPort`) |
| `username` | | Default `admin` |
| `protocol` | | `TCP`, `UDP`, or `BOTH` (default) |

```
{
	dynamic_dns {
		provider cloudflare {env.CLOUDFLARE_API_TOKEN}
		domains {
			example.com @
		}
		versions ipv6
		ip_source interface eth0
		check_interval 5m

		ip_updater zte_firewall {
			router   http://192.168.1.1
			username admin
			password {env.ZTE_ROUTER_PASSWORD}
			name     caddy
			port     443
			protocol BOTH
		}
	}
}
```

Notes:

- Uses the first IPv6 address from the IP sources; IPv4-only configs are a no-op for this updater.
- The gateway API writes a full address with `PrefixLen=128` (no suffix/MAC mask).
- Compatible with the `vuejsonData` admin API (`security_firewall_ipv6_data`), including session preempt/logout.
- Other updaters: implement `IPUpdater`, register as `dynamic_dns.ip_updaters.<name>`, configure with `ip_updater <name> { … }`.
</details>
