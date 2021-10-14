Dynamic DNS app for Caddy
=========================

**⚠️ Experimental, work in progress**

This is a simple Caddy app that keeps your DNS pointed to your machine; especially useful if your IP address is not static.

It simply queries a service (an "IP source") for your public IP address every so often and if it changes, it updates the DNS records with your configured provider. It supports multiple IPs, including IPv4 and IPv6, as well as redundant IP sources.

IP sources and DNS providers are modular. This app comes with IP source modules. However, you'll need to plug in [a DNS provider module from caddy-dns](https://github.com/caddy-dns) so that your DNS records can be updated.

Example minimal Caddy config:

```json
{
	"apps": {
		"dynamic_dns": {
			"domains": {
				"example.com": ["@"]
			},
			"dns_provider": {
				"name": "cloudflare",
				"api_token": "topsecret"
			}
		}
	}
}
```

This updates DNS records for `example.com` via Cloudflare's API. (Notice how the DNS zone is separate from record names/subdomains.)

Equivalent Caddyfile config ([global options](https://caddyserver.com/docs/caddyfile/options)):

```
{
	dynamic_dns {
		provider cloudflare {env.CLOUDFLARE_API_TOKEN}
		domains {
			example.com
		}
	}
}
```

Here's a more filled-out JSON config:

```json
{
	"apps": {
		"dynamic_dns": {
			"ip_sources": [
				{
					"source": "upnp"
				},
				{
					"source": "simple_http",
					"endpoints": ["https://icanhazip.com", "https://api.ipify.org"]
				}
			],
			"domains": {
				"example.com": ["@", "www"],
				"example.net": ["subdomain"]
			},
			"dns_provider": {
				"name": "cloudflare",
				"api_token": "topsecret"
			},
			"check_interval": "5m"
		}
	}
}
```


This config prefers to get the IP address locally via UPnP (if edge router has UPnP enabled, of course), but if that fails, will fall back to querying `icanhazip.com` for the IP address. It then updates records for `example.com`, `www.example.com`, and `subdomain.example.net`. Notice how the zones and subdomains are separate; this eliminates ambiguity since we don't have to try to be clever and figure out the zone via recursive, authoritative DNS lookups. We also check every 5 minutes instead of 30 minutes (default).

Equivalent Caddyfile:

```
{
	dynamic_dns {
		provider cloudflare {env.CLOUDFLARE_API_TOKEN}
		domains {
			example.com @ www
			example.net subdomain
		}
		check_interval 5m
		ip_source upnp
		ip_source simple_http https://icanhazip.com
		ip_source simple_http https://api.ipify.org
	}
}
```

There is an option `dynamic_domains` that can scan through the configured domains configured in this Caddy instance and will try to manage the DNS of those domains.

Example Caddyfile:

```
{
	dynamic_dns {
		provider cloudflare {env.CLOUDFLARE_API_TOKEN}
		domains {
			example.com @ www
			example.net subdomain
		}
		dynamic_domains
	}
}

# This domain will be managed.
cool.example.com {
	redir http://google.com
}

# This domain will *NOT* be managed because it's not configured in dynamic_dns.
another.host.com {
	redir http://youtube.com
}
```