Dynamic DNS app for Caddy
=========================

This is a simple Caddy app that keeps your DNS pointed to your machine; especially useful if your IP address is not static.

It simply queries a service (an "IP source") for your public IP address every so often and if it changes, it updates the DNS records with your configured provider. It supports multiple IPs, including IPv4 and IPv6, as well as redundant IP sources.

IP sources and DNS providers are modular. This app comes with IP source modules. However, you'll need to plug in [a DNS provider module from caddy-dns](https://github.com/caddy-dns) so that your DNS records can be updated.

> [!NOTE]
> This is not an official repository of the [Caddy Web Server](https://github.com/caddyserver) organization.

### Sample configurations

<details>
<summary>Minimal example config</summary>

Caddyfile config ([global options](https://caddyserver.com/docs/caddyfile/options)):

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

Here's a more filled-out config, will all the options used.

This config prefers to get the IP address locally via UPnP (if edge router has UPnP enabled, of course), but if that fails, will fall back to querying `icanhazip.com` for the IP address. If those fail, it will try to find the IP address from the eth0 interface. It then updates records for `example.com`, `www.example.com`, and `subdomain.example.net`. Notice how the zones and subdomains are separate; this eliminates ambiguity since we don't have to try to be clever and figure out the zone via recursive, authoritative DNS lookups. We also check every 5 minutes instead of 30 minutes (default), and set a TTL of 1 hour for the records.

The interface option will return at most 1 IPv4 and 1 IPv6 address. It will only return addresses that are not [private according to RFC 1918 (IPv4) and RFC 4193 (IPv6)](https://pkg.go.dev/net#IP.IsPrivate), and is a [global unicast address according to RFC 1122, RFC 4632, and RFC 4291 with the exception of IPv4 directed broadcast addresses](https://pkg.go.dev/net#IP.IsGlobalUnicast).

Note that it's redundant to specify both IP versions in the config, since the default is to enable both IPv4 and IPv6. It's purpose is to allow disabling one or the other if your server is only reachable via one of the versions. It's included in this config example for posterity.

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
			example.com
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
			example.com
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

There is an option `dynamic_domains` that can scan through the configured domains configured in this Caddy instance and will try to manage the DNS of those domains. 

Note:
* Only host matchers at the top-level of server routes will get managed.
* [`on_demand`](https://caddyserver.com/docs/automatic-https#on-demand-tls) is not supported because the hostname isn't known at config time.

Caddyfile config:

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

Equivalent JSON config:
```jsonc
{
	"apps": {
		"dynamic_dns": {
			"domains": {
				"example.com": ["@", "www"],
				"example.net": ["subdomain"]
			},
			"dynamic_domains": true,
			"dns_provider": {
				"name": "cloudflare",
				"api_token": "topsecret"
			},
		},
		"servers": {
			"srv0": {
				"routes": [{
					// omitted
					"match": [{
						"host": [
							// This domain will be managed.
							"cool.example.com"
						]
					}]
				}, {
					// omitted
					"match": [{
						"host": [
							// This domain will *NOT* be managed because it's not configured in dynamic_dns.
							"another.host.com"
						]
					}]
				}]
			}
		}
	}
}
```
</details>
