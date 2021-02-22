Dynamic DNS app for Caddy
=========================

**⚠️ Experimental, work in progress**

This is a simple Caddy app that keeps your DNS pointed to your machine; especially useful if your IP address is not static.

It simply queries a service (an "IP source") for your public IP address every so often and if it changes, it updates the DNS records with your configured provider.

The IP source and DNS providers are modular. In addition to this app module, you'll need to plug in [a DNS provider module from caddy-dns](https://github.com/caddy-dns).

Example Caddy config:

```json
{
	"apps": {
		"dynamic_dns": {
			"domain": "example.com",
			"dns_provider": {
				"name": "cloudflare",
				"api_token": "topsecret",
			}
		}
	}
}
```

Example Caddyfile config, via [global options](https://caddyserver.com/docs/caddyfile/options):
```
{
	dynamic_dns {
		domain example.com
		provider cloudflare {env.CLOUDFLARE_API_TOKEN}
		check_interval 5m
	}
}
```