Dynamic DNS app for Caddy
=========================

**⚠️ Experimental, work in progress**

This is a simple Caddy app that keeps your DNS pointed to your machine; especially useful if your IP address is not static.

It simply queries a service (an "IP source") for your public IP address every so often and if it changes, it updates the DNS records with your configured provider.

The IP source is modular, as are the DNS providers.

Example Caddy config:

```json
{
	"apps": {
		"dynamic_dns": {
			"domain": "example.com",
			"dns_provider": {
				"provider": "cloudflare",
				"api_user": "you@yours.com",
				"api_key": "topsecret"
			}
		}
	}
}
```