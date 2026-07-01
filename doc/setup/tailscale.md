# Tailscale

[日本語](tailscale.ja.md)

This page covers the extra settings to check when exposing the bridge and Lore remote through Tailscale.

Use the MagicDNS FQDN as the stable host name.

```text
<auth-host> = <machine>.<tailnet>.ts.net
<lore-host> = <machine>.<tailnet>.ts.net
```

If the bridge and `loreserver` run on the same machine, these two values can be the same host.

## loreserver

Use the Tailscale FQDN for the gRPC auth endpoint, JWT issuer, and JWT audience.

```toml
[environment.endpoint]
auth_url = "https://<machine>.<tailnet>.ts.net:8081"

[server.auth]
jwt_issuer = "https://<machine>.<tailnet>.ts.net"
jwt_audience = ["lore-service", "<machine>.<tailnet>.ts.net"]

[server.auth.jwk]
endpoint = "http://127.0.0.1:8080/.well-known/jwks.json"
```

If `loreserver` runs on the same machine as the bridge, the JWKS endpoint can remain loopback.

If `loreserver` runs elsewhere, set `endpoint` to a bridge HTTP URL reachable from `loreserver`.

## Bridge

Use the same host names on the bridge side.

```yaml
jwt:
  issuer: "https://<machine>.<tailnet>.ts.net"
  audience:
    - "lore-service"
    - "<machine>.<tailnet>.ts.net"

lore:
  auth_url: "https://<machine>.<tailnet>.ts.net:8081"
  default_remote_url: "lore://<machine>.<tailnet>.ts.net:41337"
```

Restart `lore-auth-server` and `loreserver` after changing JWT, JWKS, auth endpoint, or signing key settings.

## ReBAC allowlist

When `auth_url` uses a Tailscale FQDN, the bridge may see the caller as the Tailscale IP even if both processes run on the same VPS.

Add the `loreserver` Tailscale IP to `security.rebac_allowed_peer_cidrs` when needed.

```yaml
security:
  rebac_allowed_peer_cidrs:
    - "127.0.0.1/32"
    - "::1/128"
    - "<tailscale-ip>/32"
```

## TLS SAN

The bridge gRPC TLS certificate must include the Tailscale FQDN used by `auth_url`.

```bash
mkcert \
  -cert-file /etc/lore-auth/grpc/tls.crt \
  -key-file /etc/lore-auth/grpc/tls.key \
  <machine>.<tailnet>.ts.net \
  <tailscale-ip> \
  localhost \
  127.0.0.1
```

If clients connect by IP address, the IP address must be present as an IP SAN.

To reduce OAuth redirect URI, JWT audience, and TLS SAN mismatches, normally use the MagicDNS FQDN consistently instead of mixing FQDN and IP address forms.
