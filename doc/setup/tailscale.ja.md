# Tailscale

[English](tailscale.md)

このページでは、Tailscale 越しに bridge と Lore remote を公開する場合に追加で確認する設定を扱います。

この構成では、bridge と Lore remote を public internet に出しません。

小規模 team、固定 public IP や public DNS が不要な構成、TLS に Tailscale certificate を使いたい構成に向いています。

全体の配置判断は [Deployment](deployment.ja.md#tailscale--vpn-mesh) を参照してください。

安定した host name として MagicDNS の FQDN を使います。

```text
<auth-host> = <machine>.<tailnet>.ts.net
<lore-host> = <machine>.<tailnet>.ts.net
```

同じ machine で bridge と `loreserver` を動かす場合、二つの値は同じ host で構いません。

## loreserver

gRPC auth endpoint、JWT issuer、JWT audience には Tailscale FQDN を使います。

```toml
[environment.endpoint]
auth_url = "https://<machine>.<tailnet>.ts.net:8081"

[server.auth]
jwt_issuer = "https://<machine>.<tailnet>.ts.net"
jwt_audience = ["lore-service", "<machine>.<tailnet>.ts.net"]

[server.auth.jwk]
endpoint = "http://127.0.0.1:8080/.well-known/jwks.json"
```

`loreserver` が bridge と同じ machine で動く場合、JWKS endpoint は loopback のままで構いません。

`loreserver` を別 machine で動かす場合は、`endpoint` に `loreserver` から到達できる bridge HTTP URL を設定します。

## Bridge

bridge 側も同じ host name に揃えます。

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

JWT、JWKS、auth endpoint、signing key の設定を変えたら、`lore-auth-server` と `loreserver` を再起動します。

## ReBAC allowlist

`auth_url` に Tailscale FQDN を使うと、同じ VPS 内の接続でも bridge からは Tailscale IP に見える場合があります。

必要に応じて、`security.rebac_allowed_peer_cidrs` に `loreserver` 側の Tailscale IP を追加します。

```yaml
security:
  rebac_allowed_peer_cidrs:
    - "127.0.0.1/32"
    - "::1/128"
    - "<tailscale-ip>/32"
```

## TLS SAN

bridge gRPC TLS 証明書には、`auth_url` で使う Tailscale FQDN を含めます。

```bash
mkcert \
  -cert-file /etc/lore-auth/grpc/tls.crt \
  -key-file /etc/lore-auth/grpc/tls.key \
  <machine>.<tailnet>.ts.net \
  <tailscale-ip> \
  localhost \
  127.0.0.1
```

IP address で接続する client がある場合は、その IP address も IP SAN として必要です。

OAuth redirect URI、JWT audience、TLS SAN の不一致を減らすため、通常は FQDN と IP address を混ぜず、MagicDNS の FQDN に統一します。
