# TLS

[日本語](tls.ja.md)

Lore auth exchange must be reachable through gRPC over TLS.

The bridge HTTP/JWKS endpoint and the `UrcAuthApi` / `RebacApi` gRPC endpoint are separate endpoints.

In the Hands-on Quickstart setup, treat HTTP as `http://localhost:8080` and gRPC TLS as `https://localhost:8081`.

## mkcert

When `mkcert` is available, using a local CA is the simplest option.

```bash
mkdir -p .quickstart/grpc

mkcert -cert-file .quickstart/grpc/tls.crt -key-file .quickstart/grpc/tls.key localhost 127.0.0.1

export TRUST_CERT_FILE="$(mkcert -CAROOT)/rootCA.pem"
export SSL_CERT_FILE="$TRUST_CERT_FILE"
```

`TRUST_CERT_FILE` is the trust anchor passed to `lore` and `loreserver`.

With `mkcert`, point it at the root CA, not the leaf certificate.

## Self-signed Certificate

If `mkcert` is unavailable, a short-lived self-signed certificate is enough for verification.

```bash
mkdir -p .quickstart/grpc

openssl req -x509 -newkey rsa:2048 -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout .quickstart/grpc/tls.key \
  -out .quickstart/grpc/tls.crt \
  -days 1

export TRUST_CERT_FILE="$PWD/.quickstart/grpc/tls.crt"
export SSL_CERT_FILE="$TRUST_CERT_FILE"
```

The certificate must include `localhost` or `127.0.0.1` as a Subject Alternative Name.

Mixing `localhost` and `127.0.0.1` across CLI commands and config makes certificate verification and JWT audience debugging harder.

Choose one host form and keep it consistent.

## Production Certificate

In production, configure the bridge gRPC endpoint with a certificate for the public hostname.

```yaml
server:
  grpc_listen: "0.0.0.0:8081"
  grpc_tls_cert_file: "/etc/lore-auth/grpc/tls.crt"
  grpc_tls_key_file: "/etc/lore-auth/grpc/tls.key"
```

Even when TLS terminates at a reverse proxy or load balancer, the `auth_url` seen by Lore must be reachable as a TLS endpoint.

## Trust Settings For loreserver And lore CLI

In that setup, pass the same `SSL_CERT_FILE` to both `loreserver` and the `lore` CLI.

```bash
export SSL_CERT_FILE="$TRUST_CERT_FILE"
export LORE_CONFIG_PATH="$PWD/.quickstart/loreconfig"
export LORE_ENV=e2e
export HOME="$PWD/.quickstart/home"
```

If `SSL_CERT_FILE` is not set, `lore auth login` may succeed while authz exchange during repository operations fails.

## Common Failure: `SSL_CERT_FILE` Points To The Leaf Certificate

Check this first when the following symptoms appear:

- `lore auth login` returns `Authentication successful`.
- `lore repository create` fails with `code: 'Internal error', message: "Failed to connect to rebac service"`.

The usual cause is that `SSL_CERT_FILE` points to the `mkcert` leaf certificate, `.quickstart/grpc/tls.crt`.

During repository creation, `loreserver` connects to `auth_url` over gRPC TLS for ReBAC sync.

TLS verification is performed through `rustls` native-roots.

When `SSL_CERT_FILE` is set, `rustls` uses only that file as the trust anchor and ignores the OS certificate store.

The `mkcert` leaf certificate is issued by the root CA (`rootCA.pem`) and is not itself a CA.

If only the leaf is trusted as the anchor, no verification path can be built for the certificate presented by the bridge, the TLS handshake fails, and `connect()` reports "Failed to connect to rebac service".

`lore auth login --token` only stores the token locally and does not make a TLS connection to the bridge.

That is why login can succeed while repository operations fail.

### Fix

When using `mkcert`, set `SSL_CERT_FILE` to the root CA, not the leaf.

```bash
export SSL_CERT_FILE="$(mkcert -CAROOT)/rootCA.pem"
```

Only with a self-signed certificate where the leaf is its own issuer should the leaf be used as `SSL_CERT_FILE`.

Environment variables are read at startup, so restart `loreserver` and any `lore` CLI process using the same variable after changing it.

### Verify

Use `openssl` to check whether `SSL_CERT_FILE` is a valid trust anchor.

```bash
openssl verify -CAfile "$SSL_CERT_FILE" .quickstart/grpc/tls.crt
```

If the command returns `OK`, the file can be used as a trust anchor.

If it returns `unable to get local issuer certificate`, `SSL_CERT_FILE` points to the leaf.

If you prefer OS store trust instead of native-roots through `SSL_CERT_FILE`, unset `SSL_CERT_FILE` and install the root CA into the OS store with `mkcert -install`.
