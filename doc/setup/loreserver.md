# Loreserver

[日本語](loreserver.ja.md)

This page describes the `loreserver` settings required to use the bridge with auth enabled.

See [Configuration](configuration.md) for bridge-side settings.

See [Local Smoke Test](local-smoke-test.md) for a full local run.

## Config File

For local verification, place an environment TOML file under `LORE_CONFIG_PATH`.

The example uses `.manual/loreconfig/e2e.toml`.

```bash
mkdir -p .manual/loreconfig .manual/data .manual/home

cat > .manual/loreconfig/e2e.toml <<EOF
[environment.endpoint]
auth_url = "https://localhost:8081"

[server.auth]
jwt_issuer = "http://localhost:8080"
jwt_audience = ["lore-service", "localhost"]

[server.auth.jwk]
endpoint = "http://localhost:8080/.well-known/jwks.json"

[immutable_store.local]
path = "$PWD/.manual/data"

[mutable_store.local]
path = "$PWD/.manual/data"
EOF
```

Some `loreserver` distributions require a base config.

In that case, copy the `default.toml` bundled with Lore to `.manual/loreconfig/default.toml`.

## environment.endpoint

```toml
[environment.endpoint]
auth_url = "https://localhost:8081"
```

`auth_url` is the bridge gRPC TLS endpoint.

`loreserver` connects to `ucs.auth.RebacApi` for ReBAC sync.

The `lore` CLI requests authz token exchange from `epic_urc.UrcAuthApi` during repository operations.

For local verification, keep this value aligned with `lore.auth_url` in the bridge config: `https://localhost:8081`.

`RebacApi` is treated as a service-to-service API dedicated to `loreserver`.

The stock `loreserver` ReBAC client does not send service token metadata, so the bridge restricts callers through a peer allowlist and network boundary.

If the gRPC endpoint is exposed through a reverse proxy in production, restrict `/ucs.auth.RebacApi/*` at the proxy so only `loreserver` can call it.

## server.auth

```toml
[server.auth]
jwt_issuer = "http://localhost:8080"
jwt_audience = ["lore-service", "localhost"]
```

`jwt_issuer` must match `jwt.issuer` in the bridge config.

`jwt_audience` must be compatible with `jwt.audience` in the bridge config.

For local use, include `lore-service` and the remote host.

This example uses `localhost` because the remote host is `localhost`.

In production, use the real Lore remote host.

```toml
[server.auth]
jwt_issuer = "https://auth.example.com"
jwt_audience = ["lore-service", "lore.example.com"]
```

## server.auth.jwk

```toml
[server.auth.jwk]
endpoint = "http://localhost:8080/.well-known/jwks.json"
```

`endpoint` is the JWKS endpoint of the bridge HTTP server.

It is not the gRPC endpoint.

`loreserver` fetches public keys from this endpoint and verifies JWTs issued by the bridge.

## store path

```toml
[immutable_store.local]
path = "$PWD/.manual/data"

[mutable_store.local]
path = "$PWD/.manual/data"
```

Local verification uses the same working directory for both stores.

To avoid existing data, delete `.manual/data` and rerun the setup.

## Startup

Pass `SSL_CERT_FILE` to `loreserver` so it trusts the gRPC TLS certificate.

```bash
export TRUST_CERT_FILE="$(mkcert -CAROOT)/rootCA.pem"
# For a self-signed certificate:
# export TRUST_CERT_FILE="$PWD/.manual/grpc/tls.crt"
export SSL_CERT_FILE="$TRUST_CERT_FILE"
export LORE_CONFIG_PATH="$PWD/.manual/loreconfig"
export LORE_ENV=e2e
export HOME="$PWD/.manual/home"

loreserver
```

`TRUST_CERT_FILE` must point to the trust anchor selected when creating the TLS certificate.

For `mkcert`, use the root CA.

For a self-signed certificate, use the generated certificate.

When running the `lore` CLI in another terminal, set the same `LORE_CONFIG_PATH`, `LORE_ENV`, `HOME`, and `SSL_CERT_FILE`.

## Checks

If `loreserver` cannot connect to the bridge gRPC endpoint, check the following:

- `auth_url` is a TLS endpoint such as `https://localhost:8081`.
- The bridge is running on `server.grpc_listen`.
- `SSL_CERT_FILE` points to a certificate or CA readable by `loreserver`.
- With `mkcert`, `SSL_CERT_FILE` points to the root CA, for example `$(mkcert -CAROOT)/rootCA.pem`, not `.manual/grpc/tls.crt`.
- Restart `loreserver` after changing `SSL_CERT_FILE`.
- `jwt_issuer` matches the bridge `jwt.issuer`.
- `jwt_audience` includes the remote host.
- `endpoint` points to the bridge HTTP server JWKS endpoint.

If `lore auth login --token` succeeds but `lore repository create` fails with `"Failed to connect to rebac service"`, the `loreserver` ReBAC gRPC connection is probably failing TLS verification.

Check that `SSL_CERT_FILE` is the correct trust anchor.

```bash
openssl verify -CAfile "$SSL_CERT_FILE" .manual/grpc/tls.crt
```

If the result is not `OK`, `loreserver` cannot trust the bridge gRPC endpoint.
