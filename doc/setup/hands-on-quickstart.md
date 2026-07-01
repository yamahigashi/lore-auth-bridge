# Hands-on Quickstart

[日本語](hands-on-quickstart.ja.md)

This page walks through a no-IdP setup that runs the bridge, `loreserver`, and the `lore` CLI, then verifies repository creation and clone.

It does not use an external IdP.

Instead, it issues an authn token with `lore-authctl token mint-authn`.

For IdP login, see [Identity Providers](identity-providers.md).

## Prerequisites

```bash
which lore
which loreserver

go test ./...
go vet ./...
go build ./...
```

## Quickstart Directory

```bash
mkdir -p .quickstart/{keys,grpc,data,loreconfig,home}
```

## TLS

Use `mkcert` when it is available.

```bash
mkcert -cert-file .quickstart/grpc/tls.crt -key-file .quickstart/grpc/tls.key localhost 127.0.0.1
export TRUST_CERT_FILE="$(mkcert -CAROOT)/rootCA.pem"
export SSL_CERT_FILE="$TRUST_CERT_FILE"
```

If `mkcert` is unavailable, use a self-signed certificate.

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout .quickstart/grpc/tls.key \
  -out .quickstart/grpc/tls.crt \
  -days 1

export TRUST_CERT_FILE="$PWD/.quickstart/grpc/tls.crt"
export SSL_CERT_FILE="$TRUST_CERT_FILE"
```

Save the environment variables so the same values can be reused in other terminals.

```bash
cat > .quickstart/env <<EOF
export TRUST_CERT_FILE="$TRUST_CERT_FILE"
export SSL_CERT_FILE="$TRUST_CERT_FILE"
export LORE_CONFIG_PATH="$PWD/.quickstart/loreconfig"
export LORE_ENV=e2e
export HOME="$PWD/.quickstart/home"
EOF
```

## bridge config

```bash
cat > .quickstart/lore-auth.yaml <<'YAML'
server:
  listen: "127.0.0.1:8080"
  grpc_listen: "127.0.0.1:8081"
  grpc_tls_cert_file: ".quickstart/grpc/tls.crt"
  grpc_tls_key_file: ".quickstart/grpc/tls.key"
  public_base_url: "http://localhost:8080"

database:
  path: ".quickstart/lore-auth.sqlite3"

jwt:
  issuer: "http://localhost:8080"
  audience:
    - "lore-service"
    - "localhost"
  ttl_seconds: 3600
  signing_key_dir: ".quickstart/keys"
  active_kid: "manual-1"

lore:
  default_remote_url: "lore://localhost:41337"
  auth_url: "https://localhost:8081"

security:
  device_code_ttl_seconds: 600
  device_poll_interval_seconds: 3
  session_ttl_seconds: 3600
  rebac_allowed_peer_cidrs:
    - "127.0.0.1/32"
    - "::1/128"
YAML
```

## DB, key, user

```bash
CONFIG=.quickstart/lore-auth.yaml

go run ./cmd/lore-authctl init-db --config "$CONFIG"

go run ./cmd/lore-authctl key generate \
  --config "$CONFIG" \
  --kid manual-1

go run ./cmd/lore-authctl user add \
  --config "$CONFIG" \
  --email manual@example.com \
  --name "Manual User"
```

## Start bridge

Start the bridge in another terminal.

```bash
go run ./cmd/lore-auth-server -config .quickstart/lore-auth.yaml
```

Check the HTTP side.

```bash
curl -f http://localhost:8080/healthz
curl -f http://localhost:8080/.well-known/jwks.json
```

## authn token

```bash
go run ./cmd/lore-authctl token mint-authn \
  --config "$CONFIG" \
  --out .quickstart/authn.jwt \
  manual@example.com
```

## loreserver config

```bash
cat > .quickstart/loreconfig/e2e.toml <<EOF
[environment.endpoint]
auth_url = "https://localhost:8081"

[server.auth]
jwt_issuer = "http://localhost:8080"
jwt_audience = ["lore-service", "localhost"]

[server.auth.jwk]
endpoint = "http://localhost:8080/.well-known/jwks.json"

[immutable_store.local]
path = "$PWD/.quickstart/data"

[mutable_store.local]
path = "$PWD/.quickstart/data"
EOF
```

Some `loreserver` distributions require a base config bundled with Lore.

In that case, copy the bundled `default.toml` to `.quickstart/loreconfig/default.toml`.

## Start loreserver

Start `loreserver` in another terminal.

```bash
source .quickstart/env

loreserver
```

## lore CLI

Run the following in another terminal.

```bash
source .quickstart/env
```

Register the authn token.

```bash
lore auth login \
  --token-type lore \
  --token "$(cat .quickstart/authn.jwt)" \
  --auth-url https://localhost:8081 \
  lore://localhost:41337
```

Create a repository.

```bash
lore repository create lore://localhost:41337/manual-repo
```

Check that the repository was recorded by the bridge.

```bash
go run ./cmd/lore-authctl repo list --config "$CONFIG"
```

Add a grant.

```bash
go run ./cmd/lore-authctl grant add \
  --config "$CONFIG" \
  user:manual@example.com \
  manual-repo \
  writer
```

Check the ACL decision.

```bash
go run ./cmd/lore-authctl check \
  --config "$CONFIG" \
  manual@example.com \
  manual-repo \
  write
```

If the command prints `allow`, the grant is effective.

Check clone.

```bash
lore clone lore://localhost:41337/manual-repo .quickstart/clone-manual-repo
```

## Failure Checks

If `loreserver` cannot connect to the bridge, check `auth_url`, the gRPC TLS certificate, and `SSL_CERT_FILE`.

If `lore repository create` fails with `"Failed to connect to rebac service"`, `loreserver` cannot establish a TLS connection to the bridge `RebacApi`.

When using `mkcert`, especially check that `SSL_CERT_FILE` does not point to `.quickstart/grpc/tls.crt`.

With `mkcert`, `.quickstart/grpc/tls.crt` is a leaf certificate, not the trust anchor.

Set `SSL_CERT_FILE` to `$(mkcert -CAROOT)/rootCA.pem`.

```bash
openssl verify -CAfile "$SSL_CERT_FILE" .quickstart/grpc/tls.crt
```

If this check does not return `OK`, `loreserver` cannot verify the bridge gRPC TLS certificate.

After fixing `SSL_CERT_FILE`, restart `loreserver`.

If `lore auth login` succeeds but repository operations fail, authz token exchange may be failing.

Check the bridge gRPC logs, `loreserver` logs, and the result of `lore-authctl check` in that order.

If `PermissionDenied` is returned, check that the grant is attached to the repository name and that the user's email or ID resolves correctly.

If JWT verification fails, check `jwt.issuer`, `jwt_issuer` in `loreserver`, `jwt.audience`, and `jwt_audience`.

In these commands, do not mix `localhost` and `127.0.0.1`.
