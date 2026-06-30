# Local Smoke Test

[日本語](local-smoke-test.ja.md)

This page shows how to run the bridge, `loreserver`, and the `lore` CLI locally, then verify the path from repository creation to clone.

It does not use Google OIDC.

Instead, it issues an authn token with `lore-authctl token mint-authn`.

For Google OIDC login, see [Google OIDC](google-oidc.md).

## Prerequisites

```bash
which lore
which loreserver

go test ./...
go vet ./...
go build ./...
```

## Verification Directories

```bash
mkdir -p .manual/{keys,grpc,data,loreconfig,home}
```

## TLS

Use `mkcert` when it is available.

```bash
mkcert -cert-file .manual/grpc/tls.crt -key-file .manual/grpc/tls.key localhost 127.0.0.1
export TRUST_CERT_FILE="$(mkcert -CAROOT)/rootCA.pem"
export SSL_CERT_FILE="$TRUST_CERT_FILE"
```

If `mkcert` is unavailable, use a self-signed certificate.

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout .manual/grpc/tls.key \
  -out .manual/grpc/tls.crt \
  -days 1

export TRUST_CERT_FILE="$PWD/.manual/grpc/tls.crt"
export SSL_CERT_FILE="$TRUST_CERT_FILE"
```

Save the environment variables so the same values can be reused in other terminals.

```bash
cat > .manual/env <<EOF
export TRUST_CERT_FILE="$TRUST_CERT_FILE"
export SSL_CERT_FILE="$TRUST_CERT_FILE"
export LORE_CONFIG_PATH="$PWD/.manual/loreconfig"
export LORE_ENV=e2e
export HOME="$PWD/.manual/home"
EOF
```

## bridge config

```bash
cat > .manual/lore-auth.yaml <<'YAML'
server:
  listen: "127.0.0.1:8080"
  grpc_listen: "127.0.0.1:8081"
  grpc_tls_cert_file: ".manual/grpc/tls.crt"
  grpc_tls_key_file: ".manual/grpc/tls.key"
  public_base_url: "http://localhost:8080"

database:
  path: ".manual/lore-auth.sqlite3"

jwt:
  issuer: "http://localhost:8080"
  audience:
    - "lore-service"
    - "localhost"
  ttl_seconds: 3600
  signing_key_dir: ".manual/keys"
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
CONFIG=.manual/lore-auth.yaml

go run ./cmd/lore-authctl init-db --config "$CONFIG"

go run ./cmd/lore-authctl key generate \
  --config "$CONFIG" \
  --kid manual-1

go run ./cmd/lore-authctl user add \
  --config "$CONFIG" \
  --provider manual \
  --issuer local \
  --subject manual-subject \
  --email manual@example.com \
  --email-verified \
  --name "Manual User"
```

## Start bridge

Start the bridge in another terminal.

```bash
go run ./cmd/lore-auth-server -config .manual/lore-auth.yaml
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
  --out .manual/authn.jwt \
  manual@example.com
```

## loreserver config

```bash
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

Some `loreserver` distributions require a base config bundled with Lore.

In that case, copy the bundled `default.toml` to `.manual/loreconfig/default.toml`.

## Start loreserver

Start `loreserver` in another terminal.

```bash
source .manual/env

loreserver
```

## lore CLI

Run the following in another terminal.

```bash
source .manual/env
```

Register the authn token.

```bash
lore auth login \
  --token-type lore \
  --token "$(cat .manual/authn.jwt)" \
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
lore clone lore://localhost:41337/manual-repo .manual/clone-manual-repo
```

## Failure Checks

If `loreserver` cannot connect to the bridge, check `auth_url`, the gRPC TLS certificate, and `SSL_CERT_FILE`.

If `lore repository create` fails with `"Failed to connect to rebac service"`, `loreserver` cannot establish a TLS connection to the bridge `RebacApi`.

When using `mkcert`, especially check that `SSL_CERT_FILE` does not point to `.manual/grpc/tls.crt`.

With `mkcert`, `.manual/grpc/tls.crt` is a leaf certificate, not the trust anchor.

Set `SSL_CERT_FILE` to `$(mkcert -CAROOT)/rootCA.pem`.

```bash
openssl verify -CAfile "$SSL_CERT_FILE" .manual/grpc/tls.crt
```

If this check does not return `OK`, `loreserver` cannot verify the bridge gRPC TLS certificate.

After fixing `SSL_CERT_FILE`, restart `loreserver`.

If `lore auth login` succeeds but repository operations fail, authz token exchange may be failing.

Check the bridge gRPC logs, `loreserver` logs, and the result of `lore-authctl check` in that order.

If `PermissionDenied` is returned, check that the grant is attached to the repository name and that the user's email or ID resolves correctly.

If JWT verification fails, check `jwt.issuer`, `jwt_issuer` in `loreserver`, `jwt.audience`, and `jwt_audience`.

For local verification, do not mix `localhost` and `127.0.0.1`.
