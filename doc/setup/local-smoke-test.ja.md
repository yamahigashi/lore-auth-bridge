# Local Smoke Test

このページは、bridge、`loreserver`、`lore` CLI をローカルで起動し、repository create から clone まで動かす手順です。

Google OIDC を使わず、`lore-authctl token mint-authn` で authn token を発行します。

Google OIDC でログインする場合は [Google OIDC](google-oidc.md) を参照してください。

## 事前確認

```bash
which lore
which loreserver

go test ./...
go vet ./...
go build ./...
```

## 検証用ディレクトリ

```bash
mkdir -p .manual/{keys,grpc,data,loreconfig,home}
```

## TLS

`mkcert` がある場合は次を使います。

```bash
mkcert -cert-file .manual/grpc/tls.crt -key-file .manual/grpc/tls.key localhost 127.0.0.1
export TRUST_CERT_FILE="$(mkcert -CAROOT)/rootCA.pem"
export SSL_CERT_FILE="$TRUST_CERT_FILE"
```

`mkcert` がない場合は自己署名証明書を使います。

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

別のターミナルでも同じ値を使うため、環境変数をファイルに保存します。

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

google:
  client_id: ""
  client_secret_file: ""
  redirect_url: ""
  allowed_hosted_domains: []
  allow_personal_accounts: true

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

## DB、鍵、user

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

## bridge 起動

別のターミナルで起動します。

```bash
go run ./cmd/lore-auth-server -config .manual/lore-auth.yaml
```

HTTP 側を確認します。

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

`loreserver` が base config を要求する配布形態では、Lore に同梱された `default.toml` が必要です。

その場合は、配布物に含まれる `default.toml` を `.manual/loreconfig/default.toml` にコピーします。

## loreserver 起動

別のターミナルで起動します。

```bash
source .manual/env

loreserver
```

## lore CLI

別のターミナルで実行します。

```bash
source .manual/env
```

authn token を登録します。

```bash
lore auth login \
  --token-type lore \
  --token "$(cat .manual/authn.jwt)" \
  --auth-url https://localhost:8081 \
  lore://localhost:41337
```

repository を作成します。

```bash
lore repository create lore://localhost:41337/manual-repo
```

bridge 側に repository が入ったことを確認します。

```bash
go run ./cmd/lore-authctl repo list --config "$CONFIG"
```

grant を付けます。

```bash
go run ./cmd/lore-authctl grant add \
  --config "$CONFIG" \
  user:manual@example.com \
  manual-repo \
  writer
```

ACL 判定を確認します。

```bash
go run ./cmd/lore-authctl check \
  --config "$CONFIG" \
  manual@example.com \
  manual-repo \
  write
```

`allow` が出れば grant は有効です。

clone を確認します。

```bash
lore clone lore://localhost:41337/manual-repo .manual/clone-manual-repo
```

## 失敗時の確認点

`loreserver` が bridge に接続できない場合は、`auth_url`、gRPC TLS 証明書、`SSL_CERT_FILE` を確認します。

`lore repository create` が `"Failed to connect to rebac service"` で失敗する場合は、`loreserver` から bridge の `RebacApi` へ TLS 接続できていません。

特に mkcert を使っている場合、`SSL_CERT_FILE` に `.manual/grpc/tls.crt` を指定していないか確認してください。

mkcert では `.manual/grpc/tls.crt` は leaf 証明書であり、信頼 anchor ではありません。

`SSL_CERT_FILE` には `$(mkcert -CAROOT)/rootCA.pem` を指定します。

```bash
openssl verify -CAfile "$SSL_CERT_FILE" .manual/grpc/tls.crt
```

この確認が `OK` にならない場合、`loreserver` は bridge gRPC の TLS 証明書を検証できません。

`SSL_CERT_FILE` を直した後は、`loreserver` を再起動してください。

`lore auth login` は成功するが repository 操作が失敗する場合は、authz token exchange が失敗している可能性があります。

bridge の gRPC log、`loreserver` log、`lore-authctl check` の結果を順に確認してください。

`PermissionDenied` が返る場合は、repository 名に grant を付けているか、user の email または ID が解決できているかを確認します。

JWT 検証が失敗する場合は、`jwt.issuer`、loreserver の `jwt_issuer`、`jwt.audience`、`jwt_audience` を確認します。

ローカル確認では `localhost` と `127.0.0.1` を混ぜないでください。
