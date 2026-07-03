# Hands-on Quickstart

[English](hands-on-quickstart.md)

このページでは、IdP を使わない構成で bridge、`loreserver`、`lore` CLI を起動し、repository create から clone までの流れを確認します。

外部 IdP を使わず、`lore-authctl token mint-authn` で authn token を発行します。

IdP login を使う場合は [Identity Providers](identity-providers.ja.md) を参照してください。

## 事前確認

この quickstart では、`lore` と `loreserver` が `PATH` にある必要があります。

所属組織の Lore 配布物を使うか、Lore source tree に記載された release と install path を使います。

確認した Lore docs では、配布入口として <https://github.com/EpicGames/lore/releases>、`scripts/install.sh`、`scripts/install.ps1` が案内されています。

Lore source checkout から両方の binary を build する場合は、Lore repository root で次を実行します。

```bash
cargo build --release -p lore-client --bin lore -p lore-server --bin loreserver
export PATH="$PWD/target/release:$PATH"
```

Windows では、`target\release\lore.exe` と `target\release\loreserver.exe` を含む directory を `PATH` に追加します。

この bridge は、実機 `lore` / `loreserver` 0.8.4+283 で検証済みです。

```bash
which lore
which loreserver

cargo build --release
export PATH="$PWD/target/release:$PATH"
```

## 作業ディレクトリ

```bash
mkdir -p .quickstart/{keys,grpc,data,loreconfig,home}
```

## TLS

`mkcert` がある場合は次を使います。

```bash
mkcert -cert-file .quickstart/grpc/tls.crt -key-file .quickstart/grpc/tls.key localhost 127.0.0.1
export TRUST_CERT_FILE="$(mkcert -CAROOT)/rootCA.pem"
export SSL_CERT_FILE="$TRUST_CERT_FILE"
```

`mkcert` がない場合は自己署名証明書を使います。

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

別のターミナルでも同じ値を使うため、環境変数をファイルに保存します。

```bash
cat > .quickstart/env <<EOF
export PATH="$PWD/target/release:\$PATH"
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

## DB、鍵、user

```bash
CONFIG=.quickstart/lore-auth.yaml

lore-authctl --config "$CONFIG" init-db

lore-authctl --config "$CONFIG" key generate --kid manual-1

lore-authctl --config "$CONFIG" user add \
  --email manual@example.com \
  --name "Manual User"
```

この quickstart では IdP を設定せず、後で `token mint-authn` によって authn token を発行するため、意図的に `user add` を使います。

IdP onboarding では `user invite` を使います。

## bridge 起動

別のターミナルで起動します。

```bash
source .quickstart/env

lore-auth-server --config .quickstart/lore-auth.yaml
```

HTTP 側を確認します。

```bash
curl -f http://localhost:8080/healthz
curl -f http://localhost:8080/.well-known/jwks.json
```

## authn token

```bash
lore-authctl --config "$CONFIG" token mint-authn \
  manual@example.com \
  --out .quickstart/authn.jwt
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

`loreserver` が base config を要求する配布形態では、Lore に同梱された `default.toml` が必要です。

その場合は、配布物に含まれる `default.toml` を `.quickstart/loreconfig/default.toml` にコピーします。

## loreserver 起動

別のターミナルで起動します。

```bash
source .quickstart/env

loreserver
```

## lore CLI

別のターミナルで実行します。

```bash
source .quickstart/env
```

authn token を登録します。

```bash
lore auth login \
  --token-type lore \
  --token "$(cat .quickstart/authn.jwt)" \
  --auth-url https://localhost:8081 \
  lore://localhost:41337
```

repository を作成します。

```bash
lore repository create lore://localhost:41337/manual-repo
```

bridge 側に repository が入ったことを確認します。

```bash
lore-authctl --config "$CONFIG" repo list
```

grant を付けます。

```bash
lore-authctl --config "$CONFIG" grant add \
  user:manual@example.com \
  manual-repo \
  writer
```

ACL 判定を確認します。

```bash
lore-authctl --config "$CONFIG" check \
  manual@example.com \
  manual-repo \
  write
```

`allow` が出れば grant は有効です。

clone を確認します。

```bash
lore clone lore://localhost:41337/manual-repo .quickstart/clone-manual-repo
```

## 失敗時の確認点

`loreserver` が bridge に接続できない場合は、`auth_url`、gRPC TLS 証明書、`SSL_CERT_FILE` を確認します。

`lore repository create` が `"Failed to connect to rebac service"` で失敗する場合は、`loreserver` から bridge の `RebacApi` へ TLS 接続できていません。

特に mkcert を使っている場合、`SSL_CERT_FILE` に `.quickstart/grpc/tls.crt` を指定していないか確認してください。

mkcert では `.quickstart/grpc/tls.crt` は leaf 証明書であり、信頼 anchor ではありません。

`SSL_CERT_FILE` には `$(mkcert -CAROOT)/rootCA.pem` を指定します。

```bash
openssl verify -CAfile "$SSL_CERT_FILE" .quickstart/grpc/tls.crt
```

この確認が `OK` にならない場合、`loreserver` は bridge gRPC の TLS 証明書を検証できません。

`SSL_CERT_FILE` を直した後は、`loreserver` を再起動してください。

`lore auth login` は成功するが repository 操作が失敗する場合は、authz token exchange が失敗している可能性があります。

bridge の gRPC log、`loreserver` log、`lore-authctl check` の結果を順に確認してください。

`PermissionDenied` が返る場合は、repository 名に grant を付けているか、user の email または ID が解決できているかを確認します。

JWT 検証が失敗する場合は、`jwt.issuer`、loreserver の `jwt_issuer`、`jwt.audience`、`jwt_audience` を確認します。

この手順では `localhost` と `127.0.0.1` を混ぜないでください。
