# Loreserver

[English](loreserver.md)

このページは、auth 有効化状態の `loreserver` が bridge を使うための設定です。

bridge 側の設定は [Configuration](configuration.ja.md) を参照してください。

bridge と Lore CLI を含めた全体フローの確認は [Hands-on Quickstart](hands-on-quickstart.ja.md) を参照してください。

## 設定ファイル

Hands-on Quickstart の構成では、`LORE_CONFIG_PATH` 配下に environment 用 TOML を置きます。

例では `.quickstart/loreconfig/e2e.toml` を使います。

```bash
mkdir -p .quickstart/loreconfig .quickstart/data .quickstart/home

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

## environment.endpoint

```toml
[environment.endpoint]
auth_url = "https://localhost:8081"
```

`auth_url` は bridge の gRPC TLS endpoint です。

`loreserver` は ReBAC sync で `ucs.auth.RebacApi` に接続します。

`lore` CLI は repository 操作時に `epic_urc.UrcAuthApi` へ authz token exchange を要求します。

この構成では、bridge config の `lore.auth_url` と同じ `https://localhost:8081` に揃えます。

`RebacApi` は loreserver 専用の service-to-service API として扱います。

stock loreserver の ReBAC client は service token metadata を送らないため、bridge では peer allowlist と network boundary で caller を制限します。

本番で gRPC endpoint を reverse proxy 経由で公開する場合は、proxy 側で `/ucs.auth.RebacApi/*` を loreserver からの通信だけに通してください。

## server.auth

```toml
[server.auth]
jwt_issuer = "http://localhost:8080"
jwt_audience = ["lore-service", "localhost"]
```

`jwt_issuer` は bridge config の `jwt.issuer` と一致させます。

`jwt_audience` は bridge config の `jwt.audience` と互換にします。

ローカルでは `lore-service` と remote host を含めます。

この例では remote host が `localhost` なので、`localhost` を入れています。

本番では実際の Lore remote host を入れます。

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

`endpoint` は bridge HTTP server の JWKS endpoint です。

gRPC endpoint ではありません。

`loreserver` はここから public key を取得して、bridge が発行した JWT を検証します。

## store path

```toml
[immutable_store.local]
path = "$PWD/.quickstart/data"

[mutable_store.local]
path = "$PWD/.quickstart/data"
```

この例では同じ作業ディレクトリを使います。

既存データを避けたい場合は `.quickstart/data` を削除してからやり直します。

## 起動

`loreserver` には、gRPC TLS 証明書を信頼するための `SSL_CERT_FILE` を渡します。

```bash
export TRUST_CERT_FILE="$(mkcert -CAROOT)/rootCA.pem"
# 自己署名証明書を使う場合:
# export TRUST_CERT_FILE="$PWD/.quickstart/grpc/tls.crt"
export SSL_CERT_FILE="$TRUST_CERT_FILE"
export LORE_CONFIG_PATH="$PWD/.quickstart/loreconfig"
export LORE_ENV=e2e
export HOME="$PWD/.quickstart/home"

loreserver
```

`TRUST_CERT_FILE` には、TLS 証明書の作成時に決めた信頼 anchor を指定します。

`mkcert` の場合は root CA、自己署名証明書の場合は生成した証明書です。

`lore` CLI を別のターミナルで動かす場合も、同じ `LORE_CONFIG_PATH`、`LORE_ENV`、`HOME`、`SSL_CERT_FILE` を設定します。

`loreserver` は起動時に bridge の JWKS endpoint から public key を取得し、設定された `jwt_issuer` と `jwt_audience` で JWT 検証を初期化します。

bridge の `jwt.issuer`、`jwt.audience`、signing key、JWKS endpoint、または `lore.auth_url` を変更して `lore-auth-server` を再起動した場合は、`loreserver` も再起動してください。

## 確認点

`loreserver` 起動時に bridge gRPC endpoint へ接続できない場合は、次を確認します。

- `auth_url` が `https://localhost:8081` などの TLS endpoint になっている。
- bridge が `server.grpc_listen` で起動している。
- `SSL_CERT_FILE` が `loreserver` から読める証明書または CA を指している。
- mkcert の場合は `.quickstart/grpc/tls.crt` ではなく root CA（例: `$(mkcert -CAROOT)/rootCA.pem`）を指している。
- `SSL_CERT_FILE` を変更したら `loreserver` を再起動している。
- `jwt_issuer` と bridge の `jwt.issuer` が一致している。
- `jwt_audience` に remote host が含まれている。
- `endpoint` が bridge HTTP server の JWKS endpoint を指している。
- bridge の JWT、JWKS、auth endpoint 関連の設定を変えた後に `loreserver` を再起動している。

`lore auth login --token` は成功するのに `lore repository create` が `"Failed to connect to rebac service"` で失敗する場合、`loreserver` の ReBAC gRPC 接続が TLS 検証で落ちている可能性が高いです。

`SSL_CERT_FILE` が正しい信頼 anchor かを次で確認してください。

```bash
openssl verify -CAfile "$SSL_CERT_FILE" .quickstart/grpc/tls.crt
```

`OK` にならない場合、`loreserver` は bridge gRPC endpoint を信頼できません。
