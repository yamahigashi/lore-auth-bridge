# Signing Keys

[English](signing-keys.md)

bridge は authn token と authz token を RS256 で署名します。

loreserver は bridge の JWKS endpoint から public key を取得し、JWT を検証します。

private key は filesystem に置き、DB と JWKS には保存しません。

## key generate

DB migration 後に active key を作ります。

```bash
go run ./cmd/lore-authctl init-db --config .quickstart/lore-auth.yaml

go run ./cmd/lore-authctl key generate \
  --config .quickstart/lore-auth.yaml \
  --kid manual-1
```

`--kid` は `jwt.active_kid` と一致させます。

`key generate` は active key の作成だけを扱います。

## key list

登録された key metadata を確認します。

```bash
go run ./cmd/lore-authctl key list --config .quickstart/lore-auth.yaml
```

出力には `kid`、algorithm、status、private key path が含まれます。

## 設定項目

```yaml
jwt:
  signing_key_dir: ".quickstart/keys"
  active_kid: "manual-1"
```

`signing_key_dir` は private key file の directory です。

`active_kid` は署名に使う key ID です。

`key generate` は `signing_key_dir/<kid>.pem` に private key を作り、DB に public JWK と metadata を登録します。

## 権限

private key file は `0600` で書き出されます。

directory は運用ユーザーだけが読める権限にしてください。

検証用の `.quickstart/keys` や `.probe/` はコミットしないでください。

## JWKS

bridge HTTP server 起動後に JWKS を確認します。

```bash
curl -f http://localhost:8080/.well-known/jwks.json
```

loreserver 側には同じ endpoint を設定します。

```toml
[server.auth.jwk]
endpoint = "http://localhost:8080/.well-known/jwks.json"
```

`jwt.issuer` と loreserver の `[server.auth].jwt_issuer` も一致させます。
