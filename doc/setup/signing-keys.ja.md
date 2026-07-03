# Signing Keys

[English](signing-keys.md)

bridge は authn token と authz token を RS256 で署名します。

loreserver は bridge の JWKS endpoint から public key を取得し、JWT を検証します。

private key は filesystem に置き、DB と JWKS には保存しません。

## key generate

DB migration 後に active key を作ります。

```bash
lore-authctl --config .quickstart/lore-auth.yaml init-db

lore-authctl --config .quickstart/lore-auth.yaml key generate --kid manual-1
```

`--kid` は `jwt.active_kid` と一致させます。

`key generate` は active key の作成だけを扱います。

## key list

登録された key metadata を確認します。

```bash
lore-authctl --config .quickstart/lore-auth.yaml key list
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

private key directory と file の permission、SQLite database と揃える backup、運用上の保存規則は [Operations](operations.ja.md#data-layout) を参照してください。

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
