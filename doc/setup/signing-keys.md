# Signing Keys

[日本語](signing-keys.ja.md)

The bridge signs authn tokens and authz tokens with RS256.

`loreserver` fetches public keys from the bridge JWKS endpoint and verifies JWTs.

Private keys stay on the filesystem and are not stored in the DB or JWKS.

## key generate

Create the active key after applying DB migrations.

```bash
go run ./cmd/lore-authctl init-db --config .manual/lore-auth.yaml

go run ./cmd/lore-authctl key generate \
  --config .manual/lore-auth.yaml \
  --kid manual-1
```

`--kid` must match `jwt.active_kid`.

`key generate` only creates an active key.

## key list

Check registered key metadata.

```bash
go run ./cmd/lore-authctl key list --config .manual/lore-auth.yaml
```

The output contains `kid`, algorithm, status, and private key path.

## Settings

```yaml
jwt:
  signing_key_dir: ".manual/keys"
  active_kid: "manual-1"
```

`signing_key_dir` is the directory for private key files.

`active_kid` is the key ID used for signing.

`key generate` creates the private key at `signing_key_dir/<kid>.pem` and registers the public JWK and metadata in the DB.

## Permissions

Private key files are written with mode `0600`.

Make the directory readable only by the operating user.

Do not commit verification directories such as `.manual/keys` or `.probe/`.

## JWKS

After starting the bridge HTTP server, check the JWKS endpoint.

```bash
curl -f http://localhost:8080/.well-known/jwks.json
```

Configure the same endpoint on the `loreserver` side.

```toml
[server.auth.jwk]
endpoint = "http://localhost:8080/.well-known/jwks.json"
```

Also keep `jwt.issuer` aligned with `[server.auth].jwt_issuer` in `loreserver`.
