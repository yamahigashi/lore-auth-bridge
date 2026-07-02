# lore-goldenvec

`lore-goldenvec` は Rust 移行中の開発用ツールです。
Go 実装の `internal/adapter/rs256` signer を使い、固定入力から JWT/JWKS の golden vector を `.probe/golden/` に出力します。
リリース対象の CLI ではありません。

```bash
go run ./cmd/lore-goldenvec
```

初回実行時に `.probe/golden/key.pem` を生成し、以後は同じ鍵を再利用します。
別の鍵を使う場合は `--key` を指定します。

```bash
go run ./cmd/lore-goldenvec --out-dir .probe/golden --key .probe/golden/key.pem
```

出力:

- `authn.jwt`, `authz.jwt`
- `authn.header.json`, `authn.claims.json`
- `authz.header.json`, `authz.claims.json`
- `jwks.json`
- `key.pem`

固定値は UTC `2026-07-02T00:00:00Z`、audience `["lore-service", "127.0.0.1"]`、resource id `urc-0194b726b34e72b0b45550b88a967076` です。
