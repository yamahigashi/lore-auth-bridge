# lore-auth-bridge

`lore-auth-bridge` は、Lore の認証を外部 IdP と ACL backend に接続する Go 製 bridge です。

Lore CLI と `loreserver` に対して、ログイン、repository 単位の token 交換、JWKS による署名検証、repository lifecycle の同期を提供します。

現在の backend は Google OIDC、SQLite、Casbin です。

## 機能

- Google OIDC による browser login
- 管理 CLI による user、group、repository、grant、signing key の管理
- authn token と repository scoped authz token の RS256 署名
- JWKS endpoint による public key 配信
- Lore の UCS Auth / ReBAC protocol による token exchange と resource sync

実機 `lore` / `loreserver` 0.8.4+283 で、login、repository create、token exchange、clone の通し動作を確認しています。

## はじめに読むもの

設定と運用手順は [Setup Guide](doc/setup-guide.md) から読み始めてください。

主な個別手順:

- [Configuration](doc/setup/configuration.md)
- [TLS](doc/setup/tls.md)
- [Signing Keys](doc/setup/signing-keys.md)
- [Loreserver](doc/setup/loreserver.md)
- [Authctl](doc/setup/authctl.md)
- [Identity Providers](doc/setup/identity-providers.md)
- [Google OIDC](doc/setup/google-oidc.md)
- [Local Smoke Test](doc/setup/local-smoke-test.md)

## 実行ファイル

この repository で使う主な実行ファイルは次の 3 つです。

- `lore-auth-server`: HTTP / gRPC server
- `lore-authctl`: 管理 CLI
- `lore-claimprobe`: 使用中の Lore binary に対する claim contract 検証用 CLI

## 必要環境

- Go 1.26 以降
- 実機検証時に使用する `lore` / `loreserver` binary

## 導入

Go toolchain から直接導入する場合は、公開 module path を指定します。

```bash
go install github.com/yamahigashi/lore-auth-bridge/cmd/lore-auth-server@latest
go install github.com/yamahigashi/lore-auth-bridge/cmd/lore-authctl@latest
go install github.com/yamahigashi/lore-auth-bridge/cmd/lore-claimprobe@latest
```

手元で変更して使う場合は、この repository を clone して次の手順で build してください。

## ビルド

Unix shell:

```bash
mkdir -p ./bin
go build -o ./bin/lore-auth-server ./cmd/lore-auth-server
go build -o ./bin/lore-authctl ./cmd/lore-authctl
go build -o ./bin/lore-claimprobe ./cmd/lore-claimprobe
```

Windows PowerShell:

```powershell
New-Item -ItemType Directory -Force .\bin | Out-Null
go build -o .\bin\lore-auth-server.exe ./cmd/lore-auth-server
go build -o .\bin\lore-authctl.exe ./cmd/lore-authctl
go build -o .\bin\lore-claimprobe.exe ./cmd/lore-claimprobe
```

## 開発時の確認

`go build ./...` は全 package のビルド確認用です。

複数 package を指定するため、通常は実行ファイルを残しません。

```bash
go build ./...
go test ./...
go vet ./...
```

## 設定と起動

設定例は [configs/lore-auth.example.yaml](configs/lore-auth.example.yaml) にあります。

database、JWT issuer / audience、signing key、Google OIDC、TLS、`loreserver` 側の auth 設定をそろえて使います。

詳しい手順は [Setup Guide](doc/setup-guide.md) を参照してください。

```bash
./bin/lore-authctl init-db --config configs/lore-auth.example.yaml
./bin/lore-auth-server --config configs/lore-auth.example.yaml
```

Windows では `.\bin\lore-authctl.exe` と `.\bin\lore-auth-server.exe` を使います。

## ユーザー登録

Google OIDC を使う場合、管理者は Google アカウントの email でユーザーを登録できます。

```bash
./bin/lore-authctl user invite \
  --config configs/lore-auth.example.yaml \
  --email alice@example.com \
  --name "Alice Example"
```

詳しくは [Google OIDC](doc/setup/google-oidc.md) と [Authctl](doc/setup/authctl.md) を参照してください。

## claim contract の検証

新しい Lore binary と組み合わせる場合は、`lore-claimprobe` で JWT claim contract を確認できます。

手順は [Claim Probe Runbook](doc/claimprobe.md) を参照してください。

## セキュリティ上の注意

- private key は filesystem に `0600` で置き、DB や JWKS には出しません。
- JWT、Google client secret、private key をログや repository に残さないでください。
- `lore-authctl --print-login-command` と Web token page は token 本文を表示します。
  共有 terminal、CI log、browser history に残さない運用にしてください。
- signing key と token の rotation 手順は [Signing Keys](doc/setup/signing-keys.md) を参照してください。

## ライセンス

MIT License.
