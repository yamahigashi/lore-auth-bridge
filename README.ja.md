# lore-auth-bridge

[English](README.md)

`lore-auth-bridge` は、Lore の認証を外部 IdP と ACL backend に接続する Rust 製 bridge です。

Lore CLI と `loreserver` に対して、ログイン、repository 単位の token 交換、JWKS による署名検証、repository lifecycle の同期を提供します。

現在の backend は OIDC IdP、SQLite、SQLite-backed authorization policy です。

## 機能

- OIDC IdP による browser login
- 管理 CLI による user、group、repository、grant、signing key の管理
- authn token と repository scoped authz token の RS256 署名
- JWKS endpoint による public key 配信
- Lore の UCS Auth / ReBAC protocol による token exchange と resource sync

実機 `lore` / `loreserver` 0.8.4+283 で、login、repository create、token exchange、clone の通し動作を確認しています。

## はじめに読むもの

設定と運用手順は [Setup Guide](doc/setup-guide.ja.md) から読み始めてください。

主な個別手順:

- [Configuration](doc/setup/configuration.ja.md)
- [TLS](doc/setup/tls.ja.md)
- [Tailscale](doc/setup/tailscale.ja.md)
- [Signing Keys](doc/setup/signing-keys.ja.md)
- [Loreserver](doc/setup/loreserver.ja.md)
- [Authctl](doc/setup/authctl.ja.md)
- [Identity Providers](doc/setup/identity-providers.ja.md)
- [Google OIDC](doc/setup/google-oidc.ja.md)
- [Hands-on Quickstart](doc/setup/hands-on-quickstart.ja.md)

## 実行ファイル

この repository で使う主な実行ファイルは次の 3 つです。

- `lore-auth-server`: HTTP / gRPC server
- `lore-authctl`: 管理 CLI
- `lore-claimprobe`: 使用中の Lore binary に対する claim contract 検証用 CLI

## 必要環境

- Rust stable toolchain
- 実機検証時に使用する `lore` / `loreserver` binary

## 導入

release build を使う場合は、project の GitHub Releases から platform archive を取得し、`lore-auth-server`、`lore-authctl`、`lore-claimprobe` を `PATH` に置きます。

手元で変更して使う場合は、この repository を clone して次の手順で build してください。

## ビルド

Unix shell:

```bash
cargo build --release

target/release/lore-auth-server --help
target/release/lore-authctl --help
target/release/lore-claimprobe --help
```

Windows PowerShell:

```powershell
cargo build --release

.\target\release\lore-auth-server.exe --help
.\target\release\lore-authctl.exe --help
.\target\release\lore-claimprobe.exe --help
```

## 開発時の確認

Rust workspace の確認には Cargo を使います。

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Rust 製 end-to-end harness は、明示的に有効にした場合だけ実行します。

```bash
cargo build -p lore-auth-server -p lore-authctl
LORE_E2E=1 \
LORE_E2E_BRIDGE_BIN=target/debug/lore-auth-server \
LORE_E2E_AUTHCTL_BIN=target/debug/lore-authctl \
cargo test -p lore-auth-e2e -- --test-threads=1
```

## 設定と起動

設定例は [configs/lore-auth.example.yaml](configs/lore-auth.example.yaml) にあります。

database、JWT issuer / audience、signing key、IdP、TLS、`loreserver` 側の auth 設定をそろえて使います。

詳しい手順は [Setup Guide](doc/setup-guide.ja.md) を参照してください。

```bash
target/release/lore-authctl --config configs/lore-auth.example.yaml init-db
target/release/lore-auth-server --config configs/lore-auth.example.yaml
```

Windows では `.\target\release\lore-authctl.exe` と `.\target\release\lore-auth-server.exe` を使います。

## ユーザー登録

IdP login を使う場合、管理者は provider ID と email でユーザーを事前登録できます。

```bash
PROVIDER_ID=company-sso

target/release/lore-authctl --config configs/lore-auth.example.yaml user invite \
  --idp "$PROVIDER_ID" \
  --email alice@example.com \
  --name "Alice Example"
```

詳しくは [Identity Providers](doc/setup/identity-providers.ja.md) と [Authctl](doc/setup/authctl.ja.md) を参照してください。

## claim contract の検証

新しい Lore binary と組み合わせる場合は、`lore-claimprobe` で JWT claim contract を確認できます。

## セキュリティ上の注意

- private key は filesystem に `0600` で置き、DB や JWKS には出しません。
- JWT、Google client secret、private key をログや repository に残さないでください。
- `lore-authctl token mint-authn --print-login-command` と Web token page は token 本文を表示します。
  共有 terminal、CI log、browser history に残さない運用にしてください。
- signing key と token の rotation 手順は [Signing Keys](doc/setup/signing-keys.ja.md) を参照してください。

## ライセンス

MIT License.
