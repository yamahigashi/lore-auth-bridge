# lore-auth-bridge

[English](README.md)

`lore-auth-bridge` は、Lore の認証を外部 IdP と ACL backend に接続する Rust 製 bridge です。

Lore CLI と `loreserver` に対して、ログイン、repository 単位の token 交換、JWKS による署名検証、repository lifecycle の同期を提供します。

既定の構成では、ユーザーは OIDC IdP でログインします。

bridge は user、group、repository、grant を SQLite に保存し、その関係を ReBAC authorization engine で評価します。

## これは何か / どう接続するか

`lore-auth-bridge` は、Lore deployment、IdP、運用者が管理する access model の間に置く Lore UCS Auth / ReBAC protocol の実装です。

```text
Browser + IdP
    <---- OIDC login ----> bridge HTTP
                            /login, /device, /.well-known/jwks.json
                                      |
                                      | signs authn/authz JWTs
                                      v
lore CLI <---- repository ops ----> loreserver
    |                                  |
    | UrcAuthApi: authn token ->       | RebacApi: repository create/delete
    | repository authz token           | HTTP JWKS: JWT verification keys
    +-----------> bridge gRPC <--------+
                 epic_urc.UrcAuthApi
                 ucs.auth.RebacApi
```

ユーザーはまず、ログイン済みであることを示す **authn token** を取得します。

repository 操作時、Lore はその authn token を `UrcAuthApi` で短命の repository scoped **authz token** に交換します。

`loreserver` は `RebacApi` も呼び、repository の作成と削除を bridge に同期します。

運用上の構成要素は [Setup Guide](doc/setup-guide.ja.md#構成要素) を参照してください。

ミニ用語集:

- **UCS Auth**：Lore の認証 protocol surface です。この bridge では `epic_urc.UrcAuthApi` として提供します。
- **ReBAC**：relationship-based access control です。bridge は user -> group -> repository のような関係を評価します。
- **authn token / authz token**：authn token は auth service へのログイン証明です。authz token は permission 評価後に発行される短命の repository token です。
- **resource_id**：Lore authorization resource identifier です。形式は `urc-{lore_repository_id}` で、repository 名ではありません。
- **grant / role**：grant は user または group に対して、1 つの repository の `reader`、`writer`、`admin` role を割り当てます。この文書では通常の repository 操作に `writer` を使います。

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

## lore と loreserver の入手

運用対象の Lore deployment に合う `lore` と `loreserver` binary を使います。

Lore の参照 checkout では、release download として <https://github.com/EpicGames/lore/releases> が案内され、install script は `scripts/install.sh` と `scripts/install.ps1` にあります。

Lore を source から build する場合、確認した source は Cargo workspace を使います。

Lore repository root で次を実行します。

```bash
cargo build --release -p lore-client --bin lore -p lore-server --bin loreserver

export PATH="$PWD/target/release:$PATH"
lore --version
loreserver --help
```

Windows では、生成される binary は `target\release\lore.exe` と `target\release\loreserver.exe` です。

この bridge は、実機 `lore` / `loreserver` 0.8.4+283 で検証済みです。

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
