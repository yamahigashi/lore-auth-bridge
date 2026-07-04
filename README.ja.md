# lore-auth-bridge

[English](README.md)

[Lore](https://lore.org/) は、Epic Games による次世代のオープンソースバージョン管理システムです。

Lore サーバをチームで共有しようとすると、Lore が外部サービスに委ねている問題に突き当たります — 誰がログインでき、誰がどの repository に触れてよいのか。Lore には CLI の `lore auth login` フローと `loreserver` の JWT 検証、つまり利用する側の両端は備わっていますが、その token を**発行する側** — IdP 連携、ユーザー管理、権限管理 — は含まれていません。

`lore-auth-bridge` はその隙間を埋めます。チームメンバーは普段使っている認証基盤(Google、Microsoft Entra ID、Keycloak などの OIDC IdP)でログインし、bridge が Lore の要求する token を発行します。ユーザー・グループ・repository ごとの権限は bridge で一元管理します。

実装は、Lore の UCS Auth / ReBAC protocol を実装する単一の Rust サービスです。OIDC ログイン、repository 単位の token exchange、JWKS 配信、repository lifecycle の同期を提供し、SQLite と ReBAC 認可エンジンの上で動作します。

## これは何か / どう接続するか

一言でいえば、bridge は 3 つの相手 — ログインする **Browser**、token を使う **lore CLI**、それを検証する **`loreserver`** — の間に立つ認証サービスです。

ユーザーから見ると、システム全体は次の 2 ステップです:

```text
 ① lore auth login を実行し、開いたブラウザで
    IdP(Google など)のサインインを承認
      │
      ▼
 ② あとは普段どおり lore clone / push
    (token の取得・交換・更新は CLI と bridge が自動で処理。
     ユーザーが token を直接扱うことはない)
```

次の図は、このステップの裏側でコンポーネントが Lore の UCS Auth / ReBAC protocol を通じてどう接続されるかを示した技術要素の図です。ユーザーが直接触れるのは上の ①② だけです。

```text
 Browser ◄──── (1) OIDC ログイン ────► IdP (Google / Entra ID / Keycloak)
    │
    │ (2) ログイン完了。bridge が authn token を発行
    ▼
 ┌──────────────────────────────────────────────────┐
 │ bridge                                           │
 │   HTTP: /login, /device, /.well-known/jwks.json  │
 │   gRPC: epic_urc.UrcAuthApi, ucs.auth.RebacApi   │
 └──────────────────────────────────────────────────┘
    ▲                            ▲
    │ (3) authn token を         │ (4) repository の作成/削除を同期
    │     repository 単位の      │     (RebacApi)
    │     authz token に交換     │ (5) JWT 検証鍵を取得
    │     (UrcAuthApi)           │     (JWKS)
    │                            │
 lore CLI ◄── (6) authz token で clone / push ──► loreserver
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
- 任意で有効化できる[管理 Web UI](doc/setup/admin-ui.ja.md): アクセスモデルの閲覧・検索、grant / group / user / repository の操作、check simulator による判定確認。全書き込みは監査ログに記録
- authn token と repository scoped authz token の RS256 署名
- JWKS endpoint による public key 配信
- Lore の UCS Auth / ReBAC protocol による token exchange と resource sync

実機 `lore` / `loreserver` 0.8.4+283 で、login、repository create、token exchange、clone の通し動作を確認しています。

## はじめに読むもの

次の 2 つの track から選びます。

1. **まず動かす**：[Hands-on Quickstart](doc/setup/hands-on-quickstart.ja.md) を使います。
   IdP を使わず、bridge、`loreserver`、`lore` CLI を起動する単体完結の手順です。
2. **本番構成を整える**：[Setup Guide](doc/setup-guide.ja.md) を読みます。
   構成要素の概要から入り、quickstart で全体を体験してから本番向けの個別設定に進みます。

本番向けの参照ページ:

- [Deployment](doc/setup/deployment.ja.md)
- [Configuration](doc/setup/configuration.ja.md)
- [Operations](doc/setup/operations.ja.md)
- [TLS](doc/setup/tls.ja.md)
- [Tailscale](doc/setup/tailscale.ja.md)
- [Signing Keys](doc/setup/signing-keys.ja.md)
- [Loreserver](doc/setup/loreserver.ja.md)
- [Authctl](doc/setup/authctl.ja.md)
- [管理 Web UI](doc/setup/admin-ui.ja.md)
- [Identity Providers](doc/setup/identity-providers.ja.md)
  - [Google OIDC](doc/setup/google-oidc.ja.md)
  - [Microsoft Entra ID](doc/setup/entra-id.ja.md)
  - [Keycloak](doc/setup/keycloak.ja.md)

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

- JWT、Google client secret、private key をログや repository に残さないでください。
- CLI と browser の一部 token flow は token 本文を表示します。
  log handling は [Operations](doc/setup/operations.ja.md#logs)、Web token page は [Operations](doc/setup/operations.ja.md#web-token-page) を参照してください。
- signing key と token の rotation 手順は [Signing Keys](doc/setup/signing-keys.ja.md) を参照してください。

## ライセンス

MIT License.
