# Setup Guide

[English](setup-guide.md)

`lore-auth-bridge` の設定項目、TLS/JWKS、`loreserver` 連携、管理 CLI、管理 Web UI の使い方をまとめます。

`lore-auth-bridge` は Lore の `UrcAuthApi` と `RebacApi` を実装する bridge です。

ログインに使う IdP は差し替え可能です。

Google OIDC は、この文書セットで扱う具体例の一つです。

## 読む順番

次の順に読みます。

1. [構成要素](#構成要素) で bridge、`loreserver`、Lore CLI のつながりを把握します。
2. [Hands-on Quickstart](setup/hands-on-quickstart.ja.md) で、IdP を使わない単体完結の全体フローを体験します。
3. 本番向けの形を個別ページで仕上げます。

本番向けの設定ページ:

- [Deployment](setup/deployment.ja.md)
- [Configuration](setup/configuration.ja.md)
- [Operations](setup/operations.ja.md)
- [TLS](setup/tls.ja.md)
- [Signing Keys](setup/signing-keys.ja.md)
- [Loreserver](setup/loreserver.ja.md)
- [Authctl](setup/authctl.ja.md)
- [管理 Web UI](setup/admin-ui.ja.md)

IdP 連携を使う場合は、次も読みます。

- [Identity Providers](setup/identity-providers.ja.md)
- [Google OIDC](setup/google-oidc.ja.md)（Google を使う場合の例）

Tailscale 越しに bridge と Lore remote を公開する場合は、先に [Deployment](setup/deployment.ja.md#tailscale--vpn-mesh) を読み、その後に [Tailscale](setup/tailscale.ja.md) を読みます。

## 構成要素

bridge を使う構成は、主に次の要素で成り立ちます。

全体図と用語集は [README](../README.ja.md#これは何か--どう接続するか) を参照してください。

- **bridge HTTP**：JWKS、ブラウザログイン、device flow、health check を提供する。
- **bridge gRPC**：`UrcAuthApi` と `RebacApi` を TLS で提供する。
- **loreserver**：auth 有効化状態で bridge の JWKS と auth gRPC endpoint を使う。
- **lore CLI**：authn token を保存し、repo 操作時に authz token を bridge から交換取得する。

## ログインとユーザー登録

bridge は、Lore CLI が使う authn token を発行します。

authn token の元になるユーザー identity は、設定した IdP から取得するか、管理 CLI で登録します。

IdP login を使う場合、ユーザーはブラウザでログインします。

bridge は IdP から受け取った verified external identity を、予約済みの bridge user に bind します。

登録されていないユーザーには token を発行しません。

IdP login では、管理者が `lore-authctl --config <cfg> user invite --idp <provider-id> --email <email>` でユーザーの email を事前登録できます。

このオンボーディングでは `user invite` を使います。

`user add` は、email binding login に依存しない account 向けの低レベル escape hatch です。

登録したユーザーが初回 login し、IdP から返された確認済み email が一致した場合、その login で利用できるようになります。

IdP login を使わない場合は、管理 CLI で authn token を発行できます。

この場合、管理者が `lore-authctl --config <cfg> token mint-authn <email>` で token を発行し、`lore auth login --token-type lore` に渡して Lore CLI に登録します。

## 運用設定の流れ

運用では、deployment pattern、bridge の HTTP endpoint、gRPC endpoint、SQLite database、JWT issuer/audience、RS256 signing key、`loreserver` 側の auth 設定をそろえます。

IdP login を使う場合は、IdP 側の client 設定と bridge 側の設定を一致させます。

ユーザーとリポジトリ権限は `lore-authctl` で管理します。

machine layout と storage pattern は [Deployment](setup/deployment.ja.md) で選びます。

port 公開、data 配置、backup、log、recovery 手順は [Operations](setup/operations.ja.md) にまとめます。

## 全体フローの確認

bridge、`loreserver`、`lore` CLI の接続から repository create、clone までの確認手順は、単体完結の [Hands-on Quickstart](setup/hands-on-quickstart.ja.md) にあります。
