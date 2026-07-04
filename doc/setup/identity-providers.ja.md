# Identity Providers

[English](identity-providers.md)

identity provider は、bridge がユーザーの identity を得るための外部サービスまたは認証元です。

bridge は、IdP から受け取った identity を bridge DB のユーザーと照合します。

IdP を使わない運用では、管理 CLI で authn token を発行できます。

config の provider key は provider instance ID です。

`google`、`entra`、`keycloak-prod` のような安定した key を使い、adapter 種別だけを表す `oidc` を key にしないでください。

## Provider 別ページ

運用する IdP に合わせて、provider 別ページを参照します。

- [Google OIDC](google-oidc.ja.md)：Google Cloud OAuth client と Google Workspace trust check。
- [Microsoft Entra ID](entra-id.ja.md)：`profile: entra` を使う Entra app registration。
- [Keycloak](keycloak.ja.md)：`profile: keycloak` を使う Keycloak realm と OIDC client 設定。

正確な `trust.email_binding` と `trust.allowed_email_domains` の挙動は [Configuration](configuration.ja.md#identity_providers) にあります。

## IdP login

IdP login では、ユーザーはブラウザで IdP にログインします。

bridge は IdP から返された external identity を、既存の binding または pending invitation と照合します。

登録済みユーザーならブラウザセッションまたは CLI auth session が完了します。

未登録ユーザーなら token は発行されず、whoami 画面に identity が表示されます。

IdP が確認済み email を返す場合、管理者は `lore-authctl --config <cfg> user invite --idp <provider-id> --email <address>` でユーザーを事前登録できます。

`trust.email_binding: verified_email_invitation` では、初回 login が招待済みの確認済み email を bind できます。正確な binding と `trust.allowed_email_domains` の規則は [Configuration](configuration.ja.md#identity_providers) を参照してください。

`identity_providers` を設定している場合、`user invite` には `--idp` が必要です。

## Google OIDC

`profile: google` と `subject.strategy: oidc_sub` を使います。

Google 固有の check では、Workspace hosted-domain policy に ID token の `hd` claim を使い、個人 Google アカウントの扱いに `trust.personal_accounts` を使います。

完全な設定は [Google OIDC](google-oidc.ja.md) を参照してください。

## Microsoft Entra ID

`profile: entra` と `subject.strategy: entra_oid_tid` を使います。

subject は ID token の `tid` claim と `oid` claim から作られます。

multi-tenant Entra setup で tenant が混ざると subject が衝突し得るため、`subject.required_tid` は必須です。

完全な設定は [Microsoft Entra ID](entra-id.ja.md) を参照してください。

## Keycloak

`profile: keycloak` と `subject.strategy: oidc_sub` を使います。

Keycloak は generic OIDC path を使い、Google hosted-domain check と personal-account check は使いません。

Keycloak では `trust.personal_accounts` を設定しないでください。

完全な設定は [Keycloak](keycloak.ja.md) を参照してください。

## 管理 CLI で発行する authn token

IdP login を使わない場合は、管理 CLI で authn token を発行できます。

管理 CLI で user を登録し、`lore-authctl --config <cfg> token mint-authn <email>` で authn token を発行します。

この節では、IdP を使わない escape hatch として意図的に `user add` を使います。

確認済み email binding を使う IdP onboarding では、前節の `user invite` を使います。

```bash
lore-authctl --config .quickstart/lore-auth.yaml user add \
  --email manual@example.com \
  --name "Manual User"

lore-authctl --config .quickstart/lore-auth.yaml token mint-authn \
  manual@example.com \
  --out .quickstart/authn.jwt
```

この方法では、管理者が発行した token を `lore auth login --token-type lore` に渡して Lore CLI に登録します。
