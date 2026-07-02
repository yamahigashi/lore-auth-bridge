# Identity Providers

[English](identity-providers.md)

identity provider は、bridge がユーザーの identity を得るための外部サービスまたは認証元です。

bridge は、IdP から受け取った identity を bridge DB のユーザーと照合します。

IdP を使わない運用では、管理 CLI で authn token を発行できます。

Google OIDC は、この文書セットで扱う IdP 設定の具体例です。

Keycloak、Auth0、社内 OIDC などは、標準 OIDC discovery と authorization code flow を提供していれば generic `oidc` adapter で扱えます。

config の provider key は provider instance ID です。

`google`、`keycloak-prod`、`auth0-main` のような安定した key を使い、adapter 種別だけを表す `oidc` を key にしないでください。

## IdP login

IdP login では、ユーザーはブラウザで IdP にログインします。

bridge は IdP から返された external identity を、既存の binding または pending invitation と照合します。

登録済みユーザーならブラウザセッションまたは CLI auth session が完了します。

未登録ユーザーなら token は発行されず、whoami 画面に identity が表示されます。

IdP が確認済み email を返す場合、管理者は `lore-authctl --config <cfg> user invite --idp <provider-id> --email <address>` でユーザーを事前登録できます。

provider が `trust.email_binding: verified_email_invitation` を設定しており、招待したユーザーの初回 login で IdP から返された確認済み email が一致すると、bridge は external identity binding を作成し、その login を完了します。

`trust.allowed_email_domains` を設定している場合、invitation を消費する前に email domain もその一覧に一致する必要があります。

`identity_providers` を設定している場合、`user invite` には `--idp` が必要です。

Google OIDC を使う場合の具体的な設定は [Google OIDC](google-oidc.ja.md) を参照してください。

## 管理 CLI で発行する authn token

IdP login を使わない場合は、管理 CLI で authn token を発行できます。

管理 CLI で user を登録し、`lore-authctl --config <cfg> token mint-authn <email>` で authn token を発行します。

```bash
lore-authctl --config .quickstart/lore-auth.yaml user add \
  --email manual@example.com \
  --name "Manual User"

lore-authctl --config .quickstart/lore-auth.yaml token mint-authn \
  manual@example.com \
  --out .quickstart/authn.jwt
```

この方法では、管理者が発行した token を `lore auth login --token-type lore` に渡して Lore CLI に登録します。
