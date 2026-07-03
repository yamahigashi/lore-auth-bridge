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

## Microsoft Entra ID

`profile: entra` と `subject.strategy: entra_oid_tid` を使います。

subject は ID token の `tid` claim と `oid` claim から作られます。

```yaml
identity_providers:
  default: entra
  providers:
    entra:
      type: oidc
      profile: entra
      display_name: "Microsoft Entra ID"
      issuer: "https://login.microsoftonline.com/<tenant-id>/v2.0"
      client_id: "<application-client-id>"
      client_secret_file: "/etc/lore-auth/entra_client_secret"
      redirect_url: "https://auth.example.com/auth/entra/callback"
      scopes:
        - openid
        - email
        - profile
      pkce: required
      subject:
        strategy: entra_oid_tid
        required_tid: "<tenant-id>"
      trust:
        email_binding: verified_email_invitation
        allowed_email_domains:
          - "example.com"
```

`subject.required_tid` は accepted tenant を固定します。

multi-tenant Entra setup では tenant が混ざると subject が衝突し得るためです。

generic verified-email invitation rule も適用されます。

`user invite` を消費するには、ID token に mapped `email` claim と `email_verified=true` が含まれている必要があります。

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
