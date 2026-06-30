# Identity Providers

identity provider は、bridge がユーザーの identity を得るための外部サービスまたは認証元です。

bridge は、IdP から受け取った identity を bridge DB のユーザーと照合します。

IdP を使わない運用では、管理 CLI で authn token を発行できます。

Google OIDC は、この文書セットで扱う IdP 設定の具体例です。

Keycloak、Auth0、社内 OIDC などは、標準 OIDC discovery と authorization code flow を提供していれば generic `oidc` adapter で扱えます。

config の provider key は provider instance ID です。

`google`、`keycloak-prod`、`auth0-main` のような安定した key を使い、adapter 種別だけを表す `oidc` を key にしないでください。

## IdP login

IdP login では、ユーザーはブラウザで IdP にログインします。

bridge は IdP から返された `issuer` と `subject` を、登録済みユーザーと照合します。

登録済みユーザーならブラウザセッションまたは CLI auth session が完了します。

未登録ユーザーなら token は発行されず、whoami 画面に identity が表示されます。

Google OIDC では、管理者が `lore-authctl user invite --idp google --email <address>` でユーザーを登録できます。

登録したユーザーの初回 login で Google の確認済み email が一致すると、その login が完了します。

subject を既に知っている場合、管理者は `lore-authctl user add --idp <provider> --subject <subject>` でも登録できます。

`identity_providers` を設定している場合、`user invite` と `user add` には `--idp` が必要です。

Google OIDC を使う場合の具体的な設定は [Google OIDC](google-oidc.md) を参照してください。

## 管理 CLI で発行する authn token

IdP login を使わない場合は、管理 CLI で authn token を発行できます。

管理 CLI で user を登録し、`lore-authctl token mint-authn` で authn token を発行します。

次の `--provider manual`、`--issuer local`、`--subject manual-subject` は、IdP を使わない例の識別子です。

`--provider` と `--issuer` を直接指定する登録は、`identity_providers` を定義しない config だけで使います。

IdP login で subject を明示登録する場合は、利用する IdP が返す `issuer` と `subject` を登録します。

```bash
go run ./cmd/lore-authctl user add \
  --config .manual/lore-auth.yaml \
  --provider manual \
  --issuer local \
  --subject manual-subject \
  --email manual@example.com \
  --email-verified \
  --name "Manual User"

go run ./cmd/lore-authctl token mint-authn \
  --config .manual/lore-auth.yaml \
  --out .manual/authn.jwt \
  manual@example.com
```

この方法では、管理者が発行した token を `lore auth login --token-type lore` に渡して Lore CLI に登録します。
