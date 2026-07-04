# Microsoft Entra ID

[English](entra-id.md)

Microsoft Entra ID を login に使う場合は、tenant に Web application を登録し、その Application client ID、client secret、redirect URL を bridge に設定します。

bridge は Entra ID login で得た identity を、bridge DB に登録されたユーザーと照合します。

Entra ID login に成功しただけでは、Lore の利用者にはなりません。

このページは Microsoft Entra ID の一般的な app registration 手順に基づきます。Google OIDC ほど実環境で検証されているわけではありません。

## 必要なもの

Microsoft Entra ID を有効にするには、次の値を用意します。

- **Tenant ID**：bridge が受け入れる Directory tenant ID。
- **Application client ID**：Entra app registration の application ID。
- **Client secret**：app registration で作成した secret value。
- **Redirect URL**：Entra ID login 後に Entra ID が戻す bridge の callback URL。
- **User email**：verified-email invitation を使う場合に bridge へ登録する email。

`client_secret_file` には secret の値ではなく、secret を保存したファイルパスを書きます。

issuer には `https://login.microsoftonline.com/{tenant}/v2.0` 形式の tenant 固定 URL を使います。

`subject.required_tid` には Directory tenant ID を設定します。

Entra ID の bridge subject は、ID token の `tid` claim と `oid` claim から作ります。

email、UPN、`preferred_username` は使いません。

## Microsoft Entra で取得する値

Microsoft Entra ID で app registration を作成するか、既存のものを選びます。

Microsoft Entra admin center の画面名や導線は変わることがあるため、以下は概念手順として扱ってください。

- Register an application in Microsoft Entra ID: https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app
- Microsoft identity platform OpenID Connect: https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc

## App registration

bridge 用の app registration を作成します。

多くの bridge deployment では、Lore user を持つ tenant に対する single-tenant app registration を使います。

Application client ID と Directory tenant ID を控えます。

application を Web application として設定し、bridge の callback URL を完全一致で登録します。

ローカルでは次の URI を登録します。

```text
http://localhost:8080/auth/entra/callback
```

本番では公開 URL に合わせます。

```text
https://auth.example.com/auth/entra/callback
```

app registration の client secret を作成し、表示されている間に secret value を控えます。

Entra ID 側の redirect URI と、bridge config の `identity_providers.providers.entra.redirect_url` は同じ文字列にします。

scheme、host、port、path、末尾の slash が違うと callback は失敗します。

## bridge 設定

ローカルで Entra ID を試す場合は次のように設定します。

```yaml
server:
  public_base_url: "http://localhost:8080"

identity_providers:
  default: entra
  providers:
    entra:
      type: oidc
      profile: entra
      display_name: "Microsoft Entra ID"
      issuer: "https://login.microsoftonline.com/<tenant-id>/v2.0"
      client_id: "<Application client ID>"
      client_secret_file: ".quickstart/entra_client_secret"
      redirect_url: "http://localhost:8080/auth/entra/callback"
      scopes: [openid, email, profile]
      pkce: required
      subject:
        strategy: entra_oid_tid
        required_tid: "<tenant-id>"
      trust:
        email_binding: verified_email_invitation
        allowed_email_domains:
          - "example.com"
```

Client secret は YAML に直接書かず、ファイルに保存します。

```bash
printf '%s' '<Entra client secret>' > .quickstart/entra_client_secret
chmod 600 .quickstart/entra_client_secret
```

本番では HTTPS の公開 URL を使います。

```yaml
server:
  public_base_url: "https://auth.example.com"

identity_providers:
  default: entra
  providers:
    entra:
      type: oidc
      profile: entra
      display_name: "Microsoft Entra ID"
      issuer: "https://login.microsoftonline.com/<tenant-id>/v2.0"
      client_id: "<Application client ID>"
      client_secret_file: "/etc/lore-auth/entra_client_secret"
      redirect_url: "https://auth.example.com/auth/entra/callback"
      scopes: [openid, email, profile]
      pkce: required
      subject:
        strategy: entra_oid_tid
        required_tid: "<tenant-id>"
      trust:
        email_binding: verified_email_invitation
        allowed_email_domains:
          - "example.com"
```

`subject.strategy: entra_oid_tid` では `subject.required_tid` が必須です。

tenant を固定することで、複数 tenant が関係する Entra setup での subject 衝突を防ぎます。

OIDC adapter は ID token の `tid` claim と `oid` claim を読み、bridge subject を `tid:oid` として保存します。

`trust.email_binding: verified_email_invitation` では、ID token に pending invitation と一致する verified email が含まれる必要があります。

正確な binding と `trust.allowed_email_domains` の規則は [Configuration](configuration.ja.md#identity_providers) を参照してください。

## ユーザー登録

Entra ID login が成功しても、対応するユーザーが bridge DB に登録されていなければ token は発行されません。

通常は、管理者が対象ユーザーの email を登録します。

```bash
lore-authctl --config .quickstart/lore-auth.yaml user invite \
  --idp entra \
  --email '<Entra user email>' \
  --name '<display name>'
```

この時点では Entra account との連携がまだ完了していないため、token は発行されません。

招待されていない場合、token は発行されません。

招待を作成してから、もう一度 `/login` を開くと bridge のブラウザセッションが作成されます。

```text
http://localhost:8080/login
```

## 動作

bridge は callback で Entra ID token を検証します。

検証後、token の tenant ID を `subject.required_tid` と照合します。

次に provider ID、issuer、`tid:oid` subject を `external_identities` と照合します。

active な binding があれば、ブラウザセッションまたは CLI auth session が完了します。

active な binding がない場合は、[Configuration](configuration.ja.md#identity_providers) の generic invitation-binding policy が適用されます。

binding または invitation と照合できない場合は token を発行せず、whoami 画面を表示します。

## よくある失敗

callback handling が失敗する場合は、Entra ID に登録した redirect URI と `identity_providers.providers.entra.redirect_url` が完全一致しているか確認します。

Entra ID login は成功しているのに Lore token が発行されない場合は、`lore-authctl --config <cfg> user invite --idp entra` で verified email を招待してから login をやり直します。

callback 後に login が拒否される場合は、ID token の `tid` claim が `subject.required_tid` と一致しているか確認します。

bridge が `entra_oid_tid` には `tid` と `oid` claim が必要だと報告する場合は、app registration と issuer が想定 tenant の Entra ID token を返しているか確認します。

invitation が消費されない場合は、ID token に想定 email が含まれ、その email が provider claim 上で verified として扱われているか確認します。

`identity_providers.providers.entra.client_id`、`identity_providers.providers.entra.client_secret_file`、`identity_providers.providers.entra.redirect_url` のどれかが空の場合、Entra ID login は有効になりません。

