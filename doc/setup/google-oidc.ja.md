# Google OIDC

Google OIDC をログインに使う場合は、Google Cloud で OAuth client を作り、その Client ID、Client secret、redirect URL を bridge に設定します。

bridge は Google login で得た identity を、bridge DB に登録されたユーザーと照合します。

Google login に成功しただけでは、Lore の利用者にはなりません。

## 必要なもの

Google OIDC を有効にするには、次の値を用意します。

- **Client ID**：Google Cloud の OAuth client ID。
- **Client secret**：Google Cloud の OAuth client secret。
- **Redirect URL**：Google login 後に Google が戻す bridge の callback URL。
- **User email**：登録する Google アカウントの email。

`client_secret_file` には secret の値ではなく、secret を保存したファイルパスを書きます。

通常は、管理者が email でユーザーを登録し、ユーザーの初回 login で `iss` と `sub` を記録します。

email は初回 login の照合と表示に使います。

Google identity の主キーは、login 後に記録された `iss` と `sub` です。

## Google Cloud で取得する値

Google Cloud project を選択または作成します。

次に OAuth consent screen を設定し、OAuth client ID を作成します。

Google Cloud Console の画面名や導線は変わることがあるため、迷った場合は公式ドキュメントを参照します。

- OAuth 2.0 for Web Server Applications: https://developers.google.com/identity/protocols/oauth2/web-server
- OAuth consent screen and scopes: https://developers.google.com/workspace/guides/configure-oauth-consent
- OpenID Connect: https://developers.google.com/identity/openid-connect/openid-connect

## OAuth consent screen

OAuth consent screen では、ユーザーに表示する app name、support email、利用者範囲、scope を設定します。

Workspace 内だけで使う場合は、利用者範囲を Internal にできます。

個人 Google アカウントや Workspace 外のアカウントで試す場合は External を選びます。

External の testing 状態では、ログインに使う Google アカウントを test users に追加します。

bridge が要求する scope は `openid`、`email`、`profile` です。

追加の Google API を呼ばない限り、Google Drive や Gmail などの API scope は不要です。

## OAuth client

OAuth client は Web application として作成します。

Desktop app ではありません。

Authorized redirect URIs には、bridge の callback URL を完全一致で登録します。

ローカルでは次の URI を登録します。

```text
http://localhost:8080/auth/google/callback
```

本番では公開 URL に合わせます。

```text
https://auth.example.com/auth/google/callback
```

作成後に表示される Client ID を `identity_providers.providers.google.client_id` に設定します。

Client secret はファイルに保存し、そのパスを `identity_providers.providers.google.client_secret_file` に設定します。

Google Cloud 側の Authorized redirect URI と、bridge config の `identity_providers.providers.google.redirect_url` は同じ文字列にします。

scheme、host、port、path、末尾の slash が違うと callback は失敗します。

## bridge 設定

ローカルで Google OIDC を試す場合は次のように設定します。

```yaml
server:
  public_base_url: "http://localhost:8080"

identity_providers:
  default: google
  providers:
    google:
      type: google_oidc
      display_name: "Google"
      issuer: "https://accounts.google.com"
      client_id: "<Google OAuth Client ID>"
      client_secret_file: ".manual/google_client_secret"
      redirect_url: "http://localhost:8080/auth/google/callback"
      scopes: [openid, email, profile]
      allowed_hosted_domains: []
      allow_personal_accounts: true
```

Client secret は YAML に直接書かず、ファイルに保存します。

```bash
printf '%s' '<Google OAuth Client Secret>' > .manual/google_client_secret
chmod 600 .manual/google_client_secret
```

本番では HTTPS の公開 URL を使います。

```yaml
server:
  public_base_url: "https://auth.example.com"

identity_providers:
  default: google
  providers:
    google:
      type: google_oidc
      display_name: "Google"
      issuer: "https://accounts.google.com"
      client_id: "<Google OAuth Client ID>"
      client_secret_file: "/etc/lore-auth/google_client_secret"
      redirect_url: "https://auth.example.com/auth/google/callback"
      scopes: [openid, email, profile]
      allowed_hosted_domains:
        - "example.com"
      allow_personal_accounts: false
```

`allowed_hosted_domains` は、Google ID token の `hd` claim で許可する Workspace domain です。

値を入れると、`hd` が一致しない login は拒否されます。

`allow_personal_accounts: false` にすると、`hd` claim を持たない個人 Google アカウントを拒否します。

Google Workspace だけに絞る本番運用では、`allowed_hosted_domains` を設定し、`allow_personal_accounts: false` にします。

## ユーザー登録

Google login が成功しても、対応するユーザーが bridge DB に登録されていなければ token は発行されません。

通常は、管理者が対象ユーザーの email を登録します。

```bash
go run ./cmd/lore-authctl user invite \
  --config .manual/lore-auth.yaml \
  --idp google \
  --email '<Google email>' \
  --name '<display name>'
```

この時点では Google アカウントとの連携がまだ完了していないため、token は発行されません。

ユーザーが `/login` を開き、Google が `email_verified=true` の同じ email を返した場合、その login で browser session または CLI auth session が完了します。

## subject を明示登録する場合

email 登録を使わない場合、未登録ユーザーで `/login` を開くと whoami 画面に `issuer`、`subject`、`email`、`email_verified` が表示されます。

管理者は、その `issuer` と `subject` を使ってユーザーを登録できます。

```bash
go run ./cmd/lore-authctl user add \
  --config .manual/lore-auth.yaml \
  --idp google \
  --subject '<whoami に出た subject>' \
  --email '<Google email>' \
  --email-verified \
  --name '<display name>'
```

Google の issuer は通常 `https://accounts.google.com` です。

whoami 画面に別の issuer が出た場合は、ユーザー登録前に `identity_providers.providers.google.issuer` を修正してください。

登録後にもう一度 `/login` を開くと、bridge のブラウザセッションが作成されます。

```text
http://localhost:8080/login
```

## 動作

bridge は callback で Google ID token を検証します。

検証後、ID token の `iss` と `sub` を bridge DB のユーザーと照合します。

登録済みユーザーならブラウザセッションまたは CLI auth session が完了します。

subject が未登録でも、`email_verified=true` の email が登録済みユーザーと一致すれば、bridge は login を完了します。

登録済みユーザーと照合できない場合は token を発行せず、whoami 画面を表示します。

## よくある失敗

`redirect_uri_mismatch` が出る場合は、Google Cloud 側の Authorized redirect URI と `identity_providers.providers.google.redirect_url` が完全一致しているか確認します。

External の testing 状態で login が拒否される場合は、ログインに使う Google アカウントが test users に入っているか確認します。

`identity_providers.providers.google.client_id`、`identity_providers.providers.google.client_secret_file`、`identity_providers.providers.google.redirect_url` のどれかが空の場合、Google login は有効になりません。

管理 CLI で authn token を発行する方法だけを使うなら、`identity_providers` に Google provider を設定しなくて構いません。
