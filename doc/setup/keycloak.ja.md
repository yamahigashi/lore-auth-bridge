# Keycloak

[English](keycloak.md)

Keycloak を login に使う場合は、realm を作成または選択し、bridge 用の OpenID Connect client を作成して、その Client ID、Client secret、issuer、redirect URL を bridge に設定します。

bridge は Keycloak login で得た identity を、bridge DB に登録されたユーザーと照合します。

Keycloak login に成功しただけでは、Lore の利用者にはなりません。

このページは Keycloak の一般的な realm と client の設定手順に基づきます。Google OIDC ほど実環境で検証されているわけではありません。

## 必要なもの

Keycloak を有効にするには、次の値を用意します。

- **Realm URL**：Keycloak realm の issuer URL。
- **Client ID**：bridge 用に作成した OIDC client ID。
- **Client secret**：confidential client の secret value。
- **Redirect URL**：Keycloak login 後に Keycloak が戻す bridge の callback URL。
- **User email**：verified-email invitation を使う場合に bridge へ登録する email。

`client_secret_file` には secret の値ではなく、secret を保存したファイルパスを書きます。

Keycloak の issuer は通常 `https://{host}/realms/{realm}` 形式です。

Keycloak では `subject.strategy: oidc_sub` を使います。

永続 identity key は Keycloak OIDC の `sub` claim です。

email、username、UPN は使いません。

## Keycloak で取得する値

ユーザーを持つ Keycloak realm を作成するか、既存 realm を選びます。

Keycloak admin console の画面名や導線は変わることがあるため、以下は概念手順として扱ってください。

- Keycloak Server Administration Guide, client management: https://www.keycloak.org/docs/latest/server_admin/#assembly-managing-clients_server_administration_guide
- Keycloak OpenID Connect endpoints: https://www.keycloak.org/securing-apps/oidc-layers

## Realm

bridge に login するユーザーを含む realm を 1 つ使います。

組織で既に利用中の realm があればそれを使い、なければ専用 realm(例 `prod`)を新規作成します。

`master` realm は Keycloak 自身の管理用なので、アプリのログインには使いません。

realm、client、bridge 設定は次のように対応します。

| Keycloak 側 | bridge config 側 | 関係 |
| --- | --- | --- |
| realm 名 | `issuer` | realm 名が issuer URL の一部になります(`https://{host}/realms/{realm}`)。bridge は起動時に OIDC discovery を取得し、issuer の一致を検証します。 |
| realm 内の client | `client_id` / `client_secret_file` | client は realm に属します。issuer と client_id は同じ realm の組み合わせである必要があります。 |
| client の Valid redirect URIs | provider キー(`providers:` 直下の名前) | bridge の callback パス `/auth/{provider キー}/callback` を client 側に登録します。 |

realm issuer URL を控えます。

`sso.example.com` 上の `prod` realm なら issuer は次の値です。

```text
https://sso.example.com/realms/prod
```

bridge に設定する issuer は、Keycloak OIDC discovery が返す issuer と一致させます。

## Client

bridge 用の OpenID Connect client を作成します。

authorization code flow と、client secret を発行する confidential client または同等の client authentication 設定を使います。

### Create Client ウィザードの設定

create client ウィザードには多くの項目が並びますが、bridge に必要なのは一部だけです。

**General settings** ページ:

| 項目 | bridge 向けの値 | 理由 |
| --- | --- | --- |
| Client type | `OpenID Connect` | bridge は OIDC のみ対応します。 |
| Client ID | 任意(例 `lore-auth-bridge`) | bridge config の `client_id` と一致させます。 |
| Name / Description / Always display in UI | 任意 | 表示用の項目で、bridge の動作には影響しません。 |

**Capability config** ページ:

| 項目 | bridge 向けの値 | 理由 |
| --- | --- | --- |
| Client authentication | **On** | On にすると confidential client になり client secret が発行されます。bridge は secret 必須(`client_secret_file`)のため、デフォルトの Off のままだと token 交換が失敗します。 |
| Authorization | Off | Keycloak 自身の fine-grained authorization サービスです。repository 権限は bridge 側の ReBAC で管理するため不要です。 |
| Standard flow | **On** | authorization code flow です。bridge のブラウザログインが使う唯一のフローです。 |
| Implicit flow | Off | レガシーなブラウザフローで、使いません。 |
| Direct access grants | Off | パスワード直接渡し(ROPC)で、使いません。 |
| Service account roles | Off | client credentials によるマシンログインで、使いません。 |
| Standard Token Exchange / JWT Authorization Grant / OIDC CIBA Grant | Off | bridge では使いません。 |
| OAuth 2.0 Device Authorization Grant | Off | 紛らわしい項目です。lore CLI の device flow は「CLI と bridge の間」の仕組みで、bridge と Keycloak の間は常に standard flow です。Keycloak 側の device grant は不要です。 |
| Require PKCE | 任意 | bridge の provider 設定で `pkce: required` にすると bridge は S256 の code challenge を送ります。合わせて On にするとサーバ側でも強制できます。 |
| Require DPoP bound tokens | Off | bridge は DPoP に対応していません。 |

**Login settings** ページ:

| 項目 | bridge 向けの値 | 理由 |
| --- | --- | --- |
| Root URL | 空 | 相対 URL 解決の基点にすぎません。redirect URI を絶対 URL で入力するなら不要です。 |
| Home URL | 空 | Keycloak 自身の UI からアプリへ張るリンク先で、表示用です。 |
| Valid redirect URIs | **bridge の callback URL** | このページで唯一の必須項目です。ワイルドカードを使わず完全一致で入力します。形式は後述します。 |
| Valid post logout redirect URIs | 空 | Keycloak 起点の logout リダイレクト用です。bridge は IdP の logout フローを使いません。 |
| Web origins | 空 | ブラウザ側 JavaScript の CORS 許可リストです。bridge はサーバ側で code を交換するため不要です。 |

作成後、**Credentials** タブで client secret を取得し、`client_secret_file` が指すファイルに保存します。

bridge の callback URL を valid redirect URI として完全一致で登録します。

ローカルでは次の URI を登録します。

```text
http://localhost:8080/auth/keycloak-prod/callback
```

本番では公開 URL に合わせます。

```text
https://auth.example.com/auth/keycloak-prod/callback
```

Client ID と Client secret を保存します。

bridge config の provider key は callback path の一部です。

provider key が `keycloak-prod` なら redirect path は `/auth/keycloak-prod/callback` です。

scheme、host、port、path、末尾の slash が違うと callback は失敗します。

verified-email invitation を使う場合は、初回 login で bind するユーザーの ID token に `email` と `email_verified` が含まれるように Keycloak を設定します。

## bridge 設定

ローカルで Keycloak を試す場合は次のように設定します。

```yaml
server:
  public_base_url: "http://localhost:8080"

identity_providers:
  default: keycloak-prod
  providers:
    keycloak-prod:
      type: oidc
      profile: keycloak
      display_name: "Company SSO"
      issuer: "https://sso.example.com/realms/prod"
      client_id: "lore-auth-bridge"
      client_secret_file: ".quickstart/keycloak_client_secret"
      redirect_url: "http://localhost:8080/auth/keycloak-prod/callback"
      scopes: [openid, email, profile]
      pkce: required
      subject:
        strategy: oidc_sub
      trust:
        email_binding: verified_email_invitation
        allowed_email_domains:
          - "example.com"
```

Client secret は YAML に直接書かず、ファイルに保存します。

```bash
printf '%s' '<Keycloak client secret>' > .quickstart/keycloak_client_secret
chmod 600 .quickstart/keycloak_client_secret
```

本番では HTTPS の公開 URL を使います。

```yaml
server:
  public_base_url: "https://auth.example.com"

identity_providers:
  default: keycloak-prod
  providers:
    keycloak-prod:
      type: oidc
      profile: keycloak
      display_name: "Company SSO"
      issuer: "https://sso.example.com/realms/prod"
      client_id: "lore-auth-bridge"
      client_secret_file: "/etc/lore-auth/keycloak_client_secret"
      redirect_url: "https://auth.example.com/auth/keycloak-prod/callback"
      scopes: [openid, email, profile]
      pkce: required
      subject:
        strategy: oidc_sub
      trust:
        email_binding: verified_email_invitation
        allowed_email_domains:
          - "example.com"
```

`profile: keycloak` は、Keycloak 用の名前で generic OIDC path を使います。

実装は Keycloak に Google hosted-domain check を適用しません。

`trust.personal_accounts` は `profile: google` だけで有効です。Keycloak provider には設定しないでください。

Keycloak では `subject.strategy: oidc_sub` を使います。

config validator は、unstable identity key として `email`、`upn`、`preferred_username` を拒否します。

正確な `trust.email_binding` と `trust.allowed_email_domains` の規則は [Configuration](configuration.ja.md#identity_providers) を参照してください。

## ユーザー登録

Keycloak login が成功しても、対応するユーザーが bridge DB に登録されていなければ token は発行されません。

通常は、管理者が対象ユーザーの email を登録します。

```bash
lore-authctl --config .quickstart/lore-auth.yaml user invite \
  --idp keycloak-prod \
  --email '<Keycloak user email>' \
  --name '<display name>'
```

この時点では Keycloak account との連携がまだ完了していないため、token は発行されません。

招待されていない場合、token は発行されません。

招待を作成してから、もう一度 `/login` を開くと bridge のブラウザセッションが作成されます。

```text
http://localhost:8080/login
```

## 動作

bridge は callback で Keycloak ID token を検証します。

検証後、provider ID、issuer、OIDC `sub` subject を `external_identities` と照合します。

active な binding があれば、ブラウザセッションまたは CLI auth session が完了します。

active な binding がない場合は、[Configuration](configuration.ja.md#identity_providers) の generic invitation-binding policy が適用されます。

binding または invitation と照合できない場合は token を発行せず、whoami 画面を表示します。

## よくある失敗

callback handling が失敗する場合は、Keycloak の valid redirect URI と `identity_providers.providers.keycloak-prod.redirect_url` が完全一致しているか確認します。

Keycloak が invalid client を返す場合は、bridge の Client ID が Keycloak client と一致し、`client_secret_file` が現在の secret を含むファイルを指しているか確認します。

Keycloak login は成功しているのに Lore token が発行されない場合は、`lore-authctl --config <cfg> user invite --idp keycloak-prod` で verified email を招待してから login をやり直します。

invitation が消費されない場合は、ID token に `email` と `email_verified` が含まれ、`trust.allowed_email_domains` を設定しているときは email domain がその一覧に含まれるか確認します。

bridge が `trust.personal_accounts` は Google だけで有効だと報告する場合は、Keycloak provider から削除します。

`identity_providers.providers.keycloak-prod.client_id`、`identity_providers.providers.keycloak-prod.client_secret_file`、`identity_providers.providers.keycloak-prod.redirect_url` のどれかが空の場合、Keycloak login は有効になりません。
