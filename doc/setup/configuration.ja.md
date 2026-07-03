# Configuration

[English](configuration.md)

`lore-auth.yaml` は bridge の HTTP、gRPC、DB、JWT、Lore 連携、ログイン方式、admin UI を設定します。

unknown key は、すべての config object level で parse error になります。typo や未対応 key は、file に残さず削除してください。

このページでは、各項目の意味を説明します。

全体フローの確認は [Hands-on Quickstart](hands-on-quickstart.ja.md) を参照してください。

## server

```yaml
server:
  listen: "127.0.0.1:8080"
  grpc_listen: "127.0.0.1:8081"
  grpc_tls_cert_file: ".quickstart/grpc/tls.crt"
  grpc_tls_key_file: ".quickstart/grpc/tls.key"
  public_base_url: "http://localhost:8080"
```

`listen` は HTTP server の listen address です。

HTTP server は JWKS、health check、browser login、device flow を提供します。

`grpc_listen` は `UrcAuthApi` と `RebacApi` の listen address です。

Lore CLI と loreserver が auth exchange と ReBAC sync で接続します。

`grpc_tls_cert_file` と `grpc_tls_key_file` は gRPC TLS server certificate です。

TLS の作成と信頼設定は [TLS](tls.ja.md) を参照してください。

`public_base_url` は bridge の HTTP/JWKS 側の外部 URL です。

`jwt.issuer` と揃えると検証が分かりやすくなります。

既定 port と公開方針は [Operations](operations.ja.md#ports) を参照してください。

## database

```yaml
database:
  path: ".quickstart/lore-auth.sqlite3"
```

`path` は SQLite database のパスです。

file 配置、WAL の挙動、permission、backup は [Operations](operations.ja.md#data-layout) を参照してください。

## authz

```yaml
authz:
  backend: rebac
```

`backend` は authorization evaluator を選びます。

`rebac` が唯一の supported backend であり、既定値です。

SQLite に保存した grant と group membership（nested group を含む）を authz-core ベースの ReBAC adapter で評価します。

通常の構成では `authz.backend` を省略できます。

## jwt

```yaml
jwt:
  issuer: "http://localhost:8080"
  audience:
    - "lore-service"
    - "localhost"
  ttl_seconds: 3600
  signing_key_dir: ".quickstart/keys"
  active_kid: "manual-1"
```

`issuer` は bridge が発行する JWT の `iss` です。

loreserver の `[server.auth].jwt_issuer` と一致させます。

`audience` は JWT の `aud` です。

ローカルでは `lore-service` と remote host（例：`localhost`）を含めます。

本番では `lore-service` と実際の remote host（例：`lore.example.com`）を含めます。

`ttl_seconds` は authn token の既定 TTL です。

authz token の TTL は server と CLI の起動時設定で 15 分にしています。

`signing_key_dir` は private key file を置く directory です。

`active_kid` は署名に使う active key の key ID です。

鍵の作成は [Signing Keys](signing-keys.ja.md) を参照してください。

private key directory の permission と backup は [Operations](operations.ja.md#data-layout) を参照してください。

## lore

```yaml
lore:
  default_remote_url: "lore://localhost:41337"
  auth_url: "https://localhost:8081"
```

`default_remote_url` は token mint command や UI が表示する既定の Lore remote URL です。

`auth_url` は Lore が `UrcAuthApi` と `RebacApi` に到達する auth gRPC endpoint です。

Hands-on Quickstart の構成では `https://localhost:8081` を使います。

`lore.auth_url` を省略した場合、bridge は `server.public_base_url` の HTTP scheme を `ucs-auth://` に置き換えて既定値を作ります。

たとえば `https://auth.example.com` からは `ucs-auth://auth.example.com` が作られます。

`lore.auth_url` を明示する場合、`loreserver` integration と quickstart の例では HTTPS の gRPC endpoint を使います。

config validator は `https://...` と `ucs-auth://...` を受け付けます。

## admin

```yaml
admin:
  admin_emails:
    - "admin@example.com"
```

`admin_emails` は `/admin` Web UI を有効化し、許可する admin email address を定義します。

この list を省略した場合、または空の場合、`/admin` は mount されず 404 を返します。

admin は、先に設定済みの OIDC login flow で sign in し、その後 `/admin` を開きます。

address は正規化してから比較されます。

運用手順と security note は [管理 Web UI](admin-ui.ja.md) を参照してください。

## security

```yaml
security:
  device_code_ttl_seconds: 600
  device_poll_interval_seconds: 3
  session_ttl_seconds: 3600
  admin_allowed_peer_cidrs:
    - "127.0.0.1/32"
  rebac_allowed_peer_cidrs:
    - "127.0.0.1/32"
    - "::1/128"
```

`device_code_ttl_seconds` は device flow の user code と device code の TTL です。

`device_poll_interval_seconds` は device flow の polling interval です。

Device flow は `/api/device/start`、`/device`、`/api/device/token` を使い、browserless な Lore CLI または helper が、ログイン済み user に browser で承認してもらって repository token を取得する経路です。

endpoint の動作と token handling は [Operations](operations.ja.md#device-flow) を参照してください。

`session_ttl_seconds` はブラウザセッションの TTL です。

interactive auth session に別の TTL を使う場合は、`auth_session_ttl_seconds` を設定できます。

省略した場合、または `0` の場合は `session_ttl_seconds` が使われます。

`rebac_allowed_peer_cidrs` は `ucs.auth.RebacApi` の peer allowlist です。

`RebacApi` は loreserver からの resource lifecycle sync 専用 API として扱います。

空にした場合、bridge は ReBAC gRPC method を loopback peer からだけ受けます。

loreserver が別 host で動く場合は、loreserver から bridge へ到達する送信元 CIDR を追加します。

この判定は bridge が直接受け取る TCP peer を見ます。

公開 reverse proxy が bridge の loopback listener に転送する構成では、bridge から見える peer は proxy になります。

その場合は reverse proxy 側でも `/ucs.auth.RebacApi/*` を loreserver からの通信だけに制限してください。

`admin_allowed_peer_cidrs` は `/admin` の任意の第二層 peer allowlist です。

設定した場合、bridge が直接見る TCP peer が list に含まれない admin route は 404 を返します。

reverse proxy の背後では、proxy の address を許可し、公開側の admin 送信元制限は proxy で強制してください。

この判定では `X-Forwarded-For` を信頼しません。

公開 endpoint の rate limit は reverse proxy または load balancer 側で設定します。

対象は `/api/device/start`、`/api/device/token`、`/auth/{provider}/start`、gRPC の `/epic_urc.UrcAuthApi/StartAuthSession` です。

device flow と OAuth start は匿名 caller から到達するため、IP、forwarded client IP、または edge identity に基づいて制限してください。

bridge も、これらの公開 endpoint に小さな per-peer の in-process rate limit を適用します。

この制限は defense in depth です。
reverse proxy の背後では、trusted proxy policy を実装しない限り、bridge から見える peer は proxy になります。
したがって、app 側 rate limit は edge rate limit の代替ではありません。

`RUST_LOG`、default filter、token 表示の扱い、reverse-proxy log redaction は [Operations](operations.ja.md#logs) を参照してください。

## identity_providers

```yaml
identity_providers:
  default: google
  providers:
    google:
      type: oidc
      profile: google
      display_name: "Google"
      issuer: "https://accounts.google.com"
      client_id: "xxx.apps.googleusercontent.com"
      client_secret_file: "/etc/lore-auth/google_client_secret"
      redirect_url: "https://auth.example.com/auth/google/callback"
      scopes:
        - openid
        - email
        - profile
      subject:
        strategy: oidc_sub
      trust:
        email_binding: verified_email_invitation
        hosted_domain:
          allowed: []
        personal_accounts: allow

    keycloak-prod:
      type: oidc
      profile: keycloak
      display_name: "Company SSO"
      issuer: "https://sso.example.com/realms/prod"
      client_id: "lore-auth-bridge"
      client_secret_file: "/etc/lore-auth/keycloak_client_secret"
      redirect_url: "https://auth.example.com/auth/keycloak-prod/callback"
      scopes:
        - openid
        - email
        - profile
      pkce: required
      subject:
        strategy: oidc_sub
      trust:
        email_binding: verified_email_invitation
        allowed_email_domains:
          - "example.com"
```

`identity_providers` は、login に使う identity provider instance を 1 個以上設定します。

この節を `trust.email_binding` の一次情報とします。

`default` は `providers` 配下の key を指す必要があります。

`google` や `keycloak-prod` などの provider key は、bridge 内の identity provider instance ID として保存されます。

複数 issuer や複数 tenant を扱う可能性がある場合、provider key に `oidc` のような種別名を使わないでください。

OIDC 系 provider の `redirect_url` は `/auth/{provider}/callback` にします。

Google OIDC の具体的な設定は [Google OIDC](google-oidc.ja.md) を参照してください。

`profile: google` は Google 用の trust policy check を有効にします。

`trust.hosted_domain.allowed` は、Google ID token の `hd` claim で許可する Workspace domain です。

値を入れると、`hd` がその一覧に一致しない login を拒否します。

`trust.personal_accounts: deny` は、`hd` claim を持たない個人 Google アカウントを拒否します。

`trust.hosted_domain.allowed` が空で `trust.personal_accounts` が `deny` でない場合、bridge に登録済みの Workspace アカウントと個人 Google アカウントの両方を許可します。

`trust.email_binding` は、初回 login 時に pending invitation を消費できるかどうかを制御します。

`verified_email_invitation` は、ID token に同じ provider と issuer の pending invitation に一致する確認済み email が含まれる場合だけ、IdP login が external identity binding を作れることを意味します。

`disabled` の場合、`lore-authctl user invite` は pending invitation を作成しますが、login はそれを消費しません。

既存の external identity binding は email に関係なく `provider_id`、`issuer`、`subject` で解決されます。

`trust.allowed_email_domains` は、verified email invitation を消費するときの追加条件です。

login 全体の allowlist ではありません。

設定した場合、invitation を消費する前に、ID token の email が確認済みで、domain が設定値に含まれている必要があります。

`subject.strategy: oidc_sub` は、永続 identity subject として ID token の `sub` claim を使います。

email、preferred username、UPN claim を永続 identity subject として使わないでください。
