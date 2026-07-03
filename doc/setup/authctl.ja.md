# Authctl

[English](authctl.md)

`lore-authctl` は bridge の管理 CLI です。

user、group、repository、grant、signing key、手動発行 token を管理します。

以下の例では config path を変数にします。

```bash
CONFIG=.quickstart/lore-auth.yaml
```

## init-db

SQLite database を作成し、migration を適用します。

```bash
lore-authctl --config "$CONFIG" init-db
```

## key generate

RS256 signing key を作り、DB に public JWK metadata を登録します。

```bash
lore-authctl --config "$CONFIG" key generate --kid manual-1
```

`--kid` は `jwt.active_kid` と一致させます。

## key list

```bash
lore-authctl --config "$CONFIG" key list
```

## user invite

IdP login の通常のオンボーディングには `user invite` を使います。

このコマンドは、bridge account の作成と、確認済み email login による identity binding 予約（pending invitation）を 1 操作で行います。

この流れは、provider が `trust.email_binding: verified_email_invitation` を使う前提です。

```bash
PROVIDER_ID=company-sso

lore-authctl --config "$CONFIG" user invite \
  --idp "$PROVIDER_ID" \
  --email alice@example.com \
  --name "Alice Example"
```

この登録だけでは、まだ token は発行されません。

ユーザーが `/login` し、IdP から返された確認済み email が一致した場合、その login で利用できるようになります。

`--idp` は `identity_providers.providers` の provider instance を読み取り、保存する provider ID と issuer を補完します。

`identity_providers` を設定している場合、`user invite` には `--idp` が必要です。

## user add

`user add` は低レベルの escape hatch です。

active な bridge principal だけを作成します。

external IdP binding は作成しないため、そのままでは IdP 経由で login できません。

通常のオンボーディングには `user invite` を使います。

`user add` は、事前プロビジョニングや、email binding を使わない subject strategy の環境で使います。

```bash
lore-authctl --config "$CONFIG" user add \
  --email manual@example.com \
  --name "Manual User"
```

## user list

```bash
lore-authctl --config "$CONFIG" user list
```

## user disable

```bash
lore-authctl --config "$CONFIG" user disable manual@example.com
```

disabled user は token exchange で拒否されます。

## user enable

```bash
lore-authctl --config "$CONFIG" user enable manual@example.com
```

`user enable` は disabled user を復旧するときに使います。

## group add

```bash
lore-authctl --config "$CONFIG" group add artists \
  --description "Artists with repository access"
```

group は grant subject になります。

## group list

```bash
lore-authctl --config "$CONFIG" group list
```

## group member add

```bash
lore-authctl --config "$CONFIG" group member add artists alice@example.com
```

user argument には email address または user ID を指定できます。

## group member remove

```bash
lore-authctl --config "$CONFIG" group member remove artists alice@example.com
```

## group nest add

```bash
lore-authctl --config "$CONFIG" group nest add all-creators artists
```

`group nest` は group-in-group membership を作ります。

member group の user は、parent group に付けた grant を推移的に継承します。

cycle と自己 membership は拒否されます。

## group nest remove

```bash
lore-authctl --config "$CONFIG" group nest remove all-creators artists
```

## repo add

通常は `loreserver` からの ReBAC `CreateResource` で repository が登録されます。

手動で登録する場合は次を使います。

```bash
lore-authctl --config "$CONFIG" repo add \
  manual-repo \
  --remote lore://localhost:41337/manual-repo \
  --lore-repository-id 11111111111111111111111111111111
```

JWT claim の `resources[].resource_id` は `urc-{lore_repository_id}` です。

repo 名ではありません。

## repo list

```bash
lore-authctl --config "$CONFIG" repo list
```

## grant add

```bash
lore-authctl --config "$CONFIG" grant add \
  user:manual@example.com \
  manual-repo \
  writer
```

subject は `user:<email-or-id>` または `group:<name>` の形式です。

この文書では repository 操作用に `writer` を使います。

`reader` を read-only 権限として使う運用は、この文書では扱いません。

## grant list

```bash
lore-authctl --config "$CONFIG" grant list

lore-authctl --config "$CONFIG" grant list manual-repo
```

## grant remove

```bash
lore-authctl --config "$CONFIG" grant remove \
  user:manual@example.com \
  manual-repo \
  writer
```

## check

bridge 側の authorization backend 判定を確認します。

```bash
lore-authctl --config "$CONFIG" check \
  manual@example.com \
  manual-repo \
  write
```

許可されていれば `allow` を返します。

## token mint-authn

IdP login を使わない場合は、authn token を手動発行します。

```bash
lore-authctl --config "$CONFIG" token mint-authn \
  manual@example.com \
  --out .quickstart/authn.jwt
```

`--out` を指定すると、token は `0600` の file に書かれ、token 本文と token 入り login command は表示されません。

`--out` を指定しない場合、token は stdout に表示されます。

さらに `--print-login-command` を明示すると、token 入りの `lore auth login` command を stderr に表示します。

その出力は terminal log に残り得るため、共有 terminal や CI log では使わないでください。

発行した token は `lore auth login --token-type lore` に渡します。

既定の authn token TTL を変える場合は、`--ttl 3600s`、`--ttl 15m`、`--ttl 1h` のように指定します。

```bash
lore auth login \
  --token-type lore \
  --token "$(cat .quickstart/authn.jwt)" \
  --auth-url https://localhost:8081 \
  lore://localhost:41337
```

## token mint

repo scoped authz token を手動発行します。

通常の repository 操作では、Lore CLI が `ExchangeUserTokenForMultiresourceToken` を呼んで authz token を取得します。

```bash
lore-authctl --config "$CONFIG" token mint \
  manual@example.com \
  manual-repo \
  --role writer
```

`--out` を指定しない場合、`token mint` は token を stdout に表示します。

token 入り login command を表示するのは、`--print-login-command` を付けた場合だけです。

`/tokens` と `/tokens/mint` で browser から repository token を発行する場合は、[Operations](operations.ja.md#web-token-page) を参照してください。
