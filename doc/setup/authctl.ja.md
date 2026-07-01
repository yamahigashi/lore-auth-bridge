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
go run ./cmd/lore-authctl init-db --config "$CONFIG"
```

## key generate

RS256 signing key を作り、DB に public JWK metadata を登録します。

```bash
go run ./cmd/lore-authctl key generate \
  --config "$CONFIG" \
  --kid manual-1
```

`--kid` は `jwt.active_kid` と一致させます。

## key list

```bash
go run ./cmd/lore-authctl key list --config "$CONFIG"
```

## user invite

IdP login を使う場合、管理者は provider ID と email でユーザーを事前登録できます。

```bash
PROVIDER_ID=company-sso

go run ./cmd/lore-authctl user invite \
  --config "$CONFIG" \
  --idp "$PROVIDER_ID" \
  --email alice@example.com \
  --name "Alice Example"
```

この登録だけでは、まだ token は発行されません。

ユーザーが `/login` し、IdP から返された確認済み email が一致した場合、その login で利用できるようになります。

`--idp` は `identity_providers.providers` の provider instance を読み取り、保存する provider ID と issuer を補完します。

`identity_providers` を設定している場合、`user invite` には `--idp` が必要です。

## user add

```bash
go run ./cmd/lore-authctl user add \
  --config "$CONFIG" \
  --provider manual \
  --issuer local \
  --subject manual-subject \
  --email manual@example.com \
  --email-verified \
  --name "Manual User"
```

この例の `provider`、`issuer`、`subject` は IdP を使わない確認用です。

`--provider` と `--issuer` を直接指定するのは、`identity_providers` を定義しない token-only config の場合だけです。

IdP login で subject を明示登録する場合は、`--idp <provider-id> --subject <subject>` を優先します。

`identity_providers` を設定している場合、`user add` には `--idp` が必要です。

## user list

```bash
go run ./cmd/lore-authctl user list --config "$CONFIG"
```

## user disable

```bash
go run ./cmd/lore-authctl user disable --config "$CONFIG" manual@example.com
```

disabled user は token exchange で拒否されます。

## repo add

通常は `loreserver` からの ReBAC `CreateResource` で repository が登録されます。

手動で登録する場合は次を使います。

```bash
go run ./cmd/lore-authctl repo add \
  --config "$CONFIG" \
  manual-repo \
  --remote lore://localhost:41337/manual-repo \
  --lore-repository-id 11111111111111111111111111111111
```

JWT claim の `resources[].resource_id` は `urc-{lore_repository_id}` です。

repo 名ではありません。

## repo list

```bash
go run ./cmd/lore-authctl repo list --config "$CONFIG"
```

## grant add

```bash
go run ./cmd/lore-authctl grant add \
  --config "$CONFIG" \
  user:manual@example.com \
  manual-repo \
  writer
```

subject は `user:<email-or-id>`、`group:<name>`、`service_account:<id>` の形式です。

この文書では repository 操作用に `writer` を使います。

`reader` を read-only 権限として使う運用は、この文書では扱いません。

## grant list

```bash
go run ./cmd/lore-authctl grant list --config "$CONFIG"

go run ./cmd/lore-authctl grant list --config "$CONFIG" manual-repo
```

## grant remove

```bash
go run ./cmd/lore-authctl grant remove \
  --config "$CONFIG" \
  user:manual@example.com \
  manual-repo \
  writer
```

## check

bridge 側の authorization backend 判定を確認します。

```bash
go run ./cmd/lore-authctl check \
  --config "$CONFIG" \
  manual@example.com \
  manual-repo \
  write
```

許可されていれば `allow` を返します。

## token mint-authn

IdP login を使わない場合は、authn token を手動発行します。

```bash
go run ./cmd/lore-authctl token mint-authn \
  --config "$CONFIG" \
  --out .quickstart/authn.jwt \
  manual@example.com
```

`--out` を指定すると、token は `0600` の file に書かれ、token 入り login command は表示されません。

`--print-login-command` を明示すると、token 入りの `lore auth login` command を stderr に表示します。

その出力は terminal log に残り得るため、共有 terminal や CI log では使わないでください。

発行した token は `lore auth login --token-type lore` に渡します。

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
go run ./cmd/lore-authctl token mint \
  --config "$CONFIG" \
  manual@example.com \
  manual-repo \
  --role writer
```

`token mint` も、`--print-login-command` を付けない限り token 入り login command を stderr に出しません。
