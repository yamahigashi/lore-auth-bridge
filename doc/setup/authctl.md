# Authctl

[日本語](authctl.ja.md)

`lore-authctl` is the administrative CLI for the bridge.

It manages users, groups, repositories, grants, signing keys, and manually issued tokens.

The examples below store the config path in a variable.

```bash
CONFIG=.manual/lore-auth.yaml
```

## init-db

Create the SQLite database and apply migrations.

```bash
go run ./cmd/lore-authctl init-db --config "$CONFIG"
```

## key generate

Create an RS256 signing key and register public JWK metadata in the DB.

```bash
go run ./cmd/lore-authctl key generate \
  --config "$CONFIG" \
  --kid manual-1
```

`--kid` must match `jwt.active_kid`.

## key list

```bash
go run ./cmd/lore-authctl key list --config "$CONFIG"
```

## user invite

When Google OIDC is enabled, an administrator can preregister a user by Google account email.

```bash
go run ./cmd/lore-authctl user invite \
  --config "$CONFIG" \
  --idp google \
  --email alice@example.com \
  --name "Alice Example"
```

This registration alone does not issue a token.

When the user opens `/login` and Google returns an `email_verified=true` email that matches the invitation, that login becomes usable.

`--idp` reads the provider instance from `identity_providers.providers` and fills the stored provider ID and issuer.

When `identity_providers` is configured, `user invite` requires `--idp`.

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

The `provider`, `issuer`, and `subject` values in this example are for local verification.

Use direct `--provider` and `--issuer` only for token-only configs that do not define `identity_providers`.

When explicitly registering a Google OIDC subject for real login, prefer `--idp google --subject <subject>`.

When `identity_providers` is configured, `user add` requires `--idp`.

## user list

```bash
go run ./cmd/lore-authctl user list --config "$CONFIG"
```

## user disable

```bash
go run ./cmd/lore-authctl user disable --config "$CONFIG" manual@example.com
```

Disabled users are rejected during token exchange.

## repo add

Repositories are normally registered through ReBAC `CreateResource` calls from `loreserver`.

Use the following command for manual registration.

```bash
go run ./cmd/lore-authctl repo add \
  --config "$CONFIG" \
  manual-repo \
  --remote lore://localhost:41337/manual-repo \
  --lore-repository-id 11111111111111111111111111111111
```

The JWT `resources[].resource_id` value is `urc-{lore_repository_id}`.

It is not the repository name.

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

Subjects use the form `user:<email-or-id>`, `group:<name>`, or `service_account:<id>`.

This documentation uses `writer` for repository operations.

It does not cover using `reader` as a read-only role.

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

Check the bridge-side authorization backend decision.

```bash
go run ./cmd/lore-authctl check \
  --config "$CONFIG" \
  manual@example.com \
  manual-repo \
  write
```

The command returns `allow` when access is permitted.

## token mint-authn

When logging in without Google OIDC, manually issue an authn token.

```bash
go run ./cmd/lore-authctl token mint-authn \
  --config "$CONFIG" \
  --out .manual/authn.jwt \
  manual@example.com
```

When `--out` is specified, the token is written to a file with mode `0600`, and the login command containing the token is not printed.

If `--print-login-command` is set explicitly, the `lore auth login` command containing the token is printed to stderr.

That output can remain in terminal logs, so do not use it in shared terminals or CI logs.

Pass the issued token to `lore auth login --token-type lore`.

```bash
lore auth login \
  --token-type lore \
  --token "$(cat .manual/authn.jwt)" \
  --auth-url https://localhost:8081 \
  lore://localhost:41337
```

## token mint

Manually issue a repository-scoped authz token.

During normal repository operations, the Lore CLI obtains authz tokens by calling `ExchangeUserTokenForMultiresourceToken`.

```bash
go run ./cmd/lore-authctl token mint \
  --config "$CONFIG" \
  manual@example.com \
  manual-repo \
  --role writer
```

`token mint` also avoids printing a login command containing the token unless `--print-login-command` is set.
