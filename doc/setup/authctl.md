# Authctl

[日本語](authctl.ja.md)

`lore-authctl` is the administrative CLI for the bridge.

It manages users, groups, repositories, grants, signing keys, and manually issued tokens.

The examples below store the config path in a variable.

```bash
CONFIG=.quickstart/lore-auth.yaml
```

## init-db

Create the SQLite database and apply migrations.

```bash
lore-authctl --config "$CONFIG" init-db
```

## key generate

Create an RS256 signing key and register public JWK metadata in the DB.

```bash
lore-authctl --config "$CONFIG" key generate --kid manual-1
```

`--kid` must match `jwt.active_kid`.

## key list

```bash
lore-authctl --config "$CONFIG" key list
```

## user invite

When IdP login is enabled, an administrator can preregister a user by provider ID and email.

```bash
PROVIDER_ID=company-sso

lore-authctl --config "$CONFIG" user invite \
  --idp "$PROVIDER_ID" \
  --email alice@example.com \
  --name "Alice Example"
```

This registration alone does not issue a token.

When the user opens `/login` and the IdP returns a verified email that matches the invitation, that login becomes usable.

`--idp` reads the provider instance from `identity_providers.providers` and fills the stored provider ID and issuer.

When `identity_providers` is configured, `user invite` requires `--idp`.

## user add

```bash
lore-authctl --config "$CONFIG" user add \
  --email manual@example.com \
  --name "Manual User"
```

`user add` creates an active bridge principal.

It does not create an external IdP binding.

Use `user invite` for IdP login.

## user list

```bash
lore-authctl --config "$CONFIG" user list
```

## user disable

```bash
lore-authctl --config "$CONFIG" user disable manual@example.com
```

Disabled users are rejected during token exchange.

## repo add

Repositories are normally registered through ReBAC `CreateResource` calls from `loreserver`.

Use the following command for manual registration.

```bash
lore-authctl --config "$CONFIG" repo add \
  manual-repo \
  --remote lore://localhost:41337/manual-repo \
  --lore-repository-id 11111111111111111111111111111111
```

The JWT `resources[].resource_id` value is `urc-{lore_repository_id}`.

It is not the repository name.

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

Subjects use the form `user:<email-or-id>`, `group:<name>`, or `service_account:<id>`.

This documentation uses `writer` for repository operations.

It does not cover using `reader` as a read-only role.

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

Check the bridge-side authorization backend decision.

```bash
lore-authctl --config "$CONFIG" check \
  manual@example.com \
  manual-repo \
  write
```

The command returns `allow` when access is permitted.

## token mint-authn

When IdP login is not used, manually issue an authn token.

```bash
lore-authctl --config "$CONFIG" token mint-authn \
  manual@example.com \
  --out .quickstart/authn.jwt
```

When `--out` is specified, the token is written to a file with mode `0600`, and no token or login command is printed.

Without `--out`, the token is printed to stdout.

If `--print-login-command` is also set, the `lore auth login` command containing the token is printed to stderr.

That output can remain in terminal logs, so do not use it in shared terminals or CI logs.

Pass the issued token to `lore auth login --token-type lore`.

Use `--ttl 3600s`, `--ttl 15m`, or `--ttl 1h` to override the default authn token TTL.

```bash
lore auth login \
  --token-type lore \
  --token "$(cat .quickstart/authn.jwt)" \
  --auth-url https://localhost:8081 \
  lore://localhost:41337
```

## token mint

Manually issue a repository-scoped authz token.

During normal repository operations, the Lore CLI obtains authz tokens by calling `ExchangeUserTokenForMultiresourceToken`.

```bash
lore-authctl --config "$CONFIG" token mint \
  manual@example.com \
  manual-repo \
  --role writer
```

Without `--out`, `token mint` prints the token to stdout.

It prints a login command only when `--print-login-command` is set.
