# Operations

[日本語](operations.ja.md)

This page is the operational reference for ports, local data, backups, logs, recovery, the browser token page, and device flow.

Use it with [Configuration](configuration.md), [Authctl](authctl.md), and [Admin Web UI](admin-ui.md).

For choosing where the bridge, `loreserver`, and reverse proxy run, start with [Deployment](deployment.md).

## Ports

| Listener | Default | What runs there | Exposure |
| --- | --- | --- | --- |
| HTTP `server.listen` | `127.0.0.1:8080` | `/.well-known/jwks.json`, `/healthz`, `/login`, `/auth/{provider}/*`, `/tokens`, `/device`, `/api/device/*`, and optional `/admin` | Put behind an HTTPS reverse proxy when users or `loreserver` need to reach it. Restrict `/admin` at the edge. See [Deployment](deployment.md#reverse-proxy). |
| gRPC `server.grpc_listen` | `127.0.0.1:8081` | `epic_urc.UrcAuthApi` for auth sessions and token exchange; `ucs.auth.RebacApi` for repository create/delete sync | Expose with TLS to the Lore CLI and `loreserver`. Restrict `RebacApi` to `loreserver` with `security.rebac_allowed_peer_cidrs` or an edge ACL. See [Deployment](deployment.md#placement-principles). |

The HTTP and gRPC listeners are separate sockets.

If a reverse proxy fronts either listener, the bridge sees the proxy as the immediate TCP peer.

## Data Layout

`database.path` points to the main SQLite database file.

The server creates the parent directory when opening the database.

The database stores users, groups, repositories, grants, auth sessions, device authorizations, issued-token metadata, signing-key metadata, and admin audit entries.

Issued-token metadata does not include the JWT body.

The SQLite adapter enables WAL mode, so a running server can also create adjacent `-wal` and `-shm` files next to the main database.

Make the database directory readable and writable only by the service user.

`jwt.signing_key_dir` stores private signing-key PEM files.

On Unix, `key generate` creates the directory with mode `0700` and private key files with mode `0600`.

The database stores the public JWK and private key path, so restore the database and signing-key directory from the same backup set.

## Backups

For an offline backup, stop `lore-auth-server` and any `lore-authctl` process that may write to the DB, then copy the database and signing-key directory.

If `-wal` or `-shm` files remain beside the database after shutdown, copy them with the main database file or make a SQLite backup instead.

```bash
sudo systemctl stop lore-auth-server
cp -a /var/lib/lore-auth/lore-auth.sqlite3* /backup/lore-auth/
cp -a /etc/lore-auth/keys /backup/lore-auth/keys
```

For a live backup, use SQLite's backup mechanisms instead of copying the main database file.

Both commands below produce a single SQLite backup file.

```bash
sqlite3 /var/lib/lore-auth/lore-auth.sqlite3 ".backup '/backup/lore-auth.sqlite3'"
sqlite3 /var/lib/lore-auth/lore-auth.sqlite3 "VACUUM INTO '/backup/lore-auth-vacuum.sqlite3';"
```

Back up the signing-key directory at the same time as the database.

Without the private key files, existing signed tokens and the configured active key cannot be used after restore.

## Logs

`lore-auth-server` uses `tracing_subscriber` with `RUST_LOG`.

When `RUST_LOG` is unset, the default filter is `info,authz_core=warn`.

```bash
RUST_LOG=info,lore_auth_server=debug,lore_auth_inbound=debug \
  lore-auth-server --config /etc/lore-auth/lore-auth.yaml
```

The issued-token log stores token metadata such as `jti`, kind, user, resource, key ID, audience, issue time, and expiry.

It does not store JWT bodies.

The server does not intentionally log token bodies.

Some operator-facing flows display token bodies by design, including `lore-authctl token mint-authn` without `--out`, `--print-login-command`, `token mint`, and the Web Token Page below.

Do not capture those outputs in shared terminals, CI logs, shell history, browser history, or reverse-proxy logs.

Configure reverse-proxy access logs to omit or redact query strings and sensitive path values such as OAuth `code`, device `user_code`, `/login/session/{nonce}`, and token bodies.

## Recovery

If an admin user is disabled by mistake, re-enable the account with `authctl`.

```bash
lore-authctl --config /etc/lore-auth/lore-auth.yaml user enable admin@example.com
```

If the IdP is unavailable, continue administrative changes with `lore-authctl`.

The CLI writes through the same audited administrative adapters as the Web UI.

For no-IdP access to Lore, register the user and issue an authn token with the CLI as shown in [Authctl](authctl.md#token-mint-authn).

## Web Token Page

The HTTP server provides `/tokens` and `/tokens/mint` for browser-issued Lore tokens.

`/tokens` requires a logged-in browser session and redirects to `/login` otherwise.

It lists repositories where the current user has write permission.

`/tokens/mint` checks same-origin headers and a CSRF token, then issues a writer authz token for the selected repository.

The result page displays the token body and a `lore auth login --token-type lore` command.

Use this page only from a trusted private browser session, and do not leave the result in screenshots, browser history, shared clipboard managers, or support logs.

## Device Flow

Device flow is the HTTP path for a Lore CLI or helper running without an interactive browser to request a repository token that a logged-in user approves in a browser.

`/api/device/start` accepts JSON containing `remote_url` and `repository`, then returns a `device_code`, `user_code`, `verification_uri`, `expires_in`, and `interval`.

`/device` is the browser verification page.

Approving a code requires a logged-in browser session, and approval succeeds only if that user has write access to the requested repository.

`/api/device/token` is the polling endpoint.

After approval, it returns `token_type: "lore"`, an authz `access_token`, the configured `auth_url`, and the repository `remote_url`.

Callers use those values to complete a `lore auth login --token-type lore` style login without embedding a browser in the CLI environment.

The relevant settings are `security.device_code_ttl_seconds` and `security.device_poll_interval_seconds` in [Configuration](configuration.md#security).
