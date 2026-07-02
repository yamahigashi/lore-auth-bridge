# Admin Web UI

[日本語](admin-ui.ja.md)

The admin Web UI is served by the same HTTP process as login, JWKS, device flow, and health checks.

It is mounted under `/admin` only when `admin.admin_emails` contains at least one address.

If `admin.admin_emails` is omitted or empty, `/admin` is not mounted and returns 404.

## Enable The UI

Add the admin section to `lore-auth.yaml`.

```yaml
admin:
  admin_emails:
    - "admin@example.com"
```

The listed addresses are normalized before comparison.

An operator signs in through the configured OIDC login flow first, then opens `/admin`.

Unauthenticated and non-admin requests to `/admin` return 404 so that the deployment does not reveal whether the admin UI is enabled.

## Network Controls

`/admin` shares the public HTTP listener.

In production, put the bridge behind a reverse proxy such as NGINX or Caddy and restrict `/admin` at that edge.

Use CDN or WAF controls such as Cloudflare when the deployment needs source restrictions or stronger rate limiting at the public boundary.

The bridge also supports a second layer of peer filtering.

```yaml
security:
  admin_allowed_peer_cidrs:
    - "127.0.0.1/32"
```

This check uses the TCP peer address seen directly by the bridge.

Behind a reverse proxy, allow the proxy address and enforce the public admin allowlist at the proxy.

The bridge does not trust `X-Forwarded-For` for this check.

In a minimal deployment without a reverse proxy, the only admin protections are OIDC login, `admin.admin_emails`, and the optional `security.admin_allowed_peer_cidrs` setting.

## Features

The UI can browse and search repositories, users, groups, grants, and user access.

It can add and disable users, create invitations, add and disable manual repositories, manage grants, and manage groups.

Nested group operations are available only when `authz.backend: rebac` is configured.

The check simulator at `/admin/simulator` runs the configured authorization policy for a user, repository, and action.

The simulator also shows SQL-based grant evidence as helper information.

The policy result is authoritative; the evidence list can diverge from the policy backend in unusual cases.

Admin mutations are recorded in `admin_audit`.

For direct SQLite inspection:

```bash
sqlite3 /var/lib/lore-auth/auth.sqlite3 \
  "SELECT created_at, actor, action, object_type, object_id, detail FROM admin_audit ORDER BY created_at DESC LIMIT 20;"
```

## Recovery

If an admin user is disabled by mistake, re-enable the account with `authctl`.

```bash
lore-authctl --config /etc/lore-auth/lore-auth.yaml user enable admin@example.com
```

If the IdP is unavailable, continue operational changes with `lore-authctl`.

The CLI uses the same audited write adapters as the UI for administrative mutations.
