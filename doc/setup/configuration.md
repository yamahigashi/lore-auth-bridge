# Configuration

[日本語](configuration.ja.md)

`lore-auth.yaml` configures the bridge HTTP server, gRPC server, DB, JWT settings, Lore integration, and login method.

This page explains each setting.

See [Hands-on Quickstart](hands-on-quickstart.md) for the full flow check.

## server

```yaml
server:
  listen: "127.0.0.1:8080"
  grpc_listen: "127.0.0.1:8081"
  grpc_tls_cert_file: ".quickstart/grpc/tls.crt"
  grpc_tls_key_file: ".quickstart/grpc/tls.key"
  public_base_url: "http://localhost:8080"
```

`listen` is the HTTP server listen address.

The HTTP server provides JWKS, health checks, browser login, and device flow.

`grpc_listen` is the listen address for `UrcAuthApi` and `RebacApi`.

The Lore CLI and `loreserver` connect to it for auth exchange and ReBAC sync.

`grpc_tls_cert_file` and `grpc_tls_key_file` are the gRPC TLS server certificate and key.

See [TLS](tls.md) for certificate generation and trust configuration.

`public_base_url` is the external URL for the bridge HTTP/JWKS side.

Keeping it aligned with `jwt.issuer` makes verification easier.

## database

```yaml
database:
  path: ".quickstart/lore-auth.sqlite3"
```

`path` is the SQLite database path.

The database stores users, groups, repositories, grants, auth sessions, issued tokens, and signing key metadata.

The schema also contains an `audit_events` table, but the current implementation does not record administrative actions or token issuance as audit events.

If an operation requires auditing, provide separate records through a reverse proxy, systemd journal, SQLite backups, CLI execution logs, or another operational log.

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

`issuer` is the `iss` value in JWTs issued by the bridge.

It must match `[server.auth].jwt_issuer` in `loreserver`.

`audience` is the JWT `aud` value.

For local use, include both `lore-service` and the remote host, for example `localhost`.

In production, include `lore-service` and the actual remote host, for example `lore.example.com`.

`ttl_seconds` is the default TTL for authn tokens.

Authz token TTL is configured at server and CLI startup and is currently 15 minutes.

`signing_key_dir` is the directory that stores private key files.

`active_kid` is the key ID used for signing.

See [Signing Keys](signing-keys.md) for key generation.

## lore

```yaml
lore:
  default_remote_url: "lore://localhost:41337"
  auth_url: "https://localhost:8081"
```

`default_remote_url` is the default Lore remote URL shown by token mint commands and UI.

`auth_url` is the auth gRPC endpoint through which Lore reaches `UrcAuthApi` and `RebacApi`.

In the Hands-on Quickstart setup, use `https://localhost:8081`.

`auth_url` must be an HTTPS gRPC endpoint.

Do not use `ucs-auth://...` in this field.

## security

```yaml
security:
  device_code_ttl_seconds: 600
  device_poll_interval_seconds: 3
  session_ttl_seconds: 3600
  rebac_allowed_peer_cidrs:
    - "127.0.0.1/32"
    - "::1/128"
```

`device_code_ttl_seconds` is the TTL for device flow user codes and device codes.

`device_poll_interval_seconds` is the device flow polling interval.

`session_ttl_seconds` is the TTL for browser sessions.

`auth_session_ttl_seconds` can be set when interactive auth sessions need a different TTL.

If omitted or set to zero, it defaults to `session_ttl_seconds`.

`rebac_allowed_peer_cidrs` is the peer allowlist for `ucs.auth.RebacApi`.

`RebacApi` is treated as a service-to-service API dedicated to resource lifecycle sync from `loreserver`.

When this list is empty, the bridge only accepts ReBAC gRPC methods from loopback peers.

If `loreserver` runs on another host, add the source CIDR from which `loreserver` reaches the bridge.

This check uses the TCP peer as seen directly by the bridge.

If a public reverse proxy forwards traffic to a loopback bridge listener, the peer seen by the bridge is the proxy.

In that topology, also restrict `/ucs.auth.RebacApi/*` at the reverse proxy to traffic from `loreserver`.

Configure rate limiting for public endpoints at the reverse proxy or load balancer.

The relevant endpoints are `/api/device/start`, `/api/device/token`, `/auth/{provider}/start`, and the gRPC `/epic_urc.UrcAuthApi/StartAuthSession`.

Device flow and OAuth start endpoints are reachable by anonymous callers, so limit them by IP, forwarded client IP, or edge identity.

The bridge also applies a small per-peer in-process rate limit to these public endpoints.

That limit is defense in depth.
Behind a reverse proxy, the bridge sees the proxy as the peer unless a trusted proxy policy is implemented, so the app-level limiter is not a replacement for edge rate limiting.

Configure access logs so URL query strings and sensitive path values are not recorded.

For NGINX, prefer a log format based on `$uri` instead of `$request_uri`.
For Caddy or another reverse proxy, omit or redact query strings.

Do not log OAuth callback `code` values, device `user_code` values, `/login/session/{nonce}` nonces, or token bodies.

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

`identity_providers` configures one or more login identity provider instances.

`default` must reference a key under `providers`.

The provider key, such as `google` or `keycloak-prod`, is stored as the bridge identity provider instance ID.

Do not use a generic value like `oidc` as the provider key if multiple issuers or tenants may exist.

For OIDC providers, `redirect_url` must use `/auth/{provider}/callback`.

See [Google OIDC](google-oidc.md) for concrete Google settings.

`profile: google` enables Google trust policy checks.

`trust.hosted_domain.allowed` is the set of Workspace domains allowed through the Google ID token `hd` claim.

When set, logins whose `hd` claim is not in the list are rejected.

`trust.personal_accounts: deny` rejects personal Google accounts without an `hd` claim.

If `trust.hosted_domain.allowed` is empty and `trust.personal_accounts` is not `deny`, the bridge allows both registered Workspace accounts and registered personal Google accounts.

`trust.allowed_email_domains` is an additional condition for consuming a verified-email invitation.

It is checked only when `trust.email_binding: verified_email_invitation` is about to bind a pending invitation.

It is not a global login allowlist.

If `trust.email_binding` is `disabled`, `lore-authctl user invite` still creates pending invitations, but login will not consume them.

An existing external identity binding continues to resolve by `provider_id`, `issuer`, and `subject`.

When `trust.allowed_email_domains` is set for invitation binding, the ID token email must be verified and its domain must be in the configured list.

`subject.strategy: oidc_sub` uses the ID token `sub` claim as the persistent subject.

Do not use email, preferred username, or UPN claims as the persistent identity subject.
