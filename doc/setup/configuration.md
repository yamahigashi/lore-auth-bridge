# Configuration

[日本語](configuration.ja.md)

`lore-auth.yaml` configures the bridge HTTP server, gRPC server, DB, JWT settings, Lore integration, login method, and admin UI.

Unknown keys are parse errors at every config object level; remove typos or unsupported keys instead of leaving them in the file.

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

See [Operations](operations.md#ports) for default ports and exposure guidance.

## database

```yaml
database:
  path: ".quickstart/lore-auth.sqlite3"
```

`path` is the SQLite database path.

See [Operations](operations.md#data-layout) for file placement, WAL behavior, permissions, and backup guidance.

## authz

```yaml
authz:
  backend: rebac
```

`backend` selects the authorization evaluator.

`rebac` is the only supported backend and is the default.

It evaluates SQLite-backed grants and group membership, including nested groups, through the authz-core ReBAC adapter.

Most deployments can omit `authz.backend`.

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

See [Operations](operations.md#data-layout) for private key directory permissions and backup guidance.

## lore

```yaml
lore:
  default_remote_url: "lore://localhost:41337"
  auth_url: "https://localhost:8081"
```

`default_remote_url` is the default Lore remote URL shown by token mint commands and UI.

`auth_url` is the auth gRPC endpoint through which Lore reaches `UrcAuthApi` and `RebacApi`.

In the Hands-on Quickstart setup, use `https://localhost:8081`.

When `lore.auth_url` is omitted, the bridge derives it from `server.public_base_url` by replacing the HTTP scheme with `ucs-auth://`.

For example, `https://auth.example.com` becomes `ucs-auth://auth.example.com`.

When setting `lore.auth_url` explicitly, use an HTTPS gRPC endpoint for the `loreserver` integration and the quickstart examples.

The config validator accepts `https://...` and `ucs-auth://...`.

## admin

```yaml
admin:
  admin_emails:
    - "admin@example.com"
```

`admin_emails` enables the `/admin` Web UI and defines the allowed admin email addresses.

When this list is omitted or empty, `/admin` is not mounted and returns 404.

Admins sign in through the configured OIDC login flow first, then open `/admin`.

The addresses are normalized before comparison.

See [Admin Web UI](admin-ui.md) for the operational flow and security notes.

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

`device_code_ttl_seconds` is the TTL for device flow user codes and device codes.

`device_poll_interval_seconds` is the device flow polling interval.

Device flow uses `/api/device/start`, `/device`, and `/api/device/token` so a browserless Lore CLI or helper can request a repository token that a logged-in user approves in a browser.

See [Operations](operations.md#device-flow) for endpoint behavior and token handling.

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

`admin_allowed_peer_cidrs` is an optional second-layer peer allowlist for `/admin`.

When it is set, admin routes return 404 unless the immediate TCP peer is inside the list.

Behind a reverse proxy, allow the proxy address and enforce the public admin source policy at the proxy.

The bridge does not trust `X-Forwarded-For` for this check.

Configure rate limiting for public endpoints at the reverse proxy or load balancer.

The relevant endpoints are `/api/device/start`, `/api/device/token`, `/auth/{provider}/start`, and the gRPC `/epic_urc.UrcAuthApi/StartAuthSession`.

Device flow and OAuth start endpoints are reachable by anonymous callers, so limit them by IP, forwarded client IP, or edge identity.

The bridge also applies a small per-peer in-process rate limit to these public endpoints.

That limit is defense in depth.
Behind a reverse proxy, the bridge sees the proxy as the peer unless a trusted proxy policy is implemented, so the app-level limiter is not a replacement for edge rate limiting.

See [Operations](operations.md#logs) for `RUST_LOG`, default filters, token display handling, and reverse-proxy log redaction.

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

This section is the primary reference for `trust.email_binding`.

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

`trust.email_binding` controls whether a pending invitation can be consumed during first login.

`verified_email_invitation` means the IdP login can create an external identity binding only when the ID token contains a verified email matching a pending invitation for the same provider and issuer.

`disabled` means `lore-authctl user invite` still creates pending invitations, but login will not consume them.

An existing external identity binding resolves by `provider_id`, `issuer`, and `subject` regardless of email.

`trust.allowed_email_domains` is an additional condition for consuming a verified-email invitation.

It is not a global login allowlist.

When it is set, the ID token email must be verified and its domain must be in the configured list before the invitation can be consumed.

`subject.strategy: oidc_sub` uses the ID token `sub` claim as the persistent subject.

Do not use email, preferred username, or UPN claims as the persistent identity subject.
