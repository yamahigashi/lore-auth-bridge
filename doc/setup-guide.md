# Setup Guide

[日本語](setup-guide.ja.md)

This guide covers `lore-auth-bridge` configuration, TLS/JWKS setup, `loreserver` integration, administrative CLI usage, and the admin Web UI.

`lore-auth-bridge` is a bridge that implements Lore's `UrcAuthApi` and `RebacApi`.

The identity provider used for login is replaceable.

Google OIDC is one concrete example covered by this documentation set.

## Reading Order

Use this order:

1. Read [Components](#components) to understand how the bridge, `loreserver`, and the Lore CLI fit together.
2. Run [Hands-on Quickstart](setup/hands-on-quickstart.md) to experience the full flow in a self-contained no-IdP setup.
3. Finish the production shape with the individual setup pages.

Production setup pages:

- [Deployment](setup/deployment.md)
- [Configuration](setup/configuration.md)
- [Operations](setup/operations.md)
- [TLS](setup/tls.md)
- [Signing Keys](setup/signing-keys.md)
- [Loreserver](setup/loreserver.md)
- [Authctl](setup/authctl.md)
- [Admin Web UI](setup/admin-ui.md)

If you use IdP integration, also read:

- [Identity Providers](setup/identity-providers.md)
- [Google OIDC](setup/google-oidc.md) for the Google-specific example

If you expose the bridge and Lore remote through Tailscale, read [Deployment](setup/deployment.md#tailscale--vpn-mesh) first, then [Tailscale](setup/tailscale.md).

## Components

A bridge deployment mainly consists of these parts:

For the high-level diagram and glossary, see [README](../README.md#what-is-this--how-it-fits).

- **bridge HTTP**: serves JWKS, browser login, device flow, and health checks.
- **bridge gRPC**: serves `UrcAuthApi` and `RebacApi` over TLS.
- **loreserver**: runs with auth enabled and uses the bridge JWKS and auth gRPC endpoint.
- **lore CLI**: stores an authn token and exchanges it for authz tokens when operating on repositories.

## Login And User Registration

The bridge issues the authn token used by the Lore CLI.

The user identity behind the authn token comes either from the configured IdP or from administrative CLI registration.

When IdP login is enabled, the user signs in through a browser.

The bridge binds the verified external identity returned by the IdP to a reserved bridge user.

The bridge does not issue tokens to unregistered users.

With IdP login, an administrator can preregister a user email with `lore-authctl --config <cfg> user invite --idp <provider-id> --email <email>`.

Use `user invite` for this onboarding path.

`user add` is only a low-level escape hatch for accounts that do not rely on email-binding login.

When that user logs in for the first time and the IdP returns the same verified email, the login becomes usable.

When IdP login is not used, an administrator can issue an authn token with the CLI.

In that mode, the administrator runs `lore-authctl --config <cfg> token mint-authn <email>` and passes the token to `lore auth login --token-type lore`.

## Operational Setup Flow

In operation, align the deployment pattern, bridge HTTP endpoint, gRPC endpoint, SQLite database, JWT issuer/audience, RS256 signing key, and `loreserver` auth settings.

When IdP login is enabled, the IdP client configuration and the bridge configuration must also match.

Manage users and repository permissions with `lore-authctl`.

Choose the machine layout and storage pattern in [Deployment](setup/deployment.md).

Keep port exposure, data placement, backups, logs, and recovery procedures in [Operations](setup/operations.md).

## Full Flow Check

The repository creation and clone flow is covered by the self-contained [Hands-on Quickstart](setup/hands-on-quickstart.md).
