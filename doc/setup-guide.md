# Setup Guide

[日本語](setup-guide.ja.md)

This guide covers `lore-auth-bridge` configuration, TLS/JWKS setup, `loreserver` integration, and administrative CLI usage.

`lore-auth-bridge` is a bridge that implements Lore's `UrcAuthApi` and `RebacApi`.

The identity provider used for login is replaceable.

Google OIDC is one concrete example covered by this documentation set.

## Reading Order

Read these pages first to understand the full setup:

1. [Configuration](setup/configuration.md)
2. [TLS](setup/tls.md)
3. [Signing Keys](setup/signing-keys.md)
4. [Loreserver](setup/loreserver.md)
5. [Authctl](setup/authctl.md)

If you use IdP integration, also read:

1. [Identity Providers](setup/identity-providers.md)
2. [Google OIDC](setup/google-oidc.md) for the Google-specific example

If you expose the bridge and Lore remote through Tailscale, also read [Tailscale](setup/tailscale.md).

After the individual setup pages, use [Hands-on Quickstart](setup/hands-on-quickstart.md) to check the full bridge, `loreserver`, and `lore` CLI flow.

## Components

A bridge deployment mainly consists of these parts:

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

When that user logs in for the first time and the IdP returns the same verified email, the login becomes usable.

When IdP login is not used, an administrator can issue an authn token with the CLI.

In that mode, the administrator runs `lore-authctl --config <cfg> token mint-authn <email>` and passes the token to `lore auth login --token-type lore`.

## Operational Setup Flow

In operation, align the bridge HTTP endpoint, gRPC endpoint, SQLite database, JWT issuer/audience, RS256 signing key, and `loreserver` auth settings.

When IdP login is enabled, the IdP client configuration and the bridge configuration must also match.

Manage users and repository permissions with `lore-authctl`.

## Full Flow Check

The repository creation and clone flow is covered in [Hands-on Quickstart](setup/hands-on-quickstart.md).
