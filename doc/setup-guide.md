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

To run the bridge, `loreserver`, and the `lore` CLI locally end to end, continue with [Local Smoke Test](setup/local-smoke-test.md).

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

The bridge matches the `issuer` and `subject` returned by the IdP against registered users in the bridge DB.

The bridge does not issue tokens to unregistered users.

With Google OIDC, an administrator can preregister a user email with `lore-authctl user invite`.

When that user logs in for the first time and Google returns the same verified email, the login becomes usable.

If the subject is already known, an administrator can also register the user with `lore-authctl user add`.

When IdP login is not used, an administrator can issue an authn token with the CLI.

In that mode, the administrator runs `lore-authctl token mint-authn` and passes the token to `lore auth login --token-type lore`.

## Operational Setup Flow

In operation, align the bridge HTTP endpoint, gRPC endpoint, SQLite database, JWT issuer/audience, RS256 signing key, and `loreserver` auth settings.

When IdP login is enabled, the IdP client configuration and the bridge configuration must also match.

Manage users and repository permissions with `lore-authctl`.

## Local Verification

Concrete commands for running the bridge, `loreserver`, and the `lore` CLI locally are kept in [Local Smoke Test](setup/local-smoke-test.md).
