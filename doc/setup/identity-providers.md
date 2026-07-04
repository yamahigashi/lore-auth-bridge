# Identity Providers

[日本語](identity-providers.ja.md)

An identity provider is an external service or authentication source from which the bridge obtains a user identity.

The bridge matches the identity returned by the IdP against users in the bridge DB.

When an operation does not use an IdP, an administrator can issue authn tokens with the CLI.

Each configured provider key is a provider instance ID.

Use stable keys such as `google`, `entra`, or `keycloak-prod`, not only the adapter type `oidc`.

## Provider Pages

Use the provider-specific page that matches the IdP you operate:

- [Google OIDC](google-oidc.md): Google Cloud OAuth client and Google Workspace trust checks.
- [Microsoft Entra ID](entra-id.md): Entra app registration with `profile: entra`.
- [Keycloak](keycloak.md): Keycloak realm and OIDC client setup with `profile: keycloak`.

The exact `trust.email_binding` and `trust.allowed_email_domains` behavior is documented in [Configuration](configuration.md#identity_providers).

## IdP Login

With IdP login, the user signs in through the IdP in a browser.

The bridge resolves the returned external identity against existing bindings or pending invitations.

If the user is registered, the browser session or CLI auth session completes.

If the user is not registered, no token is issued and the whoami page displays the identity.

When the IdP returns verified email addresses, an administrator can preregister a user with `lore-authctl --config <cfg> user invite --idp <provider-id> --email <address>`.

With `trust.email_binding: verified_email_invitation`, first login can bind the invited verified email; see [Configuration](configuration.md#identity_providers) for the exact binding and `trust.allowed_email_domains` rules.

When `identity_providers` is configured, `user invite` requires `--idp`.

## Google OIDC

Use `profile: google` with `subject.strategy: oidc_sub`.

Google-specific checks use the ID token `hd` claim for Workspace hosted-domain policy and `trust.personal_accounts` for personal Google account policy.

See [Google OIDC](google-oidc.md) for the complete setup.

## Microsoft Entra ID

Use `profile: entra` with `subject.strategy: entra_oid_tid`.

The subject is built from the ID token `tid` and `oid` claims.

`subject.required_tid` is required because a multi-tenant Entra setup can otherwise mix subjects from different tenants.

See [Microsoft Entra ID](entra-id.md) for the complete setup.

## Keycloak

Use `profile: keycloak` with `subject.strategy: oidc_sub`.

Keycloak uses the generic OIDC path and does not use Google hosted-domain or personal-account checks.

Do not set `trust.personal_accounts` for Keycloak.

See [Keycloak](keycloak.md) for the complete setup.

## Authn Tokens Issued By The Administrative CLI

If IdP login is not used, an administrator can issue authn tokens with the administrative CLI.

Register a user with the CLI, then issue an authn token with `lore-authctl --config <cfg> token mint-authn <email>`.

This section intentionally uses `user add` because it is the no-IdP escape hatch.

For IdP onboarding with verified email binding, use `user invite` from the previous section.

```bash
lore-authctl --config .quickstart/lore-auth.yaml user add \
  --email manual@example.com \
  --name "Manual User"

lore-authctl --config .quickstart/lore-auth.yaml token mint-authn \
  manual@example.com \
  --out .quickstart/authn.jwt
```

With this method, the administrator passes the issued token to `lore auth login --token-type lore` to register it in the Lore CLI.
