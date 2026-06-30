# Identity Providers

[日本語](identity-providers.ja.md)

An identity provider is an external service or authentication source from which the bridge obtains a user identity.

The bridge matches the identity returned by the IdP against users in the bridge DB.

When an operation does not use an IdP, an administrator can issue authn tokens with the CLI.

Google OIDC is the concrete IdP setup example in this documentation set.

Keycloak, Auth0, or an internal OIDC provider can use the generic `oidc` adapter when they expose standard OIDC discovery and authorization code flow endpoints.

Each configured provider key is a provider instance ID.

Use stable keys such as `google`, `keycloak-prod`, or `auth0-main`, not only the adapter type `oidc`.

## IdP login

With IdP login, the user signs in through the IdP in a browser.

The bridge matches the returned `issuer` and `subject` against registered users.

If the user is registered, the browser session or CLI auth session completes.

If the user is not registered, no token is issued and the whoami page displays the identity.

With Google OIDC, an administrator can register a user with `lore-authctl user invite --idp google --email <address>`.

If the registered user's first login returns a verified Google email that matches the invitation, that login completes.

If the subject is already known, an administrator can also register the user with `lore-authctl user add --idp <provider> --subject <subject>`.

When `identity_providers` is configured, `user invite` and `user add` require `--idp`.

See [Google OIDC](google-oidc.md) for concrete Google OIDC settings.

## Authn Tokens Issued By The Administrative CLI

If IdP login is not used, an administrator can issue authn tokens with the administrative CLI.

Register a user with the CLI, then issue an authn token with `lore-authctl token mint-authn`.

The `--provider manual`, `--issuer local`, and `--subject manual-subject` values below are identifiers for the no-IdP example.

Direct `--provider` and `--issuer` registration is only for configs that do not define `identity_providers`.

When explicitly registering a subject for IdP login, register the `issuer` and `subject` returned by that IdP.

```bash
go run ./cmd/lore-authctl user add \
  --config .manual/lore-auth.yaml \
  --provider manual \
  --issuer local \
  --subject manual-subject \
  --email manual@example.com \
  --email-verified \
  --name "Manual User"

go run ./cmd/lore-authctl token mint-authn \
  --config .manual/lore-auth.yaml \
  --out .manual/authn.jwt \
  manual@example.com
```

With this method, the administrator passes the issued token to `lore auth login --token-type lore` to register it in the Lore CLI.
