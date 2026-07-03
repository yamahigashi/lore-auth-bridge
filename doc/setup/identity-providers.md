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

The bridge resolves the returned external identity against existing bindings or pending invitations.

If the user is registered, the browser session or CLI auth session completes.

If the user is not registered, no token is issued and the whoami page displays the identity.

When the IdP returns verified email addresses, an administrator can preregister a user with `lore-authctl --config <cfg> user invite --idp <provider-id> --email <address>`.

If the provider has `trust.email_binding: verified_email_invitation` and the invited user's first login returns a matching verified email from the IdP, the bridge creates the external identity binding and completes that login.

If `trust.allowed_email_domains` is set, the email domain must also match that list before the invitation is consumed.

When `identity_providers` is configured, `user invite` requires `--idp`.

See [Google OIDC](google-oidc.md) for concrete Google OIDC settings.

## Microsoft Entra ID

Use `profile: entra` with `subject.strategy: entra_oid_tid`.

The subject is built from the ID token `tid` and `oid` claims.

```yaml
identity_providers:
  default: entra
  providers:
    entra:
      type: oidc
      profile: entra
      display_name: "Microsoft Entra ID"
      issuer: "https://login.microsoftonline.com/<tenant-id>/v2.0"
      client_id: "<application-client-id>"
      client_secret_file: "/etc/lore-auth/entra_client_secret"
      redirect_url: "https://auth.example.com/auth/entra/callback"
      scopes:
        - openid
        - email
        - profile
      pkce: required
      subject:
        strategy: entra_oid_tid
        required_tid: "<tenant-id>"
      trust:
        email_binding: verified_email_invitation
        allowed_email_domains:
          - "example.com"
```

`subject.required_tid` pins the accepted tenant because a multi-tenant Entra setup can otherwise mix subjects from different tenants.

The generic verified-email invitation rules still apply: the ID token must contain the mapped `email` claim and `email_verified=true` before `user invite` can be consumed.

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
