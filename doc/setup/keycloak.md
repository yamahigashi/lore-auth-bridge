# Keycloak

[日本語](keycloak.ja.md)

To use Keycloak for login, create or choose a realm, create an OpenID Connect client for the bridge, and configure its Client ID, Client secret, issuer, and redirect URL in the bridge.

The bridge matches the identity obtained from Keycloak login against users registered in the bridge DB.

A successful Keycloak login alone does not make the user a Lore user.

This page is based on common Keycloak realm and client setup steps; this project has not been exercised with Keycloak as extensively as Google OIDC.

## Required Values

Prepare the following values to enable Keycloak:

- **Realm URL**: base issuer URL for the Keycloak realm.
- **Client ID**: OIDC client ID created for the bridge.
- **Client secret**: secret value for a confidential client.
- **Redirect URL**: bridge callback URL to which Keycloak returns after login.
- **User email**: email address to register in the bridge when using verified-email invitations.

`client_secret_file` must contain the path to a file that stores the secret, not the secret value itself.

The Keycloak issuer normally has the form `https://{host}/realms/{realm}`.

The bridge uses `subject.strategy: oidc_sub` for Keycloak.

The persistent identity key is the Keycloak OIDC `sub` claim, not email, username, or UPN.

## Values From Keycloak

Create or choose the Keycloak realm that owns the users.

Keycloak admin console labels can change, so treat the steps below as conceptual.

- Keycloak Server Administration Guide, client management: https://www.keycloak.org/docs/latest/server_admin/#assembly-managing-clients_server_administration_guide
- Keycloak OpenID Connect endpoints: https://www.keycloak.org/securing-apps/oidc-layers

## Realm

Use one realm for the users that should log in to the bridge.

Reuse a realm your organization already runs, or create a dedicated one (for example `prod`).

Do not use the `master` realm for application logins; it administers Keycloak itself.

The realm, the client, and the bridge configuration map to each other like this:

| Keycloak side | Bridge config side | Relationship |
| --- | --- | --- |
| realm name | `issuer` | The realm name is part of the issuer URL (`https://{host}/realms/{realm}`). The bridge fetches OIDC discovery at startup and verifies the issuer matches. |
| client inside the realm | `client_id` / `client_secret_file` | Clients belong to a realm, so the issuer and the client id must come from the same realm. |
| client's valid redirect URIs | provider key (the name under `providers:`) | The bridge callback path `/auth/{provider key}/callback` must be registered on the client. |

Record the realm issuer URL.

For a realm named `prod` on `sso.example.com`, the issuer is:

```text
https://sso.example.com/realms/prod
```

The issuer configured in the bridge must match the issuer advertised by Keycloak OIDC discovery.

## Client

Create an OpenID Connect client for the bridge.

Use the authorization code flow with a confidential client or equivalent client authentication setting that provides a client secret.

### Create Client Wizard Settings

The create-client wizard shows many options; the bridge only needs a few of them.

**General settings** page:

| Setting | Value for the bridge | Why |
| --- | --- | --- |
| Client type | `OpenID Connect` | The bridge only speaks OIDC. |
| Client ID | your choice, e.g. `lore-auth-bridge` | Must match `client_id` in the bridge config. |
| Name / Description / Always display in UI | anything | Display-only, no effect on the bridge. |

**Capability config** page:

| Setting | Value for the bridge | Why |
| --- | --- | --- |
| Client authentication | **On** | On makes this a confidential client and issues a client secret. The bridge requires a secret (`client_secret_file`), so leaving the default Off breaks the token exchange. |
| Authorization | Off | This is Keycloak's own fine-grained authorization service. Repository permissions live in the bridge's ReBAC model instead. |
| Standard flow | **On** | The authorization code flow. This is the only flow the bridge uses for browser login. |
| Implicit flow | Off | Legacy browser flow, not used. |
| Direct access grants | Off | Password-grant (ROPC), not used. |
| Service account roles | Off | Client-credentials machine login, not used. |
| Standard Token Exchange / JWT Authorization Grant / OIDC CIBA Grant | Off | Not used by the bridge. |
| OAuth 2.0 Device Authorization Grant | Off | Easy to confuse: the lore CLI's device flow runs between the CLI and the bridge. The bridge always talks to Keycloak with the standard flow, so Keycloak's device grant stays off. |
| Require PKCE | optional | If you set `pkce: required` in the bridge provider config, the bridge sends an S256 code challenge and you can turn this on to enforce it server-side. |
| Require DPoP bound tokens | Off | The bridge does not support DPoP. |

**Login settings** page:

| Setting | Value for the bridge | Why |
| --- | --- | --- |
| Root URL | empty | Only a base for resolving relative URLs. Not needed when the redirect URI is entered as an absolute URL. |
| Home URL | empty | Where Keycloak's own UI links to the app. Display-only. |
| Valid redirect URIs | **the bridge callback URL** | The only required field on this page. Enter it exactly, without wildcards; the format is described below. |
| Valid post logout redirect URIs | empty | Only used for Keycloak-initiated logout redirects. The bridge does not use the IdP logout flow. |
| Web origins | empty | CORS allowlist for browser-side JavaScript. The bridge exchanges the code server-side, so no origin is needed. |

After creation, open the **Credentials** tab and copy the client secret into the file referenced by `client_secret_file`.

Register the exact bridge callback URL as a valid redirect URI.

For local use, register:

```text
http://localhost:8080/auth/keycloak-prod/callback
```

For production, use the public URL.

```text
https://auth.example.com/auth/keycloak-prod/callback
```

Save the Client ID and Client secret.

The provider key in the bridge config is part of the callback path.

If the provider key is `keycloak-prod`, the redirect path must be `/auth/keycloak-prod/callback`.

Callback handling fails if the scheme, host, port, path, or trailing slash differs.

If you plan to use verified-email invitations, make sure Keycloak sends `email` and `email_verified` in the ID token for users who should bind on first login.

## Bridge Settings

For local Keycloak verification, use settings like these:

```yaml
server:
  public_base_url: "http://localhost:8080"

identity_providers:
  default: keycloak-prod
  providers:
    keycloak-prod:
      type: oidc
      profile: keycloak
      display_name: "Company SSO"
      issuer: "https://sso.example.com/realms/prod"
      client_id: "lore-auth-bridge"
      client_secret_file: ".quickstart/keycloak_client_secret"
      redirect_url: "http://localhost:8080/auth/keycloak-prod/callback"
      scopes: [openid, email, profile]
      pkce: required
      subject:
        strategy: oidc_sub
      trust:
        email_binding: verified_email_invitation
        allowed_email_domains:
          - "example.com"
```

Do not write the Client secret directly into YAML.

Store it in a file.

```bash
printf '%s' '<Keycloak client secret>' > .quickstart/keycloak_client_secret
chmod 600 .quickstart/keycloak_client_secret
```

In production, use an HTTPS public URL.

```yaml
server:
  public_base_url: "https://auth.example.com"

identity_providers:
  default: keycloak-prod
  providers:
    keycloak-prod:
      type: oidc
      profile: keycloak
      display_name: "Company SSO"
      issuer: "https://sso.example.com/realms/prod"
      client_id: "lore-auth-bridge"
      client_secret_file: "/etc/lore-auth/keycloak_client_secret"
      redirect_url: "https://auth.example.com/auth/keycloak-prod/callback"
      scopes: [openid, email, profile]
      pkce: required
      subject:
        strategy: oidc_sub
      trust:
        email_binding: verified_email_invitation
        allowed_email_domains:
          - "example.com"
```

`profile: keycloak` uses the generic OIDC path with Keycloak-specific naming.

The implementation does not apply Google hosted-domain checks to Keycloak.

`trust.personal_accounts` is valid only with `profile: google`; do not set it for Keycloak.

Use `subject.strategy: oidc_sub` for Keycloak.

The config validator rejects `email`, `upn`, and `preferred_username` as unstable identity keys.

See [Configuration](configuration.md#identity_providers) for the exact `trust.email_binding` and `trust.allowed_email_domains` rules.

## User Registration

Even after Keycloak login succeeds, the bridge does not issue a token unless the corresponding user is registered in the bridge DB.

Usually, an administrator registers the target user's email.

```bash
lore-authctl --config .quickstart/lore-auth.yaml user invite \
  --idp keycloak-prod \
  --email '<Keycloak user email>' \
  --name '<display name>'
```

At this point, linkage with the Keycloak account is not complete, so no token is issued.

If the user is not invited, no token is issued.

After the invitation is created, open `/login` again to create the bridge browser session.

```text
http://localhost:8080/login
```

## Behavior

The bridge verifies the Keycloak ID token in the callback.

After verification, it resolves the provider ID, issuer, and OIDC `sub` subject against `external_identities`.

If an active binding exists, the browser session or CLI auth session completes.

If no active binding exists, the generic invitation-binding policy from [Configuration](configuration.md#identity_providers) applies.

If no binding or invitation matches, the bridge does not issue a token and displays the whoami page.

## Common Failures

If callback handling fails, check that the valid redirect URI in Keycloak exactly matches `identity_providers.providers.keycloak-prod.redirect_url`.

If Keycloak reports an invalid client, check that the bridge Client ID matches the Keycloak client and that `client_secret_file` points to a file containing the current secret.

If login succeeds at Keycloak but no Lore token is issued, invite the verified email with `lore-authctl --config <cfg> user invite --idp keycloak-prod`, then retry login.

If the invitation is not consumed, confirm that the ID token contains `email` and `email_verified`, and that the email domain is allowed by `trust.allowed_email_domains` when that list is set.

If the bridge reports that `trust.personal_accounts` is only valid for Google, remove it from the Keycloak provider.

If any of `identity_providers.providers.keycloak-prod.client_id`, `identity_providers.providers.keycloak-prod.client_secret_file`, or `identity_providers.providers.keycloak-prod.redirect_url` is empty, Keycloak login is not enabled.
