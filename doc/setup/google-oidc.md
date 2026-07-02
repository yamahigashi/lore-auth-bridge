# Google OIDC

[日本語](google-oidc.ja.md)

To use Google OIDC for login, create an OAuth client in Google Cloud and configure its Client ID, Client secret, and redirect URL in the bridge.

The bridge matches the identity obtained from Google login against users registered in the bridge DB.

A successful Google login alone does not make the user a Lore user.

## Required Values

Prepare the following values to enable Google OIDC:

- **Client ID**: OAuth client ID from Google Cloud.
- **Client secret**: OAuth client secret from Google Cloud.
- **Redirect URL**: bridge callback URL to which Google returns after login.
- **User email**: email address of the Google account to register.

`client_secret_file` must contain the path to a file that stores the secret, not the secret value itself.

Normally, an administrator registers the user by email, and the first user login records `iss` and `sub`.

The email is used for first-login matching and display.

The primary key for the Google identity is the recorded `iss` and `sub`.

## Values From Google Cloud

Select or create a Google Cloud project.

Then configure the OAuth consent screen and create an OAuth client ID.

Google Cloud Console screen names and navigation can change, so refer to the official documentation if the UI differs.

- OAuth 2.0 for Web Server Applications: https://developers.google.com/identity/protocols/oauth2/web-server
- OAuth consent screen and scopes: https://developers.google.com/workspace/guides/configure-oauth-consent
- OpenID Connect: https://developers.google.com/identity/openid-connect/openid-connect

## OAuth Consent Screen

On the OAuth consent screen, configure the app name, support email, user type, and scopes shown to users.

If the app is used only inside a Workspace, the user type can be Internal.

For personal Google accounts or accounts outside the Workspace, choose External.

When External is in testing mode, add the Google accounts used for login to test users.

The bridge requests the `openid`, `email`, and `profile` scopes.

Unless the bridge calls additional Google APIs, it does not need Google Drive, Gmail, or other API scopes.

## OAuth Client

Create the OAuth client as a Web application.

Do not use a Desktop app client.

Register the exact bridge callback URL in Authorized redirect URIs.

For local use, register:

```text
http://localhost:8080/auth/google/callback
```

For production, use the public URL.

```text
https://auth.example.com/auth/google/callback
```

Set the displayed Client ID as `identity_providers.providers.google.client_id`.

Save the Client secret to a file and set that path as `identity_providers.providers.google.client_secret_file`.

The Authorized redirect URI in Google Cloud and `identity_providers.providers.google.redirect_url` in the bridge config must be the same string.

Callback handling fails if the scheme, host, port, path, or trailing slash differs.

## Bridge Settings

For local Google OIDC verification, use settings like these:

```yaml
server:
  public_base_url: "http://localhost:8080"

identity_providers:
  default: google
  providers:
    google:
      type: oidc
      profile: google
      display_name: "Google"
      issuer: "https://accounts.google.com"
      client_id: "<Google OAuth Client ID>"
      client_secret_file: ".quickstart/google_client_secret"
      redirect_url: "http://localhost:8080/auth/google/callback"
      scopes: [openid, email, profile]
      subject:
        strategy: oidc_sub
      trust:
        email_binding: verified_email_invitation
        hosted_domain:
          allowed: []
        personal_accounts: allow
```

Do not write the Client secret directly into YAML.

Store it in a file.

```bash
printf '%s' '<Google OAuth Client Secret>' > .quickstart/google_client_secret
chmod 600 .quickstart/google_client_secret
```

In production, use an HTTPS public URL.

```yaml
server:
  public_base_url: "https://auth.example.com"

identity_providers:
  default: google
  providers:
    google:
      type: oidc
      profile: google
      display_name: "Google"
      issuer: "https://accounts.google.com"
      client_id: "<Google OAuth Client ID>"
      client_secret_file: "/etc/lore-auth/google_client_secret"
      redirect_url: "https://auth.example.com/auth/google/callback"
      scopes: [openid, email, profile]
      subject:
        strategy: oidc_sub
      trust:
        email_binding: verified_email_invitation
        hosted_domain:
          allowed:
            - "example.com"
        personal_accounts: deny
```

`trust.hosted_domain.allowed` is the set of Workspace domains allowed through the Google ID token `hd` claim.

When set, logins whose `hd` claim does not match are rejected.

`trust.personal_accounts: deny` rejects personal Google accounts that do not have an `hd` claim.

For production restricted to Google Workspace, set `trust.hosted_domain.allowed` and use `trust.personal_accounts: deny`.

## User Registration

Even after Google login succeeds, the bridge does not issue a token unless the corresponding user is registered in the bridge DB.

Usually, an administrator registers the target user's email.

The examples above set `trust.email_binding: verified_email_invitation`, so the first verified-email login can consume that invitation and create the external identity binding.

```bash
lore-authctl --config .quickstart/lore-auth.yaml user invite \
  --idp google \
  --email '<Google email>' \
  --name '<display name>'
```

At this point, linkage with the Google account is not complete, so no token is issued.

When the user opens `/login` and Google returns the same `email_verified=true` email, that login completes the browser session or CLI auth session.

If the user is not invited, no token is issued.

Invite the verified Google email, then retry login.

After the invitation is created, open `/login` again to create the bridge browser session.

```text
http://localhost:8080/login
```

## Behavior

The bridge verifies the Google ID token in the callback.

After verification, it resolves the provider ID, issuer, and subject against `external_identities`.

If an active binding exists, the browser session or CLI auth session completes.

If no binding exists but an `email_verified=true` email matches a pending invitation for the same provider and issuer, the bridge creates the binding and completes the login.

If no binding or invitation matches, the bridge does not issue a token and displays the whoami page.

## Common Failures

If `redirect_uri_mismatch` appears, check that the Authorized redirect URI in Google Cloud exactly matches `identity_providers.providers.google.redirect_url`.

If the login flow reports `No Lore token was issued`, Google login succeeded but the bridge did not find a matching registered user.

Invite the verified email with `lore-authctl --config <cfg> user invite`, then retry login.

If login is rejected while an External app is in testing mode, check that the Google account used for login is listed in test users.

If any of `identity_providers.providers.google.client_id`, `identity_providers.providers.google.client_secret_file`, or `identity_providers.providers.google.redirect_url` is empty, Google login is not enabled.

If only CLI-issued authn tokens are used, omit the Google provider from `identity_providers`.
