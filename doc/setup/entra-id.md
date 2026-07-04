# Microsoft Entra ID

[日本語](entra-id.ja.md)

To use Microsoft Entra ID for login, register a web application in the tenant and configure its Application client ID, client secret, and redirect URL in the bridge.

The bridge matches the identity obtained from Entra ID login against users registered in the bridge DB.

A successful Entra ID login alone does not make the user a Lore user.

This page is based on common Microsoft Entra ID app-registration steps; this project has not been exercised with Entra ID as extensively as Google OIDC.

## Required Values

Prepare the following values to enable Microsoft Entra ID:

- **Tenant ID**: Directory tenant ID accepted by the bridge.
- **Application client ID**: application ID from the Entra app registration.
- **Client secret**: secret value created for the app registration.
- **Redirect URL**: bridge callback URL to which Entra ID returns after login.
- **User email**: email address to register in the bridge when using verified-email invitations.

`client_secret_file` must contain the path to a file that stores the secret, not the secret value itself.

Use a tenant-specific issuer in the form `https://login.microsoftonline.com/{tenant}/v2.0`.

Use the Directory tenant ID as `subject.required_tid`.

The bridge subject for Entra ID is built from the ID token `tid` and `oid` claims, not from email, UPN, or `preferred_username`.

## Values From Microsoft Entra

Create or choose an app registration in Microsoft Entra ID.

Microsoft Entra admin center screen names can change, so treat the steps below as conceptual.

- Register an application in Microsoft Entra ID: https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app
- Microsoft identity platform OpenID Connect: https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc

## App Registration

Create an app registration for the bridge.

For most bridge deployments, use a single-tenant app registration for the tenant that owns the Lore users.

Record the Application client ID and Directory tenant ID.

Configure the application as a web application and register the exact bridge callback URL.

For local use, register:

```text
http://localhost:8080/auth/entra/callback
```

For production, use the public URL.

```text
https://auth.example.com/auth/entra/callback
```

Create a client secret for the app registration and record the secret value before leaving the page where it is shown.

The redirect URI in Entra ID and `identity_providers.providers.entra.redirect_url` in the bridge config must be the same string.

Callback handling fails if the scheme, host, port, path, or trailing slash differs.

## Bridge Settings

For local Entra ID verification, use settings like these:

```yaml
server:
  public_base_url: "http://localhost:8080"

identity_providers:
  default: entra
  providers:
    entra:
      type: oidc
      profile: entra
      display_name: "Microsoft Entra ID"
      issuer: "https://login.microsoftonline.com/<tenant-id>/v2.0"
      client_id: "<Application client ID>"
      client_secret_file: ".quickstart/entra_client_secret"
      redirect_url: "http://localhost:8080/auth/entra/callback"
      scopes: [openid, email, profile]
      pkce: required
      subject:
        strategy: entra_oid_tid
        required_tid: "<tenant-id>"
      trust:
        email_binding: verified_email_invitation
        allowed_email_domains:
          - "example.com"
```

Do not write the Client secret directly into YAML.

Store it in a file.

```bash
printf '%s' '<Entra client secret>' > .quickstart/entra_client_secret
chmod 600 .quickstart/entra_client_secret
```

In production, use an HTTPS public URL.

```yaml
server:
  public_base_url: "https://auth.example.com"

identity_providers:
  default: entra
  providers:
    entra:
      type: oidc
      profile: entra
      display_name: "Microsoft Entra ID"
      issuer: "https://login.microsoftonline.com/<tenant-id>/v2.0"
      client_id: "<Application client ID>"
      client_secret_file: "/etc/lore-auth/entra_client_secret"
      redirect_url: "https://auth.example.com/auth/entra/callback"
      scopes: [openid, email, profile]
      pkce: required
      subject:
        strategy: entra_oid_tid
        required_tid: "<tenant-id>"
      trust:
        email_binding: verified_email_invitation
        allowed_email_domains:
          - "example.com"
```

`subject.strategy: entra_oid_tid` requires `subject.required_tid`.

The tenant pin prevents subject collisions when an Entra setup can involve more than one tenant.

The OIDC adapter reads the ID token `tid` and `oid` claims and stores the bridge subject as `tid:oid`.

`trust.email_binding: verified_email_invitation` needs the ID token to contain a verified email matching a pending invitation.

See [Configuration](configuration.md#identity_providers) for the exact binding and `trust.allowed_email_domains` rules.

## User Registration

Even after Entra ID login succeeds, the bridge does not issue a token unless the corresponding user is registered in the bridge DB.

Usually, an administrator registers the target user's email.

```bash
lore-authctl --config .quickstart/lore-auth.yaml user invite \
  --idp entra \
  --email '<Entra user email>' \
  --name '<display name>'
```

At this point, linkage with the Entra account is not complete, so no token is issued.

If the user is not invited, no token is issued.

After the invitation is created, open `/login` again to create the bridge browser session.

```text
http://localhost:8080/login
```

## Behavior

The bridge verifies the Entra ID token in the callback.

After verification, it checks the token tenant ID against `subject.required_tid`.

It then resolves the provider ID, issuer, and `tid:oid` subject against `external_identities`.

If an active binding exists, the browser session or CLI auth session completes.

If no active binding exists, the generic invitation-binding policy from [Configuration](configuration.md#identity_providers) applies.

If no binding or invitation matches, the bridge does not issue a token and displays the whoami page.

## Common Failures

If callback handling fails, check that the redirect URI registered in Entra ID exactly matches `identity_providers.providers.entra.redirect_url`.

If login succeeds at Entra ID but no Lore token is issued, invite the verified email with `lore-authctl --config <cfg> user invite --idp entra`, then retry login.

If login is rejected after callback, check that the ID token `tid` claim matches `subject.required_tid`.

If the bridge reports that `entra_oid_tid` requires `tid` and `oid` claims, confirm that the app registration and issuer are returning Entra ID tokens for the expected tenant.

If the invitation is not consumed, confirm that the ID token contains the expected email and that the email is treated as verified by the provider claims.

If any of `identity_providers.providers.entra.client_id`, `identity_providers.providers.entra.client_secret_file`, or `identity_providers.providers.entra.redirect_url` is empty, Entra ID login is not enabled.

