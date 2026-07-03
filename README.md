# lore-auth-bridge

[日本語](README.ja.md)

`lore-auth-bridge` is a Rust bridge that connects Lore authentication to external identity providers and ACL backends.

It provides login, repository-scoped token exchange, JWKS-based signature verification, and repository lifecycle synchronization for the Lore CLI and `loreserver`.

In the default deployment, users log in through an OIDC identity provider.

The bridge stores users, groups, repositories, and grants in SQLite, then evaluates those relationships with its ReBAC authorization engine.

## What Is This / How It Fits

`lore-auth-bridge` implements the Lore UCS Auth / ReBAC protocol surface that sits between a Lore deployment, an identity provider, and the operator-managed access model.

```text
Browser + IdP
    <---- OIDC login ----> bridge HTTP
                            /login, /device, /.well-known/jwks.json
                                      |
                                      | signs authn/authz JWTs
                                      v
lore CLI <---- repository ops ----> loreserver
    |                                  |
    | UrcAuthApi: authn token ->       | RebacApi: repository create/delete
    | repository authz token           | HTTP JWKS: JWT verification keys
    +-----------> bridge gRPC <--------+
                 epic_urc.UrcAuthApi
                 ucs.auth.RebacApi
```

The user first obtains an **authn token** as proof of login.

During repository operations, Lore exchanges that authn token through `UrcAuthApi` for a short-lived, repository-scoped **authz token**.

`loreserver` also calls `RebacApi` so the bridge learns when repositories are created or deleted.

For the operational component list, see [Setup Guide](doc/setup-guide.md#components).

Mini glossary:

- **UCS Auth**: Lore's authentication protocol surface, exposed here through `epic_urc.UrcAuthApi`.
- **ReBAC**: relationship-based access control. The bridge evaluates relationships such as user -> group -> repository.
- **authn token / authz token**: an authn token proves login to the auth service; an authz token is a short-lived repository token produced after permission evaluation.
- **resource_id**: the Lore authorization resource identifier, in `urc-{lore_repository_id}` form. It is not the repository name.
- **grant / role**: a grant assigns a `reader`, `writer`, or `admin` role to a user or group for one repository. This documentation uses `writer` for normal repository operations.

## Features

- Browser login with OIDC identity providers
- Administrative CLI for users, groups, repositories, grants, and signing keys
- RS256 signing for authn tokens and repository-scoped authz tokens
- Public key distribution through a JWKS endpoint
- Token exchange and resource synchronization through Lore's UCS Auth / ReBAC protocol

The end-to-end path for login, repository creation, token exchange, and clone has been verified with real `lore` / `loreserver` 0.8.4+283 binaries.

## Start Here

Start with the [Setup Guide](doc/setup-guide.md) for configuration and operations.

Main procedure pages:

- [Configuration](doc/setup/configuration.md)
- [TLS](doc/setup/tls.md)
- [Tailscale](doc/setup/tailscale.md)
- [Signing Keys](doc/setup/signing-keys.md)
- [Loreserver](doc/setup/loreserver.md)
- [Authctl](doc/setup/authctl.md)
- [Identity Providers](doc/setup/identity-providers.md)
- [Google OIDC](doc/setup/google-oidc.md)
- [Hands-on Quickstart](doc/setup/hands-on-quickstart.md)

## Binaries

This repository builds three main binaries:

- `lore-auth-server`: HTTP / gRPC server
- `lore-authctl`: administrative CLI
- `lore-claimprobe`: CLI for validating the claim contract against the Lore binary in use

## Requirements

- Rust stable toolchain
- `lore` / `loreserver` binaries for real integration checks

## Getting lore and loreserver

Use `lore` and `loreserver` binaries from a Lore distribution that matches your deployment.

The Lore reference checkout documents release downloads at <https://github.com/EpicGames/lore/releases> and install scripts under `scripts/install.sh` and `scripts/install.ps1`.

If you build Lore from source, the checked source uses a Cargo workspace.

From the Lore repository root:

```bash
cargo build --release -p lore-client --bin lore -p lore-server --bin loreserver

export PATH="$PWD/target/release:$PATH"
lore --version
loreserver --help
```

On Windows, the compiled binaries are `target\release\lore.exe` and `target\release\loreserver.exe`.

This bridge has been verified with real `lore` / `loreserver` 0.8.4+283 binaries.

## Installation

For released builds, download the platform archive from the project GitHub Releases page and put `lore-auth-server`, `lore-authctl`, and `lore-claimprobe` on `PATH`.

When working from local changes, clone this repository and build the binaries from the checkout.

## Build

Unix shell:

```bash
cargo build --release

target/release/lore-auth-server --help
target/release/lore-authctl --help
target/release/lore-claimprobe --help
```

Windows PowerShell:

```powershell
cargo build --release

.\target\release\lore-auth-server.exe --help
.\target\release\lore-authctl.exe --help
.\target\release\lore-claimprobe.exe --help
```

## Development Checks

Use Cargo for the Rust workspace checks.

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

The Rust end-to-end harness runs only when explicitly enabled.

```bash
cargo build -p lore-auth-server -p lore-authctl
LORE_E2E=1 \
LORE_E2E_BRIDGE_BIN=target/debug/lore-auth-server \
LORE_E2E_AUTHCTL_BIN=target/debug/lore-authctl \
cargo test -p lore-auth-e2e -- --test-threads=1
```

## Configuration And Startup

An example configuration is available at [configs/lore-auth.example.yaml](configs/lore-auth.example.yaml).

The database, JWT issuer / audience, signing key, IdP settings, TLS, and `loreserver` auth configuration must be aligned.

See the [Setup Guide](doc/setup-guide.md) for the full procedure.

```bash
target/release/lore-authctl --config configs/lore-auth.example.yaml init-db
target/release/lore-auth-server --config configs/lore-auth.example.yaml
```

On Windows, use `.\target\release\lore-authctl.exe` and `.\target\release\lore-auth-server.exe`.

## User Registration

When IdP login is enabled, an administrator can preregister a user by provider ID and email.

```bash
PROVIDER_ID=company-sso

target/release/lore-authctl --config configs/lore-auth.example.yaml user invite \
  --idp "$PROVIDER_ID" \
  --email alice@example.com \
  --name "Alice Example"
```

See [Identity Providers](doc/setup/identity-providers.md) and [Authctl](doc/setup/authctl.md) for details.

## Claim Contract Verification

When pairing the bridge with a new Lore binary, use `lore-claimprobe` to validate the JWT claim contract.

## Security Notes

- Store private keys on the filesystem with mode `0600`. Do not store private keys in the DB or JWKS.
- Do not leave JWTs, Google client secrets, or private keys in logs or in the repository.
- `lore-authctl token mint-authn --print-login-command` and the web token page display token bodies.
  Do not use them in shared terminals, CI logs, or browser histories.
- See [Signing Keys](doc/setup/signing-keys.md) for signing key and token rotation.

## License

MIT License.
