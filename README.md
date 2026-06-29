# lore-auth-bridge

[日本語](README.ja.md)

`lore-auth-bridge` is a Go bridge that connects Lore authentication to external identity providers and ACL backends.

It provides login, repository-scoped token exchange, JWKS-based signature verification, and repository lifecycle synchronization for the Lore CLI and `loreserver`.

The current backend set is Google OIDC, SQLite, and Casbin.

## Features

- Browser login with Google OIDC
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
- [Signing Keys](doc/setup/signing-keys.md)
- [Loreserver](doc/setup/loreserver.md)
- [Authctl](doc/setup/authctl.md)
- [Identity Providers](doc/setup/identity-providers.md)
- [Google OIDC](doc/setup/google-oidc.md)
- [Local Smoke Test](doc/setup/local-smoke-test.md)

## Binaries

This repository builds three main binaries:

- `lore-auth-server`: HTTP / gRPC server
- `lore-authctl`: administrative CLI
- `lore-claimprobe`: CLI for validating the claim contract against the Lore binary in use

## Requirements

- Go 1.26 or later
- `lore` / `loreserver` binaries for real integration checks

## Installation

When installing directly from the Go toolchain, use the public module path.

```bash
go install github.com/yamahigashi/lore-auth-bridge/cmd/lore-auth-server@latest
go install github.com/yamahigashi/lore-auth-bridge/cmd/lore-authctl@latest
go install github.com/yamahigashi/lore-auth-bridge/cmd/lore-claimprobe@latest
```

When working from local changes, clone this repository and build the binaries from the checkout.

## Build

Unix shell:

```bash
mkdir -p ./bin
go build -o ./bin/lore-auth-server ./cmd/lore-auth-server
go build -o ./bin/lore-authctl ./cmd/lore-authctl
go build -o ./bin/lore-claimprobe ./cmd/lore-claimprobe
```

Windows PowerShell:

```powershell
New-Item -ItemType Directory -Force .\bin | Out-Null
go build -o .\bin\lore-auth-server.exe ./cmd/lore-auth-server
go build -o .\bin\lore-authctl.exe ./cmd/lore-authctl
go build -o .\bin\lore-claimprobe.exe ./cmd/lore-claimprobe
```

## Development Checks

`go build ./...` checks that every package builds.

Because it targets packages rather than named binaries, it normally does not leave executable files behind.

```bash
go build ./...
go test ./...
go vet ./...
```

## Configuration And Startup

An example configuration is available at [configs/lore-auth.example.yaml](configs/lore-auth.example.yaml).

The database, JWT issuer / audience, signing key, Google OIDC settings, TLS, and `loreserver` auth configuration must be aligned.

See the [Setup Guide](doc/setup-guide.md) for the full procedure.

```bash
./bin/lore-authctl init-db --config configs/lore-auth.example.yaml
./bin/lore-auth-server --config configs/lore-auth.example.yaml
```

On Windows, use `.\bin\lore-authctl.exe` and `.\bin\lore-auth-server.exe`.

## User Registration

When Google OIDC is enabled, an administrator can preregister a user by Google account email.

```bash
./bin/lore-authctl user invite \
  --config configs/lore-auth.example.yaml \
  --email alice@example.com \
  --name "Alice Example"
```

See [Google OIDC](doc/setup/google-oidc.md) and [Authctl](doc/setup/authctl.md) for details.

## Claim Contract Verification

When pairing the bridge with a new Lore binary, use `lore-claimprobe` to validate the JWT claim contract.

The procedure is in the [Claim Probe Runbook](doc/claimprobe.md).

## Security Notes

- Store private keys on the filesystem with mode `0600`. Do not store private keys in the DB or JWKS.
- Do not leave JWTs, Google client secrets, or private keys in logs or in the repository.
- `lore-authctl --print-login-command` and the web token page display token bodies.
  Do not use them in shared terminals, CI logs, or browser histories.
- See [Signing Keys](doc/setup/signing-keys.md) for signing key and token rotation.

## License

MIT License.
