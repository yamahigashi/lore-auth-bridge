# Lore Proto Notice

Files under `third_party/lore-proto/proto/` are vendored from EpicGames/lore.

Upstream source paths:

- `lore-proto/proto/auth_api.proto`
- `lore-proto/proto/rebac_api.proto`

Upstream copyright:

- Copyright (c) 2026 Epic Games, Inc.

License:

- MIT.
- See `third_party/lore-proto/LICENSE`.

Local changes:

- `auth_api.proto` is placed at `proto/epicurc/auth_api.proto`.
- `rebac_api.proto` is placed at `proto/ucsauth/rebac_api.proto`.
- Go `go_package` options were added for generated Go package paths.

The protocol service and message definitions are otherwise unchanged.
