#!/usr/bin/env bash
# Run the lore-auth-bridge end-to-end test against the real lore/loreserver.
#
# Prerequisites:
#   - `lore` and `loreserver` installed and on PATH
#     (curl -fsSL https://raw.githubusercontent.com/EpicGames/lore/main/scripts/install.sh | bash)
#   - Rust bridge/authctl built:
#     cargo build -p lore-auth-server -p lore-authctl
#
# Usage:
#   test/e2e/run.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
export LORE_E2E=1
export LORE_E2E_BRIDGE_BIN="${LORE_E2E_BRIDGE_BIN:-target/debug/lore-auth-server}"
export LORE_E2E_AUTHCTL_BIN="${LORE_E2E_AUTHCTL_BIN:-target/debug/lore-authctl}"
go test -tags e2e -count=1 -v ./test/e2e/... "$@"
