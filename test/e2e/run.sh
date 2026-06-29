#!/usr/bin/env bash
# Run the lore-auth-bridge end-to-end test against the real lore/loreserver.
#
# Prerequisites:
#   - `lore` and `loreserver` installed and on PATH
#     (curl -fsSL https://raw.githubusercontent.com/EpicGames/lore/main/scripts/install.sh | bash)
#
# Usage:
#   test/e2e/run.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
LORE_E2E=1 go test -tags e2e -count=1 -v ./test/e2e/... "$@"
