#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATIC_DIR="$ROOT/crates/lore-auth-inbound/src/admin/static"
NOTICE="$STATIC_DIR/NOTICE.md"

asset_sha256() {
  local asset="$1"
  awk -v asset="$asset" '
    $0 == "- `" asset "`" { in_asset = 1; next }
    in_asset && $0 ~ /^- `/ { exit }
    in_asset && $0 ~ /- SHA256:/ { print $3; exit }
  ' "$NOTICE"
}

fetch_asset() {
  local asset="$1"
  local url="$2"
  local expected actual tmp

  expected="$(asset_sha256 "$asset")"
  if [[ -z "$expected" ]]; then
    echo "missing SHA256 for $asset in $NOTICE" >&2
    exit 1
  fi

  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' RETURN
  curl --fail --location --silent --show-error "$url" --output "$tmp"
  actual="$(sha256sum "$tmp" | awk '{print $1}')"
  if [[ "$actual" != "$expected" ]]; then
    echo "SHA256 mismatch for $asset" >&2
    echo "expected: $expected" >&2
    echo "actual:   $actual" >&2
    exit 1
  fi
  cp "$tmp" "$STATIC_DIR/$asset"
}

fetch_asset "htmx.min.js" "https://unpkg.com/htmx.org@2.0.4/dist/htmx.min.js"
fetch_asset "pico.min.css" "https://cdn.jsdelivr.net/npm/@picocss/pico@2.0.6/css/pico.min.css"
