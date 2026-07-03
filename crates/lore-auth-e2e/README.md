# lore-auth-e2e

Rust integration-test harness for the Lore end-to-end suite.

This crate replaces the former Go harness.
It contains the full 12-scenario Rust port and is the only maintained end-to-end harness.

Run the suite with the real Lore binaries available on `PATH`:

```bash
LORE_E2E=1 \
LORE_E2E_BRIDGE_BIN=$PWD/target/debug/lore-auth-server \
LORE_E2E_AUTHCTL_BIN=$PWD/target/debug/lore-authctl \
cargo test -p lore-auth-e2e -- --test-threads=1
```

The suite is intentionally serial for now.
The harness mirrors the Go e2e setup and still starts `loreserver` on the fixed Lore ports `41337` and `41339`, so parallel test execution would race on those ports.
