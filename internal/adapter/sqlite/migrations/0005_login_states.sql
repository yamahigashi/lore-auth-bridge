-- ADR 0005: provider-bound one-time OAuth/OIDC login state.

CREATE TABLE IF NOT EXISTS login_states (
  id TEXT PRIMARY KEY,
  state_hash TEXT NOT NULL UNIQUE,
  provider_id TEXT NOT NULL,
  login_url_nonce TEXT,
  return_path TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_login_states_provider ON login_states(provider_id);
CREATE INDEX IF NOT EXISTS idx_login_states_expires ON login_states(expires_at);

