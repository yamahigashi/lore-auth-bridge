-- ADR 0006: provider-bound one-time OAuth/OIDC login transaction.

CREATE TABLE IF NOT EXISTS login_transactions (
  id TEXT PRIMARY KEY,
  state_hash TEXT NOT NULL UNIQUE,
  provider_id TEXT NOT NULL,
  nonce TEXT,
  login_url_nonce TEXT,
  return_path TEXT,
  private_state BLOB,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_login_transactions_provider ON login_transactions(provider_id);
CREATE INDEX IF NOT EXISTS idx_login_transactions_expires ON login_transactions(expires_at);
