-- ADR 0002: UCS Auth gRPC + ReBAC + JWKS provider schema deltas.

ALTER TABLE repositories ADD COLUMN created_by_source TEXT NOT NULL DEFAULT 'manual';

-- Rebuild issued_tokens so authn tokens can have no repository/resource.
CREATE TABLE issued_tokens_new (
  jti TEXT PRIMARY KEY,
  token_kind TEXT NOT NULL,
  user_id TEXT,
  service_account_id TEXT,
  repository_id TEXT,
  lore_resource_id TEXT,
  role TEXT NOT NULL,
  kid TEXT NOT NULL,
  audience_json TEXT NOT NULL DEFAULT '[]',
  issued_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER,
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (repository_id) REFERENCES repositories(id)
);

INSERT INTO issued_tokens_new (
  jti, token_kind, user_id, service_account_id, repository_id, lore_resource_id,
  role, kid, audience_json, issued_at, expires_at, revoked_at
)
SELECT
  jti, 'authz', user_id, service_account_id, repository_id, lore_resource_id,
  role, kid, '[]', issued_at, expires_at, revoked_at
FROM issued_tokens;

DROP TABLE issued_tokens;
ALTER TABLE issued_tokens_new RENAME TO issued_tokens;

CREATE TABLE IF NOT EXISTS auth_sessions (
  id TEXT PRIMARY KEY,
  session_code_hash TEXT NOT NULL UNIQUE,
  client_state_hash TEXT NOT NULL,
  status TEXT NOT NULL,
  user_id TEXT,
  login_url_nonce TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  completed_at INTEGER,
  consumed_at INTEGER,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_status ON auth_sessions(status);
CREATE INDEX IF NOT EXISTS idx_issued_tokens_kind ON issued_tokens(token_kind);
