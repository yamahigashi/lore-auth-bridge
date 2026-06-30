-- Browser CSRF tokens for state-changing form actions.

CREATE TABLE IF NOT EXISTS csrf_tokens (
  token_hash TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER,
  FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_csrf_tokens_session ON csrf_tokens(session_id);
