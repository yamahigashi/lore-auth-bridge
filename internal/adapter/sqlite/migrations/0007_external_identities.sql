-- ADR 0006: split bridge principals from external login identities.

CREATE TABLE IF NOT EXISTS external_identities (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  provider_id TEXT NOT NULL,
  issuer TEXT NOT NULL,
  subject TEXT NOT NULL,
  subject_strategy TEXT NOT NULL,
  email TEXT,
  email_verified INTEGER NOT NULL DEFAULT 0,
  display_name TEXT,
  picture_url TEXT,
  hosted_domain TEXT,
  status TEXT NOT NULL,
  first_seen_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  UNIQUE(provider_id, issuer, subject)
);

CREATE INDEX IF NOT EXISTS idx_external_identities_user
ON external_identities(user_id);

CREATE TABLE IF NOT EXISTS identity_invitations (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  provider_id TEXT NOT NULL,
  issuer TEXT NOT NULL,
  email TEXT,
  email_normalized TEXT,
  binding_policy TEXT NOT NULL,
  status TEXT NOT NULL,
  accepted_identity_id TEXT REFERENCES external_identities(id),
  created_at INTEGER NOT NULL,
  expires_at INTEGER,
  accepted_at INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_identity_invitations_pending_email
ON identity_invitations(provider_id, issuer, email_normalized)
WHERE status = 'pending' AND email_normalized IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_identity_invitations_user
ON identity_invitations(user_id);
