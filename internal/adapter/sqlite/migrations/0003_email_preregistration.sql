-- ADR 0004: email pre-registration for Google OIDC login.

ALTER TABLE users ADD COLUMN email_normalized TEXT;

UPDATE users
SET email_normalized = lower(trim(email))
WHERE email IS NOT NULL AND trim(email) <> '';

CREATE INDEX IF NOT EXISTS idx_users_email_normalized ON users(email_normalized);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_pending_email
ON users(provider, issuer, email_normalized)
WHERE status = 'pending' AND email_normalized IS NOT NULL;
