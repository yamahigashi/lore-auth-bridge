package sqlite

import (
	"context"
	"database/sql"
	"fmt"
)

type AddIssuedTokenParams struct {
	JTI            string
	UserID         string
	RepositoryID   string
	LoreResourceID string
	Role           string
	Kid            string
	IssuedAt       int64
	ExpiresAt      int64
}

func (s *Store) AddIssuedToken(ctx context.Context, p AddIssuedTokenParams) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO issued_tokens (jti, user_id, repository_id, lore_resource_id, role, kid, issued_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, p.JTI, sql.NullString{String: p.UserID, Valid: p.UserID != ""}, p.RepositoryID, p.LoreResourceID, p.Role, p.Kid, p.IssuedAt, p.ExpiresAt)
	if err != nil {
		return fmt.Errorf("store: add issued token: %w", err)
	}
	return nil
}

func (s *Store) UserGroupNames(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT g.name FROM groups g JOIN group_members gm ON gm.group_id = g.id WHERE gm.user_id = ? ORDER BY g.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// AddIssuedTokenV2 records an issued token with its kind (authn|authz) and the
// JSON-encoded audience list.
func (s *Store) AddIssuedTokenV2(ctx context.Context, p AddIssuedTokenParams, kind, audienceJSON string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO issued_tokens (jti, user_id, repository_id, lore_resource_id, role, kid, issued_at, expires_at, token_kind, audience_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.JTI,
		sql.NullString{String: p.UserID, Valid: p.UserID != ""},
		sql.NullString{String: p.RepositoryID, Valid: p.RepositoryID != ""},
		p.LoreResourceID, p.Role, p.Kid, p.IssuedAt, p.ExpiresAt, kind, audienceJSON)
	if err != nil {
		return fmt.Errorf("store: add issued token v2: %w", err)
	}
	return nil
}

// UserResourceGrants returns the Lore resource ids a user can access (writer),
// resolved from grants (direct and via groups).
func (s *Store) UserAccessibleRepositories(ctx context.Context, userID string) ([]Repository, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT DISTINCT r.id, r.name, r.remote_url, r.lore_repository_id, r.status, r.created_at, r.updated_at
FROM repositories r
JOIN grants g ON g.repository_id = r.id
WHERE r.status = 'active' AND (
  (g.subject_type = 'user' AND g.subject_id = ?)
  OR (g.subject_type = 'group' AND g.subject_id IN (SELECT group_id FROM group_members WHERE user_id = ?))
)
ORDER BY r.name`, userID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Repository
	for rows.Next() {
		var r Repository
		if err := rows.Scan(&r.ID, &r.Name, &r.RemoteURL, &r.LoreRepositoryID, &r.Status, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
