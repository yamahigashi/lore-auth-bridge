package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
)

var ErrNotFound = model.ErrNotFound

func NewID() string { return uuid.NewString() }

func nullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func intBool(v int) bool { return v != 0 }

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

type AddUserParams struct {
	Provider      string
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	DisplayName   string
	PictureURL    string
	HostedDomain  string
}

type AddPreRegisteredUserParams struct {
	Provider    string
	Issuer      string
	Email       string
	DisplayName string
}

func (s *Store) AddUser(ctx context.Context, p AddUserParams) (*User, error) {
	now := UnixNow()
	u := &User{ID: NewID(), Provider: p.Provider, Issuer: p.Issuer, Subject: p.Subject, Email: nullString(p.Email), EmailVerified: p.EmailVerified, DisplayName: nullString(p.DisplayName), PictureURL: nullString(p.PictureURL), HostedDomain: nullString(p.HostedDomain), Status: "active", CreatedAt: now, UpdatedAt: now}
	_, err := s.db.ExecContext(ctx, `INSERT INTO users (id, provider, issuer, subject, email, email_normalized, email_verified, display_name, picture_url, hosted_domain, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, u.ID, u.Provider, u.Issuer, u.Subject, u.Email, nullString(normalizeEmail(p.Email)), boolInt(u.EmailVerified), u.DisplayName, u.PictureURL, u.HostedDomain, u.Status, u.CreatedAt, u.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("store: add user: %w", err)
	}
	return u, nil
}

func (s *Store) AddPreRegisteredUser(ctx context.Context, p AddPreRegisteredUserParams) (*User, error) {
	email := strings.TrimSpace(p.Email)
	emailNormalized := normalizeEmail(email)
	if p.Provider == "" || p.Issuer == "" || emailNormalized == "" {
		return nil, fmt.Errorf("%w: provider, issuer, and email are required", model.ErrInvalidArgument)
	}
	now := UnixNow()
	id := NewID()
	u := &User{ID: id, Provider: p.Provider, Issuer: p.Issuer, Subject: "pending:" + id, Email: nullString(email), DisplayName: nullString(p.DisplayName), Status: "pending", CreatedAt: now, UpdatedAt: now}
	_, err := s.db.ExecContext(ctx, `INSERT INTO users (id, provider, issuer, subject, email, email_normalized, email_verified, display_name, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)`, u.ID, u.Provider, u.Issuer, u.Subject, u.Email, emailNormalized, u.DisplayName, u.Status, u.CreatedAt, u.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("store: add pre-registered user: %w", err)
	}
	return u, nil
}

func (s *Store) FindUserByEmail(ctx context.Context, email string) (*User, error) {
	return s.scanUser(s.db.QueryRowContext(ctx, `SELECT id, provider, issuer, subject, email, email_verified, display_name, picture_url, hosted_domain, status, created_at, updated_at, last_login_at FROM users WHERE email_normalized = ? ORDER BY created_at LIMIT 1`, normalizeEmail(email)))
}

func (s *Store) FindUserByIdentity(ctx context.Context, provider, issuer, subject string) (*User, error) {
	return s.scanUser(s.db.QueryRowContext(ctx, `SELECT id, provider, issuer, subject, email, email_verified, display_name, picture_url, hosted_domain, status, created_at, updated_at, last_login_at FROM users WHERE provider = ? AND issuer = ? AND subject = ?`, provider, issuer, subject))
}

func (s *Store) UserByID(ctx context.Context, id string) (*User, error) {
	return s.scanUser(s.db.QueryRowContext(ctx, `SELECT id, provider, issuer, subject, email, email_verified, display_name, picture_url, hosted_domain, status, created_at, updated_at, last_login_at FROM users WHERE id = ?`, id))
}

type rowScanner interface{ Scan(dest ...any) error }

func (s *Store) scanUser(row rowScanner) (*User, error) {
	var u User
	var subject sql.NullString
	var emailVerified int
	err := row.Scan(&u.ID, &u.Provider, &u.Issuer, &subject, &u.Email, &emailVerified, &u.DisplayName, &u.PictureURL, &u.HostedDomain, &u.Status, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u.Subject = subject.String
	u.EmailVerified = intBool(emailVerified)
	return &u, nil
}

func (s *Store) BindPreRegisteredIdentity(ctx context.Context, identity model.Identity) (*User, error) {
	if !identity.EmailVerified || strings.TrimSpace(identity.Email) == "" {
		return nil, ErrNotFound
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	if user, err := s.scanUser(tx.QueryRowContext(ctx, `SELECT id, provider, issuer, subject, email, email_verified, display_name, picture_url, hosted_domain, status, created_at, updated_at, last_login_at FROM users WHERE provider = ? AND issuer = ? AND subject = ?`, identity.Provider, identity.Issuer, identity.Subject)); err == nil {
		return user, tx.Commit()
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}

	emailNormalized := normalizeEmail(identity.Email)
	pending, err := s.scanUser(tx.QueryRowContext(ctx, `SELECT id, provider, issuer, subject, email, email_verified, display_name, picture_url, hosted_domain, status, created_at, updated_at, last_login_at FROM users WHERE provider = ? AND issuer = ? AND email_normalized = ? AND status = 'pending'`, identity.Provider, identity.Issuer, emailNormalized))
	if err != nil {
		return nil, err
	}

	now := UnixNow()
	res, err := tx.ExecContext(ctx, `UPDATE users SET subject = ?, email = ?, email_normalized = ?, email_verified = 1, display_name = ?, picture_url = ?, hosted_domain = ?, status = 'active', updated_at = ?, last_login_at = ? WHERE id = ? AND status = 'pending'`, identity.Subject, identity.Email, emailNormalized, nullString(identity.Name), nullString(identity.PictureURL), nullString(identity.HostedDomain), now, now, pending.ID)
	if err != nil {
		return nil, fmt.Errorf("store: bind pre-registered identity: %w", err)
	}
	if err := requireAffected(res); err != nil {
		return nil, err
	}
	user, err := s.scanUser(tx.QueryRowContext(ctx, `SELECT id, provider, issuer, subject, email, email_verified, display_name, picture_url, hosted_domain, status, created_at, updated_at, last_login_at FROM users WHERE id = ?`, pending.ID))
	if err != nil {
		return nil, err
	}
	return user, tx.Commit()
}

func (s *Store) DisableUser(ctx context.Context, emailOrID string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET status = 'disabled', updated_at = ? WHERE id = ? OR email_normalized = ?`, UnixNow(), emailOrID, normalizeEmail(emailOrID))
	if err != nil {
		return err
	}
	return requireAffected(res)
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, provider, issuer, subject, email, email_verified, display_name, picture_url, hosted_domain, status, created_at, updated_at, last_login_at FROM users ORDER BY email, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := s.scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

func (s *Store) AddGroup(ctx context.Context, name, description string) (*Group, error) {
	now := UnixNow()
	g := &Group{ID: NewID(), Name: name, Description: nullString(description), CreatedAt: now, UpdatedAt: now}
	_, err := s.db.ExecContext(ctx, `INSERT INTO groups (id, name, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`, g.ID, g.Name, g.Description, g.CreatedAt, g.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("store: add group: %w", err)
	}
	return g, nil
}

func (s *Store) FindGroupByName(ctx context.Context, name string) (*Group, error) {
	var g Group
	err := s.db.QueryRowContext(ctx, `SELECT id, name, description, created_at, updated_at FROM groups WHERE name = ?`, name).Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt, &g.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &g, nil
}

func (s *Store) ListGroups(ctx context.Context) ([]Group, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, description, created_at, updated_at FROM groups ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Group
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *Store) AddGroupMember(ctx context.Context, groupName, userEmailOrID string) error {
	g, err := s.FindGroupByName(ctx, groupName)
	if err != nil {
		return err
	}
	u, err := s.ResolveUser(ctx, userEmailOrID)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT OR IGNORE INTO group_members (group_id, user_id, created_at) VALUES (?, ?, ?)`, g.ID, u.ID, UnixNow())
	return err
}

func (s *Store) RemoveGroupMember(ctx context.Context, groupName, userEmailOrID string) error {
	g, err := s.FindGroupByName(ctx, groupName)
	if err != nil {
		return err
	}
	u, err := s.ResolveUser(ctx, userEmailOrID)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM group_members WHERE group_id = ? AND user_id = ?`, g.ID, u.ID)
	if err != nil {
		return err
	}
	return requireAffected(res)
}

func (s *Store) ResolveUser(ctx context.Context, emailOrID string) (*User, error) {
	u, err := s.UserByID(ctx, emailOrID)
	if err == nil {
		return u, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, fmt.Errorf("store: resolve user by id: %w", err)
	}
	return s.FindUserByEmail(ctx, emailOrID)
}

func (s *Store) AddRepository(ctx context.Context, name, remoteURL, loreRepositoryID string) (*Repository, error) {
	now := UnixNow()
	r := &Repository{ID: NewID(), Name: name, RemoteURL: remoteURL, LoreRepositoryID: loreRepositoryID, Status: "active", CreatedAt: now, UpdatedAt: now}
	_, err := s.db.ExecContext(ctx, `INSERT INTO repositories (id, name, remote_url, lore_repository_id, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`, r.ID, r.Name, r.RemoteURL, r.LoreRepositoryID, r.Status, r.CreatedAt, r.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("store: add repository: %w", err)
	}
	return r, nil
}

func (s *Store) FindRepositoryByName(ctx context.Context, name string) (*Repository, error) {
	var r Repository
	err := s.db.QueryRowContext(ctx, `SELECT id, name, remote_url, lore_repository_id, status, created_at, updated_at FROM repositories WHERE name = ?`, name).Scan(&r.ID, &r.Name, &r.RemoteURL, &r.LoreRepositoryID, &r.Status, &r.CreatedAt, &r.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Store) ListRepositories(ctx context.Context) ([]Repository, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, remote_url, lore_repository_id, status, created_at, updated_at FROM repositories ORDER BY name`)
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

func (s *Store) AddGrant(ctx context.Context, subjectType, subjectID, repoName, role string) (*Grant, error) {
	repo, err := s.FindRepositoryByName(ctx, repoName)
	if err != nil {
		return nil, err
	}
	now := UnixNow()
	g := &Grant{ID: NewID(), SubjectType: subjectType, SubjectID: subjectID, RepositoryID: repo.ID, Role: role, CreatedAt: now, UpdatedAt: now}
	_, err = s.db.ExecContext(ctx, `INSERT INTO grants (id, subject_type, subject_id, repository_id, role, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`, g.ID, g.SubjectType, g.SubjectID, g.RepositoryID, g.Role, g.CreatedAt, g.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("store: add grant: %w", err)
	}
	return g, nil
}

func (s *Store) RemoveGrant(ctx context.Context, subjectType, subjectID, repoName, role string) error {
	repo, err := s.FindRepositoryByName(ctx, repoName)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM grants WHERE subject_type = ? AND subject_id = ? AND repository_id = ? AND role = ?`, subjectType, subjectID, repo.ID, role)
	if err != nil {
		return err
	}
	return requireAffected(res)
}

func (s *Store) ListGrants(ctx context.Context, repoName string) ([]Grant, error) {
	var args []any
	q := `SELECT g.id, g.subject_type, g.subject_id, g.repository_id, g.role, g.created_at, g.updated_at FROM grants g`
	if repoName != "" {
		repo, err := s.FindRepositoryByName(ctx, repoName)
		if err != nil {
			return nil, err
		}
		q += ` WHERE g.repository_id = ?`
		args = append(args, repo.ID)
	}
	q += ` ORDER BY g.repository_id, g.subject_type, g.subject_id, g.role`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Grant
	for rows.Next() {
		var g Grant
		if err := rows.Scan(&g.ID, &g.SubjectType, &g.SubjectID, &g.RepositoryID, &g.Role, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func requireAffected(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// UpsertResource creates or reactivates a repository row keyed by its Lore
// resource id (urc-{lore_repository_id}). Used by RebacApi.CreateResource.
func (s *Store) UpsertResource(ctx context.Context, resourceID, resourceName string) error {
	loreRepoID := resourceID
	if len(resourceID) >= 4 && resourceID[:4] == "urc-" {
		loreRepoID = resourceID[4:]
	}
	name := resourceName
	if name == "" {
		name = loreRepoID
	}
	now := UnixNow()
	res, err := s.db.ExecContext(ctx, `UPDATE repositories SET status = 'active', updated_at = ? WHERE lore_repository_id = ?`, now, loreRepoID)
	if err != nil {
		return fmt.Errorf("store: upsert resource update: %w", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO repositories (id, name, remote_url, lore_repository_id, status, created_by_source, created_at, updated_at) VALUES (?, ?, ?, ?, 'active', 'rebac_create_resource', ?, ?)`, NewID(), name, "", loreRepoID, now, now)
	if err != nil {
		return fmt.Errorf("store: upsert resource insert: %w", err)
	}
	return nil
}

// SoftDeleteResource marks a repository row deleted by its Lore resource id.
func (s *Store) SoftDeleteResource(ctx context.Context, resourceID string) error {
	loreRepoID := resourceID
	if len(resourceID) >= 4 && resourceID[:4] == "urc-" {
		loreRepoID = resourceID[4:]
	}
	res, err := s.db.ExecContext(ctx, `UPDATE repositories SET status = 'deleted', updated_at = ? WHERE lore_repository_id = ?`, UnixNow(), loreRepoID)
	if err != nil {
		return err
	}
	return requireAffected(res)
}

// FindRepositoryByResourceID resolves a repository from a Lore resource id of
// the form "urc-{lore_repository_id}".
func (s *Store) FindRepositoryByResourceID(ctx context.Context, resourceID string) (*Repository, error) {
	loreRepoID := resourceID
	if len(resourceID) >= 4 && resourceID[:4] == "urc-" {
		loreRepoID = resourceID[4:]
	}
	var r Repository
	err := s.db.QueryRowContext(ctx, `SELECT id, name, remote_url, lore_repository_id, status, created_at, updated_at FROM repositories WHERE lore_repository_id = ?`, loreRepoID).Scan(&r.ID, &r.Name, &r.RemoteURL, &r.LoreRepositoryID, &r.Status, &r.CreatedAt, &r.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}
