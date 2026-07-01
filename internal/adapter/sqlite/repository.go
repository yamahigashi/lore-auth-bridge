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
	Email       string
	DisplayName string
}

type AddInvitationParams struct {
	ProviderID    string
	Issuer        string
	Email         string
	DisplayName   string
	BindingPolicy string
	ExpiresAt     int64
}

const bridgePrincipalProvider = "bridge"
const bridgePrincipalIssuer = "bridge"

func (s *Store) AddUser(ctx context.Context, p AddUserParams) (*User, error) {
	now := UnixNow()
	id := NewID()
	u := &User{ID: id, Email: nullString(p.Email), DisplayName: nullString(p.DisplayName), Status: "active", CreatedAt: now, UpdatedAt: now}
	_, err := s.db.ExecContext(ctx, `INSERT INTO users (id, primary_email, primary_email_normalized, display_name, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`, u.ID, u.Email, nullString(normalizeEmail(p.Email)), u.DisplayName, u.Status, u.CreatedAt, u.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("store: add user: %w", err)
	}
	return u, nil
}

func (s *Store) AddIdentityInvitation(ctx context.Context, p AddInvitationParams) (*User, *IdentityInvitation, error) {
	email := strings.TrimSpace(p.Email)
	emailNormalized := normalizeEmail(email)
	if strings.TrimSpace(p.ProviderID) == "" || strings.TrimSpace(p.Issuer) == "" || emailNormalized == "" {
		return nil, nil, fmt.Errorf("%w: provider_id, issuer, and email are required", model.ErrInvalidArgument)
	}
	bindingPolicy := strings.TrimSpace(p.BindingPolicy)
	if bindingPolicy == "" {
		bindingPolicy = "verified_email_invitation"
	}
	now := UnixNow()
	userID := NewID()
	user := &User{
		ID:          userID,
		Email:       nullString(email),
		DisplayName: nullString(p.DisplayName),
		Status:      "pending",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	invitation := &IdentityInvitation{
		ID:              NewID(),
		UserID:          userID,
		ProviderID:      strings.TrimSpace(p.ProviderID),
		Issuer:          strings.TrimSpace(p.Issuer),
		Email:           nullString(email),
		EmailNormalized: nullString(emailNormalized),
		BindingPolicy:   bindingPolicy,
		Status:          "pending",
		CreatedAt:       now,
		ExpiresAt:       sql.NullInt64{Int64: p.ExpiresAt, Valid: p.ExpiresAt != 0},
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = tx.Rollback() }()
	_, err = tx.ExecContext(ctx, `INSERT INTO users (id, primary_email, primary_email_normalized, display_name, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		user.ID, user.Email, nullString(emailNormalized), user.DisplayName, user.Status, user.CreatedAt, user.UpdatedAt)
	if err != nil {
		return nil, nil, fmt.Errorf("store: add invitation user: %w", err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO identity_invitations (id, user_id, provider_id, issuer, email, email_normalized, binding_policy, status, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		invitation.ID, invitation.UserID, invitation.ProviderID, invitation.Issuer, invitation.Email, invitation.EmailNormalized, invitation.BindingPolicy, invitation.Status, invitation.CreatedAt, invitation.ExpiresAt)
	if err != nil {
		return nil, nil, fmt.Errorf("store: add identity invitation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}
	return user, invitation, nil
}

func (s *Store) FindUserByEmail(ctx context.Context, email string) (*User, error) {
	return s.scanUser(s.db.QueryRowContext(ctx, `SELECT id, primary_email, display_name, status, created_at, updated_at, last_login_at FROM users WHERE primary_email_normalized = ? ORDER BY created_at LIMIT 1`, normalizeEmail(email)))
}

func (s *Store) UserByID(ctx context.Context, id string) (*User, error) {
	return s.scanUser(s.db.QueryRowContext(ctx, `SELECT id, primary_email, display_name, status, created_at, updated_at, last_login_at FROM users WHERE id = ?`, id))
}

type rowScanner interface{ Scan(dest ...any) error }

func (s *Store) scanUser(row rowScanner) (*User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Email, &u.DisplayName, &u.Status, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Store) FindExternalIdentity(ctx context.Context, providerID, issuer, subject string) (*ExternalIdentity, error) {
	return s.scanExternalIdentity(s.db.QueryRowContext(ctx, `SELECT id, user_id, provider_id, issuer, subject, subject_strategy, email, email_verified, display_name, picture_url, hosted_domain, status, first_seen_at, last_seen_at FROM external_identities WHERE provider_id = ? AND issuer = ? AND subject = ?`, providerID, issuer, subject))
}

func (s *Store) IdentityInvitationByID(ctx context.Context, id string) (*IdentityInvitation, error) {
	return s.scanIdentityInvitation(s.db.QueryRowContext(ctx, `SELECT id, user_id, provider_id, issuer, email, email_normalized, binding_policy, status, accepted_identity_id, created_at, expires_at, accepted_at FROM identity_invitations WHERE id = ?`, id))
}

func (s *Store) ResolveLogin(ctx context.Context, req model.LoginResolutionRequest) (*User, *ExternalIdentity, model.LoginBindingResult, error) {
	identity := req.Identity
	providerID := strings.TrimSpace(identity.ProviderID)
	issuer := strings.TrimSpace(identity.Issuer)
	subject := strings.TrimSpace(identity.Subject)
	if providerID == "" || issuer == "" || subject == "" {
		return nil, nil, model.LoginBindingResult{}, fmt.Errorf("%w: provider_id, issuer, and subject are required", model.ErrInvalidArgument)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, model.LoginBindingResult{}, err
	}
	defer func() { _ = tx.Rollback() }()

	existingIdentity, err := s.scanExternalIdentity(tx.QueryRowContext(ctx, `SELECT id, user_id, provider_id, issuer, subject, subject_strategy, email, email_verified, display_name, picture_url, hosted_domain, status, first_seen_at, last_seen_at FROM external_identities WHERE provider_id = ? AND issuer = ? AND subject = ? AND status = 'active'`, providerID, issuer, subject))
	if err == nil {
		now := UnixNow()
		if _, err := tx.ExecContext(ctx, `UPDATE external_identities SET last_seen_at = ? WHERE id = ?`, now, existingIdentity.ID); err != nil {
			return nil, nil, model.LoginBindingResult{}, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET last_login_at = ?, updated_at = ? WHERE id = ?`, now, now, existingIdentity.UserID); err != nil {
			return nil, nil, model.LoginBindingResult{}, err
		}
		user, err := s.scanUser(tx.QueryRowContext(ctx, `SELECT id, primary_email, display_name, status, created_at, updated_at, last_login_at FROM users WHERE id = ?`, existingIdentity.UserID))
		if err != nil {
			return nil, nil, model.LoginBindingResult{}, err
		}
		if user.Status != "active" {
			return nil, nil, model.LoginBindingResult{}, fmt.Errorf("%w: user is not active", model.ErrPermissionDenied)
		}
		return user, existingIdentity, model.LoginBindingResult{Status: "existing", ExternalIdentityID: existingIdentity.ID}, tx.Commit()
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, nil, model.LoginBindingResult{}, err
	}
	if !identity.EmailVerified || strings.TrimSpace(identity.Email) == "" {
		return nil, nil, model.LoginBindingResult{}, ErrNotFound
	}
	if !allowsVerifiedEmailInvitationBinding(req.Policy) {
		return nil, nil, model.LoginBindingResult{}, ErrNotFound
	}
	emailNormalized := normalizeEmail(identity.Email)
	if !emailDomainAllowed(emailNormalized, req.Policy.AllowedEmailDomains) {
		return nil, nil, model.LoginBindingResult{}, ErrNotFound
	}
	invitation, err := s.scanIdentityInvitation(tx.QueryRowContext(ctx, `
SELECT id, user_id, provider_id, issuer, email, email_normalized, binding_policy, status, accepted_identity_id, created_at, expires_at, accepted_at
FROM identity_invitations
WHERE provider_id = ?
  AND issuer = ?
  AND email_normalized = ?
  AND binding_policy = ?
  AND status = 'pending'
  AND (expires_at IS NULL OR expires_at > ?)
ORDER BY created_at
LIMIT 1`, providerID, issuer, emailNormalized, model.LoginEmailBindingVerifiedEmailInvitation, UnixNow()))
	if err != nil {
		return nil, nil, model.LoginBindingResult{}, err
	}
	now := UnixNow()
	subjectStrategy := strings.TrimSpace(identity.SubjectStrategy)
	if subjectStrategy == "" {
		subjectStrategy = "oidc_sub"
	}
	externalIdentity := &ExternalIdentity{
		ID:              NewID(),
		UserID:          invitation.UserID,
		ProviderID:      providerID,
		Issuer:          issuer,
		Subject:         subject,
		SubjectStrategy: subjectStrategy,
		Email:           nullString(identity.Email),
		EmailVerified:   identity.EmailVerified,
		DisplayName:     nullString(identity.DisplayName),
		PictureURL:      nullString(identity.PictureURL),
		HostedDomain:    nullString(identity.HostedDomain),
		Status:          "active",
		FirstSeenAt:     now,
		LastSeenAt:      now,
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO external_identities (id, user_id, provider_id, issuer, subject, subject_strategy, email, email_verified, display_name, picture_url, hosted_domain, status, first_seen_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		externalIdentity.ID, externalIdentity.UserID, externalIdentity.ProviderID, externalIdentity.Issuer, externalIdentity.Subject, externalIdentity.SubjectStrategy, externalIdentity.Email, boolInt(externalIdentity.EmailVerified), externalIdentity.DisplayName, externalIdentity.PictureURL, externalIdentity.HostedDomain, externalIdentity.Status, externalIdentity.FirstSeenAt, externalIdentity.LastSeenAt)
	if err != nil {
		return nil, nil, model.LoginBindingResult{}, fmt.Errorf("store: add external identity: %w", err)
	}
	res, err := tx.ExecContext(ctx, `UPDATE identity_invitations SET status = 'accepted', accepted_identity_id = ?, accepted_at = ? WHERE id = ? AND status = 'pending'`, externalIdentity.ID, now, invitation.ID)
	if err != nil {
		return nil, nil, model.LoginBindingResult{}, err
	}
	if err := requireAffected(res); err != nil {
		return nil, nil, model.LoginBindingResult{}, err
	}
	displayName := identity.DisplayName
	if displayName == "" {
		displayName = invitation.Email.String
	}
	res, err = tx.ExecContext(ctx, `UPDATE users SET primary_email = ?, primary_email_normalized = ?, display_name = ?, status = 'active', updated_at = ?, last_login_at = ? WHERE id = ?`,
		identity.Email, emailNormalized, nullString(displayName), now, now, invitation.UserID)
	if err != nil {
		return nil, nil, model.LoginBindingResult{}, err
	}
	if err := requireAffected(res); err != nil {
		return nil, nil, model.LoginBindingResult{}, err
	}
	user, err := s.scanUser(tx.QueryRowContext(ctx, `SELECT id, primary_email, display_name, status, created_at, updated_at, last_login_at FROM users WHERE id = ?`, invitation.UserID))
	if err != nil {
		return nil, nil, model.LoginBindingResult{}, err
	}
	return user, externalIdentity, model.LoginBindingResult{Status: "bound_invitation", ExternalIdentityID: externalIdentity.ID, InvitationID: invitation.ID}, tx.Commit()
}

func allowsVerifiedEmailInvitationBinding(policy model.LoginTrustPolicy) bool {
	return strings.TrimSpace(policy.EmailBinding) == model.LoginEmailBindingVerifiedEmailInvitation
}

func emailDomainAllowed(email string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	domain := emailDomain(email)
	if domain == "" {
		return false
	}
	for _, allowedDomain := range allowed {
		if strings.EqualFold(strings.TrimSpace(allowedDomain), domain) {
			return true
		}
	}
	return false
}

func emailDomain(email string) string {
	email = strings.ToLower(strings.TrimSpace(email))
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return ""
	}
	return email[at+1:]
}

func (s *Store) scanExternalIdentity(row rowScanner) (*ExternalIdentity, error) {
	var id ExternalIdentity
	var emailVerified int
	err := row.Scan(&id.ID, &id.UserID, &id.ProviderID, &id.Issuer, &id.Subject, &id.SubjectStrategy, &id.Email, &emailVerified, &id.DisplayName, &id.PictureURL, &id.HostedDomain, &id.Status, &id.FirstSeenAt, &id.LastSeenAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	id.EmailVerified = intBool(emailVerified)
	return &id, nil
}

func (s *Store) scanIdentityInvitation(row rowScanner) (*IdentityInvitation, error) {
	var inv IdentityInvitation
	err := row.Scan(&inv.ID, &inv.UserID, &inv.ProviderID, &inv.Issuer, &inv.Email, &inv.EmailNormalized, &inv.BindingPolicy, &inv.Status, &inv.AcceptedIdentityID, &inv.CreatedAt, &inv.ExpiresAt, &inv.AcceptedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &inv, nil
}

func (s *Store) DisableUser(ctx context.Context, emailOrID string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET status = 'disabled', updated_at = ? WHERE id = ? OR primary_email_normalized = ?`, UnixNow(), emailOrID, normalizeEmail(emailOrID))
	if err != nil {
		return err
	}
	return requireAffected(res)
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, primary_email, display_name, status, created_at, updated_at, last_login_at FROM users ORDER BY primary_email, id`)
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
	r := &Repository{ID: NewID(), Name: name, RemoteURL: remoteURL, LoreRepositoryID: loreRepositoryID, Status: "active", CreatedBySource: "manual", CreatedAt: now, UpdatedAt: now}
	_, err := s.db.ExecContext(ctx, `INSERT INTO repositories (id, name, remote_url, lore_repository_id, status, created_by_source, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, r.ID, r.Name, r.RemoteURL, r.LoreRepositoryID, r.Status, r.CreatedBySource, r.CreatedAt, r.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("store: add repository: %w", err)
	}
	return r, nil
}

func (s *Store) FindRepositoryByName(ctx context.Context, name string) (*Repository, error) {
	return s.scanRepository(s.db.QueryRowContext(ctx, `SELECT id, name, remote_url, lore_repository_id, status, created_by_source, created_at, updated_at FROM repositories WHERE name = ? AND status = 'active'`, name))
}

func (s *Store) FindRepositoryAnyStatusByName(ctx context.Context, name string) (*Repository, error) {
	return s.scanRepository(s.db.QueryRowContext(ctx, `SELECT id, name, remote_url, lore_repository_id, status, created_by_source, created_at, updated_at FROM repositories WHERE name = ?`, name))
}

func (s *Store) ListRepositories(ctx context.Context) ([]Repository, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, remote_url, lore_repository_id, status, created_by_source, created_at, updated_at FROM repositories ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return scanRepositories(rows)
}

func (s *Store) ListActiveRepositories(ctx context.Context) ([]Repository, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, remote_url, lore_repository_id, status, created_by_source, created_at, updated_at FROM repositories WHERE status = 'active' ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return scanRepositories(rows)
}

func (s *Store) UpsertManualRepository(ctx context.Context, name, remoteURL, loreRepositoryID string) (*Repository, error) {
	resourceID := model.ResourceIDForRepositoryID(loreRepositoryID)
	existing, err := s.FindRepositoryAnyStatusByResourceID(ctx, resourceID)
	if errors.Is(err, ErrNotFound) {
		return s.AddRepository(ctx, name, remoteURL, loreRepositoryID)
	}
	if err != nil {
		return nil, err
	}
	if existing.CreatedBySource != "manual" {
		return nil, fmt.Errorf("%w: repository %s is managed by %s", model.ErrInvalidArgument, existing.LoreRepositoryID, existing.CreatedBySource)
	}
	now := UnixNow()
	res, err := s.db.ExecContext(ctx, `UPDATE repositories SET name = ?, remote_url = ?, status = 'active', updated_at = ? WHERE id = ? AND created_by_source = 'manual'`, name, remoteURL, now, existing.ID)
	if err != nil {
		return nil, fmt.Errorf("store: update manual repository: %w", err)
	}
	if err := requireAffected(res); err != nil {
		return nil, err
	}
	return s.FindRepositoryByName(ctx, name)
}

func (s *Store) scanRepository(row rowScanner) (*Repository, error) {
	var r Repository
	err := row.Scan(&r.ID, &r.Name, &r.RemoteURL, &r.LoreRepositoryID, &r.Status, &r.CreatedBySource, &r.CreatedAt, &r.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func scanRepositories(rows *sql.Rows) ([]Repository, error) {
	defer rows.Close()
	var out []Repository
	for rows.Next() {
		var r Repository
		if err := rows.Scan(&r.ID, &r.Name, &r.RemoteURL, &r.LoreRepositoryID, &r.Status, &r.CreatedBySource, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) AddGrant(ctx context.Context, subjectType, subjectID, repoName, role string) (*Grant, error) {
	if !model.IsKnownRole(role) {
		return nil, fmt.Errorf("%w: unknown grant role %q", model.ErrInvalidArgument, role)
	}
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
	return s.scanRepository(s.db.QueryRowContext(ctx, `SELECT id, name, remote_url, lore_repository_id, status, created_by_source, created_at, updated_at FROM repositories WHERE lore_repository_id = ? AND status = 'active'`, loreRepoID))
}

func (s *Store) FindRepositoryAnyStatusByResourceID(ctx context.Context, resourceID string) (*Repository, error) {
	loreRepoID := resourceID
	if len(resourceID) >= 4 && resourceID[:4] == "urc-" {
		loreRepoID = resourceID[4:]
	}
	return s.scanRepository(s.db.QueryRowContext(ctx, `SELECT id, name, remote_url, lore_repository_id, status, created_by_source, created_at, updated_at FROM repositories WHERE lore_repository_id = ?`, loreRepoID))
}
