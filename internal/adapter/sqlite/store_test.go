package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
)

func TestMigrateAndBasicCRUD(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "test.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	u, err := s.AddUser(ctx, AddUserParams{Email: "alice@example.com", DisplayName: "Alice"})
	if err != nil {
		t.Fatal(err)
	}
	if u.Status != "active" {
		t.Fatalf("unexpected status: %s", u.Status)
	}
	if _, err := s.AddGroup(ctx, "artists", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.AddGroupMember(ctx, "artists", "alice@example.com"); err != nil {
		t.Fatal(err)
	}
	repo, err := s.AddRepository(ctx, "game-assets", "lore://lore.example.com:41337/game-assets", "0194b726b34e72b0b45550b88a967076")
	if err != nil {
		t.Fatal(err)
	}
	if repo.LoreRepositoryID == "" {
		t.Fatal("missing lore repository id")
	}
	if _, err := s.AddGrant(ctx, "group", "artists", "game-assets", "writer"); err != nil {
		t.Fatal(err)
	}
	grants, err := s.ListGrants(ctx, "game-assets")
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 || grants[0].Role != "writer" {
		t.Fatalf("unexpected grants: %#v", grants)
	}
}

func TestMigrateCreatesBridgePrincipalUsersSchema(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "test.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	columns := tableColumns(t, s, "users")
	for _, removed := range []string{"provider", "issuer", "subject", "email", "email_normalized", "email_verified", "picture_url", "hosted_domain"} {
		if columns[removed] {
			t.Fatalf("users table still has external identity column %q", removed)
		}
	}
	for _, required := range []string{"id", "display_name", "primary_email", "primary_email_normalized", "status", "created_at", "updated_at", "last_login_at"} {
		if !columns[required] {
			t.Fatalf("users table missing bridge principal column %q", required)
		}
	}
}

func TestMigrateCreatesLoginTransactionsSchema(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "test.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	if !tableExists(t, s, "login_transactions") {
		t.Fatal("login_transactions table is missing")
	}
	if tableExists(t, s, "login_states") {
		t.Fatal("legacy login_states table should not exist")
	}
	columns := tableColumns(t, s, "login_transactions")
	for _, required := range []string{"id", "state_hash", "provider_id", "nonce", "login_url_nonce", "return_path", "private_state", "created_at", "expires_at", "consumed_at"} {
		if !columns[required] {
			t.Fatalf("login_transactions table missing column %q", required)
		}
	}
}

func TestLoginTransactionIsOneTimeAndCarriesPrivateState(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "test.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	state, _, err := s.CreateLoginState(ctx, CreateLoginStateParams{
		ProviderID:    "keycloak-prod",
		Nonce:         "oidc-nonce",
		LoginURLNonce: "login-url-nonce",
		TTLSeconds:    60,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetLoginStatePrivateState(ctx, state, []byte("pkce-verifier")); err != nil {
		t.Fatal(err)
	}

	got, err := s.ConsumeLoginState(ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	if got.ProviderID != "keycloak-prod" || got.Nonce.String != "oidc-nonce" || got.LoginURLNonce.String != "login-url-nonce" {
		t.Fatalf("unexpected login transaction: %#v", got)
	}
	if string(got.PrivateState) != "pkce-verifier" {
		t.Fatalf("private state = %q, want pkce verifier", string(got.PrivateState))
	}
	if _, err := s.ConsumeLoginState(ctx, state); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second ConsumeLoginState error = %v, want ErrNotFound", err)
	}
}

func TestAccountDirectoryInvitationReservesUserIDAndBindsVerifiedIdentity(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "test.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	core := NewCoreStore(s)

	user, invitation, err := core.AddInvitation(ctx, model.AddInvitationInput{
		ProviderID:    "keycloak-prod",
		Issuer:        "https://sso.example.com/realms/prod",
		Email:         "Alice@Example.com",
		DisplayName:   "Alice",
		BindingPolicy: "verified_email_invitation",
	})
	if err != nil {
		t.Fatal(err)
	}
	if user.ID == "" || invitation.UserID != user.ID {
		t.Fatalf("invitation did not reserve user id: user=%#v invitation=%#v", user, invitation)
	}
	if user.Status != "pending" {
		t.Fatalf("reserved user status = %q, want pending", user.Status)
	}

	principal, binding, err := core.ResolveLogin(ctx, model.LoginResolutionRequest{
		Identity: model.ExternalIdentity{
			ProviderID:      "keycloak-prod",
			Issuer:          "https://sso.example.com/realms/prod",
			Subject:         "subject:with:colon",
			SubjectStrategy: "oidc_sub",
			Email:           "alice@example.com",
			EmailVerified:   true,
			DisplayName:     "Alice Example",
		},
		Policy: model.LoginTrustPolicy{EmailBinding: "verified_email_invitation"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if principal.UserID != user.ID || principal.TokenSubject != "user:"+user.ID || principal.TokenIDP != "keycloak-prod" {
		t.Fatalf("unexpected principal: %#v", principal)
	}
	if binding.Status != "bound_invitation" || binding.InvitationID != invitation.ID || binding.ExternalIdentityID == "" {
		t.Fatalf("unexpected binding result: %#v", binding)
	}

	identity, err := s.FindExternalIdentity(ctx, "keycloak-prod", "https://sso.example.com/realms/prod", "subject:with:colon")
	if err != nil {
		t.Fatal(err)
	}
	if identity.UserID != user.ID || identity.SubjectStrategy != "oidc_sub" {
		t.Fatalf("unexpected stored external identity: %#v", identity)
	}
	existing, existingBinding, err := core.ResolveLogin(ctx, model.LoginResolutionRequest{
		Identity: model.ExternalIdentity{
			ProviderID: "keycloak-prod",
			Issuer:     "https://sso.example.com/realms/prod",
			Subject:    "subject:with:colon",
		},
		Policy: model.LoginTrustPolicy{EmailBinding: "disabled", AllowedEmailDomains: []string{"other.example"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if existing.UserID != user.ID || existingBinding.Status != "existing" || existingBinding.ExternalIdentityID != identity.ID {
		t.Fatalf("existing binding lookup = principal %#v binding %#v", existing, existingBinding)
	}
	active, err := s.UserByID(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if active.Status != "active" {
		t.Fatalf("user row should be an active bridge principal without external subject: %#v", active)
	}
}

func TestAccountDirectoryInvitationRejectsUnverifiedEmailAndProviderIssuerMismatch(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		identity model.ExternalIdentity
	}{
		{
			name: "unverified email",
			identity: model.ExternalIdentity{
				ProviderID:    "keycloak-prod",
				Issuer:        "https://sso.example.com/realms/prod",
				Subject:       "subject-1",
				Email:         "alice@example.com",
				EmailVerified: false,
			},
		},
		{
			name: "provider mismatch",
			identity: model.ExternalIdentity{
				ProviderID:    "google",
				Issuer:        "https://sso.example.com/realms/prod",
				Subject:       "subject-1",
				Email:         "alice@example.com",
				EmailVerified: true,
			},
		},
		{
			name: "issuer mismatch",
			identity: model.ExternalIdentity{
				ProviderID:    "keycloak-prod",
				Issuer:        "https://sso.example.com/realms/staging",
				Subject:       "subject-1",
				Email:         "alice@example.com",
				EmailVerified: true,
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			s, err := Open(filepath.Join(t.TempDir(), "test.sqlite3"))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if err := s.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			core := NewCoreStore(s)
			_, invitation, err := core.AddInvitation(ctx, model.AddInvitationInput{
				ProviderID:    "keycloak-prod",
				Issuer:        "https://sso.example.com/realms/prod",
				Email:         "Alice@Example.com",
				DisplayName:   "Alice",
				BindingPolicy: "verified_email_invitation",
			})
			if err != nil {
				t.Fatal(err)
			}

			_, _, err = core.ResolveLogin(ctx, model.LoginResolutionRequest{
				Identity: tc.identity,
				Policy:   model.LoginTrustPolicy{EmailBinding: "verified_email_invitation"},
			})
			if !errors.Is(err, ErrNotFound) {
				t.Fatalf("ResolveLogin error = %v, want ErrNotFound", err)
			}
			got, err := s.IdentityInvitationByID(ctx, invitation.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != "pending" || got.AcceptedIdentityID.Valid {
				t.Fatalf("invitation should remain pending: %#v", got)
			}
		})
	}
}

func TestAccountDirectoryInvitationRequiresProviderEmailBindingPolicy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "test.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	core := NewCoreStore(s)
	_, invitation, err := core.AddInvitation(ctx, model.AddInvitationInput{
		ProviderID:    "keycloak-prod",
		Issuer:        "https://sso.example.com/realms/prod",
		Email:         "Alice@Example.com",
		DisplayName:   "Alice",
		BindingPolicy: "verified_email_invitation",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = core.ResolveLogin(ctx, model.LoginResolutionRequest{
		Identity: model.ExternalIdentity{
			ProviderID:    "keycloak-prod",
			Issuer:        "https://sso.example.com/realms/prod",
			Subject:       "subject-1",
			Email:         "alice@example.com",
			EmailVerified: true,
		},
		Policy: model.LoginTrustPolicy{EmailBinding: "disabled"},
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("ResolveLogin error = %v, want ErrNotFound", err)
	}
	got, err := s.IdentityInvitationByID(ctx, invitation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "pending" || got.AcceptedIdentityID.Valid {
		t.Fatalf("invitation should remain pending: %#v", got)
	}
}

func TestAccountDirectoryInvitationRequiresInvitationBindingPolicy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "test.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	core := NewCoreStore(s)
	_, invitation, err := core.AddInvitation(ctx, model.AddInvitationInput{
		ProviderID:    "keycloak-prod",
		Issuer:        "https://sso.example.com/realms/prod",
		Email:         "Alice@Example.com",
		DisplayName:   "Alice",
		BindingPolicy: "unknown_policy",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = core.ResolveLogin(ctx, model.LoginResolutionRequest{
		Identity: model.ExternalIdentity{
			ProviderID:    "keycloak-prod",
			Issuer:        "https://sso.example.com/realms/prod",
			Subject:       "subject-1",
			Email:         "alice@example.com",
			EmailVerified: true,
		},
		Policy: model.LoginTrustPolicy{EmailBinding: "verified_email_invitation"},
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("ResolveLogin error = %v, want ErrNotFound", err)
	}
	got, err := s.IdentityInvitationByID(ctx, invitation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "pending" || got.AcceptedIdentityID.Valid {
		t.Fatalf("invitation should remain pending: %#v", got)
	}
}

func TestAccountDirectoryInvitationRequiresAllowedEmailDomain(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "test.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	core := NewCoreStore(s)
	_, invitation, err := core.AddInvitation(ctx, model.AddInvitationInput{
		ProviderID:    "keycloak-prod",
		Issuer:        "https://sso.example.com/realms/prod",
		Email:         "Alice@Example.com",
		DisplayName:   "Alice",
		BindingPolicy: "verified_email_invitation",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = core.ResolveLogin(ctx, model.LoginResolutionRequest{
		Identity: model.ExternalIdentity{
			ProviderID:    "keycloak-prod",
			Issuer:        "https://sso.example.com/realms/prod",
			Subject:       "subject-1",
			Email:         "alice@example.com",
			EmailVerified: true,
		},
		Policy: model.LoginTrustPolicy{
			EmailBinding:        "verified_email_invitation",
			AllowedEmailDomains: []string{"contractor.example"},
		},
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("ResolveLogin error = %v, want ErrNotFound", err)
	}
	got, err := s.IdentityInvitationByID(ctx, invitation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "pending" || got.AcceptedIdentityID.Valid {
		t.Fatalf("invitation should remain pending: %#v", got)
	}
}

func TestFindActiveAuthnTokenUserRejectsExpiredAndRevokedTokens(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "test.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	user, err := s.AddUser(ctx, AddUserParams{Email: "alice@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	core := NewCoreStore(s)
	now := UnixNow()

	if err := core.Record(ctx, model.IssuedToken{JTI: "active-jti", Kind: "authn", UserID: user.ID, Kid: "kid", IssuedAt: now, ExpiresAt: now + 60, Audience: []string{"auth.example.com"}}); err != nil {
		t.Fatal(err)
	}
	if err := core.Record(ctx, model.IssuedToken{JTI: "expired-jti", Kind: "authn", UserID: user.ID, Kid: "kid", IssuedAt: now - 120, ExpiresAt: now - 60, Audience: []string{"auth.example.com"}}); err != nil {
		t.Fatal(err)
	}
	if err := core.Record(ctx, model.IssuedToken{JTI: "revoked-jti", Kind: "authn", UserID: user.ID, Kid: "kid", IssuedAt: now, ExpiresAt: now + 60, Audience: []string{"auth.example.com"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE issued_tokens SET revoked_at = ? WHERE jti = ?`, now, "revoked-jti"); err != nil {
		t.Fatal(err)
	}

	active, err := core.FindActiveAuthnTokenUser(ctx, "active-jti")
	if err != nil {
		t.Fatal(err)
	}
	if active.ID != user.ID {
		t.Fatalf("active token user ID = %q, want %q", active.ID, user.ID)
	}
	if _, err := core.FindActiveAuthnTokenUser(ctx, "expired-jti"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired token lookup error = %v, want ErrNotFound", err)
	}
	if _, err := core.FindActiveAuthnTokenUser(ctx, "revoked-jti"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked token lookup error = %v, want ErrNotFound", err)
	}
}

func TestValidateSchemaRejectsUnmigratedDatabase(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "test.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	err = s.ValidateSchema(ctx)
	if err == nil {
		t.Fatal("expected unmigrated database to fail schema validation")
	}
	if !strings.Contains(err.Error(), "schema_migrations") {
		t.Fatalf("error = %q, want schema_migrations context", err)
	}
}

func tableColumns(t *testing.T, s *Store, table string) map[string]bool {
	t.Helper()
	rows, err := s.db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	columns := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull int
		var defaultValue any
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			t.Fatal(err)
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return columns
}

func tableExists(t *testing.T, s *Store, table string) bool {
	t.Helper()
	var name string
	err := s.db.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return false
	}
	if err != nil {
		t.Fatal(err)
	}
	return name == table
}

func TestValidateSchemaAcceptsMigratedDatabase(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "test.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	if err := s.ValidateSchema(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestDeletedRepositoryIsHiddenFromActiveResolversButVisibleInList(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "test.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	repo, err := s.AddRepository(ctx, "game-assets", "lore://example", "0194b726b34e72b0b45550b88a967076")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SoftDeleteResource(ctx, model.ResourceIDForRepositoryID(repo.LoreRepositoryID)); err != nil {
		t.Fatal(err)
	}

	if _, err := s.FindRepositoryByName(ctx, "game-assets"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("FindRepositoryByName error = %v, want ErrNotFound", err)
	}
	if _, err := s.FindRepositoryByResourceID(ctx, model.ResourceIDForRepositoryID(repo.LoreRepositoryID)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("FindRepositoryByResourceID error = %v, want ErrNotFound", err)
	}
	all, err := s.ListRepositories(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].Status != "deleted" {
		t.Fatalf("ListRepositories = %#v, want deleted row visible", all)
	}
}

func TestCoreStoreListReturnsOnlyActiveRepositories(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "test.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	active, err := s.AddRepository(ctx, "active-repo", "lore://active", "active-id")
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := s.AddRepository(ctx, "deleted-repo", "lore://deleted", "deleted-id")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SoftDeleteResource(ctx, model.ResourceIDForRepositoryID(deleted.LoreRepositoryID)); err != nil {
		t.Fatal(err)
	}

	resources, err := NewCoreStore(s).List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 1 || resources[0].ID != active.ID {
		t.Fatalf("CoreStore.List = %#v, want only active repository %q", resources, active.ID)
	}

	all, err := s.ListRepositories(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("ListRepositories = %#v, want active and deleted rows", all)
	}
}

func TestManualRepoAddDoesNotUpdateReBACCreatedRepository(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "test.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	core := NewCoreStore(s)
	resourceID := model.ResourceIDForRepositoryID("0194b726b34e72b0b45550b88a967076")
	if err := core.Upsert(ctx, model.Resource{ResourceID: resourceID, Name: "rebac-name"}); err != nil {
		t.Fatal(err)
	}

	err = core.Upsert(ctx, model.Resource{Name: "manual-name", RemoteURL: "lore://manual.example", LoreRepositoryID: "0194b726b34e72b0b45550b88a967076"})
	if err == nil {
		t.Fatal("expected manual upsert to reject existing ReBAC-created repository")
	}
	repo, err := s.FindRepositoryAnyStatusByResourceID(ctx, resourceID)
	if err != nil {
		t.Fatal(err)
	}
	if repo.Name != "rebac-name" || repo.RemoteURL != "" || repo.Status != "active" {
		t.Fatalf("ReBAC-created row changed unexpectedly: %#v", repo)
	}
}

func TestConsumeAuthSessionRejectsExpiredCompletedSession(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "test.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddUser(ctx, AddUserParams{Email: "alice@example.com"}); err != nil {
		t.Fatal(err)
	}
	_, sess, err := s.CreateAuthSession(ctx, "client-state", 60)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE auth_sessions SET status = 'completed', user_id = (SELECT id FROM users WHERE primary_email = 'alice@example.com'), expires_at = ? WHERE id = ?`, UnixNow()-1, sess.ID); err != nil {
		t.Fatal(err)
	}

	if err := s.ConsumeAuthSession(ctx, sess.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ConsumeAuthSession error = %v, want ErrNotFound", err)
	}
	var status string
	if err := s.db.QueryRowContext(ctx, `SELECT status FROM auth_sessions WHERE id = ?`, sess.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status == "consumed" {
		t.Fatalf("expired session was consumed")
	}
}
