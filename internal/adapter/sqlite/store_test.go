package sqlite

import (
	"context"
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
	u, err := s.AddUser(ctx, AddUserParams{Provider: "google", Issuer: "https://accounts.google.com", Subject: "sub", Email: "alice@example.com", DisplayName: "Alice"})
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

func TestPreRegisteredUserBindsVerifiedIdentity(t *testing.T) {
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

	pending, err := s.AddPreRegisteredUser(ctx, AddPreRegisteredUserParams{Provider: "google", Issuer: "https://accounts.google.com", Email: "Alice@Example.com", DisplayName: "Alice"})
	if err != nil {
		t.Fatal(err)
	}

	bound, err := s.BindPreRegisteredIdentity(ctx, model.Identity{Provider: "google", Issuer: "https://accounts.google.com", Subject: "google-sub", Email: "alice@example.com", EmailVerified: true, Name: "Alice Example"})
	if err != nil {
		t.Fatal(err)
	}
	if bound.ID != pending.ID {
		t.Fatalf("bound ID = %q, want pending ID %q", bound.ID, pending.ID)
	}
	if bound.Status != "active" || bound.Subject != "google-sub" || !bound.EmailVerified {
		t.Fatalf("unexpected bound user: %#v", bound)
	}

	found, err := s.FindUserByIdentity(ctx, "google", "https://accounts.google.com", "google-sub")
	if err != nil {
		t.Fatal(err)
	}
	if found.ID != pending.ID {
		t.Fatalf("identity lookup returned %q, want %q", found.ID, pending.ID)
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
	if _, err := s.AddUser(ctx, AddUserParams{Provider: "google", Issuer: "https://accounts.google.com", Subject: "sub", Email: "alice@example.com"}); err != nil {
		t.Fatal(err)
	}
	_, sess, err := s.CreateAuthSession(ctx, "client-state", 60)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE auth_sessions SET status = 'completed', user_id = (SELECT id FROM users WHERE email = 'alice@example.com'), expires_at = ? WHERE id = ?`, UnixNow()-1, sess.ID); err != nil {
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
