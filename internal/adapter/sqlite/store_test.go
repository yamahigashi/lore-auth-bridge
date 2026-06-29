package sqlite

import (
	"context"
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
