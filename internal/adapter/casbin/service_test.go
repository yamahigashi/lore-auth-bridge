package casbin

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/yamahigashi/lore-auth-bridge/internal/adapter/sqlite"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
)

func TestCanWithGroupWriterGrant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "db.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddUser(ctx, sqlite.AddUserParams{Provider: "google", Issuer: "https://accounts.google.com", Subject: "sub", Email: "alice@example.com"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddGroup(ctx, "artists", ""); err != nil {
		t.Fatal(err)
	}
	if err := st.AddGroupMember(ctx, "artists", "alice@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddRepository(ctx, "game-assets", "lore://example", "0194b726b34e72b0b45550b88a967076"); err != nil {
		t.Fatal(err)
	}
	g, err := st.FindGroupByName(ctx, "artists")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddGrant(ctx, "group", g.ID, "game-assets", "writer"); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"read", "write"} {
		ok, err := NewService(st).Can(ctx, "alice@example.com", "game-assets", action)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatalf("expected allow for %s", action)
		}
	}
	ok, err := NewService(st).Can(ctx, "alice@example.com", "game-assets", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected admin deny")
	}
}

func TestDeletedRepositoryGrantIsNotLoaded(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "db.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	u, err := st.AddUser(ctx, sqlite.AddUserParams{Provider: "google", Issuer: "https://accounts.google.com", Subject: "sub", Email: "alice@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	repo, err := st.AddRepository(ctx, "game-assets", "lore://example", "0194b726b34e72b0b45550b88a967076")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddGrant(ctx, "user", u.ID, "game-assets", "writer"); err != nil {
		t.Fatal(err)
	}
	if err := st.SoftDeleteResource(ctx, model.ResourceIDForRepositoryID(repo.LoreRepositoryID)); err != nil {
		t.Fatal(err)
	}

	ok, err := NewService(st).CanAccess(ctx, u.ID, model.ResourceIDForRepositoryID(repo.LoreRepositoryID), "write")
	if err != nil && !errors.Is(err, model.ErrNotFound) && !errors.Is(err, sqlite.ErrNotFound) {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("deleted repository grant should not allow access")
	}
}

func TestRoleSemanticsAreAppliedToLookupAndChecks(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "db.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	u, err := st.AddUser(ctx, sqlite.AddUserParams{Provider: "google", Issuer: "https://accounts.google.com", Subject: "sub", Email: "alice@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddRepository(ctx, "readable", "lore://readable", "readable-id"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddRepository(ctx, "adminable", "lore://adminable", "adminable-id"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddGrant(ctx, "user", u.ID, "readable", "reader"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddGrant(ctx, "user", u.ID, "adminable", "admin"); err != nil {
		t.Fatal(err)
	}
	svc := NewService(st)

	canWriteReadable, err := svc.CanAccess(ctx, u.ID, model.ResourceIDForRepositoryID("readable-id"), "write")
	if err != nil {
		t.Fatal(err)
	}
	if canWriteReadable {
		t.Fatal("reader grant must not allow write")
	}
	canAdmin, err := svc.CanAccess(ctx, u.ID, model.ResourceIDForRepositoryID("adminable-id"), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !canAdmin {
		t.Fatal("admin grant should allow admin check")
	}
	perms, err := svc.ListAccessible(ctx, u.ID, model.ResourceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, perm := range perms {
		got[perm.ResourceID] = perm.Permission
	}
	if len(got[model.ResourceIDForRepositoryID("readable-id")]) != 1 || got[model.ResourceIDForRepositoryID("readable-id")][0] != "read" {
		t.Fatalf("reader permissions = %#v, want read only", got[model.ResourceIDForRepositoryID("readable-id")])
	}
	if len(got[model.ResourceIDForRepositoryID("adminable-id")]) != 3 {
		t.Fatalf("admin permissions = %#v, want read/write/admin", got[model.ResourceIDForRepositoryID("adminable-id")])
	}
}

func TestUnknownGrantRoleIsRejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "db.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddRepository(ctx, "game-assets", "lore://example", "repo-id"); err != nil {
		t.Fatal(err)
	}

	_, err = st.AddGrant(ctx, "user", "user-1", "game-assets", "typo-role")
	if !errors.Is(err, model.ErrInvalidArgument) {
		t.Fatalf("AddGrant error = %v, want ErrInvalidArgument", err)
	}
}
