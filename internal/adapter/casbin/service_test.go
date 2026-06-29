package casbin

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/yamahigashi/lore-auth-bridge/internal/adapter/sqlite"
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
