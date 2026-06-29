//go:build e2e

package e2e

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/yamahigashi/lore-auth-bridge/internal/adapter/sqlite"
	pbAuth "github.com/yamahigashi/lore-auth-bridge/internal/loreproto/epicurc"
	pbRebac "github.com/yamahigashi/lore-auth-bridge/internal/loreproto/ucsauth"
)

func TestExactResourceClone(t *testing.T) {
	requireE2E(t)
	h := newHarness(t)
	u := registerUser(t, h)
	authn := h.mintAuthnToken("e2e@example.com")
	if _, err := h.loreLoginAuthn(authn); err != nil {
		t.Fatalf("login failed: %v", err)
	}
	repoName := "matrix-exact"
	if out, err := h.runLore("repository", "create", "lore://localhost:41337/"+repoName); err != nil {
		t.Fatalf("repository create failed: %v\noutput:\n%s\nloreserver log:\n%s", err, out, h.tailServerLog(60))
	}
	repo := h.singleRepository(t)
	if _, err := h.store.AddGrant(context.Background(), "user", u.ID, repo.Name, "writer"); err != nil {
		t.Fatalf("add grant: %v", err)
	}
	if out, err := h.runLore("clone", "lore://localhost:41337/"+repoName, filepath.Join(h.dir, "clone-exact")); err != nil {
		t.Fatalf("clone failed: %v\noutput:\n%s\nloreserver log:\n%s", err, out, h.tailServerLog(60))
	}
}

func TestNoGrantDeniedAtExchange(t *testing.T) {
	requireE2E(t)
	h := newHarness(t)
	registerUser(t, h)
	repo := h.addRepository(t, "no-grant", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	authn := h.mintAuthnToken("e2e@example.com")
	_, err := h.exchange(authn, repoResourceID(repo.LoreRepositoryID))
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
}

func TestWrongResourceDenied(t *testing.T) {
	requireE2E(t)
	h := newHarness(t)
	u := registerUser(t, h)
	allowed := h.addRepository(t, "allowed", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	denied := h.addRepository(t, "denied", "cccccccccccccccccccccccccccccccc")
	if _, err := h.store.AddGrant(context.Background(), "user", u.ID, allowed.Name, "writer"); err != nil {
		t.Fatalf("add grant: %v", err)
	}
	authn := h.mintAuthnToken("e2e@example.com")
	_, err := h.exchange(authn, repoResourceID(denied.LoreRepositoryID))
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
}

func TestDisabledUserDenied(t *testing.T) {
	requireE2E(t)
	h := newHarness(t)
	u := registerUser(t, h)
	repo := h.addRepository(t, "disabled", "dddddddddddddddddddddddddddddddd")
	if _, err := h.store.AddGrant(context.Background(), "user", u.ID, repo.Name, "writer"); err != nil {
		t.Fatalf("add grant: %v", err)
	}
	authn := h.mintAuthnToken("e2e@example.com")
	if err := h.store.DisableUser(context.Background(), "e2e@example.com"); err != nil {
		t.Fatalf("disable user: %v", err)
	}
	_, err := h.exchange(authn, repoResourceID(repo.LoreRepositoryID))
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}
}

func TestExpiredAuthnRejected(t *testing.T) {
	requireE2E(t)
	h := newHarness(t)
	u := registerUser(t, h)
	repo := h.addRepository(t, "expired", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
	if _, err := h.store.AddGrant(context.Background(), "user", u.ID, repo.Name, "writer"); err != nil {
		t.Fatalf("add grant: %v", err)
	}
	authn := h.mintAuthnTokenTTL("e2e@example.com", -time.Hour)
	_, err := h.exchange(authn, repoResourceID(repo.LoreRepositoryID))
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}
}

func TestWrongAudienceRejected(t *testing.T) {
	requireE2E(t)
	h := newHarness(t)
	u := registerUser(t, h)
	repo := h.addRepository(t, "wrong-audience", "ffffffffffffffffffffffffffffffff")
	if _, err := h.store.AddGrant(context.Background(), "user", u.ID, repo.Name, "writer"); err != nil {
		t.Fatalf("add grant: %v", err)
	}
	authn := h.mintAuthnTokenAudience("e2e@example.com", []string{"lore-service"})
	_, err := h.exchange(authn, repoResourceID(repo.LoreRepositoryID))
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}
}

func TestLookupUserPermissions(t *testing.T) {
	requireE2E(t)
	h := newHarness(t)
	u := registerUser(t, h)
	repo := h.addRepository(t, "lookup", "11111111111111111111111111111111")
	if _, err := h.store.AddGrant(context.Background(), "user", u.ID, repo.Name, "writer"); err != nil {
		t.Fatalf("add grant: %v", err)
	}
	authn := h.mintAuthnToken("e2e@example.com")
	client, closeClient := h.authClient()
	defer closeClient()
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+authn))
	resp, err := client.LookupUserPermissions(ctx, &pbAuth.LookupUserPermissionsRequest{ResourceFilter: "urc"})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(resp.GetResourcePermission()) != 1 || resp.GetResourcePermission()[0].GetResourceId() != repoResourceID(repo.LoreRepositoryID) {
		t.Fatalf("unexpected lookup: %#v", resp.GetResourcePermission())
	}
}

func TestRebacCreateThenDelete(t *testing.T) {
	requireE2E(t)
	h := newHarness(t)
	client, closeClient := h.rebacClient()
	defer closeClient()
	resourceID := "urc-22222222222222222222222222222222"
	if _, err := client.CreateResource(context.Background(), &pbRebac.CreateResourceRequest{ResourceId: resourceID, ResourceName: "rebac-matrix"}); err != nil {
		t.Fatalf("create resource: %v", err)
	}
	repo, err := h.store.FindRepositoryByResourceID(context.Background(), resourceID)
	if err != nil {
		t.Fatalf("find created resource: %v", err)
	}
	if repo.Status != "active" {
		t.Fatalf("resource not active: %#v", repo)
	}
	if _, err := client.DeleteResource(context.Background(), &pbRebac.DeleteResourceRequest{ResourceId: resourceID}); err != nil {
		t.Fatalf("delete resource: %v", err)
	}
	repo, err = h.store.FindRepositoryByResourceID(context.Background(), resourceID)
	if err != nil {
		t.Fatalf("find deleted resource: %v", err)
	}
	if repo.Status != "deleted" {
		t.Fatalf("resource not deleted: %#v", repo)
	}
}

func TestReadOnlyPushBehavior(t *testing.T) {
	requireE2E(t)
	t.Skip("read-only push behavior is intentionally recorded, not asserted, until a write workflow fixture is added")
}

func (h *harness) exchange(authnToken, resourceID string) (*pbAuth.ExchangeUserTokenForMultiresourceTokenResponse, error) {
	h.t.Helper()
	client, closeClient := h.authClient()
	defer closeClient()
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+authnToken))
	return client.ExchangeUserTokenForMultiresourceToken(ctx, &pbAuth.ExchangeUserTokenForMultiresourceTokenRequest{ResourceId: []string{resourceID}})
}

func (h *harness) addRepository(t *testing.T, name, loreRepositoryID string) *sqlite.Repository {
	t.Helper()
	repo, err := h.store.AddRepository(context.Background(), name, "lore://localhost:41337/"+name, loreRepositoryID)
	if err != nil {
		t.Fatalf("add repository: %v", err)
	}
	return repo
}

func (h *harness) singleRepository(t *testing.T) *sqlite.Repository {
	t.Helper()
	repos, err := h.store.ListRepositories(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 1 {
		t.Fatalf("expected exactly one repository, got %#v", repos)
	}
	return &repos[0]
}

func repoResourceID(loreRepositoryID string) string {
	if len(loreRepositoryID) >= 4 && loreRepositoryID[:4] == "urc-" {
		return loreRepositoryID
	}
	return "urc-" + loreRepositoryID
}
