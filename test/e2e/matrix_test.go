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

	pbAuth "github.com/yamahigashi/lore-auth-bridge/test/e2e/internal/loreproto/epicurc"
	pbRebac "github.com/yamahigashi/lore-auth-bridge/test/e2e/internal/loreproto/ucsauth"
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
	h.addGrant(t, u, repo, "writer")
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
	h.addGrant(t, u, allowed, "writer")
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
	h.addGrant(t, u, repo, "writer")
	authn := h.mintAuthnToken("e2e@example.com")
	h.runAuthctl("user", "disable", "e2e@example.com")
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
	h.addGrant(t, u, repo, "writer")
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
	h.addGrant(t, u, repo, "writer")
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
	h.addGrant(t, u, repo, "writer")
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

func TestNestedGroupGrant(t *testing.T) {
	requireE2E(t)
	h := newHarness(t)
	registerUser(t, h)
	repo := h.addRepository(t, "nested-group", "33333333333333333333333333333333")
	h.runAuthctl("group", "add", "parent")
	h.runAuthctl("group", "add", "child")
	h.runAuthctl("group", "member", "add", "child", "e2e@example.com")
	h.runAuthctl("group", "nest", "add", "parent", "child")
	h.addGroupGrant(t, "parent", repo, "writer")

	authn := h.mintAuthnToken("e2e@example.com")
	resourceID := repoResourceID(repo.LoreRepositoryID)
	if _, err := h.exchange(authn, resourceID); err != nil {
		t.Fatalf("exchange should allow nested group writer grant: %v", err)
	}
	if permissions := h.lookupPermissions(t, authn, "urc"); !hasPermission(permissions, resourceID, "write") {
		t.Fatalf("lookup should include nested group writer grant for %s: %#v", resourceID, permissions)
	}

	h.runAuthctl("group", "nest", "remove", "parent", "child")
	if _, err := h.exchange(authn, resourceID); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied after nested group removal, got %v", err)
	}
	if permissions := h.lookupPermissions(t, authn, "urc"); hasResource(permissions, resourceID) {
		t.Fatalf("lookup should no longer include %s after nested group removal: %#v", resourceID, permissions)
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
	repo := h.findRepositoryByResourceID(t, resourceID, false)
	if repo.Status != "active" {
		t.Fatalf("resource not active: %#v", repo)
	}
	if _, err := client.DeleteResource(context.Background(), &pbRebac.DeleteResourceRequest{ResourceId: resourceID}); err != nil {
		t.Fatalf("delete resource: %v", err)
	}
	repo = h.findRepositoryByResourceID(t, resourceID, true)
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

func (h *harness) addRepository(t *testing.T, name, loreRepositoryID string) *e2eRepository {
	t.Helper()
	h.runAuthctl("repo", "add", name, "--remote", "lore://localhost:41337/"+name, "--lore-repository-id", loreRepositoryID)
	return h.findRepositoryByResourceID(t, repoResourceID(loreRepositoryID), false)
}

func (h *harness) addGrant(t *testing.T, user *e2eUser, repo *e2eRepository, role string) {
	t.Helper()
	h.runAuthctl("grant", "add", "user:"+user.Email, repo.Name, role)
}

func (h *harness) addGroupGrant(t *testing.T, group string, repo *e2eRepository, role string) {
	t.Helper()
	h.runAuthctl("grant", "add", "group:"+group, repo.Name, role)
}

func (h *harness) lookupPermissions(t *testing.T, authnToken, resourceFilter string) []*pbAuth.ResourcePermission {
	t.Helper()
	client, closeClient := h.authClient()
	defer closeClient()
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+authnToken))
	resp, err := client.LookupUserPermissions(ctx, &pbAuth.LookupUserPermissionsRequest{ResourceFilter: resourceFilter})
	if err != nil {
		t.Fatalf("lookup permissions: %v", err)
	}
	return resp.GetResourcePermission()
}

func hasResource(permissions []*pbAuth.ResourcePermission, resourceID string) bool {
	for _, permission := range permissions {
		if permission.GetResourceId() == resourceID {
			return true
		}
	}
	return false
}

func hasPermission(permissions []*pbAuth.ResourcePermission, resourceID, want string) bool {
	for _, permission := range permissions {
		if permission.GetResourceId() != resourceID {
			continue
		}
		for _, got := range permission.GetPermission() {
			if got == want {
				return true
			}
		}
	}
	return false
}

func (h *harness) singleRepository(t *testing.T) *e2eRepository {
	t.Helper()
	repos := h.listRepositories(t)
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
