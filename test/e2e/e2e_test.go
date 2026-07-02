//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var repoIDRe = regexp.MustCompile(`urc-[0-9a-fA-F]{32}|[0-9a-fA-F]{32}`)

// TestTrustChain proves the broker JWKS is fetched and trusted by a real
// loreserver, and that a broker-signed authn token is accepted at login.
func TestTrustChain(t *testing.T) {
	requireE2E(t)
	h := newHarness(t)
	registerUser(t, h)
	authn := h.mintAuthnToken("e2e@example.com")
	if _, err := h.loreLoginAuthn(authn); err != nil {
		t.Fatalf("authn login failed (trust chain broken): %v\nloreserver log:\n%s", err, h.tailServerLog(40))
	}
}

// TestRepositoryWorkflow runs the full UCS Auth + ReBAC path: login with an
// authn token, create a repository (loreserver calls RebacApi.CreateResource),
// grant access, and clone (client exchanges the authn token for an authz token
// via UrcAuthApi.ExchangeUserTokenForMultiresourceToken).
func TestRepositoryWorkflow(t *testing.T) {
	requireE2E(t)
	h := newHarness(t)
	u := registerUser(t, h)

	authn := h.mintAuthnToken("e2e@example.com")
	if _, err := h.loreLoginAuthn(authn); err != nil {
		t.Fatalf("login failed: %v", err)
	}

	repoName := "e2e-repo"
	out, err := h.runLore("repository", "create", "lore://localhost:41337/"+repoName)
	if err != nil {
		t.Fatalf("repository create failed: %v\noutput:\n%s\nloreserver log:\n%s", err, out, h.tailServerLog(60))
	}

	// loreserver should have synced the resource into the broker via ReBAC.
	repos := h.listRepositories(t)
	if len(repos) == 0 {
		t.Fatalf("expected a repository synced via RebacApi.CreateResource; output:\n%s", out)
	}
	created := repos[0]
	t.Logf("repository synced: name=%s lore_repository_id=%s source=%s", created.Name, created.LoreRepositoryID, created.Status)

	// Grant the user write access, then a clone must succeed via authz exchange.
	h.addGrant(t, u, &created, "writer")
	cloneDir := filepath.Join(h.dir, "clone")
	if cout, err := h.runLore("clone", "lore://localhost:41337/"+repoName, cloneDir); err != nil {
		t.Fatalf("clone failed after grant: %v\noutput:\n%s\nloreserver log:\n%s", err, cout, h.tailServerLog(60))
	}
}

func registerUser(t *testing.T, h *harness) *e2eUser {
	t.Helper()
	h.runAuthctl("user", "add", "--email", "e2e@example.com", "--name", "E2E User")
	return h.userByEmail(t, "e2e@example.com")
}

var _ = repoIDRe
var _ = os.Getenv
var _ = strings.TrimSpace
