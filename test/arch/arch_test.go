package arch

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const modulePath = "github.com/yamahigashi/lore-auth-bridge"

func TestADR0003ImportBoundaries(t *testing.T) {
	root := repoRoot(t)
	forEachGoFile(t, root, func(path string, imports []string) {
		rel := filepath.ToSlash(mustRel(t, root, path))
		if strings.HasPrefix(rel, "lore/") {
			return
		}

		switch {
		case strings.HasPrefix(rel, "internal/core/"):
			forbidImports(t, rel, imports,
				modulePath+"/internal/adapter",
				modulePath+"/internal/store",
				modulePath+"/internal/acl",
				modulePath+"/internal/googleauth",
				"net/http",
				"modernc.org/sqlite",
				"github.com/casbin",
			)
		case strings.HasPrefix(rel, "internal/grpcauth/"),
			strings.HasPrefix(rel, "internal/grpcrebac/"),
			strings.HasPrefix(rel, "internal/httpserver/"):
			forbidImports(t, rel, imports,
				modulePath+"/internal/adapter/sqlite",
				modulePath+"/internal/adapter/casbin",
				modulePath+"/internal/adapter/google",
				modulePath+"/internal/adapter/oidc",
				modulePath+"/internal/store",
				modulePath+"/internal/acl",
				modulePath+"/internal/googleauth",
				modulePath+"/internal/issuer",
				modulePath+"/internal/token",
			)
		case strings.HasPrefix(rel, "cmd/lore-authctl/"):
			forbidImports(t, rel, imports,
				modulePath+"/internal/store",
				modulePath+"/internal/acl",
				modulePath+"/internal/issuer",
				modulePath+"/internal/token",
			)
		case strings.HasPrefix(rel, "cmd/lore-auth-server/"):
			forbidImports(t, rel, imports,
				modulePath+"/internal/adapter/staticidp",
			)
		}
	})
}

func TestADR0003LegacyInternalPackagesRemoved(t *testing.T) {
	root := repoRoot(t)
	for _, rel := range []string{
		"internal/store",
		"internal/acl",
		"internal/googleauth",
		"internal/issuer",
		"internal/token",
	} {
		if _, err := os.Stat(filepath.Join(root, rel)); err == nil {
			t.Fatalf("%s still exists; ADR 0003 requires it to be absorbed into internal/core or internal/adapter", rel)
		} else if !os.IsNotExist(err) {
			t.Fatalf("stat %s: %v", rel, err)
		}
	}
}

func TestADR0003AuthctlAdminCommandsUseManagementPorts(t *testing.T) {
	root := repoRoot(t)
	src := readRepoFile(t, root, "cmd/lore-authctl/main.go")
	normalized := strings.Join(strings.Fields(src), " ")
	for _, required := range []string{
		"groups ports.GroupAdmin",
		"grants ports.GrantAdmin",
		"keys ports.SigningKeyAdmin",
	} {
		if !strings.Contains(normalized, required) {
			t.Errorf("cmd/lore-authctl/main.go should declare %s", required)
		}
	}
	for _, forbidden := range []string{
		"rs256.GenerateSigningKey(",
		"env.core.AddGroup(",
		"env.core.ListGroups(",
		"env.core.AddGroupMember(",
		"env.core.RemoveGroupMember(",
		"env.core.AddGrant(",
		"env.core.ListGrants(",
		"env.core.RemoveGrant(",
		"env.core.AddSigningKeyMeta(",
		"env.core.ListSigningKeyMeta(",
	} {
		if strings.Contains(src, forbidden) {
			t.Errorf("cmd/lore-authctl/main.go should use management ports instead of %s", forbidden)
		}
	}
}

func TestADR0003StatePortHidesAuthCodeHashing(t *testing.T) {
	root := repoRoot(t)
	src := readRepoFile(t, root, "internal/core/ports/session.go")
	if strings.Contains(src, "HashAuthCode") {
		t.Fatal("StateStore must not expose HashAuthCode; hashing is an adapter detail")
	}
	if !strings.Contains(src, "MatchClientState") {
		t.Fatal("StateStore should expose a client_state comparison boundary")
	}
}

func forbidImports(t *testing.T, file string, imports []string, forbidden ...string) {
	t.Helper()
	for _, imp := range imports {
		for _, prefix := range forbidden {
			if imp == prefix || strings.HasPrefix(imp, prefix+"/") {
				t.Errorf("%s imports forbidden dependency %q", file, imp)
			}
		}
	}
}

func readRepoFile(t *testing.T, root, rel string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func forEachGoFile(t *testing.T, root string, fn func(path string, imports []string)) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".probe", "lore":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		imports, err := parseImports(path)
		if err != nil {
			return err
		}
		fn(path, imports)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func parseImports(path string) ([]string, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(file.Imports))
	for _, spec := range file.Imports {
		out = append(out, strings.Trim(spec.Path.Value, `"`))
	}
	return out, nil
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

func mustRel(t *testing.T, base, target string) string {
	t.Helper()
	rel, err := filepath.Rel(base, target)
	if err != nil {
		t.Fatal(err)
	}
	return rel
}
