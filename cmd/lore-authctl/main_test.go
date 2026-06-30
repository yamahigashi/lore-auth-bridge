package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yamahigashi/lore-auth-bridge/internal/adapter/sqlite"
)

func TestUserInviteCreatesPendingPreRegisteredUser(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := writeTestConfig(t, dir)

	if err := cmdUser([]string{"invite", "--config", cfgPath, "--email", "Alice@Example.com"}); err != nil {
		t.Fatal(err)
	}

	st, err := sqlite.Open(filepath.Join(dir, "db.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	user, err := st.FindUserByEmail(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if user.Status != "pending" {
		t.Fatalf("status = %q, want pending", user.Status)
	}
	if !strings.HasPrefix(user.Subject, "pending:") {
		t.Fatalf("subject = %q, want internal pending subject", user.Subject)
	}
}

func TestUserInviteIDPUsesConfiguredIssuer(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := writeTestConfigWithIDP(t, dir)

	if err := cmdUser([]string{"invite", "--config", cfgPath, "--idp", "keycloak-prod", "--email", "Alice@Example.com"}); err != nil {
		t.Fatal(err)
	}

	st, err := sqlite.Open(filepath.Join(dir, "db.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	user, err := st.FindUserByEmail(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if user.Provider != "keycloak-prod" || user.Issuer != "https://sso.example.com/realms/prod" {
		t.Fatalf("identity provider = %s issuer = %s", user.Provider, user.Issuer)
	}
}

func TestUserInviteRequiresIDP(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := writeTestConfigWithIDP(t, dir)

	err := cmdUser([]string{"invite", "--config", cfgPath, "--email", "Alice@Example.com"})
	if err == nil {
		t.Fatal("expected user invite without --idp to fail")
	}
	if !strings.Contains(err.Error(), "--idp is required") {
		t.Fatalf("error = %q, want --idp requirement", err)
	}
}

func TestUserAddIDPUsesConfiguredIssuer(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := writeTestConfigWithIDP(t, dir)

	if err := cmdUser([]string{"add", "--config", cfgPath, "--idp", "keycloak-prod", "--subject", "subject:with:colon", "--email", "Alice@Example.com", "--email-verified"}); err != nil {
		t.Fatal(err)
	}

	st, err := sqlite.Open(filepath.Join(dir, "db.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	user, err := st.FindUserByIdentity(context.Background(), "keycloak-prod", "https://sso.example.com/realms/prod", "subject:with:colon")
	if err != nil {
		t.Fatal(err)
	}
	if user.Status != "active" || !user.EmailVerified {
		t.Fatalf("unexpected user: %#v", user)
	}
}

func TestUserAddRequiresIDP(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := writeTestConfigWithIDP(t, dir)

	err := cmdUser([]string{"add", "--config", cfgPath, "--subject", "subject:with:colon", "--email", "Alice@Example.com", "--email-verified"})
	if err == nil {
		t.Fatal("expected user add without --idp to fail")
	}
	if !strings.Contains(err.Error(), "--idp is required") {
		t.Fatalf("error = %q, want --idp requirement", err)
	}
}

func TestOpenEnvWrapsConfigPath(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "missing.yaml")
	_, err := openEnv(missing, "")
	if err == nil {
		t.Fatal("expected missing config to fail")
	}
	if !strings.Contains(err.Error(), "load config") || !strings.Contains(err.Error(), missing) {
		t.Fatalf("error = %q, want config path context", err)
	}
}

func TestOpenEnvWrapsDatabasePath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := writeTestConfig(t, dir)
	notDir := filepath.Join(dir, "not-dir")
	if err := os.WriteFile(notDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(notDir, "db.sqlite3")
	_, err := openEnv(cfgPath, dbPath)
	if err == nil {
		t.Fatal("expected database open to fail")
	}
	if !strings.Contains(err.Error(), "open database") || !strings.Contains(err.Error(), dbPath) {
		t.Fatalf("error = %q, want database path context", err)
	}
}

func TestCheckWrapsUserResolutionContext(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := writeTestConfig(t, dir)

	err := cmdCheck([]string{"--config", cfgPath, "missing@example.com", "game-assets", "write"})
	if err == nil {
		t.Fatal("expected check to fail")
	}
	if !strings.Contains(err.Error(), `check: resolve user "missing@example.com"`) {
		t.Fatalf("error = %q, want check user context", err)
	}
}

func TestShouldPrintLoginCommand(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		out       string
		requested bool
		want      bool
	}{
		{name: "default suppressed", requested: false, want: false},
		{name: "explicit print", requested: true, want: true},
		{name: "out suppresses even when requested", out: "token.jwt", requested: true, want: false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := shouldPrintLoginCommand(tc.out, tc.requested); got != tc.want {
				t.Fatalf("shouldPrintLoginCommand(%q, %v) = %v, want %v", tc.out, tc.requested, got, tc.want)
			}
		})
	}
}

func writeTestConfig(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "config.yaml")
	raw := []byte(`
server:
  public_base_url: "https://auth.example.com"
database:
  path: "` + filepath.Join(dir, "db.sqlite3") + `"
jwt:
  issuer: "https://auth.example.com"
  audience: ["lore-service", "lore.example.com"]
  signing_key_dir: "` + filepath.Join(dir, "keys") + `"
lore:
  default_remote_url: "lore://lore.example.com:41337"
security: {}
`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeTestConfigWithIDP(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "config.yaml")
	raw := []byte(`
server:
  public_base_url: "https://auth.example.com"
identity_providers:
  default: keycloak-prod
  providers:
    keycloak-prod:
      type: oidc
      display_name: "Company SSO"
      issuer: "https://sso.example.com/realms/prod"
      client_id: "lore-auth-bridge"
      client_secret_file: "` + filepath.Join(dir, "idp_secret") + `"
      redirect_url: "https://auth.example.com/auth/keycloak-prod/callback"
database:
  path: "` + filepath.Join(dir, "db.sqlite3") + `"
jwt:
  issuer: "https://auth.example.com"
  audience: ["lore-service", "lore.example.com"]
  signing_key_dir: "` + filepath.Join(dir, "keys") + `"
lore:
  default_remote_url: "lore://lore.example.com:41337"
security: {}
`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
