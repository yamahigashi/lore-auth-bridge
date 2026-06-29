package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yamahigashi/lore-auth-bridge/internal/config"
)

func TestOpenConfiguredStoreWithoutMigrateValidatesSchema(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Database.Path = filepath.Join(t.TempDir(), "db.sqlite3")

	st, err := openConfiguredStore(context.Background(), cfg, false)
	if st != nil {
		_ = st.Close()
	}
	if err == nil {
		t.Fatal("expected unmigrated database to fail")
	}
	if !strings.Contains(err.Error(), "validate database schema") {
		t.Fatalf("error = %q, want schema validation context", err)
	}
}

func TestOpenConfiguredStoreWithMigrateInitializesSchema(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Database.Path = filepath.Join(t.TempDir(), "db.sqlite3")

	st, err := openConfiguredStore(context.Background(), cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
}

func TestRebacAllowedPeerCIDRsDefaultToLoopback(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}

	got := rebacAllowedPeerCIDRs(cfg)
	if strings.Join(got, ",") != "127.0.0.1/32,::1/128" {
		t.Fatalf("rebac allowlist = %#v, want loopback defaults", got)
	}
}

func TestRebacAllowedPeerCIDRsUsesConfiguredValues(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Security.RebacAllowedPeerCIDRs = []string{"10.0.0.0/24"}

	got := rebacAllowedPeerCIDRs(cfg)
	if strings.Join(got, ",") != "10.0.0.0/24" {
		t.Fatalf("rebac allowlist = %#v, want configured values", got)
	}
}

func TestGoogleConfigFromConfigIncludesAccountPolicy(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Google.ClientID = "client"
	cfg.Google.ClientSecretFile = "secret"
	cfg.Google.RedirectURL = "https://auth.example.com/oauth/google/callback"
	cfg.Google.AllowedHostedDomains = []string{"example.com"}
	cfg.Google.AllowPersonalAccounts = true

	got := googleConfigFromConfig(cfg, "client-secret")
	if got.ClientID != "client" || got.ClientSecret != "client-secret" || got.RedirectURL != cfg.Google.RedirectURL {
		t.Fatalf("unexpected google config: %#v", got)
	}
	if strings.Join(got.AllowedHostedDomains, ",") != "example.com" {
		t.Fatalf("allowed hosted domains = %#v", got.AllowedHostedDomains)
	}
	if !got.AllowPersonalAccounts {
		t.Fatal("allow personal accounts was not propagated")
	}
}
