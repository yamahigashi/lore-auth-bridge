package main

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestOIDCConfigFromProviderIncludesGoogleProfilePolicy(t *testing.T) {
	t.Parallel()
	providerCfg := config.IdentityProviderConfig{
		Type:             "oidc",
		Profile:          "google",
		DisplayName:      "Google",
		Issuer:           "https://accounts.google.com",
		ClientID:         "client",
		ClientSecretFile: "secret",
		RedirectURL:      "https://auth.example.com/auth/google/callback",
		PKCE:             "required",
		Subject:          config.SubjectConfig{Strategy: "oidc_sub"},
		Trust: config.TrustConfig{
			HostedDomain:     config.HostedDomainTrust{Allowed: []string{"example.com"}},
			PersonalAccounts: "deny",
		},
	}

	got := oidcConfigFromProvider("google", providerCfg, "client-secret")
	if got.ProviderID != "google" || got.Profile != "google" || got.DisplayName != "Google" || got.Issuer != providerCfg.Issuer {
		t.Fatalf("unexpected oidc descriptor config: %#v", got)
	}
	if got.ClientID != "client" || got.ClientSecret != "client-secret" || got.RedirectURL != providerCfg.RedirectURL {
		t.Fatalf("unexpected oidc config: %#v", got)
	}
	if strings.Join(got.AllowedHostedDomains, ",") != "example.com" {
		t.Fatalf("allowed hosted domains = %#v", got.AllowedHostedDomains)
	}
	if got.PersonalAccounts != "deny" {
		t.Fatalf("personal account policy = %q", got.PersonalAccounts)
	}
	if got.PKCE != "required" {
		t.Fatalf("pkce policy = %q, want required", got.PKCE)
	}
}

func TestBuildIdentityProvidersRejectsStaticProvider(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.IdentityProviders.Default = "static"
	cfg.IdentityProviders.Providers = map[string]config.IdentityProviderConfig{
		"static": {
			Type:        "static",
			DisplayName: "Static Login",
			Issuer:      "https://auth.example.com/static",
		},
	}

	reg, err := buildIdentityProviders(context.Background(), cfg)
	if err == nil {
		t.Fatalf("expected static provider to be rejected, got registry %#v", reg)
	}
	if !strings.Contains(err.Error(), "unknown identity provider type") {
		t.Fatalf("error = %q, want unknown provider type", err)
	}
}

func TestNewHTTPServerSetsTimeouts(t *testing.T) {
	t.Parallel()
	srv := newHTTPServer("127.0.0.1:0", http.NewServeMux())
	if srv.ReadHeaderTimeout == 0 || srv.ReadTimeout == 0 || srv.WriteTimeout == 0 || srv.IdleTimeout == 0 {
		t.Fatalf("timeouts not fully set: read_header=%s read=%s write=%s idle=%s", srv.ReadHeaderTimeout, srv.ReadTimeout, srv.WriteTimeout, srv.IdleTimeout)
	}
	if srv.ReadTimeout < 5*time.Second || srv.WriteTimeout < 5*time.Second {
		t.Fatalf("timeouts too small: read=%s write=%s", srv.ReadTimeout, srv.WriteTimeout)
	}
}
