package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestLoadConfigWithDefaults(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
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
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Listen != "127.0.0.1:8080" {
		t.Fatalf("unexpected listen: %s", cfg.Server.Listen)
	}
	if cfg.Lore.AuthURL != "ucs-auth://auth.example.com" {
		t.Fatalf("unexpected auth URL: %s", cfg.Lore.AuthURL)
	}
	if cfg.JWT.TTLSeconds != 3600 {
		t.Fatalf("unexpected ttl: %d", cfg.JWT.TTLSeconds)
	}
	if len(cfg.Security.RebacAllowedPeerCIDRs) != 0 {
		t.Fatalf("unexpected rebac peer allowlist: %#v", cfg.Security.RebacAllowedPeerCIDRs)
	}
	if cfg.Security.AuthSessionTTLSeconds != cfg.Security.SessionTTLSeconds {
		t.Fatalf("auth session ttl = %d, want session ttl fallback %d", cfg.Security.AuthSessionTTLSeconds, cfg.Security.SessionTTLSeconds)
	}
}

func TestLoadConfigAuthSessionTTLCanDifferFromBrowserSessionTTL(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
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
security:
  session_ttl_seconds: 3600
  auth_session_ttl_seconds: 600
`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Security.SessionTTLSeconds != 3600 || cfg.Security.AuthSessionTTLSeconds != 600 {
		t.Fatalf("session ttls = browser %d auth %d", cfg.Security.SessionTTLSeconds, cfg.Security.AuthSessionTTLSeconds)
	}
}

func TestPublicHostExtractsIPv4DNSAndIPv6Hosts(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"https://auth.example.com/path":      "auth.example.com",
		"https://auth.example.com:8443/path": "auth.example.com",
		"https://[::1]:8080/path":            "::1",
		"http://127.0.0.1:8080":              "127.0.0.1",
	}
	for input, want := range cases {
		got, err := PublicHost(input)
		if err != nil {
			t.Fatalf("PublicHost(%q) error = %v", input, err)
		}
		if got != want {
			t.Fatalf("PublicHost(%q) = %q, want %q", input, got, want)
		}
	}
	if _, err := PublicHost("not-a-url"); err == nil {
		t.Fatal("expected invalid URL to fail")
	}
}

func TestLoadRejectsPartialGoogleConfig(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	raw := []byte(`
server:
  public_base_url: "https://auth.example.com"
google:
  client_id: "client"
  redirect_url: "https://auth.example.com/oauth/google/callback"
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
	if _, err := Load(path); err == nil {
		t.Fatal("expected partial google config to fail")
	}
}

func TestLoadIdentityProvidersConfig(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	raw := []byte(`
server:
  public_base_url: "https://auth.example.com"
identity_providers:
  default: keycloak-prod
  providers:
    google:
      type: google_oidc
      display_name: "Google"
      issuer: "https://accounts.google.com"
      client_id: "client"
      client_secret_file: "` + filepath.Join(dir, "google_secret") + `"
      redirect_url: "https://auth.example.com/auth/google/callback"
    keycloak-prod:
      type: oidc
      display_name: "Company SSO"
      issuer: "https://sso.example.com/realms/prod"
      client_id: "lore-auth-bridge"
      client_secret_file: "` + filepath.Join(dir, "keycloak_secret") + `"
      redirect_url: "https://auth.example.com/auth/keycloak-prod/callback"
      scopes: ["openid", "email"]
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
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IdentityProviders.Default != "keycloak-prod" {
		t.Fatalf("default provider = %q", cfg.IdentityProviders.Default)
	}
	if got := cfg.IdentityProviders.Providers["google"].Scopes; strings.Join(got, ",") != "openid,email,profile" {
		t.Fatalf("google default scopes = %#v", got)
	}
	if cfg.IdentityProviders.Providers["keycloak-prod"].DisplayName != "Company SSO" {
		t.Fatalf("missing keycloak provider: %#v", cfg.IdentityProviders.Providers["keycloak-prod"])
	}
}

func TestLoadRejectsStaticIdentityProvider(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	raw := []byte(`
server:
  public_base_url: "https://auth.example.com"
identity_providers:
  default: static
  providers:
    static:
      type: static
      issuer: "https://auth.example.com/static"
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
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected static identity provider config to fail")
	}
	if !strings.Contains(err.Error(), `type "static"`) {
		t.Fatalf("error = %q, want static provider rejection", err)
	}
}

func TestLoadRejectsStaticOnlyIdentityProviderFields(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	raw := []byte(`
server:
  public_base_url: "https://auth.example.com"
identity_providers:
  default: keycloak-prod
  providers:
    keycloak-prod:
      type: oidc
      issuer: "https://sso.example.com/realms/prod"
      client_id: "client"
      client_secret_file: "` + filepath.Join(dir, "secret") + `"
      redirect_url: "https://auth.example.com/auth/keycloak-prod/callback"
      subject: "static-subject"
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
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected static-only provider field to fail")
	}
	if !strings.Contains(err.Error(), "field subject not found") {
		t.Fatalf("error = %q, want unknown subject field", err)
	}
}

func TestLoadRejectsLegacyGoogleCallbackForGenericOIDCProvider(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	raw := []byte(`
server:
  public_base_url: "https://auth.example.com"
identity_providers:
  default: google
  providers:
    google:
      type: oidc
      issuer: "https://sso.example.com/realms/prod"
      client_id: "client"
      client_secret_file: "` + filepath.Join(dir, "secret") + `"
      redirect_url: "https://auth.example.com/oauth/google/callback"
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
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected generic OIDC provider to reject legacy Google callback path")
	}
	if !strings.Contains(err.Error(), `/auth/google/callback`) {
		t.Fatalf("error = %q, want new callback path context", err)
	}
}

func TestLoadLegacyGoogleNormalizesIdentityProvider(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	raw := []byte(`
server:
  public_base_url: "https://auth.example.com"
google:
  client_id: "client"
  client_secret_file: "` + filepath.Join(dir, "google_secret") + `"
  redirect_url: "https://auth.example.com/oauth/google/callback"
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
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IdentityProviders.Default != "google" {
		t.Fatalf("default provider = %q, want google", cfg.IdentityProviders.Default)
	}
	if cfg.IdentityProviders.Providers["google"].Type != "google_oidc" {
		t.Fatalf("legacy google provider not normalized: %#v", cfg.IdentityProviders.Providers["google"])
	}
}

func TestLoadRejectsUnsafeIdentityProviderID(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	raw := []byte(`
server:
  public_base_url: "https://auth.example.com"
identity_providers:
  default: "../bad"
  providers:
    "../bad":
      type: oidc
      issuer: "https://sso.example.com/realms/prod"
      client_id: "client"
      client_secret_file: "` + filepath.Join(dir, "secret") + `"
      redirect_url: "https://auth.example.com/auth/bad/callback"
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
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "identity_providers.providers") {
		t.Fatalf("error = %v, want identity provider id validation", err)
	}
}

func TestLoadRejectsCookieSecretFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	raw := []byte(`
server:
  public_base_url: "https://auth.example.com"
  cookie_secret_file: "` + filepath.Join(dir, "cookie_secret") + `"
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
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected cookie_secret_file to be rejected")
	}
	if !strings.Contains(err.Error(), "cookie_secret_file") {
		t.Fatalf("error = %q, want cookie_secret_file context", err)
	}
}

func TestLoadRejectsInvalidOperationalConfig(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		mutate  func(*configParts)
		wantErr string
	}{
		{
			name:    "grpc tls cert without key",
			mutate:  func(p *configParts) { p.grpcTLSCertFile = filepath.Join(p.dir, "tls.crt") },
			wantErr: "server.grpc_tls_key_file",
		},
		{
			name:    "negative jwt ttl",
			mutate:  func(p *configParts) { p.jwtTTLSeconds = -1 },
			wantErr: "jwt.ttl_seconds",
		},
		{
			name:    "empty audience element",
			mutate:  func(p *configParts) { p.audience = `["lore-service", ""]` },
			wantErr: "jwt.audience",
		},
		{
			name:    "remote host missing from audience",
			mutate:  func(p *configParts) { p.audience = `["lore-service"]` },
			wantErr: "jwt.audience",
		},
		{
			name:    "invalid public base url",
			mutate:  func(p *configParts) { p.publicBaseURL = "://bad" },
			wantErr: "server.public_base_url",
		},
		{
			name:    "invalid lore auth url",
			mutate:  func(p *configParts) { p.authURL = "not-a-url" },
			wantErr: "lore.auth_url",
		},
		{
			name:    "invalid rebac peer cidr",
			mutate:  func(p *configParts) { p.rebacAllowedPeerCIDRs = `["not-a-cidr"]` },
			wantErr: "security.rebac_allowed_peer_cidrs",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			parts := defaultConfigParts(dir)
			tc.mutate(&parts)
			path := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(path, []byte(parts.yaml()), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if err == nil {
				t.Fatal("expected config load to fail")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want substring %q", err, tc.wantErr)
			}
		})
	}
}

type configParts struct {
	dir                   string
	grpcTLSCertFile       string
	grpcTLSKeyFile        string
	publicBaseURL         string
	audience              string
	jwtTTLSeconds         int
	defaultRemoteURL      string
	authURL               string
	rebacAllowedPeerCIDRs string
}

func defaultConfigParts(dir string) configParts {
	return configParts{
		dir:                   dir,
		publicBaseURL:         "https://auth.example.com",
		audience:              `["lore-service", "lore.example.com"]`,
		jwtTTLSeconds:         3600,
		defaultRemoteURL:      "lore://lore.example.com:41337",
		authURL:               "https://auth.example.com",
		rebacAllowedPeerCIDRs: `[]`,
	}
}

func (p configParts) yaml() string {
	return `
server:
  public_base_url: "` + p.publicBaseURL + `"
  grpc_tls_cert_file: "` + p.grpcTLSCertFile + `"
  grpc_tls_key_file: "` + p.grpcTLSKeyFile + `"
database:
  path: "` + filepath.Join(p.dir, "db.sqlite3") + `"
jwt:
  issuer: "https://auth.example.com"
  audience: ` + p.audience + `
  ttl_seconds: ` + strconv.Itoa(p.jwtTTLSeconds) + `
  signing_key_dir: "` + filepath.Join(p.dir, "keys") + `"
lore:
  default_remote_url: "` + p.defaultRemoteURL + `"
  auth_url: "` + p.authURL + `"
security:
  rebac_allowed_peer_cidrs: ` + p.rebacAllowedPeerCIDRs + `
`
}
