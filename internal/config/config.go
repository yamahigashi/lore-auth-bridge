// Package config loads the broker's YAML configuration and validates the
// operational settings used by the server and admin CLI.
package config

import (
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var providerIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

type Config struct {
	Server            ServerConfig            `yaml:"server"`
	IdentityProviders IdentityProvidersConfig `yaml:"identity_providers"`
	Database          DatabaseConfig          `yaml:"database"`
	JWT               JWTConfig               `yaml:"jwt"`
	Lore              LoreConfig              `yaml:"lore"`
	Security          SecurityConfig          `yaml:"security"`
}

type ServerConfig struct {
	Listen          string `yaml:"listen"`
	GRPCListen      string `yaml:"grpc_listen"`
	GRPCTLSCertFile string `yaml:"grpc_tls_cert_file"`
	GRPCTLSKeyFile  string `yaml:"grpc_tls_key_file"`
	PublicBaseURL   string `yaml:"public_base_url"`
}

type IdentityProvidersConfig struct {
	Default   string                            `yaml:"default"`
	Providers map[string]IdentityProviderConfig `yaml:"providers"`
}

type IdentityProviderConfig struct {
	Type             string            `yaml:"type"`
	Profile          string            `yaml:"profile"`
	DisplayName      string            `yaml:"display_name"`
	Issuer           string            `yaml:"issuer"`
	ClientID         string            `yaml:"client_id"`
	ClientSecretFile string            `yaml:"client_secret_file"`
	RedirectURL      string            `yaml:"redirect_url"`
	Scopes           []string          `yaml:"scopes"`
	PKCE             string            `yaml:"pkce"`
	Subject          SubjectConfig     `yaml:"subject"`
	Claims           map[string]string `yaml:"claims"`
	Trust            TrustConfig       `yaml:"trust"`
}

type SubjectConfig struct {
	Strategy    string `yaml:"strategy"`
	RequiredTID string `yaml:"required_tid"`
}

type TrustConfig struct {
	EmailBinding        string            `yaml:"email_binding"`
	AllowedEmailDomains []string          `yaml:"allowed_email_domains"`
	HostedDomain        HostedDomainTrust `yaml:"hosted_domain"`
	PersonalAccounts    string            `yaml:"personal_accounts"`
}

type HostedDomainTrust struct {
	Allowed []string `yaml:"allowed"`
}

type DatabaseConfig struct {
	Path string `yaml:"path"`
}

type JWTConfig struct {
	Issuer        string   `yaml:"issuer"`
	Audience      []string `yaml:"audience"`
	TTLSeconds    int      `yaml:"ttl_seconds"`
	SigningKeyDir string   `yaml:"signing_key_dir"`
	ActiveKID     string   `yaml:"active_kid"`
}

type LoreConfig struct {
	DefaultRemoteURL string `yaml:"default_remote_url"`
	AuthURL          string `yaml:"auth_url"`
}

type SecurityConfig struct {
	DeviceCodeTTLSeconds      int      `yaml:"device_code_ttl_seconds"`
	DevicePollIntervalSeconds int      `yaml:"device_poll_interval_seconds"`
	SessionTTLSeconds         int      `yaml:"session_ttl_seconds"`
	AuthSessionTTLSeconds     int      `yaml:"auth_session_ttl_seconds"`
	RebacAllowedPeerCIDRs     []string `yaml:"rebac_allowed_peer_cidrs"`
}

// Load reads and validates the YAML config at path.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var cfg Config
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Server.Listen == "" {
		c.Server.Listen = "127.0.0.1:8080"
	}
	if c.Server.GRPCListen == "" {
		c.Server.GRPCListen = "127.0.0.1:8081"
	}
	if c.JWT.TTLSeconds == 0 {
		c.JWT.TTLSeconds = 3600
	}
	if c.Security.DeviceCodeTTLSeconds == 0 {
		c.Security.DeviceCodeTTLSeconds = 600
	}
	if c.Security.DevicePollIntervalSeconds == 0 {
		c.Security.DevicePollIntervalSeconds = 3
	}
	if c.Security.SessionTTLSeconds == 0 {
		c.Security.SessionTTLSeconds = 3600
	}
	if c.Security.AuthSessionTTLSeconds == 0 {
		c.Security.AuthSessionTTLSeconds = c.Security.SessionTTLSeconds
	}
	if c.Lore.AuthURL == "" && c.Server.PublicBaseURL != "" {
		c.Lore.AuthURL = "ucs-auth://" + stripScheme(c.Server.PublicBaseURL)
	}
	for id, provider := range c.IdentityProviders.Providers {
		if len(provider.Scopes) == 0 {
			provider.Scopes = []string{"openid", "email", "profile"}
		}
		if provider.Subject.Strategy == "" {
			provider.Subject.Strategy = "oidc_sub"
		}
		if provider.Trust.EmailBinding == "" {
			provider.Trust.EmailBinding = "disabled"
			c.IdentityProviders.Providers[id] = provider
			continue
		}
		c.IdentityProviders.Providers[id] = provider
	}
}

func (c *Config) validate() error {
	if c.Database.Path == "" {
		return fmt.Errorf("config: database.path is required")
	}
	if c.Server.PublicBaseURL == "" {
		return fmt.Errorf("config: server.public_base_url is required")
	}
	if err := validateURL("server.public_base_url", c.Server.PublicBaseURL, "http", "https"); err != nil {
		return err
	}
	if (c.Server.GRPCTLSCertFile == "") != (c.Server.GRPCTLSKeyFile == "") {
		if c.Server.GRPCTLSCertFile == "" {
			return fmt.Errorf("config: server.grpc_tls_cert_file is required when server.grpc_tls_key_file is set")
		}
		return fmt.Errorf("config: server.grpc_tls_key_file is required when server.grpc_tls_cert_file is set")
	}
	if c.JWT.Issuer == "" {
		return fmt.Errorf("config: jwt.issuer is required")
	}
	if err := validateURL("jwt.issuer", c.JWT.Issuer, "http", "https"); err != nil {
		return err
	}
	if len(c.JWT.Audience) == 0 {
		return fmt.Errorf("config: jwt.audience must not be empty")
	}
	for i, aud := range c.JWT.Audience {
		if strings.TrimSpace(aud) == "" {
			return fmt.Errorf("config: jwt.audience[%d] must not be empty", i)
		}
	}
	if c.JWT.TTLSeconds <= 0 {
		return fmt.Errorf("config: jwt.ttl_seconds must be positive")
	}
	if c.JWT.SigningKeyDir == "" {
		return fmt.Errorf("config: jwt.signing_key_dir is required")
	}
	if c.Lore.DefaultRemoteURL != "" {
		remote, err := parseURL("lore.default_remote_url", c.Lore.DefaultRemoteURL, "lore")
		if err != nil {
			return err
		}
		host := remote.Hostname()
		if host == "" {
			return fmt.Errorf("config: lore.default_remote_url must include a host")
		}
		if !containsStringFold(c.JWT.Audience, host) {
			return fmt.Errorf("config: jwt.audience must include lore.default_remote_url host %q", host)
		}
	}
	if c.Lore.AuthURL != "" {
		if err := validateURL("lore.auth_url", c.Lore.AuthURL, "https", "ucs-auth"); err != nil {
			return err
		}
	}
	if c.Security.DeviceCodeTTLSeconds <= 0 {
		return fmt.Errorf("config: security.device_code_ttl_seconds must be positive")
	}
	if c.Security.DevicePollIntervalSeconds <= 0 {
		return fmt.Errorf("config: security.device_poll_interval_seconds must be positive")
	}
	if c.Security.SessionTTLSeconds <= 0 {
		return fmt.Errorf("config: security.session_ttl_seconds must be positive")
	}
	if c.Security.AuthSessionTTLSeconds <= 0 {
		return fmt.Errorf("config: security.auth_session_ttl_seconds must be positive")
	}
	for i, cidr := range c.Security.RebacAllowedPeerCIDRs {
		if err := validateCIDROrIP("security.rebac_allowed_peer_cidrs", cidr); err != nil {
			return fmt.Errorf("config: security.rebac_allowed_peer_cidrs[%d]: %w", i, err)
		}
	}
	if err := c.validateIdentityProviders(); err != nil {
		return err
	}
	return nil
}

func (c *Config) validateIdentityProviders() error {
	if len(c.IdentityProviders.Providers) == 0 {
		if strings.TrimSpace(c.IdentityProviders.Default) != "" {
			return fmt.Errorf("config: identity_providers.default must reference a configured provider")
		}
		return nil
	}
	if c.IdentityProviders.Default == "" {
		return fmt.Errorf("config: identity_providers.default is required when identity providers are configured")
	}
	if _, ok := c.IdentityProviders.Providers[c.IdentityProviders.Default]; !ok {
		return fmt.Errorf("config: identity_providers.default %q is not configured", c.IdentityProviders.Default)
	}
	for id, provider := range c.IdentityProviders.Providers {
		if !providerIDPattern.MatchString(id) {
			return fmt.Errorf("config: identity_providers.providers[%q] has an unsafe provider id", id)
		}
		if provider.Type == "" {
			return fmt.Errorf("config: identity_providers.providers[%q].type is required", id)
		}
		if provider.Type != "oidc" {
			return fmt.Errorf("config: identity_providers.providers[%q].type %q is unknown", id, provider.Type)
		}
		switch provider.Profile {
		case "", "google", "keycloak", "entra":
		default:
			return fmt.Errorf("config: identity_providers.providers[%q].profile %q is unknown", id, provider.Profile)
		}
		if provider.Issuer == "" {
			return fmt.Errorf("config: identity_providers.providers[%q].issuer is required", id)
		}
		if err := validateURL("identity_providers.providers."+id+".issuer", provider.Issuer, "http", "https"); err != nil {
			return err
		}
		if provider.ClientID == "" {
			return fmt.Errorf("config: identity_providers.providers[%q].client_id is required", id)
		}
		if provider.ClientSecretFile == "" {
			return fmt.Errorf("config: identity_providers.providers[%q].client_secret_file is required", id)
		}
		if provider.RedirectURL == "" {
			return fmt.Errorf("config: identity_providers.providers[%q].redirect_url is required", id)
		}
		redirect, err := parseURL("identity_providers.providers."+id+".redirect_url", provider.RedirectURL, "http", "https")
		if err != nil {
			return err
		}
		expectedPath := "/auth/" + id + "/callback"
		if redirect.Path != expectedPath {
			return fmt.Errorf("config: identity_providers.providers[%q].redirect_url path must be %q", id, expectedPath)
		}
		if !containsString(provider.Scopes, "openid") {
			return fmt.Errorf("config: identity_providers.providers[%q].scopes must include openid", id)
		}
		switch provider.Subject.Strategy {
		case "oidc_sub":
		case "entra_oid_tid":
			if strings.TrimSpace(provider.Subject.RequiredTID) == "" {
				return fmt.Errorf("config: identity_providers.providers[%q].subject.required_tid is required for entra_oid_tid", id)
			}
		case "email", "upn", "preferred_username":
			return fmt.Errorf("config: identity_providers.providers[%q].subject.strategy %q is not a stable identity key", id, provider.Subject.Strategy)
		default:
			return fmt.Errorf("config: identity_providers.providers[%q].subject.strategy %q is unknown", id, provider.Subject.Strategy)
		}
		switch provider.Trust.EmailBinding {
		case "disabled", "verified_email_invitation":
		default:
			return fmt.Errorf("config: identity_providers.providers[%q].trust.email_binding %q is unknown", id, provider.Trust.EmailBinding)
		}
		personalAccounts := strings.TrimSpace(provider.Trust.PersonalAccounts)
		switch personalAccounts {
		case "", "allow", "deny":
		default:
			return fmt.Errorf("config: identity_providers.providers[%q].trust.personal_accounts %q is unknown", id, provider.Trust.PersonalAccounts)
		}
		if personalAccounts != "" && provider.Profile != "google" {
			return fmt.Errorf("config: identity_providers.providers[%q].trust.personal_accounts is only valid for google profile", id)
		}
		switch provider.PKCE {
		case "", "required":
		default:
			return fmt.Errorf("config: identity_providers.providers[%q].pkce %q is unknown", id, provider.PKCE)
		}
	}
	return nil
}

func validateCIDROrIP(field, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("%s must not be empty", field)
	}
	if strings.Contains(value, "/") {
		if _, err := netip.ParsePrefix(value); err != nil {
			return fmt.Errorf("%s must be a valid CIDR or IP address", field)
		}
		return nil
	}
	if _, err := netip.ParseAddr(value); err != nil {
		return fmt.Errorf("%s must be a valid CIDR or IP address", field)
	}
	return nil
}

func validateURL(field, value string, allowedSchemes ...string) error {
	_, err := parseURL(field, value, allowedSchemes...)
	return err
}

func PublicHost(value string) (string, error) {
	parsed, err := parseURL("server.public_base_url", value, "http", "https")
	if err != nil {
		return "", err
	}
	host := parsed.Hostname()
	if host == "" {
		return "", fmt.Errorf("config: server.public_base_url must include a host")
	}
	return host, nil
}

func parseURL(field, value string, allowedSchemes ...string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("config: %s must be an absolute URL", field)
	}
	for _, scheme := range allowedSchemes {
		if parsed.Scheme == scheme {
			return parsed, nil
		}
	}
	return nil, fmt.Errorf("config: %s scheme must be one of %s", field, strings.Join(allowedSchemes, ", "))
}

func containsStringFold(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(value, want) {
			return true
		}
	}
	return false
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func stripScheme(url string) string {
	if i := strings.Index(url, "://"); i >= 0 {
		return url[i+3:]
	}
	return url
}

// ReadSecretFile reads a secret value from a file and trims surrounding
// whitespace. Empty path returns an empty string without error so optional
// secrets stay optional.
func ReadSecretFile(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("config: read secret %s: %w", path, err)
	}
	return strings.TrimSpace(string(raw)), nil
}
