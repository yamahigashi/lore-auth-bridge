package oidcadapter

import (
	"context"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/ports"
)

type Provider struct {
	id                  string
	displayName         string
	issuer              string
	oauth2Config        oauth2.Config
	verifier            *oidc.IDTokenVerifier
	claimMapping        map[string]string
	allowedEmailDomains map[string]struct{}
}

type Config struct {
	ProviderID          string
	DisplayName         string
	Issuer              string
	ClientID            string
	ClientSecret        string
	RedirectURL         string
	Scopes              []string
	ClaimMapping        map[string]string
	AllowedEmailDomains []string
}

func New(ctx context.Context, cfg Config) (*Provider, error) {
	if cfg.ProviderID == "" {
		return nil, fmt.Errorf("oidc: provider id is required")
	}
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("oidc: issuer is required")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("oidc: client id is required")
	}
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: discover provider %q: %w", cfg.Issuer, err)
	}
	var discoveryClaims struct {
		Issuer string `json:"issuer"`
	}
	if err := provider.Claims(&discoveryClaims); err != nil {
		return nil, fmt.Errorf("oidc: decode discovery claims for %q: %w", cfg.Issuer, err)
	}
	issuer := strings.TrimSpace(discoveryClaims.Issuer)
	if issuer == "" {
		issuer = cfg.Issuer
	}
	scopes := append([]string(nil), cfg.Scopes...)
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "email", "profile"}
	}
	return &Provider{
		id:          cfg.ProviderID,
		displayName: displayNameOrDefault(cfg.DisplayName, cfg.ProviderID),
		issuer:      issuer,
		oauth2Config: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       scopes,
			Endpoint:     provider.Endpoint(),
		},
		verifier:            provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		claimMapping:        copyClaimMapping(cfg.ClaimMapping),
		allowedEmailDomains: normalizeDomains(cfg.AllowedEmailDomains),
	}, nil
}

func (p *Provider) Descriptor() ports.IdentityProviderDescriptor {
	return ports.IdentityProviderDescriptor{
		ID:          p.id,
		Type:        "oidc",
		DisplayName: p.displayName,
		Issuer:      p.issuer,
	}
}

func (p *Provider) BeginAuth(ctx context.Context, req ports.BeginAuthRequest) (ports.BeginAuthResult, error) {
	options := []oauth2.AuthCodeOption{oauth2.AccessTypeOnline}
	if req.Nonce != "" {
		options = append(options, oidc.Nonce(req.Nonce))
	}
	if req.LoginHint != "" {
		options = append(options, oauth2.SetAuthURLParam("login_hint", req.LoginHint))
	}
	return ports.BeginAuthResult{RedirectURL: p.oauth2Config.AuthCodeURL(req.State, options...)}, nil
}

func (p *Provider) CompleteAuth(ctx context.Context, req ports.CompleteAuthRequest) (model.Identity, error) {
	token, err := p.oauth2Config.Exchange(ctx, req.Code)
	if err != nil {
		return model.Identity{}, fmt.Errorf("oidc: exchange code: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return model.Identity{}, fmt.Errorf("oidc: oauth response missing id_token")
	}
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return model.Identity{}, fmt.Errorf("oidc: verify id token: %w", err)
	}
	if req.Nonce != "" && idToken.Nonce != req.Nonce {
		return model.Identity{}, fmt.Errorf("oidc: id token nonce mismatch")
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return model.Identity{}, fmt.Errorf("oidc: decode id token claims: %w", err)
	}
	identity := model.Identity{
		Provider: p.id,
		Issuer:   idToken.Issuer,
		Subject:  idToken.Subject,
	}
	identity.Email = stringClaim(claims, p.claim("email", "email"))
	identity.EmailVerified = boolClaim(claims, p.claim("email_verified", "email_verified"))
	identity.Name = stringClaim(claims, p.claim("name", "name"))
	identity.PictureURL = stringClaim(claims, p.claim("picture", "picture"))
	identity.HostedDomain = stringClaim(claims, p.claim("hosted_domain", "hd"))
	if err := p.validateEmailDomain(identity.Email, identity.EmailVerified); err != nil {
		return model.Identity{}, err
	}
	return identity, nil
}

func (p *Provider) claim(canonical, fallback string) string {
	if name := strings.TrimSpace(p.claimMapping[canonical]); name != "" {
		return name
	}
	return fallback
}

func (p *Provider) validateEmailDomain(email string, verified bool) error {
	if len(p.allowedEmailDomains) == 0 {
		return nil
	}
	if !verified {
		return fmt.Errorf("%w: oidc email must be verified", model.ErrPermissionDenied)
	}
	domain := emailDomain(email)
	if domain == "" {
		return fmt.Errorf("%w: oidc email domain is required", model.ErrPermissionDenied)
	}
	if _, ok := p.allowedEmailDomains[domain]; !ok {
		return fmt.Errorf("%w: oidc email domain is not allowed", model.ErrPermissionDenied)
	}
	return nil
}

func copyClaimMapping(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return out
}

func normalizeDomains(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" {
			out[value] = struct{}{}
		}
	}
	return out
}

func emailDomain(email string) string {
	email = strings.TrimSpace(strings.ToLower(email))
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return ""
	}
	return email[at+1:]
}

func stringClaim(claims map[string]any, name string) string {
	value, _ := claims[name].(string)
	return value
}

func boolClaim(claims map[string]any, name string) bool {
	switch value := claims[name].(type) {
	case bool:
		return value
	case string:
		return strings.EqualFold(strings.TrimSpace(value), "true")
	default:
		return false
	}
}

func displayNameOrDefault(displayName, providerID string) string {
	if displayName = strings.TrimSpace(displayName); displayName != "" {
		return displayName
	}
	return providerID
}
