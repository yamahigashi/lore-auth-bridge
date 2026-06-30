package googleid

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/oauth2"
	googleoauth "golang.org/x/oauth2/google"
	"google.golang.org/api/idtoken"

	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/ports"
)

type Identity = model.Identity

type Authenticator interface {
	ports.IdentityProvider
}

type GoogleAuthenticator struct {
	id                    string
	displayName           string
	issuer                string
	clientID              string
	config                oauth2.Config
	allowedHostedDomains  map[string]struct{}
	allowPersonalAccounts bool
}

type Config struct {
	ProviderID            string
	DisplayName           string
	Issuer                string
	ClientID              string
	ClientSecret          string
	RedirectURL           string
	Scopes                []string
	AllowedHostedDomains  []string
	AllowPersonalAccounts bool
}

func New(cfg Config) *GoogleAuthenticator {
	providerID := cfg.ProviderID
	if providerID == "" {
		providerID = "google"
	}
	displayName := cfg.DisplayName
	if displayName == "" {
		displayName = "Google"
	}
	issuer := cfg.Issuer
	if issuer == "" {
		issuer = "https://accounts.google.com"
	}
	scopes := append([]string(nil), cfg.Scopes...)
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}
	return &GoogleAuthenticator{
		id:                    providerID,
		displayName:           displayName,
		issuer:                issuer,
		clientID:              cfg.ClientID,
		config:                oauth2.Config{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, RedirectURL: cfg.RedirectURL, Scopes: scopes, Endpoint: googleoauth.Endpoint},
		allowedHostedDomains:  normalizeHostedDomains(cfg.AllowedHostedDomains),
		allowPersonalAccounts: cfg.AllowPersonalAccounts,
	}
}

func (g *GoogleAuthenticator) Descriptor() ports.IdentityProviderDescriptor {
	return ports.IdentityProviderDescriptor{ID: g.id, Type: "google_oidc", DisplayName: g.displayName, Issuer: g.issuer}
}

func (g *GoogleAuthenticator) BeginAuth(ctx context.Context, req ports.BeginAuthRequest) (ports.BeginAuthResult, error) {
	options := []oauth2.AuthCodeOption{oauth2.AccessTypeOnline}
	if req.Nonce != "" {
		options = append(options, oauth2.SetAuthURLParam("nonce", req.Nonce))
	}
	if req.LoginHint != "" {
		options = append(options, oauth2.SetAuthURLParam("login_hint", req.LoginHint))
	}
	return ports.BeginAuthResult{RedirectURL: g.config.AuthCodeURL(req.State, options...)}, nil
}

func (g *GoogleAuthenticator) CompleteAuth(ctx context.Context, req ports.CompleteAuthRequest) (model.Identity, error) {
	tok, err := g.config.Exchange(ctx, req.Code)
	if err != nil {
		return model.Identity{}, fmt.Errorf("googleauth: exchange code: %w", err)
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return model.Identity{}, fmt.Errorf("googleauth: oauth response missing id_token")
	}
	payload, err := idtoken.Validate(ctx, rawIDToken, g.clientID)
	if err != nil {
		return model.Identity{}, fmt.Errorf("googleauth: validate id token: %w", err)
	}
	if req.Nonce != "" {
		nonce, _ := payload.Claims["nonce"].(string)
		if nonce != req.Nonce {
			return model.Identity{}, fmt.Errorf("googleauth: id token nonce mismatch")
		}
	}
	id := model.Identity{Provider: g.id, Issuer: payload.Issuer, Subject: payload.Subject}
	if v, ok := payload.Claims["email"].(string); ok {
		id.Email = v
	}
	if v, ok := payload.Claims["email_verified"].(bool); ok {
		id.EmailVerified = v
	}
	if v, ok := payload.Claims["name"].(string); ok {
		id.Name = v
	}
	if v, ok := payload.Claims["picture"].(string); ok {
		id.PictureURL = v
	}
	if v, ok := payload.Claims["hd"].(string); ok {
		id.HostedDomain = v
	}
	if err := g.validateHostedDomain(id); err != nil {
		return model.Identity{}, err
	}
	return id, nil
}

func normalizeHostedDomains(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" {
			out[value] = struct{}{}
		}
	}
	return out
}

func (g *GoogleAuthenticator) validateHostedDomain(id model.Identity) error {
	hostedDomain := strings.ToLower(strings.TrimSpace(id.HostedDomain))
	if len(g.allowedHostedDomains) > 0 {
		if _, ok := g.allowedHostedDomains[hostedDomain]; !ok {
			return fmt.Errorf("%w: google hosted domain is not allowed", model.ErrPermissionDenied)
		}
		return nil
	}
	if hostedDomain == "" && !g.allowPersonalAccounts {
		return fmt.Errorf("%w: google personal accounts are not allowed", model.ErrPermissionDenied)
	}
	return nil
}
