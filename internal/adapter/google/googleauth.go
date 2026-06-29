package googleid

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/oauth2"
	googleoauth "golang.org/x/oauth2/google"
	"google.golang.org/api/idtoken"

	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
)

type Identity = model.Identity

type Authenticator interface {
	AuthCodeURL(state string) string
	ExchangeAndVerify(ctx context.Context, code string) (Identity, error)
}

type GoogleAuthenticator struct {
	clientID              string
	config                oauth2.Config
	allowedHostedDomains  map[string]struct{}
	allowPersonalAccounts bool
}

type Config struct {
	ClientID              string
	ClientSecret          string
	RedirectURL           string
	AllowedHostedDomains  []string
	AllowPersonalAccounts bool
}

func New(cfg Config) *GoogleAuthenticator {
	return &GoogleAuthenticator{
		clientID:              cfg.ClientID,
		config:                oauth2.Config{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, RedirectURL: cfg.RedirectURL, Scopes: []string{"openid", "email", "profile"}, Endpoint: googleoauth.Endpoint},
		allowedHostedDomains:  normalizeHostedDomains(cfg.AllowedHostedDomains),
		allowPersonalAccounts: cfg.AllowPersonalAccounts,
	}
}

func (g *GoogleAuthenticator) AuthCodeURL(state string) string {
	return g.config.AuthCodeURL(state, oauth2.AccessTypeOnline)
}

func (g *GoogleAuthenticator) ExchangeAndVerify(ctx context.Context, code string) (model.Identity, error) {
	tok, err := g.config.Exchange(ctx, code)
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
	id := model.Identity{Provider: "google", Issuer: payload.Issuer, Subject: payload.Subject}
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

func (g *GoogleAuthenticator) Issuer() string { return "https://accounts.google.com" }

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
