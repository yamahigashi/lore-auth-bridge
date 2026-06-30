package staticidp

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/ports"
)

const callbackCode = "static"

type Provider struct {
	id          string
	displayName string
	identity    model.Identity
}

type Config struct {
	ProviderID    string
	DisplayName   string
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	PictureURL    string
	HostedDomain  string
}

func New(cfg Config) (*Provider, error) {
	id := strings.TrimSpace(cfg.ProviderID)
	if id == "" {
		return nil, fmt.Errorf("staticidp: provider id is required")
	}
	if strings.TrimSpace(cfg.Issuer) == "" {
		return nil, fmt.Errorf("staticidp: issuer is required")
	}
	if strings.TrimSpace(cfg.Subject) == "" {
		return nil, fmt.Errorf("staticidp: subject is required")
	}
	displayName := strings.TrimSpace(cfg.DisplayName)
	if displayName == "" {
		displayName = id
	}
	return &Provider{
		id:          id,
		displayName: displayName,
		identity: model.Identity{
			Provider:      id,
			Issuer:        cfg.Issuer,
			Subject:       cfg.Subject,
			Email:         cfg.Email,
			EmailVerified: cfg.EmailVerified,
			Name:          cfg.Name,
			PictureURL:    cfg.PictureURL,
			HostedDomain:  cfg.HostedDomain,
		},
	}, nil
}

func (p *Provider) Descriptor() ports.IdentityProviderDescriptor {
	return ports.IdentityProviderDescriptor{ID: p.id, Type: "static", DisplayName: p.displayName, Issuer: p.identity.Issuer}
}

func (p *Provider) BeginAuth(ctx context.Context, req ports.BeginAuthRequest) (ports.BeginAuthResult, error) {
	callback, err := url.Parse(req.RedirectURL)
	if err != nil {
		return ports.BeginAuthResult{}, fmt.Errorf("staticidp: parse callback url: %w", err)
	}
	values := callback.Query()
	values.Set("state", req.State)
	values.Set("code", callbackCode)
	callback.RawQuery = values.Encode()
	return ports.BeginAuthResult{RedirectURL: callback.String()}, nil
}

func (p *Provider) CompleteAuth(ctx context.Context, req ports.CompleteAuthRequest) (model.Identity, error) {
	if req.Code != callbackCode {
		return model.Identity{}, fmt.Errorf("staticidp: invalid callback code")
	}
	return p.identity, nil
}
