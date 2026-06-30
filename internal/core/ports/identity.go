package ports

import (
	"context"

	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
)

type IdentityProvider interface {
	Descriptor() IdentityProviderDescriptor
	BeginAuth(ctx context.Context, req BeginAuthRequest) (BeginAuthResult, error)
	CompleteAuth(ctx context.Context, req CompleteAuthRequest) (model.Identity, error)
}

type IdentityProviderDescriptor struct {
	ID          string
	Type        string
	DisplayName string
	Issuer      string
}

type BeginAuthRequest struct {
	State       string
	Nonce       string
	RedirectURL string
	LoginHint   string
}

type BeginAuthResult struct {
	RedirectURL string
}

type CompleteAuthRequest struct {
	Code        string
	State       string
	Nonce       string
	RedirectURL string
	Params      map[string][]string
}

type IdentityProviderRegistry interface {
	Get(id string) (IdentityProvider, bool)
	DefaultID() string
	List() []IdentityProviderDescriptor
}
