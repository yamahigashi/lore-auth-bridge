package ports

import (
	"context"

	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
)

var _ IdentityProvider = externalIdentityProviderContract{}

type externalIdentityProviderContract struct{}

func (externalIdentityProviderContract) Descriptor() IdentityProviderDescriptor {
	return IdentityProviderDescriptor{ID: "keycloak-prod", Type: "oidc"}
}

func (externalIdentityProviderContract) BeginAuth(context.Context, BeginAuthRequest) (BeginAuthResult, error) {
	return BeginAuthResult{}, nil
}

func (externalIdentityProviderContract) CompleteAuth(context.Context, CompleteAuthRequest) (model.ExternalIdentity, error) {
	return model.ExternalIdentity{}, nil
}
