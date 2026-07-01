package ports

import (
	"context"

	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
)

type AccountDirectory interface {
	ResolveLogin(ctx context.Context, req model.LoginResolutionRequest) (model.TokenPrincipal, model.LoginBindingResult, error)
	PrincipalByUserID(ctx context.Context, userID string) (model.TokenPrincipal, error)
	PrincipalByAuthnTokenJTI(ctx context.Context, jti string) (model.TokenPrincipal, error)
	AddUser(ctx context.Context, input model.AddUserInput) (model.User, error)
	AddInvitation(ctx context.Context, input model.AddInvitationInput) (model.User, model.IdentityInvitation, error)
}
