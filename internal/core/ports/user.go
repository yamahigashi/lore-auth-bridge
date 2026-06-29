package ports

import (
	"context"

	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
)

type UserDirectory interface {
	FindByIdentity(ctx context.Context, provider, issuer, subject string) (model.User, error)
	BindPreRegisteredIdentity(ctx context.Context, identity model.Identity) (model.User, error)
	Resolve(ctx context.Context, emailOrID string) (model.User, error)
	FindByID(ctx context.Context, id string) (model.User, error)
	GroupNames(ctx context.Context, userID string) ([]string, error)
	AddUser(ctx context.Context, input model.AddUserInput) (model.User, error)
	AddPreRegisteredUser(ctx context.Context, input model.AddPreRegisteredUserInput) (model.User, error)
	ListUsers(ctx context.Context) ([]model.User, error)
	DisableUser(ctx context.Context, emailOrID string) error
}
