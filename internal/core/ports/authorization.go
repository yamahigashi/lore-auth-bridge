package ports

import (
	"context"

	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
)

type AuthorizationPolicy interface {
	CanAccess(ctx context.Context, userID, resourceID, action string) (bool, error)
	ListAccessible(ctx context.Context, userID string, filter model.ResourceFilter) ([]model.ResourcePermission, error)
}
