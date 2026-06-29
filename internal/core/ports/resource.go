package ports

import (
	"context"

	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
)

type ResourceStore interface {
	Upsert(ctx context.Context, r model.Resource) error
	Delete(ctx context.Context, resourceID string) error
	GetByResourceID(ctx context.Context, resourceID string) (model.Resource, error)
	GetByName(ctx context.Context, name string) (model.Resource, error)
	List(ctx context.Context) ([]model.Resource, error)
}
