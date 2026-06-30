package service

import (
	"context"

	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/ports"
)

type ResourceService struct {
	store ports.ResourceStore
}

func NewResourceService(store ports.ResourceStore) *ResourceService {
	return &ResourceService{store: store}
}

func (s *ResourceService) CreateResource(ctx context.Context, resourceID, resourceName string) error {
	return s.store.Upsert(ctx, model.Resource{ResourceID: resourceID, Name: resourceName})
}

func (s *ResourceService) DeleteResource(ctx context.Context, resourceID string) error {
	return s.store.Delete(ctx, resourceID)
}

func (s *ResourceService) Get(ctx context.Context, resourceID string) (model.Resource, error) {
	return s.store.GetByResourceID(ctx, resourceID)
}

func (s *ResourceService) GetByName(ctx context.Context, name string) (model.Resource, error) {
	return s.store.GetByName(ctx, name)
}

func (s *ResourceService) List(ctx context.Context) ([]model.Resource, error) {
	return s.store.List(ctx)
}
