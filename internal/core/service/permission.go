package service

import (
	"context"

	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/ports"
)

type PermissionService struct {
	resources ports.ResourceStore
	authz     ports.AuthorizationPolicy
}

func NewPermissionService(resources ports.ResourceStore, authz ports.AuthorizationPolicy) *PermissionService {
	return &PermissionService{resources: resources, authz: authz}
}

type CheckedPermission struct {
	ResourceID string
	Allowed    bool
	Permission []string
}

func (s *PermissionService) Check(ctx context.Context, userID string, resourceIDs []string) ([]CheckedPermission, error) {
	out := make([]CheckedPermission, 0, len(resourceIDs))
	for _, resourceID := range resourceIDs {
		resource, err := s.resources.GetByResourceID(ctx, resourceID)
		if err != nil {
			out = append(out, CheckedPermission{ResourceID: resourceID})
			continue
		}
		allowed, err := s.authz.CanAccess(ctx, userID, resource.ResourceID, "write")
		if err != nil {
			return nil, err
		}
		out = append(out, CheckedPermission{ResourceID: resource.ResourceID, Allowed: allowed, Permission: []string{"read", "write"}})
	}
	return out, nil
}

func (s *PermissionService) Lookup(ctx context.Context, userID string, filter model.ResourceFilter) ([]model.ResourcePermission, error) {
	return s.authz.ListAccessible(ctx, userID, filter)
}
