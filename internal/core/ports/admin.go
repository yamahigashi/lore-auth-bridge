package ports

import (
	"context"

	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
)

type GroupAdmin interface {
	AddGroup(ctx context.Context, name, description string) (model.Group, error)
	ListGroups(ctx context.Context) ([]model.Group, error)
	AddGroupMember(ctx context.Context, group, userEmailOrID string) error
	RemoveGroupMember(ctx context.Context, group, userEmailOrID string) error
}

type GrantAdmin interface {
	AddGrant(ctx context.Context, subjectType, subjectID, repo, role string) (model.Grant, error)
	RemoveGrant(ctx context.Context, subjectType, subjectID, repo, role string) error
	ListGrants(ctx context.Context, repo string) ([]model.Grant, error)
}

type SigningKeyAdmin interface {
	GenerateActiveKey(ctx context.Context, kid, alg string, bits int) (model.SigningKeyMeta, error)
	ListKeys(ctx context.Context) ([]model.SigningKeyMeta, error)
}
