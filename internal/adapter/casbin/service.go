package casbin

import (
	"context"
	"embed"
	"fmt"
	"sort"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"

	"github.com/yamahigashi/lore-auth-bridge/internal/adapter/sqlite"
	coremodel "github.com/yamahigashi/lore-auth-bridge/internal/core/model"
)

//go:embed model.conf
var modelFS embed.FS

type Service struct{ store *sqlite.Store }

func NewService(st *sqlite.Store) *Service { return &Service{store: st} }

func (s *Service) Can(ctx context.Context, userEmailOrID, repoName, action string) (bool, error) {
	enforcer, err := s.buildEnforcer(ctx)
	if err != nil {
		return false, err
	}
	u, err := s.store.ResolveUser(ctx, userEmailOrID)
	if err != nil {
		return false, err
	}
	repo, err := s.store.FindRepositoryByName(ctx, repoName)
	if err != nil {
		return false, err
	}
	return enforcer.Enforce("user:"+u.ID, "repo:"+repo.ID, action)
}

func (s *Service) CanAccess(ctx context.Context, userID, resourceID, action string) (bool, error) {
	enforcer, err := s.buildEnforcer(ctx)
	if err != nil {
		return false, err
	}
	repo, err := s.store.FindRepositoryByResourceID(ctx, resourceID)
	if err != nil {
		return false, err
	}
	return enforcer.Enforce("user:"+userID, "repo:"+repo.ID, action)
}

func (s *Service) ListAccessible(ctx context.Context, userID string, filter coremodel.ResourceFilter) ([]coremodel.ResourcePermission, error) {
	rows, err := s.store.DB().QueryContext(ctx, `
SELECT r.lore_repository_id, g.role
FROM repositories r
JOIN grants g ON g.repository_id = r.id
WHERE r.status = 'active' AND (
  (g.subject_type = 'user' AND g.subject_id = ?)
  OR (g.subject_type = 'group' AND g.subject_id IN (SELECT group_id FROM group_members WHERE user_id = ?))
)
ORDER BY r.name, g.role`, userID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byResource := map[string]map[string]bool{}
	for rows.Next() {
		var loreRepositoryID, role string
		if err := rows.Scan(&loreRepositoryID, &role); err != nil {
			return nil, err
		}
		resourceID := coremodel.ResourceIDForRepositoryID(loreRepositoryID)
		if filter.Prefix != "" && !strings.HasPrefix(resourceID, filter.Prefix) {
			continue
		}
		perms, ok := coremodel.RolePermissions(role)
		if !ok {
			return nil, fmt.Errorf("%w: unknown grant role %q", coremodel.ErrInvalidArgument, role)
		}
		if byResource[resourceID] == nil {
			byResource[resourceID] = map[string]bool{}
		}
		for _, perm := range perms {
			byResource[resourceID][perm] = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	resourceIDs := make([]string, 0, len(byResource))
	for resourceID := range byResource {
		resourceIDs = append(resourceIDs, resourceID)
	}
	sort.Strings(resourceIDs)
	out := make([]coremodel.ResourcePermission, 0, len(resourceIDs))
	for _, resourceID := range resourceIDs {
		set := byResource[resourceID]
		permissions := make([]string, 0, len(set))
		for _, perm := range []string{coremodel.PermissionRead, coremodel.PermissionWrite, coremodel.PermissionAdmin} {
			if set[perm] {
				permissions = append(permissions, perm)
			}
		}
		out = append(out, coremodel.ResourcePermission{ResourceID: resourceID, Permission: permissions})
	}
	return out, nil
}

func (s *Service) buildEnforcer(ctx context.Context) (*casbin.Enforcer, error) {
	raw, err := modelFS.ReadFile("model.conf")
	if err != nil {
		return nil, err
	}
	m, err := model.NewModelFromString(string(raw))
	if err != nil {
		return nil, err
	}
	enforcer, err := casbin.NewEnforcer(m)
	if err != nil {
		return nil, err
	}
	if err := s.loadGroupMemberships(ctx, enforcer); err != nil {
		return nil, err
	}
	if err := s.loadGrants(ctx, enforcer); err != nil {
		return nil, err
	}
	return enforcer, nil
}

func (s *Service) loadGroupMemberships(ctx context.Context, enforcer *casbin.Enforcer) error {
	rows, err := s.store.DB().QueryContext(ctx, `SELECT group_id, user_id FROM group_members`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var groupID, userID string
		if err := rows.Scan(&groupID, &userID); err != nil {
			return err
		}
		if _, err := enforcer.AddGroupingPolicy("user:"+userID, "group:"+groupID); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (s *Service) loadGrants(ctx context.Context, enforcer *casbin.Enforcer) error {
	rows, err := s.store.DB().QueryContext(ctx, `
SELECT g.subject_type, g.subject_id, g.repository_id, g.role
FROM grants g
JOIN repositories r ON r.id = g.repository_id
WHERE r.status = 'active'`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var subjectType, subjectID, repositoryID, role string
		if err := rows.Scan(&subjectType, &subjectID, &repositoryID, &role); err != nil {
			return err
		}
		subject, err := policySubject(subjectType, subjectID)
		if err != nil {
			return err
		}
		acts, ok := coremodel.RolePermissions(role)
		if !ok {
			return fmt.Errorf("%w: unknown grant role %q", coremodel.ErrInvalidArgument, role)
		}
		for _, act := range acts {
			if _, err := enforcer.AddPolicy(subject, "repo:"+repositoryID, act); err != nil {
				return err
			}
		}
	}
	return rows.Err()
}

func policySubject(subjectType, subjectID string) (string, error) {
	switch subjectType {
	case "user", "group", "service_account":
		return subjectType + ":" + subjectID, nil
	default:
		return "", fmt.Errorf("acl: unknown subject type %q", subjectType)
	}
}
