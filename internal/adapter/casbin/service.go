package casbin

import (
	"context"
	"embed"
	"fmt"
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
	repos, err := s.store.UserAccessibleRepositories(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]coremodel.ResourcePermission, 0, len(repos))
	for _, repo := range repos {
		resourceID := coremodel.ResourceIDForRepositoryID(repo.LoreRepositoryID)
		if filter.Prefix != "" && !strings.HasPrefix(resourceID, filter.Prefix) {
			continue
		}
		out = append(out, coremodel.ResourcePermission{ResourceID: resourceID, Permission: []string{"read", "write"}})
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
	rows, err := s.store.DB().QueryContext(ctx, `SELECT subject_type, subject_id, repository_id, role FROM grants`)
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
		for _, act := range roleActions(role) {
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

func roleActions(role string) []string {
	switch role {
	case "reader":
		return []string{"read"}
	case "writer":
		return []string{"read", "write"}
	case "admin":
		return []string{"read", "write", "admin"}
	default:
		return []string{role}
	}
}
