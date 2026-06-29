package sqlite

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
)

type CoreStore struct {
	*Store
}

func NewCoreStore(st *Store) *CoreStore { return &CoreStore{Store: st} }

func (s *CoreStore) FindByIdentity(ctx context.Context, provider, issuer, subject string) (model.User, error) {
	u, err := s.Store.FindUserByIdentity(ctx, provider, issuer, subject)
	return toModelUser(u), err
}

func (s *CoreStore) BindPreRegisteredIdentity(ctx context.Context, identity model.Identity) (model.User, error) {
	u, err := s.Store.BindPreRegisteredIdentity(ctx, identity)
	return toModelUser(u), err
}

func (s *CoreStore) Resolve(ctx context.Context, emailOrID string) (model.User, error) {
	u, err := s.Store.ResolveUser(ctx, emailOrID)
	return toModelUser(u), err
}

func (s *CoreStore) FindByID(ctx context.Context, id string) (model.User, error) {
	u, err := s.Store.UserByID(ctx, id)
	return toModelUser(u), err
}

func (s *CoreStore) GroupNames(ctx context.Context, userID string) ([]string, error) {
	return s.Store.UserGroupNames(ctx, userID)
}

func (s *CoreStore) AddUser(ctx context.Context, input model.AddUserInput) (model.User, error) {
	u, err := s.Store.AddUser(ctx, AddUserParams{
		Provider:      input.Provider,
		Issuer:        input.Issuer,
		Subject:       input.Subject,
		Email:         input.Email,
		EmailVerified: input.EmailVerified,
		DisplayName:   input.DisplayName,
		PictureURL:    input.PictureURL,
		HostedDomain:  input.HostedDomain,
	})
	return toModelUser(u), err
}

func (s *CoreStore) AddPreRegisteredUser(ctx context.Context, input model.AddPreRegisteredUserInput) (model.User, error) {
	u, err := s.Store.AddPreRegisteredUser(ctx, AddPreRegisteredUserParams{
		Provider:    input.Provider,
		Issuer:      input.Issuer,
		Email:       input.Email,
		DisplayName: input.DisplayName,
	})
	return toModelUser(u), err
}

func (s *CoreStore) ListUsers(ctx context.Context) ([]model.User, error) {
	users, err := s.Store.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]model.User, 0, len(users))
	for i := range users {
		out = append(out, toModelUser(&users[i]))
	}
	return out, nil
}

func (s *CoreStore) Upsert(ctx context.Context, r model.Resource) error {
	resourceID := r.ResourceID
	if resourceID == "" {
		resourceID = model.ResourceIDForRepositoryID(r.LoreRepositoryID)
	}
	if r.RemoteURL != "" {
		if _, err := s.Store.FindRepositoryByResourceID(ctx, resourceID); err == nil {
			return s.Store.UpsertResource(ctx, resourceID, r.Name)
		} else if !errors.Is(err, ErrNotFound) {
			return fmt.Errorf("store: check repository before resource upsert: %w", err)
		}
		_, err := s.Store.AddRepository(ctx, r.Name, r.RemoteURL, model.RepositoryIDFromResourceID(resourceID))
		return err
	}
	return s.Store.UpsertResource(ctx, resourceID, r.Name)
}

func (s *CoreStore) Delete(ctx context.Context, resourceID string) error {
	return s.Store.SoftDeleteResource(ctx, resourceID)
}

func (s *CoreStore) GetByResourceID(ctx context.Context, resourceID string) (model.Resource, error) {
	r, err := s.Store.FindRepositoryByResourceID(ctx, resourceID)
	return toModelResource(r), err
}

func (s *CoreStore) GetByName(ctx context.Context, name string) (model.Resource, error) {
	r, err := s.Store.FindRepositoryByName(ctx, name)
	return toModelResource(r), err
}

func (s *CoreStore) List(ctx context.Context) ([]model.Resource, error) {
	repos, err := s.Store.ListRepositories(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]model.Resource, 0, len(repos))
	for i := range repos {
		out = append(out, toModelResource(&repos[i]))
	}
	return out, nil
}

func (s *CoreStore) CreateAuthSession(ctx context.Context, clientState string, ttl time.Duration) (string, model.AuthSession, error) {
	code, sess, err := s.Store.CreateAuthSession(ctx, clientState, int(ttl.Seconds()))
	return code, toModelAuthSession(sess), err
}

func (s *CoreStore) GetAuthSessionByCode(ctx context.Context, code string) (model.AuthSession, error) {
	sess, err := s.Store.AuthSessionByCode(ctx, code)
	return toModelAuthSession(sess), err
}

func (s *CoreStore) GetAuthSessionByNonce(ctx context.Context, nonce string) (model.AuthSession, error) {
	sess, err := s.Store.AuthSessionByNonce(ctx, nonce)
	return toModelAuthSession(sess), err
}

func (s *CoreStore) CreateBrowserSession(ctx context.Context, userID string, ttl time.Duration) (model.BrowserSession, error) {
	sess, err := s.Store.CreateSession(ctx, userID, int(ttl.Seconds()))
	return toModelBrowserSession(sess), err
}

func (s *CoreStore) UserByBrowserSession(ctx context.Context, sessionID string) (model.User, error) {
	u, err := s.Store.UserBySession(ctx, sessionID)
	return toModelUser(u), err
}

func (s *CoreStore) RevokeBrowserSession(ctx context.Context, sessionID string) error {
	return s.Store.RevokeSession(ctx, sessionID)
}

func (s *CoreStore) MatchClientState(session model.AuthSession, clientState string) bool {
	return session.ClientStateHash == HashAuthCode(clientState)
}

func (s *CoreStore) Record(ctx context.Context, token model.IssuedToken) error {
	audJSON, _ := json.Marshal(token.Audience)
	return s.Store.AddIssuedTokenV2(ctx, AddIssuedTokenParams{
		JTI:            token.JTI,
		UserID:         token.UserID,
		RepositoryID:   token.RepositoryID,
		LoreResourceID: token.LoreResourceID,
		Role:           token.Role,
		Kid:            token.Kid,
		IssuedAt:       token.IssuedAt,
		ExpiresAt:      token.ExpiresAt,
	}, token.Kind, string(audJSON))
}

func (s *CoreStore) AddGroup(ctx context.Context, name, description string) (model.Group, error) {
	g, err := s.Store.AddGroup(ctx, name, description)
	return toModelGroup(g), err
}

func (s *CoreStore) ListGroups(ctx context.Context) ([]model.Group, error) {
	groups, err := s.Store.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]model.Group, 0, len(groups))
	for i := range groups {
		out = append(out, toModelGroup(&groups[i]))
	}
	return out, nil
}

func (s *CoreStore) AddGrant(ctx context.Context, subjectType, subjectID, repo, role string) (model.Grant, error) {
	g, err := s.Store.AddGrant(ctx, subjectType, subjectID, repo, role)
	return toModelGrant(g), err
}

func (s *CoreStore) ListGrants(ctx context.Context, repo string) ([]model.Grant, error) {
	grants, err := s.Store.ListGrants(ctx, repo)
	if err != nil {
		return nil, err
	}
	out := make([]model.Grant, 0, len(grants))
	for i := range grants {
		out = append(out, toModelGrant(&grants[i]))
	}
	return out, nil
}

func (s *CoreStore) ActiveSigningKey(ctx context.Context, kid string) (model.SigningKeyMeta, error) {
	key, err := s.Store.ActiveSigningKey(ctx, kid)
	return toModelSigningKey(key), err
}

func (s *CoreStore) SigningKeyByKID(ctx context.Context, kid string) (model.SigningKeyMeta, error) {
	key, err := s.Store.SigningKeyByKID(ctx, kid)
	return toModelSigningKey(key), err
}

func (s *CoreStore) AddSigningKeyMeta(ctx context.Context, key model.SigningKeyMeta) (model.SigningKeyMeta, error) {
	got, err := s.Store.AddSigningKey(ctx, AddSigningKeyParams{Kid: key.Kid, Alg: key.Alg, PublicJWKJSON: key.PublicJWKJSON, PrivateKeyPath: key.PrivateKeyPath, Status: key.Status})
	return toModelSigningKey(got), err
}

func (s *CoreStore) ListSigningKeyMeta(ctx context.Context) ([]model.SigningKeyMeta, error) {
	keys, err := s.Store.ListSigningKeys(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]model.SigningKeyMeta, 0, len(keys))
	for i := range keys {
		out = append(out, toModelSigningKey(&keys[i]))
	}
	return out, nil
}

func toModelUser(u *User) model.User {
	if u == nil {
		return model.User{}
	}
	return model.User{ID: u.ID, Provider: u.Provider, Issuer: u.Issuer, Subject: u.Subject, Email: u.Email.String, EmailVerified: u.EmailVerified, DisplayName: u.DisplayName.String, PictureURL: u.PictureURL.String, HostedDomain: u.HostedDomain.String, Status: u.Status}
}

func toModelResource(r *Repository) model.Resource {
	if r == nil {
		return model.Resource{}
	}
	return model.Resource{ID: r.ID, Name: r.Name, RemoteURL: r.RemoteURL, LoreRepositoryID: r.LoreRepositoryID, ResourceID: model.ResourceIDForRepositoryID(r.LoreRepositoryID), Status: r.Status}
}

func toModelGroup(g *Group) model.Group {
	if g == nil {
		return model.Group{}
	}
	return model.Group{ID: g.ID, Name: g.Name, Description: g.Description.String}
}

func toModelGrant(g *Grant) model.Grant {
	if g == nil {
		return model.Grant{}
	}
	return model.Grant{ID: g.ID, SubjectType: g.SubjectType, SubjectID: g.SubjectID, RepositoryID: g.RepositoryID, Role: g.Role}
}

func toModelAuthSession(s *AuthSession) model.AuthSession {
	if s == nil {
		return model.AuthSession{}
	}
	return model.AuthSession{ID: s.ID, ClientStateHash: s.ClientStateHash, Status: s.Status, UserID: s.UserID.String, LoginURLNonce: s.LoginURLNonce, ExpiresAt: s.ExpiresAt}
}

func toModelBrowserSession(s *Session) model.BrowserSession {
	if s == nil {
		return model.BrowserSession{}
	}
	return model.BrowserSession{ID: s.ID, UserID: s.UserID, ExpiresAt: s.ExpiresAt}
}

func toModelSigningKey(k *SigningKeyMetadata) model.SigningKeyMeta {
	if k == nil {
		return model.SigningKeyMeta{}
	}
	return model.SigningKeyMeta{Kid: k.Kid, Alg: k.Alg, PublicJWKJSON: k.PublicJWKJSON, PrivateKeyPath: k.PrivateKeyPath, Status: k.Status}
}
