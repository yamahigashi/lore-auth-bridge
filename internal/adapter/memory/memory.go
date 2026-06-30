package memory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
)

type Store struct {
	mu        sync.Mutex
	users     map[string]model.User
	groups    map[string][]string
	resources map[string]model.Resource
	grants    map[string]map[string]string
	auth      map[string]model.AuthSession
	nonces    map[string]string
	sessions  map[string]string
	csrf      map[string]csrfToken
	tokens    map[string]model.VerifiedToken
}

type csrfToken struct {
	SessionID string
	ExpiresAt int64
	Consumed  bool
}

func New() *Store {
	return &Store{
		users:     map[string]model.User{},
		groups:    map[string][]string{},
		resources: map[string]model.Resource{},
		grants:    map[string]map[string]string{},
		auth:      map[string]model.AuthSession{},
		nonces:    map[string]string{},
		sessions:  map[string]string{},
		csrf:      map[string]csrfToken{},
		tokens:    map[string]model.VerifiedToken{},
	}
}

func (s *Store) AddTestUser(u model.User) model.User {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u.ID == "" {
		u.ID = uuid.NewString()
	}
	if u.Provider == "" {
		u.Provider = "google"
	}
	if u.Issuer == "" {
		u.Issuer = "https://accounts.google.com"
	}
	if u.Status == "" {
		u.Status = "active"
	}
	s.users[u.ID] = u
	return u
}

func (s *Store) AddTestResource(r model.Resource) model.Resource {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.ID == "" {
		r.ID = uuid.NewString()
	}
	if r.ResourceID == "" {
		r.ResourceID = model.ResourceIDForRepositoryID(r.LoreRepositoryID)
	}
	if r.LoreRepositoryID == "" {
		r.LoreRepositoryID = model.RepositoryIDFromResourceID(r.ResourceID)
	}
	if r.Status == "" {
		r.Status = "active"
	}
	s.resources[r.ResourceID] = r
	return r
}

func (s *Store) Grant(userID, resourceID string) {
	s.GrantRole(userID, resourceID, model.RoleWriter)
}

func (s *Store) GrantRole(userID, resourceID, role string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.grants[userID] == nil {
		s.grants[userID] = map[string]string{}
	}
	s.grants[userID][resourceID] = role
}

func (s *Store) FindByIdentity(ctx context.Context, provider, issuer, subject string) (model.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, user := range s.users {
		if user.Provider == provider && user.Issuer == issuer && user.Subject == subject {
			return user, nil
		}
	}
	return model.User{}, model.ErrNotFound
}

func (s *Store) BindPreRegisteredIdentity(ctx context.Context, identity model.Identity) (model.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !identity.EmailVerified || strings.TrimSpace(identity.Email) == "" {
		return model.User{}, model.ErrNotFound
	}
	for id, user := range s.users {
		if user.Provider != identity.Provider || user.Issuer != identity.Issuer {
			continue
		}
		if user.Subject == identity.Subject && user.Status == "active" {
			return user, nil
		}
		if user.Subject == "" && user.Status == "pending" && strings.EqualFold(strings.TrimSpace(user.Email), strings.TrimSpace(identity.Email)) {
			user.Subject = identity.Subject
			user.Email = identity.Email
			user.EmailVerified = identity.EmailVerified
			user.DisplayName = identity.Name
			user.PictureURL = identity.PictureURL
			user.HostedDomain = identity.HostedDomain
			user.Status = "active"
			s.users[id] = user
			return user, nil
		}
	}
	return model.User{}, model.ErrNotFound
}

func (s *Store) Resolve(ctx context.Context, emailOrID string) (model.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, user := range s.users {
		if user.ID == emailOrID || user.Email == emailOrID {
			return user, nil
		}
	}
	return model.User{}, model.ErrNotFound
}

func (s *Store) FindByID(ctx context.Context, id string) (model.User, error) {
	return s.Resolve(ctx, id)
}

func (s *Store) GroupNames(ctx context.Context, userID string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.groups[userID]...), nil
}

func (s *Store) AddUser(ctx context.Context, input model.AddUserInput) (model.User, error) {
	return s.AddTestUser(model.User{Provider: input.Provider, Issuer: input.Issuer, Subject: input.Subject, Email: input.Email, EmailVerified: input.EmailVerified, DisplayName: input.DisplayName, PictureURL: input.PictureURL, HostedDomain: input.HostedDomain}), nil
}

func (s *Store) AddPreRegisteredUser(ctx context.Context, input model.AddPreRegisteredUserInput) (model.User, error) {
	if strings.TrimSpace(input.Email) == "" {
		return model.User{}, model.ErrInvalidArgument
	}
	id := uuid.NewString()
	if input.Provider == "" {
		input.Provider = "google"
	}
	if input.Issuer == "" {
		input.Issuer = "https://accounts.google.com"
	}
	user := model.User{ID: id, Provider: input.Provider, Issuer: input.Issuer, Subject: "pending:" + id, Email: strings.TrimSpace(input.Email), DisplayName: input.DisplayName, Status: "pending"}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[user.ID] = user
	return user, nil
}

func (s *Store) ListUsers(ctx context.Context) ([]model.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.User, 0, len(s.users))
	for _, user := range s.users {
		out = append(out, user)
	}
	return out, nil
}

func (s *Store) DisableUser(ctx context.Context, emailOrID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, user := range s.users {
		if user.ID == emailOrID || user.Email == emailOrID {
			user.Status = "disabled"
			s.users[id] = user
			return nil
		}
	}
	return model.ErrNotFound
}

func (s *Store) Upsert(ctx context.Context, r model.Resource) error {
	s.AddTestResource(r)
	return nil
}

func (s *Store) Delete(ctx context.Context, resourceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.resources[resourceID]; !ok {
		return model.ErrNotFound
	}
	delete(s.resources, resourceID)
	return nil
}

func (s *Store) GetByResourceID(ctx context.Context, resourceID string) (model.Resource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.resources[resourceID]
	if !ok {
		return model.Resource{}, model.ErrNotFound
	}
	return r, nil
}

func (s *Store) GetByName(ctx context.Context, name string) (model.Resource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, resource := range s.resources {
		if resource.Name == name {
			return resource, nil
		}
	}
	return model.Resource{}, model.ErrNotFound
}

func (s *Store) List(ctx context.Context) ([]model.Resource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.Resource, 0, len(s.resources))
	for _, resource := range s.resources {
		out = append(out, resource)
	}
	return out, nil
}

func (s *Store) CanAccess(ctx context.Context, userID, resourceID, action string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	role := s.grants[userID][resourceID]
	return model.RoleAllows(role, action), nil
}

func (s *Store) ListAccessible(ctx context.Context, userID string, filter model.ResourceFilter) ([]model.ResourcePermission, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []model.ResourcePermission
	for resourceID, role := range s.grants[userID] {
		if filter.Prefix != "" && !strings.HasPrefix(resourceID, filter.Prefix) {
			continue
		}
		perms, ok := model.RolePermissions(role)
		if !ok {
			return nil, model.ErrInvalidArgument
		}
		out = append(out, model.ResourcePermission{ResourceID: resourceID, Permission: perms})
	}
	return out, nil
}

func (s *Store) CreateAuthSession(ctx context.Context, clientState string, ttl time.Duration) (string, model.AuthSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	code := uuid.NewString()
	sess := model.AuthSession{ID: uuid.NewString(), ClientStateHash: hashAuthCode(clientState), Status: "pending", LoginURLNonce: uuid.NewString(), ExpiresAt: time.Now().Add(ttl).Unix()}
	s.auth[hashAuthCode(code)] = sess
	s.nonces[sess.LoginURLNonce] = sess.ID
	return code, sess, nil
}

func (s *Store) GetAuthSessionByCode(ctx context.Context, code string) (model.AuthSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.auth[hashAuthCode(code)]
	if !ok || sess.ExpiresAt <= time.Now().Unix() {
		return model.AuthSession{}, model.ErrNotFound
	}
	return sess, nil
}

func (s *Store) GetAuthSessionByNonce(ctx context.Context, nonce string) (model.AuthSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.nonces[nonce]
	if !ok {
		return model.AuthSession{}, model.ErrNotFound
	}
	for _, sess := range s.auth {
		if sess.ID == id && sess.ExpiresAt > time.Now().Unix() {
			return sess, nil
		}
	}
	return model.AuthSession{}, model.ErrNotFound
}

func (s *Store) CompleteAuthSession(ctx context.Context, id, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for code, sess := range s.auth {
		if sess.ID == id && sess.Status == "pending" && sess.ExpiresAt > time.Now().Unix() {
			sess.Status = "completed"
			sess.UserID = userID
			s.auth[code] = sess
			return nil
		}
	}
	return model.ErrNotFound
}

func (s *Store) ConsumeAuthSession(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for code, sess := range s.auth {
		if sess.ID == id && sess.Status == "completed" && sess.ExpiresAt > time.Now().Unix() {
			sess.Status = "consumed"
			s.auth[code] = sess
			return nil
		}
	}
	return model.ErrNotFound
}

func (s *Store) CreateBrowserSession(ctx context.Context, userID string, ttl time.Duration) (model.BrowserSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session := model.BrowserSession{ID: uuid.NewString(), UserID: userID, ExpiresAt: time.Now().Add(ttl).Unix()}
	s.sessions[session.ID] = userID
	return session, nil
}

func (s *Store) UserByBrowserSession(ctx context.Context, sessionID string) (model.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	userID, ok := s.sessions[sessionID]
	if !ok {
		return model.User{}, model.ErrNotFound
	}
	user, ok := s.users[userID]
	if !ok {
		return model.User{}, model.ErrNotFound
	}
	return user, nil
}

func (s *Store) RevokeBrowserSession(ctx context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
	return nil
}

func (s *Store) CreateCSRFToken(ctx context.Context, sessionID string, ttl time.Duration) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token := uuid.NewString()
	s.csrf[hashAuthCode(token)] = csrfToken{SessionID: sessionID, ExpiresAt: time.Now().Add(ttl).Unix()}
	return token, nil
}

func (s *Store) ConsumeCSRFToken(ctx context.Context, sessionID, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	hashed := hashAuthCode(token)
	issue, ok := s.csrf[hashed]
	if !ok || issue.SessionID != sessionID || issue.Consumed || issue.ExpiresAt <= time.Now().Unix() {
		return model.ErrNotFound
	}
	issue.Consumed = true
	s.csrf[hashed] = issue
	return nil
}

func (s *Store) MatchClientState(session model.AuthSession, clientState string) bool {
	return session.ClientStateHash == hashAuthCode(clientState)
}

func hashAuthCode(code string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(code)))
	return hex.EncodeToString(sum[:])
}

func (s *Store) SignAuthn(ctx context.Context, input model.AuthnTokenInput) (model.SignedToken, error) {
	token := "authn:" + input.Subject + ":" + uuid.NewString()
	expires := time.Now().Add(input.TTL).Unix()
	if input.TTL == 0 {
		expires = time.Now().Add(time.Hour).Unix()
	}
	s.mu.Lock()
	s.tokens[token] = model.VerifiedToken{Subject: input.Subject, ExpiresAt: expires, Audience: append([]string(nil), input.Audience...)}
	s.mu.Unlock()
	return model.SignedToken{Token: token, JTI: uuid.NewString(), Kid: "memory", IssuedAt: time.Now().Unix(), ExpiresAt: expires, Audience: input.Audience}, nil
}

func (s *Store) SignAuthz(ctx context.Context, input model.AuthzTokenInput) (model.SignedToken, error) {
	token := "authz:" + input.Subject + ":" + uuid.NewString()
	expires := time.Now().Add(input.TTL).Unix()
	if input.TTL == 0 {
		expires = time.Now().Add(15 * time.Minute).Unix()
	}
	firstResource := ""
	permissions := []string(nil)
	if len(input.Resources) > 0 {
		firstResource = input.Resources[0].ResourceID
		permissions = input.Resources[0].Permission
	}
	return model.SignedToken{Token: token, JTI: uuid.NewString(), Kid: "memory", LoreResourceID: firstResource, IssuedAt: time.Now().Unix(), ExpiresAt: expires, Permissions: permissions, Audience: input.Audience}, nil
}

func (s *Store) Verify(ctx context.Context, compact string, opts model.VerifyOptions) (model.VerifiedToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, ok := s.tokens[strings.TrimPrefix(compact, "Bearer ")]
	if !ok {
		return model.VerifiedToken{}, fmt.Errorf("%w: memory token not found", model.ErrUnauthenticated)
	}
	return token, nil
}

func (s *Store) JWKS(ctx context.Context) (json.RawMessage, error) {
	return json.RawMessage(`{"keys":[]}`), nil
}

func (s *Store) Record(ctx context.Context, token model.IssuedToken) error { return nil }
