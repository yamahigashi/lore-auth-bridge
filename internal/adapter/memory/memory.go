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
	mu          sync.Mutex
	users       map[string]model.User
	identities  map[string]model.ExternalIdentity
	invitations map[string]model.IdentityInvitation
	groups      map[string][]string
	resources   map[string]model.Resource
	grants      map[string]map[string]string
	auth        map[string]model.AuthSession
	login       map[string]model.LoginState
	nonces      map[string]string
	sessions    map[string]string
	csrf        map[string]csrfToken
	tokens      map[string]model.VerifiedToken
	issued      map[string]model.IssuedToken
}

type csrfToken struct {
	SessionID string
	ExpiresAt int64
	Consumed  bool
}

func New() *Store {
	return &Store{
		users:       map[string]model.User{},
		identities:  map[string]model.ExternalIdentity{},
		invitations: map[string]model.IdentityInvitation{},
		groups:      map[string][]string{},
		resources:   map[string]model.Resource{},
		grants:      map[string]map[string]string{},
		auth:        map[string]model.AuthSession{},
		login:       map[string]model.LoginState{},
		nonces:      map[string]string{},
		sessions:    map[string]string{},
		csrf:        map[string]csrfToken{},
		tokens:      map[string]model.VerifiedToken{},
		issued:      map[string]model.IssuedToken{},
	}
}

func (s *Store) AddTestUser(u model.User) model.User {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u.ID == "" {
		u.ID = uuid.NewString()
	}
	if u.Status == "" {
		u.Status = "active"
	}
	s.users[u.ID] = u
	return u
}

func (s *Store) AddTestExternalIdentity(identity model.ExternalIdentity) model.ExternalIdentity {
	s.mu.Lock()
	defer s.mu.Unlock()
	if identity.ID == "" {
		identity.ID = uuid.NewString()
	}
	if identity.SubjectStrategy == "" {
		identity.SubjectStrategy = "oidc_sub"
	}
	if identity.Status == "" {
		identity.Status = "active"
	}
	s.identities[externalIdentityKey(identity.ProviderID, identity.Issuer, identity.Subject)] = identity
	return identity
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

func (s *Store) ResolveLogin(ctx context.Context, req model.LoginResolutionRequest) (model.TokenPrincipal, model.LoginBindingResult, error) {
	identity := req.Identity
	s.mu.Lock()
	defer s.mu.Unlock()
	key := externalIdentityKey(identity.ProviderID, identity.Issuer, identity.Subject)
	if existing, ok := s.identities[key]; ok && existing.Status == "active" {
		user, ok := s.users[existing.UserID]
		if !ok {
			return model.TokenPrincipal{}, model.LoginBindingResult{}, model.ErrNotFound
		}
		if user.Status != "active" {
			return model.TokenPrincipal{}, model.LoginBindingResult{}, fmt.Errorf("%w: user is not active", model.ErrPermissionDenied)
		}
		return tokenPrincipalFromMemoryUser(user, identity.ProviderID, s.groups[user.ID]), model.LoginBindingResult{Status: "existing", ExternalIdentityID: existing.ID}, nil
	}
	if identity.EmailVerified && strings.TrimSpace(identity.Email) != "" && memoryAllowsVerifiedEmailInvitationBinding(req.Policy) && memoryEmailDomainAllowed(identity.Email, req.Policy.AllowedEmailDomains) {
		now := time.Now().Unix()
		for id, invitation := range s.invitations {
			if invitation.ProviderID != identity.ProviderID || invitation.Issuer != identity.Issuer || invitation.Status != "pending" {
				continue
			}
			if invitation.ExpiresAt != 0 && invitation.ExpiresAt <= now {
				continue
			}
			if strings.TrimSpace(invitation.BindingPolicy) != model.LoginEmailBindingVerifiedEmailInvitation {
				continue
			}
			if !strings.EqualFold(strings.TrimSpace(invitation.Email), strings.TrimSpace(identity.Email)) {
				continue
			}
			user, ok := s.users[invitation.UserID]
			if !ok {
				return model.TokenPrincipal{}, model.LoginBindingResult{}, model.ErrNotFound
			}
			external := identity
			external.ID = uuid.NewString()
			external.UserID = user.ID
			if external.SubjectStrategy == "" {
				external.SubjectStrategy = "oidc_sub"
			}
			external.Status = "active"
			s.identities[key] = external
			invitation.Status = "accepted"
			invitation.AcceptedIdentityID = external.ID
			s.invitations[id] = invitation
			user.Email = identity.Email
			user.DisplayName = identity.DisplayName
			user.Status = "active"
			s.users[user.ID] = user
			return tokenPrincipalFromMemoryUser(user, identity.ProviderID, s.groups[user.ID]), model.LoginBindingResult{Status: "bound_invitation", ExternalIdentityID: external.ID, InvitationID: invitation.ID}, nil
		}
	}
	return model.TokenPrincipal{}, model.LoginBindingResult{}, model.ErrNotFound
}

func memoryAllowsVerifiedEmailInvitationBinding(policy model.LoginTrustPolicy) bool {
	return strings.TrimSpace(policy.EmailBinding) == model.LoginEmailBindingVerifiedEmailInvitation
}

func memoryEmailDomainAllowed(email string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	domain := memoryEmailDomain(email)
	if domain == "" {
		return false
	}
	for _, allowedDomain := range allowed {
		if strings.EqualFold(strings.TrimSpace(allowedDomain), domain) {
			return true
		}
	}
	return false
}

func memoryEmailDomain(email string) string {
	email = strings.ToLower(strings.TrimSpace(email))
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return ""
	}
	return email[at+1:]
}

func (s *Store) PrincipalByUserID(ctx context.Context, userID string) (model.TokenPrincipal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[userID]
	if !ok {
		return model.TokenPrincipal{}, model.ErrNotFound
	}
	if user.Status != "active" {
		return model.TokenPrincipal{}, model.ErrPermissionDenied
	}
	return tokenPrincipalFromMemoryUser(user, "bridge", s.groups[user.ID]), nil
}

func (s *Store) PrincipalByAuthnTokenJTI(ctx context.Context, jti string) (model.TokenPrincipal, error) {
	user, err := s.FindActiveAuthnTokenUser(ctx, jti)
	if err != nil {
		return model.TokenPrincipal{}, err
	}
	s.mu.Lock()
	groups := append([]string(nil), s.groups[user.ID]...)
	s.mu.Unlock()
	return tokenPrincipalFromMemoryUser(user, "bridge", groups), nil
}

func tokenPrincipalFromMemoryUser(user model.User, tokenIDP string, groups []string) model.TokenPrincipal {
	return model.TokenPrincipal{
		UserID:            user.ID,
		TokenSubject:      user.BridgeSubject(),
		TokenIDP:          tokenIDP,
		DisplayName:       user.Display(),
		PreferredUsername: user.PreferredUsername(),
		Groups:            append([]string(nil), groups...),
	}
}

func externalIdentityKey(providerID, issuer, subject string) string {
	return strings.Join([]string{providerID, issuer, subject}, "\x00")
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
	id := uuid.NewString()
	user := model.User{ID: id, Email: strings.TrimSpace(input.Email), DisplayName: input.DisplayName, Status: "active"}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[user.ID] = user
	return user, nil
}

func (s *Store) AddInvitation(ctx context.Context, input model.AddInvitationInput) (model.User, model.IdentityInvitation, error) {
	if strings.TrimSpace(input.ProviderID) == "" || strings.TrimSpace(input.Issuer) == "" || strings.TrimSpace(input.Email) == "" {
		return model.User{}, model.IdentityInvitation{}, model.ErrInvalidArgument
	}
	userID := uuid.NewString()
	user := model.User{ID: userID, Email: strings.TrimSpace(input.Email), DisplayName: input.DisplayName, Status: "pending"}
	bindingPolicy := strings.TrimSpace(input.BindingPolicy)
	if bindingPolicy == "" {
		bindingPolicy = "verified_email_invitation"
	}
	invitation := model.IdentityInvitation{ID: uuid.NewString(), UserID: user.ID, ProviderID: input.ProviderID, Issuer: input.Issuer, Email: input.Email, BindingPolicy: bindingPolicy, Status: "pending", ExpiresAt: input.ExpiresAt}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[user.ID] = user
	s.invitations[invitation.ID] = invitation
	return user, invitation, nil
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

func (s *Store) CreateLoginState(ctx context.Context, input model.LoginStateInput, ttl time.Duration) (string, model.LoginState, error) {
	state := uuid.NewString()
	loginState := model.LoginState{ID: uuid.NewString(), ProviderID: input.ProviderID, Nonce: input.Nonce, LoginURLNonce: input.LoginURLNonce, ReturnPath: input.ReturnPath, PrivateState: append([]byte(nil), input.PrivateState...), ExpiresAt: time.Now().Add(ttl).Unix()}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.login[hashAuthCode(state)] = loginState
	return state, loginState, nil
}

func (s *Store) SetLoginStatePrivateState(ctx context.Context, state string, privateState []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hashAuthCode(state)
	loginState, ok := s.login[key]
	if !ok || loginState.ExpiresAt <= time.Now().Unix() {
		return model.ErrNotFound
	}
	loginState.PrivateState = append([]byte(nil), privateState...)
	s.login[key] = loginState
	return nil
}

func (s *Store) ConsumeLoginState(ctx context.Context, state string) (model.LoginState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hashAuthCode(state)
	loginState, ok := s.login[key]
	if !ok || loginState.ExpiresAt <= time.Now().Unix() {
		return model.LoginState{}, model.ErrNotFound
	}
	delete(s.login, key)
	return loginState, nil
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
	if input.JTI == "" {
		input.JTI = uuid.NewString()
	}
	token := "authn:" + input.Subject + ":" + uuid.NewString()
	now := input.Now.UTC()
	if now.IsZero() {
		now = time.Now()
	}
	expires := now.Add(input.TTL).Unix()
	if input.TTL == 0 {
		expires = now.Add(time.Hour).Unix()
	}
	s.mu.Lock()
	s.tokens[token] = model.VerifiedToken{Subject: input.Subject, JTI: input.JTI, IDP: input.IDP, ExpiresAt: expires, Audience: append([]string(nil), input.Audience...)}
	s.mu.Unlock()
	return model.SignedToken{Token: token, JTI: input.JTI, Kid: "memory", IssuedAt: now.Unix(), ExpiresAt: expires, Audience: input.Audience}, nil
}

func (s *Store) SignAuthz(ctx context.Context, input model.AuthzTokenInput) (model.SignedToken, error) {
	if input.JTI == "" {
		input.JTI = uuid.NewString()
	}
	token := "authz:" + input.Subject + ":" + uuid.NewString()
	now := input.Now.UTC()
	if now.IsZero() {
		now = time.Now()
	}
	expires := now.Add(input.TTL).Unix()
	if input.TTL == 0 {
		expires = now.Add(15 * time.Minute).Unix()
	}
	firstResource := ""
	permissions := []string(nil)
	if len(input.Resources) > 0 {
		firstResource = input.Resources[0].ResourceID
		permissions = input.Resources[0].Permission
	}
	return model.SignedToken{Token: token, JTI: input.JTI, Kid: "memory", LoreResourceID: firstResource, IssuedAt: now.Unix(), ExpiresAt: expires, Permissions: permissions, Audience: input.Audience}, nil
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

func (s *Store) Record(ctx context.Context, token model.IssuedToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.issued[token.JTI] = token
	return nil
}

func (s *Store) FindActiveAuthnTokenUser(ctx context.Context, jti string) (model.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, ok := s.issued[jti]
	if !ok || token.Kind != "authn" || token.ExpiresAt <= time.Now().Unix() || token.UserID == "" {
		return model.User{}, model.ErrNotFound
	}
	user, ok := s.users[token.UserID]
	if !ok || user.Status != "active" {
		return model.User{}, model.ErrNotFound
	}
	return user, nil
}
