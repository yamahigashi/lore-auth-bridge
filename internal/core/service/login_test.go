package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/ports"
)

func TestGetAuthSessionClientStateMismatchReturnsInvalidArgument(t *testing.T) {
	t.Parallel()
	state := &loginStateStub{
		session: model.AuthSession{ID: "session-1", ClientStateHash: "expected", Status: "completed", UserID: "user-1", ExpiresAt: time.Now().Add(time.Minute).Unix()},
	}
	svc := NewLoginService(LoginConfig{}, nil, nil, state, nil)

	_, err := svc.GetAuthSession(context.Background(), "session-code", "wrong-client-state")
	if !errors.Is(err, model.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
}

func TestBeginAuthUsesRequestedProvider(t *testing.T) {
	t.Parallel()
	idps := loginRegistryStub{
		defaultID: "google",
		providers: map[string]loginIDPStub{
			"google":        {descriptor: ports.IdentityProviderDescriptor{ID: "google", Issuer: "https://accounts.google.com"}, authURL: "https://google.example/auth"},
			"keycloak-prod": {descriptor: ports.IdentityProviderDescriptor{ID: "keycloak-prod", Issuer: "https://sso.example.com/realms/prod"}, authURL: "https://sso.example.com/auth"},
		},
	}
	svc := NewLoginService(LoginConfig{}, idps, nil, nil, nil)

	res, err := svc.BeginAuth(context.Background(), "keycloak-prod", ports.BeginAuthRequest{State: "state-1", Nonce: "nonce-1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.RedirectURL != "https://sso.example.com/auth?state=state-1&nonce=nonce-1" {
		t.Fatalf("redirect URL = %q", res.RedirectURL)
	}
}

func TestCompleteAuthRejectsIdentityProviderMismatch(t *testing.T) {
	t.Parallel()
	idps := loginRegistryStub{defaultID: "google", providers: map[string]loginIDPStub{
		"google": {descriptor: ports.IdentityProviderDescriptor{ID: "google", Issuer: "https://accounts.google.com"}, id: model.ExternalIdentity{
			ProviderID: "keycloak-prod",
			Issuer:     "https://accounts.google.com",
			Subject:    "subject-1",
		}},
	}}
	svc := NewLoginService(LoginConfig{}, idps, &preRegistrationUsersStub{}, &callbackStateStub{}, nil)

	_, err := svc.CompleteAuth(context.Background(), "google", ports.CompleteAuthRequest{}, "")
	if !errors.Is(err, model.ErrUnauthenticated) {
		t.Fatalf("CompleteAuth error = %v, want ErrUnauthenticated", err)
	}
}

func TestCompleteAuthRejectsIdentityIssuerMismatch(t *testing.T) {
	t.Parallel()
	idps := loginRegistryStub{defaultID: "google", providers: map[string]loginIDPStub{
		"google": {descriptor: ports.IdentityProviderDescriptor{ID: "google", Issuer: "https://accounts.google.com"}, id: model.ExternalIdentity{
			ProviderID: "google",
			Issuer:     "https://evil.example.com",
			Subject:    "subject-1",
		}},
	}}
	svc := NewLoginService(LoginConfig{}, idps, &preRegistrationUsersStub{}, &callbackStateStub{}, nil)

	_, err := svc.CompleteAuth(context.Background(), "google", ports.CompleteAuthRequest{}, "")
	if !errors.Is(err, model.ErrUnauthenticated) {
		t.Fatalf("CompleteAuth error = %v, want ErrUnauthenticated", err)
	}
}

func TestCompleteOAuthCallbackBindsVerifiedEmailPreRegistration(t *testing.T) {
	t.Parallel()
	users := &preRegistrationUsersStub{
		pending: model.User{
			ID:     "user-1",
			Email:  "alice@example.com",
			Status: "pending",
		},
	}
	state := &callbackStateStub{}
	svc := NewLoginService(
		LoginConfig{SessionTTL: time.Hour},
		loginRegistryStub{defaultID: "google", providers: map[string]loginIDPStub{"google": {descriptor: ports.IdentityProviderDescriptor{
			ID:          "google",
			Issuer:      "https://accounts.google.com",
			TrustPolicy: model.LoginTrustPolicy{EmailBinding: "verified_email_invitation"},
		}, id: model.ExternalIdentity{
			Issuer:          "https://accounts.google.com",
			Subject:         "google-sub",
			SubjectStrategy: "oidc_sub",
			Email:           "Alice@Example.com",
			EmailVerified:   true,
			DisplayName:     "Alice",
		}}}},
		users,
		state,
		nil,
	)

	res, err := svc.CompleteOAuthCallback(context.Background(), "code", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.UnknownUser {
		t.Fatal("verified pending user should be activated, not shown as unknown")
	}
	if res.User.ID != "user-1" || res.User.Status != "active" {
		t.Fatalf("unexpected bound user: %#v", res.User)
	}
	if state.createdFor != "user-1" {
		t.Fatalf("browser session created for %q, want user-1", state.createdFor)
	}
}

func TestCompleteOAuthCallbackDoesNotBindUnverifiedEmail(t *testing.T) {
	t.Parallel()
	users := &preRegistrationUsersStub{
		pending: model.User{
			ID:     "user-1",
			Email:  "alice@example.com",
			Status: "pending",
		},
	}
	svc := NewLoginService(
		LoginConfig{SessionTTL: time.Hour},
		loginRegistryStub{defaultID: "google", providers: map[string]loginIDPStub{"google": {descriptor: ports.IdentityProviderDescriptor{ID: "google", Issuer: "https://accounts.google.com"}, id: model.ExternalIdentity{
			Issuer:          "https://accounts.google.com",
			Subject:         "google-sub",
			SubjectStrategy: "oidc_sub",
			Email:           "alice@example.com",
			EmailVerified:   false,
		}}}},
		users,
		&callbackStateStub{},
		nil,
	)

	res, err := svc.CompleteOAuthCallback(context.Background(), "code", "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.UnknownUser {
		t.Fatalf("unverified email should remain unknown: %#v", res)
	}
	if users.pending.Status != "pending" {
		t.Fatalf("pending user changed unexpectedly: %#v", users.pending)
	}
}

type loginStateStub struct {
	session model.AuthSession
	match   bool
}

func (s *loginStateStub) CreateAuthSession(ctx context.Context, clientState string, ttl time.Duration) (string, model.AuthSession, error) {
	panic("not used")
}

func (s *loginStateStub) GetAuthSessionByCode(ctx context.Context, code string) (model.AuthSession, error) {
	return s.session, nil
}

func (s *loginStateStub) GetAuthSessionByNonce(ctx context.Context, nonce string) (model.AuthSession, error) {
	panic("not used")
}

func (s *loginStateStub) CompleteAuthSession(ctx context.Context, id, userID string) error {
	panic("not used")
}

func (s *loginStateStub) ConsumeAuthSession(ctx context.Context, id string) error {
	panic("not used")
}

func (s *loginStateStub) CreateLoginState(ctx context.Context, input model.LoginStateInput, ttl time.Duration) (string, model.LoginState, error) {
	panic("not used")
}

func (s *loginStateStub) SetLoginStatePrivateState(ctx context.Context, state string, privateState []byte) error {
	panic("not used")
}

func (s *loginStateStub) ConsumeLoginState(ctx context.Context, state string) (model.LoginState, error) {
	panic("not used")
}

func (s *loginStateStub) CreateBrowserSession(ctx context.Context, userID string, ttl time.Duration) (model.BrowserSession, error) {
	panic("not used")
}

func (s *loginStateStub) UserByBrowserSession(ctx context.Context, sessionID string) (model.User, error) {
	panic("not used")
}

func (s *loginStateStub) RevokeBrowserSession(ctx context.Context, sessionID string) error {
	panic("not used")
}

func (s *loginStateStub) CreateCSRFToken(ctx context.Context, sessionID string, ttl time.Duration) (string, error) {
	panic("not used")
}

func (s *loginStateStub) ConsumeCSRFToken(ctx context.Context, sessionID, token string) error {
	panic("not used")
}

func (s *loginStateStub) MatchClientState(session model.AuthSession, clientState string) bool {
	return s.match
}

func TestGetAuthSessionExpiredCompletedSessionReturnsNotFound(t *testing.T) {
	t.Parallel()
	state := &loginStateStub{
		session: model.AuthSession{ID: "session-1", ClientStateHash: "expected", Status: "completed", UserID: "user-1", ExpiresAt: time.Now().Add(-time.Minute).Unix()},
		match:   true,
	}
	svc := NewLoginService(LoginConfig{}, nil, nil, state, nil)

	_, err := svc.GetAuthSession(context.Background(), "session-code", "client-state")
	if !errors.Is(err, model.ErrAuthSessionNotFound) {
		t.Fatalf("expected ErrAuthSessionNotFound, got %v", err)
	}
}

type loginIDPStub struct {
	descriptor ports.IdentityProviderDescriptor
	authURL    string
	id         model.ExternalIdentity
}

func (s loginIDPStub) Descriptor() ports.IdentityProviderDescriptor {
	return s.descriptor
}

func (s loginIDPStub) BeginAuth(ctx context.Context, req ports.BeginAuthRequest) (ports.BeginAuthResult, error) {
	return ports.BeginAuthResult{RedirectURL: s.authURL + "?state=" + req.State + "&nonce=" + req.Nonce}, nil
}

func (s loginIDPStub) CompleteAuth(ctx context.Context, req ports.CompleteAuthRequest) (model.ExternalIdentity, error) {
	return s.id, nil
}

type loginRegistryStub struct {
	defaultID string
	providers map[string]loginIDPStub
}

func (s loginRegistryStub) Get(id string) (ports.IdentityProvider, bool) {
	provider, ok := s.providers[id]
	return provider, ok
}

func (s loginRegistryStub) DefaultID() string { return s.defaultID }

func (s loginRegistryStub) List() []ports.IdentityProviderDescriptor {
	out := make([]ports.IdentityProviderDescriptor, 0, len(s.providers))
	for _, provider := range s.providers {
		out = append(out, provider.Descriptor())
	}
	return out
}

type preRegistrationUsersStub struct {
	pending model.User
}

func (s *preRegistrationUsersStub) Resolve(ctx context.Context, emailOrID string) (model.User, error) {
	if s.pending.ID == emailOrID || s.pending.Email == emailOrID {
		return s.pending, nil
	}
	return model.User{}, model.ErrNotFound
}

func (s *preRegistrationUsersStub) FindByID(ctx context.Context, id string) (model.User, error) {
	return s.Resolve(ctx, id)
}

func (s *preRegistrationUsersStub) GroupNames(ctx context.Context, userID string) ([]string, error) {
	return nil, nil
}

func (s *preRegistrationUsersStub) AddUser(ctx context.Context, input model.AddUserInput) (model.User, error) {
	panic("not used")
}

func (s *preRegistrationUsersStub) ResolveLogin(ctx context.Context, req model.LoginResolutionRequest) (model.TokenPrincipal, model.LoginBindingResult, error) {
	identity := req.Identity
	if req.Policy.EmailBinding != "verified_email_invitation" {
		return model.TokenPrincipal{}, model.LoginBindingResult{}, model.ErrNotFound
	}
	if !identity.EmailVerified || s.pending.Email != "alice@example.com" {
		return model.TokenPrincipal{}, model.LoginBindingResult{}, model.ErrNotFound
	}
	s.pending.Email = identity.Email
	s.pending.DisplayName = identity.DisplayName
	s.pending.Status = "active"
	return model.TokenPrincipal{
		UserID:            s.pending.ID,
		TokenSubject:      "user:" + s.pending.ID,
		TokenIDP:          identity.ProviderID,
		DisplayName:       s.pending.DisplayName,
		PreferredUsername: s.pending.Email,
	}, model.LoginBindingResult{Status: "bound_invitation"}, nil
}

func (s *preRegistrationUsersStub) PrincipalByUserID(ctx context.Context, userID string) (model.TokenPrincipal, error) {
	if s.pending.ID != userID {
		return model.TokenPrincipal{}, model.ErrNotFound
	}
	return model.TokenPrincipal{UserID: s.pending.ID, TokenSubject: "user:" + s.pending.ID, PreferredUsername: s.pending.Email}, nil
}

func (s *preRegistrationUsersStub) PrincipalByAuthnTokenJTI(ctx context.Context, jti string) (model.TokenPrincipal, error) {
	panic("not used")
}

func (s *preRegistrationUsersStub) AddInvitation(ctx context.Context, input model.AddInvitationInput) (model.User, model.IdentityInvitation, error) {
	panic("not used")
}

func (s *preRegistrationUsersStub) ListUsers(ctx context.Context) ([]model.User, error) {
	return []model.User{s.pending}, nil
}

func (s *preRegistrationUsersStub) DisableUser(ctx context.Context, emailOrID string) error {
	panic("not used")
}

type callbackStateStub struct {
	createdFor string
}

func (s *callbackStateStub) CreateAuthSession(ctx context.Context, clientState string, ttl time.Duration) (string, model.AuthSession, error) {
	panic("not used")
}

func (s *callbackStateStub) GetAuthSessionByCode(ctx context.Context, code string) (model.AuthSession, error) {
	panic("not used")
}

func (s *callbackStateStub) GetAuthSessionByNonce(ctx context.Context, nonce string) (model.AuthSession, error) {
	panic("not used")
}

func (s *callbackStateStub) CompleteAuthSession(ctx context.Context, id, userID string) error {
	panic("not used")
}

func (s *callbackStateStub) ConsumeAuthSession(ctx context.Context, id string) error {
	panic("not used")
}

func (s *callbackStateStub) CreateLoginState(ctx context.Context, input model.LoginStateInput, ttl time.Duration) (string, model.LoginState, error) {
	panic("not used")
}

func (s *callbackStateStub) SetLoginStatePrivateState(ctx context.Context, state string, privateState []byte) error {
	panic("not used")
}

func (s *callbackStateStub) ConsumeLoginState(ctx context.Context, state string) (model.LoginState, error) {
	panic("not used")
}

func (s *callbackStateStub) CreateBrowserSession(ctx context.Context, userID string, ttl time.Duration) (model.BrowserSession, error) {
	s.createdFor = userID
	return model.BrowserSession{ID: "browser-session", UserID: userID, ExpiresAt: time.Now().Add(ttl).Unix()}, nil
}

func (s *callbackStateStub) UserByBrowserSession(ctx context.Context, sessionID string) (model.User, error) {
	panic("not used")
}

func (s *callbackStateStub) RevokeBrowserSession(ctx context.Context, sessionID string) error {
	panic("not used")
}

func (s *callbackStateStub) CreateCSRFToken(ctx context.Context, sessionID string, ttl time.Duration) (string, error) {
	panic("not used")
}

func (s *callbackStateStub) ConsumeCSRFToken(ctx context.Context, sessionID, token string) error {
	panic("not used")
}

func (s *callbackStateStub) MatchClientState(session model.AuthSession, clientState string) bool {
	panic("not used")
}
