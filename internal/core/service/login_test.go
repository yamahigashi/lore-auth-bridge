package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
)

func TestGetAuthSessionClientStateMismatchReturnsInvalidArgument(t *testing.T) {
	t.Parallel()
	state := &loginStateStub{
		session: model.AuthSession{ID: "session-1", ClientStateHash: "expected", Status: "completed", UserID: "user-1"},
	}
	svc := NewLoginService(LoginConfig{}, nil, nil, state, nil)

	_, err := svc.GetAuthSession(context.Background(), "session-code", "wrong-client-state")
	if !errors.Is(err, model.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
}

func TestCompleteOAuthCallbackBindsVerifiedEmailPreRegistration(t *testing.T) {
	t.Parallel()
	users := &preRegistrationUsersStub{
		pending: model.User{
			ID:       "user-1",
			Provider: "google",
			Issuer:   "https://accounts.google.com",
			Email:    "alice@example.com",
			Status:   "pending",
		},
	}
	state := &callbackStateStub{}
	svc := NewLoginService(
		LoginConfig{SessionTTL: time.Hour},
		loginIDPStub{id: model.Identity{
			Provider:      "google",
			Issuer:        "https://accounts.google.com",
			Subject:       "google-sub",
			Email:         "Alice@Example.com",
			EmailVerified: true,
			Name:          "Alice",
		}},
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
	if res.User.ID != "user-1" || res.User.Subject != "google-sub" || res.User.Status != "active" {
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
			ID:       "user-1",
			Provider: "google",
			Issuer:   "https://accounts.google.com",
			Email:    "alice@example.com",
			Status:   "pending",
		},
	}
	svc := NewLoginService(
		LoginConfig{SessionTTL: time.Hour},
		loginIDPStub{id: model.Identity{
			Provider:      "google",
			Issuer:        "https://accounts.google.com",
			Subject:       "google-sub",
			Email:         "alice@example.com",
			EmailVerified: false,
		}},
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
	if users.pending.Status != "pending" || users.pending.Subject != "" {
		t.Fatalf("pending user changed unexpectedly: %#v", users.pending)
	}
}

type loginStateStub struct {
	session model.AuthSession
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

func (s *loginStateStub) CreateBrowserSession(ctx context.Context, userID string, ttl time.Duration) (model.BrowserSession, error) {
	panic("not used")
}

func (s *loginStateStub) UserByBrowserSession(ctx context.Context, sessionID string) (model.User, error) {
	panic("not used")
}

func (s *loginStateStub) RevokeBrowserSession(ctx context.Context, sessionID string) error {
	panic("not used")
}

func (s *loginStateStub) MatchClientState(session model.AuthSession, clientState string) bool {
	return false
}

type loginIDPStub struct {
	id model.Identity
}

func (s loginIDPStub) AuthCodeURL(state string) string {
	return "https://idp.example/auth?state=" + state
}

func (s loginIDPStub) ExchangeAndVerify(ctx context.Context, code string) (model.Identity, error) {
	return s.id, nil
}

func (s loginIDPStub) Issuer() string { return s.id.Issuer }

type preRegistrationUsersStub struct {
	pending model.User
}

func (s *preRegistrationUsersStub) FindByIdentity(ctx context.Context, provider, issuer, subject string) (model.User, error) {
	if s.pending.Provider == provider && s.pending.Issuer == issuer && s.pending.Subject == subject && s.pending.Status == "active" {
		return s.pending, nil
	}
	return model.User{}, model.ErrNotFound
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

func (s *preRegistrationUsersStub) AddPreRegisteredUser(ctx context.Context, input model.AddPreRegisteredUserInput) (model.User, error) {
	panic("not used")
}

func (s *preRegistrationUsersStub) BindPreRegisteredIdentity(ctx context.Context, identity model.Identity) (model.User, error) {
	if !identity.EmailVerified || s.pending.Email != "alice@example.com" {
		return model.User{}, model.ErrNotFound
	}
	s.pending.Subject = identity.Subject
	s.pending.Email = identity.Email
	s.pending.EmailVerified = identity.EmailVerified
	s.pending.DisplayName = identity.Name
	s.pending.PictureURL = identity.PictureURL
	s.pending.HostedDomain = identity.HostedDomain
	s.pending.Status = "active"
	return s.pending, nil
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

func (s *callbackStateStub) MatchClientState(session model.AuthSession, clientState string) bool {
	panic("not used")
}
