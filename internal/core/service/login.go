package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/ports"
)

type LoginConfig struct {
	PublicBaseURL string
	SessionTTL    time.Duration
}

type LoginService struct {
	cfg    LoginConfig
	idp    ports.IdentityProvider
	users  ports.UserDirectory
	state  ports.StateStore
	tokens *TokenService
}

func NewLoginService(cfg LoginConfig, idp ports.IdentityProvider, users ports.UserDirectory, state ports.StateStore, tokens *TokenService) *LoginService {
	return &LoginService{cfg: cfg, idp: idp, users: users, state: state, tokens: tokens}
}

type StartAuthSessionResult struct {
	SessionCode string
	LoginURL    string
}

type AuthSessionTokenResult struct {
	Token model.SignedToken
	User  model.User
	Ready bool
}

type OAuthCallbackResult struct {
	Identity       model.Identity
	User           model.User
	BrowserSession model.BrowserSession
	UnknownUser    bool
	CLIComplete    bool
}

func (s *LoginService) AuthCodeURL(state string) (string, error) {
	if s.idp == nil {
		return "", model.ErrUnsupported
	}
	return s.idp.AuthCodeURL(state), nil
}

func (s *LoginService) StartAuthSession(ctx context.Context, clientState string) (StartAuthSessionResult, error) {
	ttl := s.cfg.SessionTTL
	if ttl == 0 {
		ttl = 10 * time.Minute
	}
	code, sess, err := s.state.CreateAuthSession(ctx, clientState, ttl)
	if err != nil {
		return StartAuthSessionResult{}, err
	}
	base := strings.TrimRight(s.cfg.PublicBaseURL, "/")
	return StartAuthSessionResult{SessionCode: code, LoginURL: base + "/login/session/" + sess.LoginURLNonce}, nil
}

func (s *LoginService) GetAuthSession(ctx context.Context, sessionCode, clientState string) (AuthSessionTokenResult, error) {
	sess, err := s.state.GetAuthSessionByCode(ctx, sessionCode)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return AuthSessionTokenResult{}, fmt.Errorf("%w: %w", model.ErrAuthSessionNotFound, err)
		}
		return AuthSessionTokenResult{}, err
	}
	if !s.state.MatchClientState(sess, clientState) {
		return AuthSessionTokenResult{}, fmt.Errorf("%w: client_state mismatch", model.ErrInvalidArgument)
	}
	if sess.Status != "completed" || sess.UserID == "" {
		return AuthSessionTokenResult{}, nil
	}
	token, user, err := s.tokens.MintAuthn(ctx, sess.UserID, 0)
	if err != nil {
		return AuthSessionTokenResult{}, err
	}
	if err := s.state.ConsumeAuthSession(ctx, sess.ID); err != nil {
		return AuthSessionTokenResult{}, err
	}
	return AuthSessionTokenResult{Token: token, User: user, Ready: true}, nil
}

func (s *LoginService) CompleteOAuthCallback(ctx context.Context, code, loginNonce string) (OAuthCallbackResult, error) {
	if s.idp == nil {
		return OAuthCallbackResult{}, model.ErrUnsupported
	}
	identity, err := s.idp.ExchangeAndVerify(ctx, code)
	if err != nil {
		return OAuthCallbackResult{}, fmt.Errorf("%w: oauth identity exchange: %w", model.ErrUnauthenticated, err)
	}
	if identity.Provider == "" {
		identity.Provider = "google"
	}
	user, err := s.users.FindByIdentity(ctx, identity.Provider, identity.Issuer, identity.Subject)
	if errors.Is(err, model.ErrNotFound) {
		user, err = s.users.BindPreRegisteredIdentity(ctx, identity)
		if errors.Is(err, model.ErrNotFound) {
			return OAuthCallbackResult{Identity: identity, UnknownUser: true}, nil
		}
	}
	if err != nil {
		return OAuthCallbackResult{}, err
	}
	if user.Status != "active" {
		return OAuthCallbackResult{}, fmt.Errorf("%w: user disabled", model.ErrPermissionDenied)
	}
	if loginNonce != "" {
		authSession, err := s.state.GetAuthSessionByNonce(ctx, loginNonce)
		if err == nil {
			if err := s.state.CompleteAuthSession(ctx, authSession.ID, user.ID); err != nil {
				return OAuthCallbackResult{}, err
			}
			return OAuthCallbackResult{Identity: identity, User: user, CLIComplete: true}, nil
		}
		if !errors.Is(err, model.ErrNotFound) {
			return OAuthCallbackResult{}, err
		}
	}
	ttl := s.cfg.SessionTTL
	if ttl == 0 {
		ttl = time.Hour
	}
	session, err := s.state.CreateBrowserSession(ctx, user.ID, ttl)
	if err != nil {
		return OAuthCallbackResult{}, err
	}
	return OAuthCallbackResult{Identity: identity, User: user, BrowserSession: session}, nil
}
