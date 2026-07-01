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
	PublicBaseURL  string
	SessionTTL     time.Duration
	AuthSessionTTL time.Duration
}

type LoginService struct {
	cfg    LoginConfig
	idps   ports.IdentityProviderRegistry
	users  ports.AccountDirectory
	state  ports.StateStore
	tokens *TokenService
}

func NewLoginService(cfg LoginConfig, idps ports.IdentityProviderRegistry, users ports.AccountDirectory, state ports.StateStore, tokens *TokenService) *LoginService {
	return &LoginService{cfg: cfg, idps: idps, users: users, state: state, tokens: tokens}
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
	Identity       model.ExternalIdentity
	User           model.User
	BrowserSession model.BrowserSession
	UnknownUser    bool
	CLIComplete    bool
}

func (s *LoginService) AuthCodeURL(state string) (string, error) {
	res, err := s.BeginAuth(context.Background(), "", ports.BeginAuthRequest{State: state})
	if err != nil {
		return "", err
	}
	return res.RedirectURL, nil
}

func (s *LoginService) BeginAuth(ctx context.Context, providerID string, req ports.BeginAuthRequest) (ports.BeginAuthResult, error) {
	provider, _, err := s.identityProvider(providerID)
	if err != nil {
		return ports.BeginAuthResult{}, err
	}
	return provider.BeginAuth(ctx, req)
}

func (s *LoginService) Providers() []ports.IdentityProviderDescriptor {
	if s.idps == nil {
		return nil
	}
	return s.idps.List()
}

func (s *LoginService) DefaultProviderID() string {
	if s.idps == nil {
		return ""
	}
	return s.idps.DefaultID()
}

func (s *LoginService) HasProvider(providerID string) bool {
	if s.idps == nil {
		return false
	}
	if providerID == "" {
		providerID = s.idps.DefaultID()
	}
	if providerID == "" {
		return false
	}
	_, ok := s.idps.Get(providerID)
	return ok
}

func (s *LoginService) StartAuthSession(ctx context.Context, clientState string) (StartAuthSessionResult, error) {
	ttl := s.cfg.AuthSessionTTL
	if ttl == 0 {
		ttl = s.cfg.SessionTTL
	}
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
	if sess.ExpiresAt <= time.Now().Unix() {
		return AuthSessionTokenResult{}, fmt.Errorf("%w: expired", model.ErrAuthSessionNotFound)
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
	return s.CompleteAuth(ctx, "", ports.CompleteAuthRequest{Code: code}, loginNonce)
}

func (s *LoginService) CompleteAuth(ctx context.Context, providerID string, req ports.CompleteAuthRequest, loginNonce string) (OAuthCallbackResult, error) {
	provider, descriptor, err := s.identityProvider(providerID)
	if err != nil {
		return OAuthCallbackResult{}, err
	}
	identity, err := provider.CompleteAuth(ctx, req)
	if err != nil {
		return OAuthCallbackResult{}, fmt.Errorf("%w: oauth identity exchange: %w", model.ErrUnauthenticated, err)
	}
	if identity.ProviderID == "" {
		identity.ProviderID = descriptor.ID
	}
	if identity.ProviderID != descriptor.ID {
		return OAuthCallbackResult{}, fmt.Errorf("%w: identity provider mismatch", model.ErrUnauthenticated)
	}
	if identity.Issuer == "" {
		identity.Issuer = descriptor.Issuer
	}
	if descriptor.Issuer != "" && identity.Issuer != descriptor.Issuer {
		return OAuthCallbackResult{}, fmt.Errorf("%w: identity issuer mismatch", model.ErrUnauthenticated)
	}
	principal, _, err := s.users.ResolveLogin(ctx, model.LoginResolutionRequest{
		Identity: identity,
		Policy:   descriptor.TrustPolicy,
	})
	if errors.Is(err, model.ErrNotFound) {
		return OAuthCallbackResult{Identity: identity, UnknownUser: true}, nil
	}
	if err != nil {
		return OAuthCallbackResult{}, err
	}
	user := userFromPrincipal(principal)
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

func userFromPrincipal(principal model.TokenPrincipal) model.User {
	return model.User{
		ID:          principal.UserID,
		Email:       principal.PreferredUsername,
		DisplayName: principal.DisplayName,
		Status:      "active",
	}
}

func (s *LoginService) identityProvider(providerID string) (ports.IdentityProvider, ports.IdentityProviderDescriptor, error) {
	if s.idps == nil {
		return nil, ports.IdentityProviderDescriptor{}, model.ErrUnsupported
	}
	if providerID == "" {
		providerID = s.idps.DefaultID()
	}
	if providerID == "" {
		return nil, ports.IdentityProviderDescriptor{}, model.ErrUnsupported
	}
	provider, ok := s.idps.Get(providerID)
	if !ok {
		return nil, ports.IdentityProviderDescriptor{}, model.ErrNotFound
	}
	descriptor := provider.Descriptor()
	if descriptor.ID == "" {
		descriptor.ID = providerID
	}
	return provider, descriptor, nil
}
