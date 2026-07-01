package service

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
)

func TestManualMintAuthzRejectsPendingUser(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	users := pendingTokenUsersStub{user: model.User{ID: "user-1", Email: "alice@example.com", Status: "pending"}}
	svc := NewTokenService(TokenConfig{Issuer: "https://auth.example.com", Audience: []string{"lore-service"}}, users, nil, nil, nil, nil)

	_, err := svc.ManualMintAuthz(ctx, "user-1", "game-assets", "writer", 0)
	if !errors.Is(err, model.ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
}

func TestMintAuthnUsesPrincipalByUserIDWithoutHandleResolver(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	accounts := principalOnlyAccountsStub{principal: model.TokenPrincipal{
		UserID:            "user-1",
		TokenSubject:      "user:user-1",
		TokenIDP:          "bridge",
		DisplayName:       "Alice",
		PreferredUsername: "alice@example.com",
		Groups:            []string{"dev"},
	}}
	signer := &staticSignSigner{}
	svc := NewTokenService(TokenConfig{Issuer: "https://auth.example.com", Audience: []string{"lore-service"}}, accounts, nil, nil, signer, nil)

	signed, user, err := svc.MintAuthn(ctx, "user-1", 0)
	if err != nil {
		t.Fatalf("MintAuthn error = %v", err)
	}
	if signed.Token == "" {
		t.Fatal("MintAuthn returned empty token")
	}
	if user.ID != "user-1" {
		t.Fatalf("MintAuthn user ID = %q, want user-1", user.ID)
	}
	if signer.authnInput.Subject != "user:user-1" {
		t.Fatalf("authn subject = %q, want bridge principal subject", signer.authnInput.Subject)
	}
	if signer.authnInput.IDP != "bridge" {
		t.Fatalf("authn idp = %q, want bridge", signer.authnInput.IDP)
	}
}

func TestVerifyAuthnResolvesUserByJTI(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	user := model.User{ID: "user-1", Status: "active"}
	users := pendingTokenUsersStub{user: user, authnJTI: "jti-1"}
	signer := staticVerifySigner{verified: model.VerifiedToken{Subject: "keycloak-prod:subject:with:colon", JTI: "jti-1", IDP: "keycloak-prod", Audience: []string{"auth.example.com"}, ExpiresAt: 4102444800}}
	svc := NewTokenService(TokenConfig{Issuer: "https://auth.example.com", AuthServiceAudience: "auth.example.com"}, users, nil, nil, signer, nil)

	authn, err := svc.VerifyAuthn(ctx, "Bearer authn-token")
	if err != nil {
		t.Fatalf("VerifyAuthn error = %v", err)
	}
	if authn.User.ID != "user-1" {
		t.Fatalf("VerifyAuthn user ID = %q, want user-1", authn.User.ID)
	}
	if authn.Subject != "keycloak-prod:subject:with:colon" {
		t.Fatalf("VerifyAuthn subject = %q", authn.Subject)
	}
}

func TestVerifyAuthnPreservesSignedIDPOnPrincipal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	user := model.User{ID: "user-1", Status: "active"}
	users := pendingTokenUsersStub{user: user, authnJTI: "jti-1", authnPrincipalIDP: "bridge"}
	signer := staticVerifySigner{verified: model.VerifiedToken{Subject: "user:user-1", JTI: "jti-1", IDP: "keycloak-prod", Audience: []string{"auth.example.com"}, ExpiresAt: 4102444800}}
	svc := NewTokenService(TokenConfig{Issuer: "https://auth.example.com", AuthServiceAudience: "auth.example.com"}, users, nil, nil, signer, nil)

	authn, err := svc.VerifyAuthn(ctx, "Bearer authn-token")
	if err != nil {
		t.Fatalf("VerifyAuthn error = %v", err)
	}
	if authn.Principal.TokenIDP != "keycloak-prod" {
		t.Fatalf("principal token idp = %q, want signed authn token idp", authn.Principal.TokenIDP)
	}
}

func TestVerifyAuthnRejectsMissingJTI(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	users := pendingTokenUsersStub{}
	signer := staticVerifySigner{verified: model.VerifiedToken{Subject: "google:sub", Audience: []string{"auth.example.com"}, ExpiresAt: 4102444800}}
	svc := NewTokenService(TokenConfig{Issuer: "https://auth.example.com", AuthServiceAudience: "auth.example.com"}, users, nil, nil, signer, nil)

	_, err := svc.VerifyAuthn(ctx, "Bearer authn-token")
	if !errors.Is(err, model.ErrUnauthenticated) {
		t.Fatalf("VerifyAuthn error = %v, want ErrUnauthenticated", err)
	}
}

func TestExchangeAuthzRejectsLegacyUserOnlyAuthn(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc := NewTokenService(TokenConfig{Issuer: "https://auth.example.com", Audience: []string{"lore-service"}}, pendingTokenUsersStub{}, nil, nil, nil, nil)

	_, err := svc.ExchangeAuthz(ctx, model.VerifiedAuthn{Subject: "legacy-subject", User: model.User{ID: "user-1", Status: "active"}}, nil, 0)
	if !errors.Is(err, model.ErrUnauthenticated) {
		t.Fatalf("ExchangeAuthz error = %v, want ErrUnauthenticated", err)
	}
}

type pendingTokenUsersStub struct {
	user              model.User
	authnJTI          string
	authnPrincipalIDP string
}

func (s pendingTokenUsersStub) Resolve(ctx context.Context, emailOrID string) (model.User, error) {
	if s.user.ID == emailOrID || s.user.Email == emailOrID {
		return s.user, nil
	}
	return model.User{}, model.ErrNotFound
}

func (s pendingTokenUsersStub) FindByID(ctx context.Context, id string) (model.User, error) {
	return s.Resolve(ctx, id)
}

func (s pendingTokenUsersStub) GroupNames(ctx context.Context, userID string) ([]string, error) {
	panic("not used")
}

func (s pendingTokenUsersStub) AddUser(ctx context.Context, input model.AddUserInput) (model.User, error) {
	panic("not used")
}

func (s pendingTokenUsersStub) ResolveLogin(ctx context.Context, req model.LoginResolutionRequest) (model.TokenPrincipal, model.LoginBindingResult, error) {
	panic("not used")
}

func (s pendingTokenUsersStub) PrincipalByUserID(ctx context.Context, userID string) (model.TokenPrincipal, error) {
	if s.user.ID != userID {
		return model.TokenPrincipal{}, model.ErrNotFound
	}
	if s.user.Status != "active" {
		return model.TokenPrincipal{}, model.ErrPermissionDenied
	}
	return model.TokenPrincipal{
		UserID:            s.user.ID,
		TokenSubject:      s.user.BridgeSubject(),
		TokenIDP:          "bridge",
		DisplayName:       s.user.Display(),
		PreferredUsername: s.user.PreferredUsername(),
	}, nil
}

func (s pendingTokenUsersStub) PrincipalByAuthnTokenJTI(ctx context.Context, jti string) (model.TokenPrincipal, error) {
	if s.authnJTI == "" || s.authnJTI != jti {
		return model.TokenPrincipal{}, model.ErrNotFound
	}
	tokenIDP := s.authnPrincipalIDP
	if tokenIDP == "" {
		tokenIDP = "keycloak-prod"
	}
	return model.TokenPrincipal{
		UserID:            s.user.ID,
		TokenSubject:      s.user.BridgeSubject(),
		TokenIDP:          tokenIDP,
		DisplayName:       s.user.Display(),
		PreferredUsername: s.user.PreferredUsername(),
	}, nil
}

func (s pendingTokenUsersStub) AddInvitation(ctx context.Context, input model.AddInvitationInput) (model.User, model.IdentityInvitation, error) {
	panic("not used")
}

func (s pendingTokenUsersStub) ListUsers(ctx context.Context) ([]model.User, error) {
	panic("not used")
}

func (s pendingTokenUsersStub) DisableUser(ctx context.Context, emailOrID string) error {
	panic("not used")
}

type principalOnlyAccountsStub struct {
	principal model.TokenPrincipal
}

func (s principalOnlyAccountsStub) ResolveLogin(ctx context.Context, req model.LoginResolutionRequest) (model.TokenPrincipal, model.LoginBindingResult, error) {
	panic("not used")
}

func (s principalOnlyAccountsStub) PrincipalByUserID(ctx context.Context, userID string) (model.TokenPrincipal, error) {
	if s.principal.UserID != userID {
		return model.TokenPrincipal{}, model.ErrNotFound
	}
	return s.principal, nil
}

func (s principalOnlyAccountsStub) PrincipalByAuthnTokenJTI(ctx context.Context, jti string) (model.TokenPrincipal, error) {
	panic("not used")
}

func (s principalOnlyAccountsStub) AddUser(ctx context.Context, input model.AddUserInput) (model.User, error) {
	panic("not used")
}

func (s principalOnlyAccountsStub) AddInvitation(ctx context.Context, input model.AddInvitationInput) (model.User, model.IdentityInvitation, error) {
	panic("not used")
}

type staticVerifySigner struct {
	verified model.VerifiedToken
	err      error
}

func (s staticVerifySigner) SignAuthn(ctx context.Context, input model.AuthnTokenInput) (model.SignedToken, error) {
	panic("not used")
}

func (s staticVerifySigner) SignAuthz(ctx context.Context, input model.AuthzTokenInput) (model.SignedToken, error) {
	panic("not used")
}

func (s staticVerifySigner) Verify(ctx context.Context, compact string, opts model.VerifyOptions) (model.VerifiedToken, error) {
	if s.err != nil {
		return model.VerifiedToken{}, s.err
	}
	return s.verified, nil
}

func (s staticVerifySigner) JWKS(ctx context.Context) (json.RawMessage, error) {
	panic("not used")
}

type staticSignSigner struct {
	authnInput model.AuthnTokenInput
}

func (s *staticSignSigner) SignAuthn(ctx context.Context, input model.AuthnTokenInput) (model.SignedToken, error) {
	s.authnInput = input
	return model.SignedToken{Token: "authn-token", JTI: "jti-1", Audience: input.Audience}, nil
}

func (s *staticSignSigner) SignAuthz(ctx context.Context, input model.AuthzTokenInput) (model.SignedToken, error) {
	panic("not used")
}

func (s *staticSignSigner) Verify(ctx context.Context, compact string, opts model.VerifyOptions) (model.VerifiedToken, error) {
	panic("not used")
}

func (s *staticSignSigner) JWKS(ctx context.Context) (json.RawMessage, error) {
	panic("not used")
}
