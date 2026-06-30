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
	users := pendingTokenUsersStub{user: model.User{ID: "user-1", Provider: "google", Issuer: "https://accounts.google.com", Subject: "pending:user-1", Email: "alice@example.com", Status: "pending"}}
	svc := NewTokenService(TokenConfig{Issuer: "https://auth.example.com", Audience: []string{"lore-service"}}, users, nil, nil, nil, nil, nil)

	_, err := svc.ManualMintAuthz(ctx, "alice@example.com", "game-assets", "writer", 0)
	if !errors.Is(err, model.ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
}

func TestVerifyAuthnResolvesUserByJTI(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	user := model.User{ID: "user-1", Provider: "keycloak-prod", Issuer: "https://sso.example.com/realms/prod", Subject: "subject:with:colon", Status: "active"}
	users := pendingTokenUsersStub{user: user}
	lookup := authnTokenLookupStub{jti: "jti-1", user: user}
	signer := staticVerifySigner{verified: model.VerifiedToken{Subject: "keycloak-prod:subject:with:colon", JTI: "jti-1", IDP: "keycloak-prod", Audience: []string{"auth.example.com"}, ExpiresAt: 4102444800}}
	svc := NewTokenService(TokenConfig{Issuer: "https://auth.example.com", AuthServiceAudience: "auth.example.com"}, users, nil, nil, signer, nil, lookup)

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

func TestVerifyAuthnRejectsMissingJTI(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	users := pendingTokenUsersStub{}
	signer := staticVerifySigner{verified: model.VerifiedToken{Subject: "google:sub", Audience: []string{"auth.example.com"}, ExpiresAt: 4102444800}}
	svc := NewTokenService(TokenConfig{Issuer: "https://auth.example.com", AuthServiceAudience: "auth.example.com"}, users, nil, nil, signer, nil, authnTokenLookupStub{})

	_, err := svc.VerifyAuthn(ctx, "Bearer authn-token")
	if !errors.Is(err, model.ErrUnauthenticated) {
		t.Fatalf("VerifyAuthn error = %v, want ErrUnauthenticated", err)
	}
}

type pendingTokenUsersStub struct {
	user model.User
}

func (s pendingTokenUsersStub) FindByIdentity(ctx context.Context, provider, issuer, subject string) (model.User, error) {
	panic("not used")
}

func (s pendingTokenUsersStub) BindPreRegisteredIdentity(ctx context.Context, identity model.Identity) (model.User, error) {
	panic("not used")
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

func (s pendingTokenUsersStub) AddPreRegisteredUser(ctx context.Context, input model.AddPreRegisteredUserInput) (model.User, error) {
	panic("not used")
}

func (s pendingTokenUsersStub) ListUsers(ctx context.Context) ([]model.User, error) {
	panic("not used")
}

func (s pendingTokenUsersStub) DisableUser(ctx context.Context, emailOrID string) error {
	panic("not used")
}

type authnTokenLookupStub struct {
	jti  string
	user model.User
	err  error
}

func (s authnTokenLookupStub) FindActiveAuthnTokenUser(ctx context.Context, jti string) (model.User, error) {
	if s.err != nil {
		return model.User{}, s.err
	}
	if jti == s.jti {
		return s.user, nil
	}
	return model.User{}, model.ErrNotFound
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
