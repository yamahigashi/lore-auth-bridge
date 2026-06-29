package service

import (
	"context"
	"errors"
	"testing"

	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
)

func TestManualMintAuthzRejectsPendingUser(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	users := pendingTokenUsersStub{user: model.User{ID: "user-1", Provider: "google", Issuer: "https://accounts.google.com", Subject: "pending:user-1", Email: "alice@example.com", Status: "pending"}}
	svc := NewTokenService(TokenConfig{Issuer: "https://auth.example.com", Audience: []string{"lore-service"}}, users, nil, nil, nil, nil)

	_, err := svc.ManualMintAuthz(ctx, "alice@example.com", "game-assets", "writer", 0)
	if !errors.Is(err, model.ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
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
