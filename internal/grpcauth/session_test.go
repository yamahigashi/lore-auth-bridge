package grpcauth

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/yamahigashi/lore-auth-bridge/internal/adapter/memory"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/service"
	pb "github.com/yamahigashi/lore-auth-bridge/internal/loreproto/epicurc"
)

func TestStartAndGetAuthSession(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	srv, mem, _ := newTestServer()
	u := addAlice(mem)

	start, err := srv.StartAuthSession(ctx, &pb.StartAuthSessionRequest{ClientState: "client-state"})
	if err != nil {
		t.Fatal(err)
	}
	if start.GetSessionCode() == "" || start.GetLoginUrl() == "" {
		t.Fatalf("bad start: %#v", start)
	}
	pending, err := srv.GetAuthSession(ctx, &pb.GetAuthSessionRequest{SessionCode: start.GetSessionCode(), ClientState: "client-state"})
	if err != nil {
		t.Fatal(err)
	}
	if pending.GetUserToken() != nil {
		t.Fatal("expected pending response without token")
	}
	sess, err := mem.GetAuthSessionByCode(ctx, start.GetSessionCode())
	if err != nil {
		t.Fatal(err)
	}
	if err := mem.CompleteAuthSession(ctx, sess.ID, u.ID); err != nil {
		t.Fatal(err)
	}
	complete, err := srv.GetAuthSession(ctx, &pb.GetAuthSessionRequest{SessionCode: start.GetSessionCode(), ClientState: "client-state"})
	if err != nil {
		t.Fatal(err)
	}
	if complete.GetUserToken().GetUserToken() == "" {
		t.Fatal("missing authn token")
	}
}

func TestGetAuthSessionTokenIssueFailureIsInternal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	mem := memory.New()
	u := addAlice(mem)
	tokenSvc := service.NewTokenService(service.TokenConfig{
		Issuer:              "https://auth.example.com",
		Audience:            []string{"lore-service", "lore.example.com"},
		AuthServiceAudience: "auth.example.com",
		AuthnTTL:            time.Hour,
		AuthzTTL:            15 * time.Minute,
	}, mem, mem, mem, failingSigner{authnErr: model.ErrNotFound}, mem, mem)
	loginSvc := service.NewLoginService(service.LoginConfig{PublicBaseURL: "https://auth.example.com", SessionTTL: 10 * time.Minute}, nil, mem, mem, tokenSvc)
	srv := New(Services{Login: loginSvc, Tokens: tokenSvc, Permissions: service.NewPermissionService(mem, mem)})

	start, err := srv.StartAuthSession(ctx, &pb.StartAuthSessionRequest{ClientState: "client-state"})
	if err != nil {
		t.Fatal(err)
	}
	sess, err := mem.GetAuthSessionByCode(ctx, start.GetSessionCode())
	if err != nil {
		t.Fatal(err)
	}
	if err := mem.CompleteAuthSession(ctx, sess.ID, u.ID); err != nil {
		t.Fatal(err)
	}

	_, err = srv.GetAuthSession(ctx, &pb.GetAuthSessionRequest{SessionCode: start.GetSessionCode(), ClientState: "client-state"})
	if status.Code(err) != codes.Internal {
		t.Fatalf("status.Code = %s, want %s (err=%v)", status.Code(err), codes.Internal, err)
	}
	if errors.Is(err, model.ErrNotFound) {
		t.Fatalf("gRPC status should not expose ErrNotFound for token issue failure: %v", err)
	}
}

type failingSigner struct {
	authnErr error
	authzErr error
}

func (s failingSigner) SignAuthn(ctx context.Context, input model.AuthnTokenInput) (model.SignedToken, error) {
	if s.authnErr != nil {
		return model.SignedToken{}, s.authnErr
	}
	return model.SignedToken{Token: "authn-token", JTI: "jti", Kid: "test", IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix(), Audience: input.Audience}, nil
}

func (s failingSigner) SignAuthz(ctx context.Context, input model.AuthzTokenInput) (model.SignedToken, error) {
	if s.authzErr != nil {
		return model.SignedToken{}, s.authzErr
	}
	return model.SignedToken{Token: "authz-token", JTI: "jti", Kid: "test", IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix(), Audience: input.Audience}, nil
}

func (s failingSigner) Verify(ctx context.Context, compact string, opts model.VerifyOptions) (model.VerifiedToken, error) {
	return model.VerifiedToken{}, model.ErrUnauthenticated
}

func (s failingSigner) JWKS(ctx context.Context) (json.RawMessage, error) {
	return json.RawMessage(`{"keys":[]}`), nil
}
