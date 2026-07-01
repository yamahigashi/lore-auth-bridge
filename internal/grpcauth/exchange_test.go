package grpcauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/yamahigashi/lore-auth-bridge/internal/adapter/memory"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/service"
	pb "github.com/yamahigashi/lore-auth-bridge/internal/loreproto/epicurc"
)

func TestExchangeFlow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	srv, mem, tokenSvc := newTestServer()
	u := addAlice(mem)
	resource := addGameAssets(mem)
	mem.Grant(u.ID, resource.ResourceID)

	authn, _, err := tokenSvc.MintAuthn(ctx, u.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	mdCtx := metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "Bearer "+authn.Token))

	resp, err := srv.ExchangeUserTokenForMultiresourceToken(mdCtx, &pb.ExchangeUserTokenForMultiresourceTokenRequest{ResourceId: []string{resource.ResourceID}})
	if err != nil {
		t.Fatalf("exchange failed: %v", err)
	}
	if resp.GetToken().GetUserToken() == "" {
		t.Fatal("empty authz token")
	}

	secret := mem.AddTestResource(resourceWithID("secret", "urc-f6ca55437aa34198ba0f0fdc33154d51"))
	if _, err := srv.ExchangeUserTokenForMultiresourceToken(mdCtx, &pb.ExchangeUserTokenForMultiresourceTokenRequest{ResourceId: []string{secret.ResourceID}}); err == nil {
		t.Fatal("expected permission denied for ungranted repo")
	}

	lookup, err := srv.LookupUserPermissions(mdCtx, &pb.LookupUserPermissionsRequest{ResourceFilter: "urc"})
	if err != nil {
		t.Fatal(err)
	}
	if len(lookup.GetResourcePermission()) != 1 {
		t.Fatalf("unexpected lookup: %#v", lookup.GetResourcePermission())
	}
}

func TestExchangeAuthnTokenUsesJTIForNonGoogleSubject(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	srv, mem, tokenSvc := newTestServer()
	u := mem.AddTestUser(model.User{Email: "alice@example.com"})
	resource := addGameAssets(mem)
	mem.Grant(u.ID, resource.ResourceID)

	authn, _, err := tokenSvc.MintAuthn(ctx, u.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	mdCtx := metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "Bearer "+authn.Token))

	resp, err := srv.ExchangeUserTokenForMultiresourceToken(mdCtx, &pb.ExchangeUserTokenForMultiresourceTokenRequest{ResourceId: []string{resource.ResourceID}})
	if err != nil {
		t.Fatalf("exchange failed: %v", err)
	}
	if resp.GetToken().GetUserToken() == "" {
		t.Fatal("empty authz token")
	}
}

func TestExchangeRequiresBearer(t *testing.T) {
	t.Parallel()
	srv, _, _ := newTestServer()
	if _, err := srv.ExchangeUserTokenForMultiresourceToken(context.Background(), &pb.ExchangeUserTokenForMultiresourceTokenRequest{ResourceId: []string{"urc-x"}}); err == nil {
		t.Fatal("expected unauthenticated without bearer")
	}
}

func TestExchangeInternalTokenIssueFailureIsInternal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	mem := memory.New()
	u := addAlice(mem)
	resource := addGameAssets(mem)
	mem.Grant(u.ID, resource.ResourceID)

	authnSvc := service.NewTokenService(service.TokenConfig{
		Issuer:              "https://auth.example.com",
		Audience:            []string{"lore-service", "lore.example.com"},
		AuthServiceAudience: "auth.example.com",
		AuthnTTL:            time.Hour,
		AuthzTTL:            15 * time.Minute,
	}, mem, mem, mem, mem, mem)
	authn, _, err := authnSvc.MintAuthn(ctx, u.ID, 0)
	if err != nil {
		t.Fatal(err)
	}

	tokenSvc := service.NewTokenService(service.TokenConfig{
		Issuer:              "https://auth.example.com",
		Audience:            []string{"lore-service", "lore.example.com"},
		AuthServiceAudience: "auth.example.com",
		AuthnTTL:            time.Hour,
		AuthzTTL:            15 * time.Minute,
	}, mem, mem, mem, mem, failingTokenLog{})
	srv := New(Services{Login: nil, Tokens: tokenSvc, Permissions: service.NewPermissionService(mem, mem)})
	mdCtx := metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "Bearer "+authn.Token))

	_, err = srv.ExchangeUserTokenForMultiresourceToken(mdCtx, &pb.ExchangeUserTokenForMultiresourceTokenRequest{ResourceId: []string{resource.ResourceID}})
	if status.Code(err) != codes.Internal {
		t.Fatalf("status.Code = %s, want %s (err=%v)", status.Code(err), codes.Internal, err)
	}
}

type failingTokenLog struct{}

func (failingTokenLog) Record(ctx context.Context, token model.IssuedToken) error {
	return errors.New("record failed")
}

func resourceWithID(name, resourceID string) model.Resource {
	return model.Resource{Name: name, ResourceID: resourceID}
}
