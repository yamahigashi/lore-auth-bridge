package grpcauth

import (
	"time"

	"github.com/yamahigashi/lore-auth-bridge/internal/adapter/memory"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/service"
)

func newTestServer() (*Server, *memory.Store, *service.TokenService) {
	mem := memory.New()
	tokenSvc := service.NewTokenService(service.TokenConfig{
		Issuer:              "https://auth.example.com",
		Audience:            []string{"lore-service", "lore.example.com"},
		AuthServiceAudience: "auth.example.com",
		AuthnTTL:            time.Hour,
		AuthzTTL:            15 * time.Minute,
	}, mem, mem, mem, mem, mem, mem)
	loginSvc := service.NewLoginService(service.LoginConfig{PublicBaseURL: "https://auth.example.com", SessionTTL: 10 * time.Minute}, nil, mem, mem, tokenSvc)
	permissionSvc := service.NewPermissionService(mem, mem)
	return New(Services{Login: loginSvc, Tokens: tokenSvc, Permissions: permissionSvc}), mem, tokenSvc
}

func addAlice(mem *memory.Store) model.User {
	return mem.AddTestUser(model.User{Provider: "google", Issuer: "https://accounts.google.com", Subject: "sub", Email: "alice@example.com", DisplayName: "Alice"})
}

func addGameAssets(mem *memory.Store) model.Resource {
	return mem.AddTestResource(model.Resource{Name: "game-assets", LoreRepositoryID: "0194b726b34e72b0b45550b88a967076"})
}
