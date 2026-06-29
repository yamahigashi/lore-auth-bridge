package grpcrebac

import (
	"context"
	"testing"

	"github.com/yamahigashi/lore-auth-bridge/internal/adapter/memory"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/service"
	pb "github.com/yamahigashi/lore-auth-bridge/internal/loreproto/ucsauth"
)

func TestCreateAndDeleteResource(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	mem := memory.New()
	srv := New(service.NewResourceService(mem))
	rid := "urc-0194b726b34e72b0b45550b88a967076"
	if _, err := srv.CreateResource(ctx, &pb.CreateResourceRequest{ResourceId: rid, ResourceName: "game-assets"}); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.CreateResource(ctx, &pb.CreateResourceRequest{ResourceId: rid, ResourceName: "game-assets"}); err != nil {
		t.Fatal(err)
	}
	repos, err := mem.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 1 || repos[0].LoreRepositoryID != "0194b726b34e72b0b45550b88a967076" {
		t.Fatalf("unexpected repos: %#v", repos)
	}
	if _, err := srv.DeleteResource(ctx, &pb.DeleteResourceRequest{ResourceId: rid}); err != nil {
		t.Fatal(err)
	}
}
