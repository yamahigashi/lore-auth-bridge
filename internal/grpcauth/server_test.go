package grpcauth

import (
	"context"
	"testing"

	pb "github.com/yamahigashi/lore-auth-bridge/internal/loreproto/epicurc"
)

func TestHealthCheck(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	srv, _, _ := newTestServer()
	resp, err := srv.HealthCheck(ctx, &pb.HealthCheckRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetStatus() != "ok" {
		t.Fatalf("unexpected status: %s", resp.GetStatus())
	}
}
