package grpcrebac

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	pb "github.com/yamahigashi/lore-auth-bridge/internal/loreproto/ucsauth"
)

func TestPeerAllowlistRejectsRebacMethodFromDisallowedPeer(t *testing.T) {
	t.Parallel()
	prefixes, err := ParseAllowedPeerCIDRs([]string{"10.0.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	interceptor := UnaryPeerAllowlistInterceptor(prefixes)
	ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 443}})

	_, err = interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: pb.RebacApi_CreateResource_FullMethodName}, func(context.Context, any) (any, error) {
		t.Fatal("handler should not be called")
		return nil, nil
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %s, want %s; err = %v", status.Code(err), codes.PermissionDenied, err)
	}
}

func TestPeerAllowlistAllowsRebacMethodFromAllowedPeer(t *testing.T) {
	t.Parallel()
	prefixes, err := ParseAllowedPeerCIDRs([]string{"10.0.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	interceptor := UnaryPeerAllowlistInterceptor(prefixes)
	ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.42"), Port: 443}})

	called := false
	_, err = interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: pb.RebacApi_DeleteResource_FullMethodName}, func(context.Context, any) (any, error) {
		called = true
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("handler was not called")
	}
}

func TestPeerAllowlistDoesNotApplyToOtherServices(t *testing.T) {
	t.Parallel()
	prefixes, err := ParseAllowedPeerCIDRs([]string{"10.0.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	interceptor := UnaryPeerAllowlistInterceptor(prefixes)
	ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 443}})

	called := false
	_, err = interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/epic_urc.UrcAuthApi/StartAuthSession"}, func(context.Context, any) (any, error) {
		called = true
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("handler was not called")
	}
}
