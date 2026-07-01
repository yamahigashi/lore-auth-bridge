package grpcauth

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	pb "github.com/yamahigashi/lore-auth-bridge/internal/loreproto/epicurc"
)

func TestStartAuthSessionRateLimitReturnsResourceExhausted(t *testing.T) {
	t.Parallel()
	interceptor := UnaryRateLimitInterceptor()
	ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("203.0.113.20"), Port: 443}})

	var err error
	for i := 0; i < 65; i++ {
		_, err = interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: pb.UrcAuthApi_StartAuthSession_FullMethodName}, func(context.Context, any) (any, error) {
			return nil, nil
		})
	}
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("code = %s, want %s; err = %v", status.Code(err), codes.ResourceExhausted, err)
	}

	otherPeer := peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("203.0.113.21"), Port: 443}})
	_, err = interceptor(otherPeer, nil, &grpc.UnaryServerInfo{FullMethod: pb.UrcAuthApi_StartAuthSession_FullMethodName}, func(context.Context, any) (any, error) {
		return nil, nil
	})
	if err != nil {
		t.Fatalf("other peer should not share rate bucket: %v", err)
	}
}

func TestRateLimitDoesNotApplyToOtherAuthMethods(t *testing.T) {
	t.Parallel()
	interceptor := UnaryRateLimitInterceptor()
	ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("203.0.113.22"), Port: 443}})

	for i := 0; i < 65; i++ {
		if _, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: pb.UrcAuthApi_GetAuthSession_FullMethodName}, func(context.Context, any) (any, error) {
			return nil, nil
		}); err != nil {
			t.Fatalf("non-start method was rate limited: %v", err)
		}
	}
}
