package grpcauth

import (
	"context"
	"net"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	pb "github.com/yamahigashi/lore-auth-bridge/internal/loreproto/epicurc"
	"github.com/yamahigashi/lore-auth-bridge/internal/ratelimit"
)

func UnaryRateLimitInterceptor() grpc.UnaryServerInterceptor {
	limiter := ratelimit.New(60, time.Minute)
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if info != nil && info.FullMethod == pb.UrcAuthApi_StartAuthSession_FullMethodName && !limiter.Allow(grpcPeerKey(ctx)) {
			return nil, status.Error(codes.ResourceExhausted, "rate limit exceeded")
		}
		return handler(ctx, req)
	}
}

func grpcPeerKey(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err == nil && host != "" {
		return host
	}
	return strings.TrimSpace(p.Addr.String())
}
