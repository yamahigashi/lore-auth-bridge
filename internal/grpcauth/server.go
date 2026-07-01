// Package grpcauth implements epic_urc.UrcAuthApi, the gRPC service the Lore CLI
// uses for login, token exchange, and permission lookups.
package grpcauth

import (
	"context"
	"errors"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/service"
	pb "github.com/yamahigashi/lore-auth-bridge/internal/loreproto/epicurc"
)

type Server struct {
	pb.UnimplementedUrcAuthApiServer
	login       *service.LoginService
	tokens      *service.TokenService
	permissions *service.PermissionService
}

type Services struct {
	Login       *service.LoginService
	Tokens      *service.TokenService
	Permissions *service.PermissionService
}

func New(services Services) *Server {
	return &Server{login: services.Login, tokens: services.Tokens, permissions: services.Permissions}
}

func (s *Server) HealthCheck(ctx context.Context, _ *pb.HealthCheckRequest) (*pb.HealthCheckResponse, error) {
	return &pb.HealthCheckResponse{Status: "ok"}, nil
}

func (s *Server) StartAuthSession(ctx context.Context, req *pb.StartAuthSessionRequest) (*pb.StartAuthSessionResponse, error) {
	res, err := s.login.StartAuthSession(ctx, req.GetClientState())
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to start auth session")
	}
	return &pb.StartAuthSessionResponse{SessionCode: res.SessionCode, LoginUrl: res.LoginURL}, nil
}

func (s *Server) GetAuthSession(ctx context.Context, req *pb.GetAuthSessionRequest) (*pb.GetAuthSessionResponse, error) {
	res, err := s.login.GetAuthSession(ctx, req.GetSessionCode(), req.GetClientState())
	if err != nil {
		if errors.Is(err, model.ErrAuthSessionNotFound) {
			return nil, status.Error(codes.NotFound, "unknown session")
		}
		if errors.Is(err, model.ErrInvalidArgument) {
			return nil, status.Error(codes.InvalidArgument, "client_state mismatch")
		}
		slog.Error("get auth session failed", "error", err)
		return nil, status.Error(codes.Internal, "failed to get auth session")
	}
	if !res.Ready {
		return &pb.GetAuthSessionResponse{}, nil
	}
	return &pb.GetAuthSessionResponse{UserToken: &pb.UserToken{
		UserToken: res.Token.Token,
		ExpiresAt: res.Token.ExpiresAt,
		UserId:    res.User.BridgeSubject(),
		UserName:  res.User.Display(),
	}}, nil
}

func (s *Server) ExchangeUserTokenForMultiresourceToken(ctx context.Context, req *pb.ExchangeUserTokenForMultiresourceTokenRequest) (*pb.ExchangeUserTokenForMultiresourceTokenResponse, error) {
	authn, err := s.authnFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if len(req.GetResourceId()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "resource_id is required")
	}
	res, err := s.tokens.ExchangeAuthz(ctx, authn, req.GetResourceId(), 0)
	if err != nil {
		if errors.Is(err, model.ErrInvalidArgument) {
			return nil, status.Error(codes.InvalidArgument, "invalid token exchange request")
		}
		if errors.Is(err, model.ErrNotFound) || errors.Is(err, model.ErrPermissionDenied) {
			return nil, status.Error(codes.PermissionDenied, "resource not authorized")
		}
		slog.Error("exchange resource token failed", "resource_count", len(req.GetResourceId()), "error", err)
		return nil, status.Error(codes.Internal, "failed to issue resource token")
	}
	return &pb.ExchangeUserTokenForMultiresourceTokenResponse{Token: &pb.UserToken{
		UserToken: res.Token,
		ExpiresAt: res.ExpiresAt,
		UserId:    authn.User.BridgeSubject(),
		UserName:  authn.User.Display(),
	}}, nil
}

func (s *Server) CheckUserPermission(ctx context.Context, req *pb.CheckUserPermissionRequest) (*pb.CheckUserPermissionResponse, error) {
	user, err := s.resolveSubjectUser(ctx, req.GetTargetUser())
	if err != nil {
		return nil, err
	}
	checked, err := s.permissions.Check(ctx, user.ID, req.GetResourceId())
	if err != nil {
		return nil, status.Error(codes.Internal, "acl evaluation failed")
	}
	resp := &pb.CheckUserPermissionResponse{}
	for _, item := range checked {
		rp := &pb.ResourcePermission{ResourceId: item.ResourceID, Permission: item.Permission}
		if item.Allowed {
			resp.AllowedResourcePermission = append(resp.AllowedResourcePermission, rp)
		} else {
			resp.DeniedResourcePermission = append(resp.DeniedResourcePermission, &pb.ResourcePermission{ResourceId: rp.ResourceId})
		}
	}
	return resp, nil
}

func (s *Server) LookupUserPermissions(ctx context.Context, req *pb.LookupUserPermissionsRequest) (*pb.LookupUserPermissionsResponse, error) {
	authn, err := s.authnFromContext(ctx)
	if err != nil {
		return nil, err
	}
	permissions, err := s.permissions.Lookup(ctx, authn.User.ID, model.ResourceFilter{Prefix: req.GetResourceFilter()})
	if err != nil {
		return nil, status.Error(codes.Internal, "lookup failed")
	}
	resp := &pb.LookupUserPermissionsResponse{}
	for _, permission := range permissions {
		resp.ResourcePermission = append(resp.ResourcePermission, &pb.ResourcePermission{
			ResourceId: permission.ResourceID,
			Permission: permission.Permission,
		})
	}
	return resp, nil
}

func (s *Server) authnFromContext(ctx context.Context) (model.VerifiedAuthn, error) {
	bearer := bearerFromContext(ctx)
	if bearer == "" {
		return model.VerifiedAuthn{}, status.Error(codes.Unauthenticated, "authorization header required")
	}
	authn, err := s.tokens.VerifyAuthn(ctx, bearer)
	if err != nil {
		return model.VerifiedAuthn{}, status.Error(codes.Unauthenticated, "invalid authn token")
	}
	return authn, nil
}

func (s *Server) resolveSubjectUser(ctx context.Context, target *pb.TargetUser) (model.User, error) {
	if target != nil && target.GetUserToken() != "" {
		authn, err := s.tokens.VerifyAuthn(ctx, target.GetUserToken())
		if err != nil {
			return model.User{}, status.Error(codes.InvalidArgument, "invalid target_user token")
		}
		return authn.User, nil
	}
	authn, err := s.authnFromContext(ctx)
	if err != nil {
		return model.User{}, err
	}
	return authn.User, nil
}

func bearerFromContext(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	values := md.Get("authorization")
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
