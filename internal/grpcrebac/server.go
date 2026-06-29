// Package grpcrebac implements ucs.auth.RebacApi, the gRPC service loreserver
// calls to synchronise repository resource lifecycle (create/delete).
package grpcrebac

import (
	"context"
	"errors"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/service"
	pb "github.com/yamahigashi/lore-auth-bridge/internal/loreproto/ucsauth"
)

type Server struct {
	pb.UnimplementedRebacApiServer
	resources *service.ResourceService
}

func New(resources *service.ResourceService) *Server { return &Server{resources: resources} }

func (s *Server) CreateResource(ctx context.Context, req *pb.CreateResourceRequest) (*pb.CreateResourceResponse, error) {
	if req.GetResourceId() == "" {
		return nil, status.Error(codes.InvalidArgument, "resource_id is required")
	}
	if err := s.resources.CreateResource(ctx, req.GetResourceId(), req.GetResourceName()); err != nil {
		slog.Error("rebac create resource failed", "resource_id", req.GetResourceId(), "error", err)
		return nil, status.Error(codes.Internal, "failed to create resource")
	}
	slog.Info("rebac resource created", "resource_id", req.GetResourceId(), "name", req.GetResourceName())
	return &pb.CreateResourceResponse{}, nil
}

func (s *Server) DeleteResource(ctx context.Context, req *pb.DeleteResourceRequest) (*pb.DeleteResourceResponse, error) {
	if req.GetResourceId() == "" {
		return nil, status.Error(codes.InvalidArgument, "resource_id is required")
	}
	if err := s.resources.DeleteResource(ctx, req.GetResourceId()); err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return &pb.DeleteResourceResponse{}, nil
		}
		slog.Error("rebac delete resource failed", "resource_id", req.GetResourceId(), "error", err)
		return nil, status.Error(codes.Internal, "failed to delete resource")
	}
	slog.Info("rebac resource deleted", "resource_id", req.GetResourceId())
	return &pb.DeleteResourceResponse{}, nil
}
