package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/ports"
)

type TokenConfig struct {
	Issuer              string
	Audience            []string
	AuthServiceAudience string
	AuthnTTL            time.Duration
	AuthzTTL            time.Duration
}

type TokenService struct {
	cfg         TokenConfig
	users       ports.UserDirectory
	resources   ports.ResourceStore
	authz       ports.AuthorizationPolicy
	signer      ports.TokenSigner
	log         ports.IssuedTokenLog
	authnLookup ports.AuthnTokenLookup
}

func NewTokenService(cfg TokenConfig, users ports.UserDirectory, resources ports.ResourceStore, authz ports.AuthorizationPolicy, signer ports.TokenSigner, log ports.IssuedTokenLog, authnLookup ports.AuthnTokenLookup) *TokenService {
	return &TokenService{cfg: cfg, users: users, resources: resources, authz: authz, signer: signer, log: log, authnLookup: authnLookup}
}

func (s *TokenService) MintAuthn(ctx context.Context, userEmailOrID string, ttl time.Duration) (model.SignedToken, model.User, error) {
	user, err := s.users.Resolve(ctx, userEmailOrID)
	if err != nil {
		return model.SignedToken{}, model.User{}, err
	}
	if user.Status != "active" {
		return model.SignedToken{}, model.User{}, fmt.Errorf("%w: user is not active", model.ErrPermissionDenied)
	}
	if ttl == 0 {
		ttl = s.cfg.AuthnTTL
	}
	groups, err := s.users.GroupNames(ctx, user.ID)
	if err != nil {
		return model.SignedToken{}, model.User{}, err
	}
	signed, err := s.signer.SignAuthn(ctx, model.AuthnTokenInput{
		Issuer:            s.cfg.Issuer,
		Audience:          s.authnAudience(),
		Subject:           user.SubjectClaim(),
		Name:              user.Display(),
		PreferredUsername: user.PreferredUsername(),
		Groups:            groups,
		IDP:               user.Provider,
		TTL:               ttl,
	})
	if err != nil {
		return model.SignedToken{}, model.User{}, fmt.Errorf("%w: sign authn token: %w", model.ErrTokenIssueFailed, err)
	}
	if err := s.record(ctx, signed, user.ID, "authn", "authn"); err != nil {
		return model.SignedToken{}, model.User{}, fmt.Errorf("%w: record authn token: %w", model.ErrTokenIssueFailed, err)
	}
	return signed, user, nil
}

func (s *TokenService) VerifyAuthn(ctx context.Context, bearer string) (model.VerifiedAuthn, error) {
	compact := strings.TrimSpace(strings.TrimPrefix(bearer, "Bearer "))
	if compact == "" {
		return model.VerifiedAuthn{}, fmt.Errorf("%w: missing bearer token", model.ErrUnauthenticated)
	}
	verified, err := s.signer.Verify(ctx, compact, model.VerifyOptions{Issuer: s.cfg.Issuer, Audience: s.cfg.AuthServiceAudience})
	if err != nil {
		return model.VerifiedAuthn{}, fmt.Errorf("%w: invalid authn token", model.ErrUnauthenticated)
	}
	if verified.JTI == "" {
		return model.VerifiedAuthn{}, fmt.Errorf("%w: authn token missing jti", model.ErrUnauthenticated)
	}
	if s.authnLookup == nil {
		return model.VerifiedAuthn{}, fmt.Errorf("%w: authn token lookup unavailable", model.ErrUnauthenticated)
	}
	user, err := s.authnLookup.FindActiveAuthnTokenUser(ctx, verified.JTI)
	if err != nil {
		return model.VerifiedAuthn{}, err
	}
	if user.Status != "active" {
		return model.VerifiedAuthn{}, fmt.Errorf("%w: user is not active", model.ErrPermissionDenied)
	}
	return model.VerifiedAuthn{Subject: verified.Subject, User: user}, nil
}

func (s *TokenService) ExchangeAuthz(ctx context.Context, authn model.VerifiedAuthn, resourceIDs []string, ttl time.Duration) (model.SignedToken, error) {
	if authn.User.ID == "" {
		return model.SignedToken{}, fmt.Errorf("%w: missing authn", model.ErrUnauthenticated)
	}
	if len(resourceIDs) == 0 {
		return model.SignedToken{}, fmt.Errorf("%w: resource_id is required", model.ErrInvalidArgument)
	}
	if ttl == 0 {
		ttl = s.cfg.AuthzTTL
	}
	resources := make([]model.ResourcePermission, 0, len(resourceIDs))
	for _, resourceID := range resourceIDs {
		resource, err := s.resources.GetByResourceID(ctx, resourceID)
		if err != nil {
			return model.SignedToken{}, err
		}
		allowed, err := s.authz.CanAccess(ctx, authn.User.ID, resource.ResourceID, "write")
		if err != nil {
			return model.SignedToken{}, err
		}
		if !allowed {
			return model.SignedToken{}, fmt.Errorf("%w: user is not allowed for %s", model.ErrPermissionDenied, resourceID)
		}
		resources = append(resources, model.ResourcePermission{ResourceID: resource.ResourceID, Permission: []string{"read", "write"}})
	}
	groups, err := s.users.GroupNames(ctx, authn.User.ID)
	if err != nil {
		return model.SignedToken{}, err
	}
	signed, err := s.signer.SignAuthz(ctx, model.AuthzTokenInput{
		Issuer:            s.cfg.Issuer,
		Audience:          s.cfg.Audience,
		Subject:           authn.Subject,
		Name:              authn.User.Display(),
		PreferredUsername: authn.User.PreferredUsername(),
		Groups:            groups,
		IDP:               authn.User.Provider,
		Resources:         resources,
		TTL:               ttl,
	})
	if err != nil {
		return model.SignedToken{}, fmt.Errorf("%w: sign authz token: %w", model.ErrTokenIssueFailed, err)
	}
	if err := s.record(ctx, signed, authn.User.ID, "authz", "authz"); err != nil {
		return model.SignedToken{}, fmt.Errorf("%w: record authz token: %w", model.ErrTokenIssueFailed, err)
	}
	return signed, nil
}

func (s *TokenService) ManualMintAuthz(ctx context.Context, userEmailOrID, repoName, role string, ttl time.Duration) (model.SignedToken, error) {
	if role == "" {
		role = "writer"
	}
	if role != "writer" {
		return model.SignedToken{}, fmt.Errorf("%w: MVP only issues writer tokens; got %q", model.ErrInvalidArgument, role)
	}
	user, err := s.users.Resolve(ctx, userEmailOrID)
	if err != nil {
		return model.SignedToken{}, err
	}
	if user.Status != "active" {
		return model.SignedToken{}, fmt.Errorf("%w: user is not active", model.ErrPermissionDenied)
	}
	resource, err := s.resources.GetByName(ctx, repoName)
	if err != nil {
		return model.SignedToken{}, err
	}
	allowed, err := s.authz.CanAccess(ctx, user.ID, resource.ResourceID, "write")
	if err != nil {
		return model.SignedToken{}, err
	}
	if !allowed {
		return model.SignedToken{}, fmt.Errorf("%w: user is not allowed to write repository", model.ErrPermissionDenied)
	}
	return s.ExchangeAuthz(ctx, model.VerifiedAuthn{Subject: user.SubjectClaim(), User: user}, []string{resource.ResourceID}, ttl)
}

func (s *TokenService) record(ctx context.Context, signed model.SignedToken, userID, kind, role string) error {
	if s.log == nil {
		return nil
	}
	return s.log.Record(ctx, model.IssuedToken{JTI: signed.JTI, Kind: kind, UserID: userID, LoreResourceID: signed.LoreResourceID, Role: role, Kid: signed.Kid, Audience: signed.Audience, IssuedAt: signed.IssuedAt, ExpiresAt: signed.ExpiresAt})
}

func (s *TokenService) authnAudience() []string {
	out := append([]string(nil), s.cfg.Audience...)
	if s.cfg.AuthServiceAudience != "" && !contains(out, s.cfg.AuthServiceAudience) {
		out = append(out, s.cfg.AuthServiceAudience)
	}
	return out
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func IsPermissionDenied(err error) bool {
	return errors.Is(err, model.ErrPermissionDenied)
}
