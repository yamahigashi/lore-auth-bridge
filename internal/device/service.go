package device

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yamahigashi/lore-auth-bridge/internal/adapter/casbin"
	"github.com/yamahigashi/lore-auth-bridge/internal/adapter/rs256"
	"github.com/yamahigashi/lore-auth-bridge/internal/adapter/sqlite"
	"github.com/yamahigashi/lore-auth-bridge/internal/config"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/service"
)

var (
	ErrInvalidCode             = errors.New("device: invalid code")
	ErrExpiredCode             = errors.New("device: expired code")
	ErrAuthorizationNotPending = errors.New("device: authorization is not pending")
	ErrIncompleteAuthorization = errors.New("device: incomplete authorization")
)

type Service struct {
	cfg    *config.Config
	store  *sqlite.Store
	acl    *casbin.Service
	tokens *service.TokenService
}

type StartResult struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type TokenResult struct {
	Status      string `json:"status"`
	TokenType   string `json:"token_type,omitempty"`
	AccessToken string `json:"access_token,omitempty"`
	ExpiresIn   int    `json:"expires_in,omitempty"`
	AuthURL     string `json:"auth_url,omitempty"`
	RemoteURL   string `json:"remote_url,omitempty"`
}

type Repository struct {
	Name      string
	RemoteURL string
}

type PreviewResult struct {
	Repository         Repository
	RequestedRemoteURL string
}

func NewService(cfg *config.Config, st *sqlite.Store, tokenSvc ...*service.TokenService) *Service {
	var tokens *service.TokenService
	if len(tokenSvc) > 0 {
		tokens = tokenSvc[0]
	}
	if tokens == nil {
		coreStore := sqlite.NewCoreStore(st)
		authz := casbin.NewService(st)
		authServiceAudience, _ := config.PublicHost(cfg.Server.PublicBaseURL)
		tokens = service.NewTokenService(service.TokenConfig{
			Issuer:              cfg.JWT.Issuer,
			Audience:            cfg.JWT.Audience,
			AuthServiceAudience: authServiceAudience,
			AuthnTTL:            seconds(cfg.JWT.TTLSeconds),
			AuthzTTL:            15 * time.Minute,
		}, coreStore, coreStore, authz, rs256.NewSigner(cfg.JWT.ActiveKID, coreStore), coreStore)
	}
	return &Service{cfg: cfg, store: st, acl: casbin.NewService(st), tokens: tokens}
}

func (s *Service) Start(ctx context.Context, remoteURL, repoName string) (*StartResult, error) {
	repo, err := s.store.FindRepositoryByName(ctx, repoName)
	if err != nil {
		if errors.Is(err, sqlite.ErrNotFound) || errors.Is(err, model.ErrNotFound) {
			return nil, fmt.Errorf("%w: repository", model.ErrNotFound)
		}
		return nil, fmt.Errorf("device: lookup repository: %w", err)
	}
	deviceCode, err := randomSecret(32)
	if err != nil {
		return nil, fmt.Errorf("device: generate device code: %w", err)
	}
	userCode, err := randomUserCode()
	if err != nil {
		return nil, fmt.Errorf("device: generate user code: %w", err)
	}
	if _, err := s.store.CreateDeviceAuthorization(ctx, sqlite.CreateDeviceAuthorizationParams{DeviceCodeHash: HashCode(deviceCode), UserCodeHash: HashCode(userCode), RequestedRemoteURL: remoteURL, RequestedRepositoryID: repo.ID, TTLSeconds: s.cfg.Security.DeviceCodeTTLSeconds}); err != nil {
		return nil, fmt.Errorf("device: create authorization: %w", err)
	}
	return &StartResult{DeviceCode: deviceCode, UserCode: userCode, VerificationURI: strings.TrimRight(s.cfg.Server.PublicBaseURL, "/") + "/device", ExpiresIn: s.cfg.Security.DeviceCodeTTLSeconds, Interval: s.cfg.Security.DevicePollIntervalSeconds}, nil
}

func (s *Service) Preview(ctx context.Context, userCode string) (*PreviewResult, error) {
	d, err := s.store.DeviceByUserCodeHash(ctx, HashCode(userCode))
	if err != nil {
		if errors.Is(err, sqlite.ErrNotFound) || errors.Is(err, model.ErrNotFound) {
			return nil, ErrInvalidCode
		}
		return nil, fmt.Errorf("device: lookup user code: %w", err)
	}
	if d.Status != "pending" {
		return nil, fmt.Errorf("%w: status %s", ErrAuthorizationNotPending, d.Status)
	}
	if d.ExpiresAt <= sqlite.UnixNow() {
		_ = s.store.ExpireDeviceAuthorization(ctx, d.ID)
		return nil, ErrExpiredCode
	}
	if !d.RequestedRepositoryID.Valid {
		return nil, fmt.Errorf("%w: missing repository", ErrIncompleteAuthorization)
	}
	repo, err := repositoryByID(ctx, s.store, d.RequestedRepositoryID.String)
	if err != nil {
		if errors.Is(err, sqlite.ErrNotFound) || errors.Is(err, model.ErrNotFound) {
			return nil, fmt.Errorf("%w: repository", model.ErrNotFound)
		}
		return nil, fmt.Errorf("device: lookup requested repository: %w", err)
	}
	return &PreviewResult{Repository: Repository{Name: repo.Name, RemoteURL: repo.RemoteURL}, RequestedRemoteURL: d.RequestedRemoteURL}, nil
}

func (s *Service) Approve(ctx context.Context, userEmailOrID, userCode string) (*Repository, error) {
	d, err := s.store.DeviceByUserCodeHash(ctx, HashCode(userCode))
	if err != nil {
		if errors.Is(err, sqlite.ErrNotFound) || errors.Is(err, model.ErrNotFound) {
			return nil, ErrInvalidCode
		}
		return nil, fmt.Errorf("device: lookup user code: %w", err)
	}
	if d.Status != "pending" {
		return nil, fmt.Errorf("%w: status %s", ErrAuthorizationNotPending, d.Status)
	}
	if d.ExpiresAt <= sqlite.UnixNow() {
		_ = s.store.ExpireDeviceAuthorization(ctx, d.ID)
		return nil, ErrExpiredCode
	}
	if !d.RequestedRepositoryID.Valid {
		return nil, fmt.Errorf("%w: missing repository", ErrIncompleteAuthorization)
	}
	repo, err := repositoryByID(ctx, s.store, d.RequestedRepositoryID.String)
	if err != nil {
		if errors.Is(err, sqlite.ErrNotFound) || errors.Is(err, model.ErrNotFound) {
			return nil, fmt.Errorf("%w: repository", model.ErrNotFound)
		}
		return nil, fmt.Errorf("device: lookup requested repository: %w", err)
	}
	ok, err := s.acl.Can(ctx, userEmailOrID, repo.Name, "write")
	if err != nil {
		return nil, fmt.Errorf("device: check repository permission: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("%w: device approval denied", model.ErrPermissionDenied)
	}
	u, err := s.store.ResolveUser(ctx, userEmailOrID)
	if err != nil {
		return nil, fmt.Errorf("device: resolve approving user: %w", err)
	}
	if err := s.store.ApproveDeviceAuthorization(ctx, d.ID, u.ID); err != nil {
		return nil, fmt.Errorf("device: approve authorization: %w", err)
	}
	return &Repository{Name: repo.Name, RemoteURL: repo.RemoteURL}, nil
}

func (s *Service) Token(ctx context.Context, deviceCode string) (*TokenResult, error) {
	d, err := s.store.DeviceByDeviceCodeHash(ctx, HashCode(deviceCode))
	if err != nil {
		if errors.Is(err, sqlite.ErrNotFound) || errors.Is(err, model.ErrNotFound) {
			return nil, ErrInvalidCode
		}
		return nil, fmt.Errorf("device: lookup device code: %w", err)
	}
	if d.ExpiresAt <= sqlite.UnixNow() && d.Status == "pending" {
		_ = s.store.ExpireDeviceAuthorization(ctx, d.ID)
		return &TokenResult{Status: "expired_token"}, nil
	}
	switch d.Status {
	case "pending":
		return &TokenResult{Status: "authorization_pending"}, nil
	case "approved":
	default:
		return &TokenResult{Status: d.Status}, nil
	}
	if !d.ApprovedUserID.Valid || !d.RequestedRepositoryID.Valid {
		return nil, ErrIncompleteAuthorization
	}
	repo, err := repositoryByID(ctx, s.store, d.RequestedRepositoryID.String)
	if err != nil {
		if errors.Is(err, sqlite.ErrNotFound) || errors.Is(err, model.ErrNotFound) {
			return nil, fmt.Errorf("%w: repository", model.ErrNotFound)
		}
		return nil, fmt.Errorf("device: lookup requested repository: %w", err)
	}
	res, err := s.tokens.ManualMintAuthz(ctx, d.ApprovedUserID.String, repo.Name, "writer", 0)
	if err != nil {
		return nil, fmt.Errorf("device: issue token: %w", err)
	}
	if err := s.store.ConsumeDeviceAuthorization(ctx, d.ID); err != nil {
		return nil, fmt.Errorf("device: consume authorization: %w", err)
	}
	return &TokenResult{Status: "ok", TokenType: "lore", AccessToken: res.Token, ExpiresIn: expiresInSeconds(res.ExpiresAt, time.Now()), AuthURL: s.cfg.Lore.AuthURL, RemoteURL: repo.RemoteURL}, nil
}

func expiresInSeconds(expiresAt int64, now time.Time) int {
	remaining := expiresAt - now.Unix()
	if remaining <= 0 {
		return 0
	}
	return int(remaining)
}

func HashCode(code string) string {
	sum := sha256.Sum256([]byte(strings.ToUpper(strings.TrimSpace(code))))
	return hex.EncodeToString(sum[:])
}
func randomSecret(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
func randomUserCode() (string, error) {
	b, err := randomSecret(5)
	if err != nil {
		return "", err
	}
	b = strings.ToUpper(strings.ReplaceAll(b, "_", "A"))
	if len(b) > 8 {
		b = b[:4] + "-" + b[4:8]
	}
	return b, nil
}

func repositoryByID(ctx context.Context, st *sqlite.Store, id string) (*sqlite.Repository, error) {
	rows, err := st.DB().QueryContext(ctx, `SELECT id, name, remote_url, lore_repository_id, status, created_by_source, created_at, updated_at FROM repositories WHERE id = ? AND status = 'active'`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, model.ErrNotFound
	}
	var r sqlite.Repository
	if err := rows.Scan(&r.ID, &r.Name, &r.RemoteURL, &r.LoreRepositoryID, &r.Status, &r.CreatedBySource, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return nil, fmt.Errorf("device: scan repository: %w", err)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("device: read repository: %w", err)
	}
	return &r, nil
}

func seconds(value int) time.Duration {
	if value == 0 {
		return 0
	}
	return time.Duration(value) * time.Second
}
