package device

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/yamahigashi/lore-auth-bridge/internal/adapter/rs256"
	"github.com/yamahigashi/lore-auth-bridge/internal/adapter/sqlite"
	"github.com/yamahigashi/lore-auth-bridge/internal/config"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
)

func TestDeviceFlowStartApproveToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	st, cfg := setupDeviceTest(t, dir)
	defer st.Close()
	svc := NewService(cfg, st)
	start, err := svc.Start(ctx, "lore://example", "game-assets")
	if err != nil {
		t.Fatal(err)
	}
	pending, err := svc.Token(ctx, start.DeviceCode)
	if err != nil {
		t.Fatal(err)
	}
	if pending.Status != "authorization_pending" {
		t.Fatalf("unexpected pending status: %#v", pending)
	}
	if _, err := svc.Approve(ctx, "alice@example.com", start.UserCode); err != nil {
		t.Fatal(err)
	}
	res, err := svc.Token(ctx, start.DeviceCode)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "ok" || res.AccessToken == "" {
		t.Fatalf("unexpected token result: %#v", res)
	}
	consumed, err := svc.Token(ctx, start.DeviceCode)
	if err != nil {
		t.Fatal(err)
	}
	if consumed.Status != "consumed" {
		t.Fatalf("expected consumed, got %#v", consumed)
	}
}

func TestDevicePreviewShowsRequestedRepositoryAndRemote(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	st, cfg := setupDeviceTest(t, dir)
	defer st.Close()
	svc := NewService(cfg, st)
	start, err := svc.Start(ctx, "lore://requested.example/repo", "game-assets")
	if err != nil {
		t.Fatal(err)
	}

	preview, err := svc.Preview(ctx, start.UserCode)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Repository.Name != "game-assets" || preview.Repository.RemoteURL != "lore://example" {
		t.Fatalf("unexpected preview repository: %#v", preview.Repository)
	}
	if preview.RequestedRemoteURL != "lore://requested.example/repo" {
		t.Fatalf("requested remote = %q", preview.RequestedRemoteURL)
	}
}

func TestDeviceApprovalAndTokenRejectDeletedRepository(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	st, cfg := setupDeviceTest(t, dir)
	defer st.Close()
	svc := NewService(cfg, st)
	start, err := svc.Start(ctx, "lore://example", "game-assets")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SoftDeleteResource(ctx, model.ResourceIDForRepositoryID("0194b726b34e72b0b45550b88a967076")); err != nil {
		t.Fatal(err)
	}

	if _, err := svc.Approve(ctx, "alice@example.com", start.UserCode); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("Approve error = %v, want ErrNotFound", err)
	}

	if _, err = svc.Start(ctx, "lore://example", "game-assets"); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("Start after delete error = %v, want ErrNotFound", err)
	}
}

func TestDeviceTokenRejectsRepositoryDeletedAfterApproval(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	st, cfg := setupDeviceTest(t, dir)
	defer st.Close()
	svc := NewService(cfg, st)
	start, err := svc.Start(ctx, "lore://example", "game-assets")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Approve(ctx, "alice@example.com", start.UserCode); err != nil {
		t.Fatal(err)
	}
	if err := st.SoftDeleteResource(ctx, model.ResourceIDForRepositoryID("0194b726b34e72b0b45550b88a967076")); err != nil {
		t.Fatal(err)
	}

	_, err = svc.Token(ctx, start.DeviceCode)
	if !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("Token error = %v, want ErrNotFound", err)
	}
}

func TestDeviceTokenExpiresInUsesIssuedAuthzExpiration(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	st, cfg := setupDeviceTest(t, dir)
	defer st.Close()
	svc := NewService(cfg, st)
	start, err := svc.Start(ctx, "lore://example", "game-assets")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Approve(ctx, "alice@example.com", start.UserCode); err != nil {
		t.Fatal(err)
	}

	res, err := svc.Token(ctx, start.DeviceCode)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExpiresIn <= 0 || res.ExpiresIn > 15*60 {
		t.Fatalf("expires_in = %d, want issued authz token remaining TTL", res.ExpiresIn)
	}
	if res.ExpiresIn == cfg.JWT.TTLSeconds {
		t.Fatalf("expires_in = jwt.ttl_seconds = %d, want authz token remaining TTL", res.ExpiresIn)
	}
}

func TestDeviceApproveInvalidCodeIsClassified(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	st, cfg := setupDeviceTest(t, dir)
	defer st.Close()
	svc := NewService(cfg, st)

	_, err := svc.Approve(ctx, "alice@example.com", "NOPE-NOPE")
	if !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("error = %v, want ErrInvalidCode", err)
	}
}

func TestDeviceApproveDeniedUserIsPermissionDenied(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	st, cfg := setupDeviceTest(t, dir)
	defer st.Close()
	if _, err := st.AddUser(ctx, sqlite.AddUserParams{Provider: "google", Issuer: "https://accounts.google.com", Subject: "other", Email: "bob@example.com"}); err != nil {
		t.Fatal(err)
	}
	svc := NewService(cfg, st)
	start, err := svc.Start(ctx, "lore://example", "game-assets")
	if err != nil {
		t.Fatal(err)
	}

	_, err = svc.Approve(ctx, "bob@example.com", start.UserCode)
	if !errors.Is(err, model.ErrPermissionDenied) {
		t.Fatalf("error = %v, want ErrPermissionDenied", err)
	}
}

func TestDeviceTokenInvalidCodeIsClassified(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	st, cfg := setupDeviceTest(t, dir)
	defer st.Close()
	svc := NewService(cfg, st)

	_, err := svc.Token(ctx, "missing-device-code")
	if !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("error = %v, want ErrInvalidCode", err)
	}
}

func setupDeviceTest(t *testing.T, dir string) (*sqlite.Store, *config.Config) {
	t.Helper()
	ctx := context.Background()
	st, err := sqlite.Open(filepath.Join(dir, "db.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	key, err := rs256.GenerateSigningKey("kid-device", 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "kid-device.pem")
	if err := key.WritePrivatePEM(keyPath); err != nil {
		t.Fatal(err)
	}
	jwk, err := json.Marshal(rs256.NewRSAJWK(key.Kid, key.Alg, key.Public()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddSigningKey(ctx, sqlite.AddSigningKeyParams{Kid: key.Kid, Alg: key.Alg, PublicJWKJSON: string(jwk), PrivateKeyPath: keyPath, Status: "active"}); err != nil {
		t.Fatal(err)
	}
	u, err := st.AddUser(ctx, sqlite.AddUserParams{Provider: "google", Issuer: "https://accounts.google.com", Subject: "sub", Email: "alice@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddRepository(ctx, "game-assets", "lore://example", "0194b726b34e72b0b45550b88a967076"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddGrant(ctx, "user", u.ID, "game-assets", "writer"); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Server.PublicBaseURL = "https://auth.example.com"
	cfg.JWT.Issuer = "https://auth.example.com"
	cfg.JWT.Audience = []string{"lore-service", "lore.example.com"}
	cfg.JWT.TTLSeconds = 3600
	cfg.JWT.ActiveKID = "kid-device"
	cfg.Lore.AuthURL = "ucs-auth://auth.example.com"
	cfg.Lore.DefaultRemoteURL = "lore://example"
	cfg.Security.DeviceCodeTTLSeconds = 600
	cfg.Security.DevicePollIntervalSeconds = 3
	cfg.Security.SessionTTLSeconds = 3600
	return st, cfg
}
