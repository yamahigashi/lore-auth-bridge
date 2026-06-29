package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yamahigashi/lore-auth-bridge/internal/adapter/memory"
	"github.com/yamahigashi/lore-auth-bridge/internal/config"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/service"
	"github.com/yamahigashi/lore-auth-bridge/internal/device"
)

type fakeIDP struct{ id model.Identity }

func (f fakeIDP) AuthCodeURL(state string) string {
	return "https://accounts.google.com/o/oauth2/v2/auth?state=" + state
}

func (f fakeIDP) ExchangeAndVerify(ctx context.Context, code string) (model.Identity, error) {
	return f.id, nil
}

func (f fakeIDP) Issuer() string { return "https://accounts.google.com" }

type fakeDevice struct {
	startErr error
	tokenErr error
}

func (d fakeDevice) Start(ctx context.Context, remoteURL, repoName string) (*device.StartResult, error) {
	if d.startErr != nil {
		return nil, d.startErr
	}
	return &device.StartResult{DeviceCode: "device-code", UserCode: "ABCD-EFGH", VerificationURI: "https://auth.example.com/device", ExpiresIn: 600, Interval: 3}, nil
}

func (fakeDevice) Approve(ctx context.Context, userEmailOrID, userCode string) (*device.Repository, error) {
	return &device.Repository{Name: "game-assets"}, nil
}

func (d fakeDevice) Token(ctx context.Context, deviceCode string) (*device.TokenResult, error) {
	if d.tokenErr != nil {
		return nil, d.tokenErr
	}
	return &device.TokenResult{Status: "authorization_pending"}, nil
}

func newHTTPTestServer(cfg *config.Config, idp fakeIDP) (*Server, *memory.Store) {
	if cfg == nil {
		cfg = &config.Config{}
	}
	cfg.Server.PublicBaseURL = "https://auth.example.com"
	cfg.JWT.Issuer = "https://auth.example.com"
	cfg.JWT.Audience = []string{"lore-service", "lore.example.com"}
	cfg.JWT.TTLSeconds = 3600
	cfg.Lore.AuthURL = "ucs-auth://auth.example.com"
	cfg.Lore.DefaultRemoteURL = "lore://lore.example.com:41337"
	cfg.Security.SessionTTLSeconds = 3600
	mem := memory.New()
	tokenSvc := service.NewTokenService(service.TokenConfig{
		Issuer:              cfg.JWT.Issuer,
		Audience:            cfg.JWT.Audience,
		AuthServiceAudience: "auth.example.com",
		AuthnTTL:            time.Hour,
		AuthzTTL:            15 * time.Minute,
	}, mem, mem, mem, mem, mem)
	loginSvc := service.NewLoginService(service.LoginConfig{PublicBaseURL: cfg.Server.PublicBaseURL, SessionTTL: time.Duration(cfg.Security.SessionTTLSeconds) * time.Second}, idp, mem, mem, tokenSvc)
	resourceSvc := service.NewResourceService(mem)
	return NewWithOptions(Options{Config: cfg, Login: loginSvc, Tokens: tokenSvc, Resources: resourceSvc, State: mem, JWKS: mem, Device: fakeDevice{}}), mem
}

func TestJWKSHandlerPublishesKeys(t *testing.T) {
	t.Parallel()
	srv, _ := newHTTPTestServer(nil, fakeIDP{})
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Keys == nil {
		t.Fatalf("unexpected jwks: %#v", body)
	}
}

func TestGoogleCallbackCreatesSessionForRegisteredUser(t *testing.T) {
	t.Parallel()
	srv, mem := newHTTPTestServer(nil, fakeIDP{id: model.Identity{Provider: "google", Issuer: "https://accounts.google.com", Subject: "sub", Email: "alice@example.com"}})
	mem.AddTestUser(model.User{Provider: "google", Issuer: "https://accounts.google.com", Subject: "sub", Email: "alice@example.com"})

	req := httptest.NewRequest(http.MethodGet, "/oauth/google/callback?state=state&code=code", nil)
	req.AddCookie(&http.Cookie{Name: stateCookieName, Value: "state"})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("unexpected status: %d body=%s", rr.Code, rr.Body.String())
	}
	if len(rr.Result().Cookies()) == 0 {
		t.Fatal("expected session cookie")
	}
}

func TestGoogleCallbackShowsWhoamiForUnregisteredUser(t *testing.T) {
	t.Parallel()
	srv, _ := newHTTPTestServer(nil, fakeIDP{id: model.Identity{Provider: "google", Issuer: "https://accounts.google.com", Subject: "sub", Email: "new@example.com"}})
	req := httptest.NewRequest(http.MethodGet, "/oauth/google/callback?state=state&code=code", nil)
	req.AddCookie(&http.Cookie{Name: stateCookieName, Value: "state"})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "new@example.com") {
		t.Fatalf("whoami missing email: %s", rr.Body.String())
	}
}

func TestGoogleCallbackDisabledUserIsForbidden(t *testing.T) {
	t.Parallel()
	srv, mem := newHTTPTestServer(nil, fakeIDP{id: model.Identity{Provider: "google", Issuer: "https://accounts.google.com", Subject: "sub", Email: "alice@example.com"}})
	mem.AddTestUser(model.User{Provider: "google", Issuer: "https://accounts.google.com", Subject: "sub", Email: "alice@example.com", Status: "disabled"})
	req := httptest.NewRequest(http.MethodGet, "/oauth/google/callback?state=state&code=code", nil)
	req.AddCookie(&http.Cookie{Name: stateCookieName, Value: "state"})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d body=%s", rr.Code, http.StatusForbidden, rr.Body.String())
	}
}

func TestGoogleCallbackLoginSessionStoreFailureIsInternal(t *testing.T) {
	t.Parallel()
	srv, mem := newHTTPTestServer(nil, fakeIDP{id: model.Identity{Provider: "google", Issuer: "https://accounts.google.com", Subject: "sub", Email: "alice@example.com"}})
	mem.AddTestUser(model.User{Provider: "google", Issuer: "https://accounts.google.com", Subject: "sub", Email: "alice@example.com"})
	srv.login = service.NewLoginService(service.LoginConfig{PublicBaseURL: srv.cfg.Server.PublicBaseURL, SessionTTL: time.Hour}, fakeIDP{id: model.Identity{Provider: "google", Issuer: "https://accounts.google.com", Subject: "sub", Email: "alice@example.com"}}, mem, failingNonceState{Store: mem}, srv.tokens)

	req := httptest.NewRequest(http.MethodGet, "/oauth/google/callback?state=state&code=code", nil)
	req.AddCookie(&http.Cookie{Name: stateCookieName, Value: "state"})
	req.AddCookie(&http.Cookie{Name: loginSessionCookie, Value: "nonce"})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d body=%s", rr.Code, http.StatusInternalServerError, rr.Body.String())
	}
}

func TestTokenMintPageIssuesWriterToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	srv, mem := newHTTPTestServer(nil, fakeIDP{})
	u := mem.AddTestUser(model.User{Provider: "google", Issuer: "https://accounts.google.com", Subject: "sub", Email: "alice@example.com"})
	resource := mem.AddTestResource(model.Resource{Name: "game-assets", RemoteURL: "lore://example", LoreRepositoryID: "0194b726b34e72b0b45550b88a967076"})
	mem.Grant(u.ID, resource.ResourceID)
	sess, err := mem.CreateBrowserSession(ctx, u.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/tokens/mint", strings.NewReader("repository=game-assets"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "lore auth login") {
		t.Fatalf("missing login command: %s", rr.Body.String())
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if got := rr.Header().Get("Pragma"); got != "no-cache" {
		t.Fatalf("Pragma = %q, want no-cache", got)
	}
	if got := rr.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("Referrer-Policy = %q, want no-referrer", got)
	}
}

func TestTokenMintPermissionDeniedUsesSafeBody(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	srv, mem := newHTTPTestServer(nil, fakeIDP{})
	u := mem.AddTestUser(model.User{Provider: "google", Issuer: "https://accounts.google.com", Subject: "sub", Email: "alice@example.com"})
	mem.AddTestResource(model.Resource{Name: "game-assets", RemoteURL: "lore://example", LoreRepositoryID: "0194b726b34e72b0b45550b88a967076"})
	sess, err := mem.CreateBrowserSession(ctx, u.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/tokens/mint", strings.NewReader("repository=game-assets"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d body=%s", rr.Code, http.StatusForbidden, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "core:") || strings.Contains(rr.Body.String(), "not allowed") {
		t.Fatalf("body exposes raw error: %s", rr.Body.String())
	}
}

func TestDeviceStartAndPendingTokenHTTP(t *testing.T) {
	t.Parallel()
	srv, _ := newHTTPTestServer(nil, fakeIDP{})
	startReq := httptest.NewRequest(http.MethodPost, "/api/device/start", strings.NewReader(`{"remote_url":"lore://example","repository":"game-assets"}`))
	startReq.Header.Set("Content-Type", "application/json")
	startRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(startRR, startReq)
	if startRR.Code != http.StatusOK {
		t.Fatalf("unexpected start status: %d body=%s", startRR.Code, startRR.Body.String())
	}
	var start struct {
		DeviceCode string `json:"device_code"`
	}
	if err := json.Unmarshal(startRR.Body.Bytes(), &start); err != nil {
		t.Fatal(err)
	}
	if start.DeviceCode == "" {
		t.Fatal("missing device code")
	}
	tokenReq := httptest.NewRequest(http.MethodPost, "/api/device/token", strings.NewReader(`{"device_code":"`+start.DeviceCode+`"}`))
	tokenReq.Header.Set("Content-Type", "application/json")
	tokenRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(tokenRR, tokenReq)
	if tokenRR.Code != http.StatusOK {
		t.Fatalf("unexpected token status: %d body=%s", tokenRR.Code, tokenRR.Body.String())
	}
	if !strings.Contains(tokenRR.Body.String(), "authorization_pending") {
		t.Fatalf("unexpected body: %s", tokenRR.Body.String())
	}
}

func TestDeviceStartUnexpectedErrorUsesSafeBody(t *testing.T) {
	t.Parallel()
	srv, _ := newHTTPTestServer(nil, fakeIDP{})
	srv.device = fakeDevice{startErr: errors.New("database path /tmp/private.sqlite failed")}

	req := httptest.NewRequest(http.MethodPost, "/api/device/start", strings.NewReader(`{"remote_url":"lore://example","repository":"game-assets"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d body=%s", rr.Code, http.StatusInternalServerError, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "private.sqlite") {
		t.Fatalf("body exposes raw error: %s", rr.Body.String())
	}
}

func TestDeviceTokenLookupErrorUsesSafeBody(t *testing.T) {
	t.Parallel()
	srv, _ := newHTTPTestServer(nil, fakeIDP{})
	srv.device = fakeDevice{tokenErr: device.ErrInvalidCode}

	req := httptest.NewRequest(http.MethodPost, "/api/device/token", strings.NewReader(`{"device_code":"missing"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d body=%s", rr.Code, http.StatusBadRequest, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "core:") {
		t.Fatalf("body exposes raw error: %s", rr.Body.String())
	}
}

func TestLoginSessionCompletesViaGoogleCallback(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	srv, mem := newHTTPTestServer(nil, fakeIDP{id: model.Identity{Provider: "google", Issuer: "https://accounts.google.com", Subject: "sub", Email: "alice@example.com"}})
	u := mem.AddTestUser(model.User{Provider: "google", Issuer: "https://accounts.google.com", Subject: "sub", Email: "alice@example.com"})
	code, sess, err := mem.CreateAuthSession(ctx, "client-state", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_ = code
	req := httptest.NewRequest(http.MethodGet, "/oauth/google/callback?state=state&code=code", nil)
	req.AddCookie(&http.Cookie{Name: stateCookieName, Value: "state"})
	req.AddCookie(&http.Cookie{Name: loginSessionCookie, Value: sess.LoginURLNonce})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "Login complete") {
		t.Fatalf("unexpected body: %s", rr.Body.String())
	}
	updated, err := mem.GetAuthSessionByNonce(ctx, sess.LoginURLNonce)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != "completed" || updated.UserID != u.ID {
		t.Fatalf("session not completed: %#v", updated)
	}
}

func TestLoginSessionStoreFailureIsInternal(t *testing.T) {
	t.Parallel()
	srv, mem := newHTTPTestServer(nil, fakeIDP{})
	srv.state = failingNonceState{Store: mem}

	req := httptest.NewRequest(http.MethodGet, "/login/session/nonce", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d body=%s", rr.Code, http.StatusInternalServerError, rr.Body.String())
	}
}

func TestCurrentUserStoreFailureIsInternal(t *testing.T) {
	t.Parallel()
	srv, mem := newHTTPTestServer(nil, fakeIDP{})
	srv.state = failingBrowserSessionState{Store: mem}

	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session"})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d body=%s", rr.Code, http.StatusInternalServerError, rr.Body.String())
	}
}

type failingNonceState struct {
	*memory.Store
}

func (s failingNonceState) GetAuthSessionByNonce(ctx context.Context, nonce string) (model.AuthSession, error) {
	return model.AuthSession{}, errors.New("state store failed")
}

type failingBrowserSessionState struct {
	*memory.Store
}

func (s failingBrowserSessionState) UserByBrowserSession(ctx context.Context, sessionID string) (model.User, error) {
	return model.User{}, errors.New("session store failed")
}
