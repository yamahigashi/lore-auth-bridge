package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yamahigashi/lore-auth-bridge/internal/adapter/idpregistry"
	"github.com/yamahigashi/lore-auth-bridge/internal/adapter/memory"
	"github.com/yamahigashi/lore-auth-bridge/internal/config"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/ports"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/service"
	"github.com/yamahigashi/lore-auth-bridge/internal/device"
)

type fakeIDP struct {
	descriptor ports.IdentityProviderDescriptor
	authURL    string
	id         model.Identity
}

func (f fakeIDP) Descriptor() ports.IdentityProviderDescriptor {
	if f.descriptor.ID != "" {
		return f.descriptor
	}
	return ports.IdentityProviderDescriptor{ID: "google", Type: "google_oidc", DisplayName: "Google", Issuer: "https://accounts.google.com"}
}

func (f fakeIDP) BeginAuth(ctx context.Context, req ports.BeginAuthRequest) (ports.BeginAuthResult, error) {
	authURL := f.authURL
	if authURL == "" {
		authURL = "https://accounts.google.com/o/oauth2/v2/auth"
	}
	values := url.Values{}
	values.Set("state", req.State)
	if req.Nonce != "" {
		values.Set("nonce", req.Nonce)
	}
	return ports.BeginAuthResult{RedirectURL: authURL + "?" + values.Encode()}, nil
}

func (f fakeIDP) CompleteAuth(ctx context.Context, req ports.CompleteAuthRequest) (model.Identity, error) {
	return f.id, nil
}

type fakeDevice struct {
	startErr     error
	tokenErr     error
	approveCalls *int
}

func (d fakeDevice) Start(ctx context.Context, remoteURL, repoName string) (*device.StartResult, error) {
	if d.startErr != nil {
		return nil, d.startErr
	}
	return &device.StartResult{DeviceCode: "device-code", UserCode: "ABCD-EFGH", VerificationURI: "https://auth.example.com/device", ExpiresIn: 600, Interval: 3}, nil
}

func (fakeDevice) Preview(ctx context.Context, userCode string) (*device.PreviewResult, error) {
	return &device.PreviewResult{Repository: device.Repository{Name: "game-assets", RemoteURL: "lore://stored.example/repo"}, RequestedRemoteURL: "lore://requested.example/repo"}, nil
}

func (d fakeDevice) Approve(ctx context.Context, userEmailOrID, userCode string) (*device.Repository, error) {
	if d.approveCalls != nil {
		(*d.approveCalls)++
	}
	return &device.Repository{Name: "game-assets", RemoteURL: "lore://stored.example/repo"}, nil
}

func (d fakeDevice) Token(ctx context.Context, deviceCode string) (*device.TokenResult, error) {
	if d.tokenErr != nil {
		return nil, d.tokenErr
	}
	return &device.TokenResult{Status: "authorization_pending"}, nil
}

func newHTTPTestServer(cfg *config.Config, idp fakeIDP) (*Server, *memory.Store) {
	return newHTTPTestServerWithIDPs(cfg, idp)
}

func newHTTPTestServerWithIDPs(cfg *config.Config, providers ...fakeIDP) (*Server, *memory.Store) {
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
	defaultID := ""
	if len(providers) > 0 {
		defaultID = providers[0].Descriptor().ID
	}
	idps := idpregistry.New(defaultID)
	for _, provider := range providers {
		if err := idps.Register(provider); err != nil {
			panic(err)
		}
	}
	tokenSvc := service.NewTokenService(service.TokenConfig{
		Issuer:              cfg.JWT.Issuer,
		Audience:            cfg.JWT.Audience,
		AuthServiceAudience: "auth.example.com",
		AuthnTTL:            time.Hour,
		AuthzTTL:            15 * time.Minute,
	}, mem, mem, mem, mem, mem, mem)
	loginSvc := service.NewLoginService(service.LoginConfig{PublicBaseURL: cfg.Server.PublicBaseURL, SessionTTL: time.Duration(cfg.Security.SessionTTLSeconds) * time.Second}, idps, mem, mem, tokenSvc)
	resourceSvc := service.NewResourceService(mem)
	permissionSvc := service.NewPermissionService(mem, mem)
	return NewWithOptions(Options{Config: cfg, Login: loginSvc, Tokens: tokenSvc, Resources: resourceSvc, Permissions: permissionSvc, State: mem, JWKS: mem, Device: fakeDevice{}}), mem
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

func TestSecurityHeadersAreSet(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	srv, mem := newHTTPTestServer(nil, fakeIDP{})
	u := mem.AddTestUser(model.User{Provider: "google", Issuer: "https://accounts.google.com", Subject: "sub", Email: "alice@example.com"})
	sess, err := mem.CreateBrowserSession(ctx, u.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	htmlReq := httptest.NewRequest(http.MethodGet, "/tokens", nil)
	htmlReq.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	htmlRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(htmlRR, htmlReq)
	if htmlRR.Code != http.StatusOK {
		t.Fatalf("html status = %d, want %d body=%s", htmlRR.Code, http.StatusOK, htmlRR.Body.String())
	}
	assertSecurityHeaders(t, htmlRR)

	jwksReq := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	jwksRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(jwksRR, jwksReq)
	if got := jwksRR.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("JWKS Content-Type = %q, want application/json", got)
	}
	assertSecurityHeaders(t, jwksRR)
}

func TestLoginRedirectsToSingleDefaultProvider(t *testing.T) {
	t.Parallel()
	srv, _ := newHTTPTestServer(nil, fakeIDP{})
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rr := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d body=%s", rr.Code, http.StatusFound, rr.Body.String())
	}
	if got := rr.Header().Get("Location"); got != "/auth/google/start" {
		t.Fatalf("Location = %q, want /auth/google/start", got)
	}
}

func TestGoogleStartAliasCreatesProviderBoundState(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	srv, mem := newHTTPTestServer(nil, fakeIDP{})
	_, sess, err := mem.CreateAuthSession(ctx, "client-state", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth/google/start?login_nonce="+sess.LoginURLNonce, nil)
	rr := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d body=%s", rr.Code, http.StatusFound, rr.Body.String())
	}
	redirect, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	state := redirect.Query().Get("state")
	if state == "" {
		t.Fatalf("redirect missing state: %s", redirect.String())
	}
	loginState, err := mem.ConsumeLoginState(ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	if loginState.ProviderID != "google" || loginState.LoginURLNonce != sess.LoginURLNonce {
		t.Fatalf("unexpected login state: %#v", loginState)
	}
}

func TestLoginShowsProviderPickerForMultipleProviders(t *testing.T) {
	t.Parallel()
	srv, _ := newHTTPTestServerWithIDPs(nil,
		fakeIDP{},
		fakeIDP{descriptor: ports.IdentityProviderDescriptor{ID: "keycloak-prod", Type: "oidc", DisplayName: "Company SSO", Issuer: "https://sso.example.com/realms/prod"}, authURL: "https://sso.example.com/auth"},
	)
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rr := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "Company SSO") || !strings.Contains(rr.Body.String(), "/auth/keycloak-prod/start") {
		t.Fatalf("provider picker missing keycloak provider: %s", rr.Body.String())
	}
}

func TestUnknownProviderStartIsNotFound(t *testing.T) {
	t.Parallel()
	srv, _ := newHTTPTestServer(nil, fakeIDP{})
	req := httptest.NewRequest(http.MethodGet, "/auth/missing/start", nil)
	rr := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d body=%s", rr.Code, http.StatusNotFound, rr.Body.String())
	}
}

func TestUnknownProviderStartDoesNotCreateLoginState(t *testing.T) {
	t.Parallel()
	srv, mem := newHTTPTestServer(nil, fakeIDP{})
	counting := &countingLoginStateStore{Store: mem}
	srv.state = counting
	req := httptest.NewRequest(http.MethodGet, "/auth/missing/start", nil)
	rr := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d body=%s", rr.Code, http.StatusNotFound, rr.Body.String())
	}
	if counting.createLoginStateCalls != 0 {
		t.Fatalf("CreateLoginState called %d time(s), want 0", counting.createLoginStateCalls)
	}
}

func TestGoogleStartAliasDoesNotCreateLoginStateWithoutGoogleProvider(t *testing.T) {
	t.Parallel()
	srv, mem := newHTTPTestServerWithIDPs(nil,
		fakeIDP{descriptor: ports.IdentityProviderDescriptor{ID: "keycloak-prod", Type: "oidc", DisplayName: "Company SSO", Issuer: "https://sso.example.com/realms/prod"}, authURL: "https://sso.example.com/auth"},
	)
	counting := &countingLoginStateStore{Store: mem}
	srv.state = counting
	req := httptest.NewRequest(http.MethodGet, "/oauth/google/start", nil)
	rr := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d body=%s", rr.Code, http.StatusNotFound, rr.Body.String())
	}
	if counting.createLoginStateCalls != 0 {
		t.Fatalf("CreateLoginState called %d time(s), want 0", counting.createLoginStateCalls)
	}
}

func TestAuthStartUsesDistinctStateAndNonce(t *testing.T) {
	t.Parallel()
	srv, _ := newHTTPTestServer(nil, fakeIDP{})
	req := httptest.NewRequest(http.MethodGet, "/auth/google/start", nil)
	rr := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d body=%s", rr.Code, http.StatusFound, rr.Body.String())
	}
	redirect, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	state := redirect.Query().Get("state")
	nonce := redirect.Query().Get("nonce")
	if state == "" || nonce == "" {
		t.Fatalf("redirect missing state or nonce: %s", redirect.String())
	}
	if state == nonce {
		t.Fatalf("state and nonce must be distinct, both were %q", state)
	}
}

func TestAuthCallbackRejectsStateProviderMismatch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	srv, mem := newHTTPTestServerWithIDPs(nil,
		fakeIDP{},
		fakeIDP{descriptor: ports.IdentityProviderDescriptor{ID: "keycloak-prod", Type: "oidc", DisplayName: "Company SSO", Issuer: "https://sso.example.com/realms/prod"}, authURL: "https://sso.example.com/auth"},
	)
	state, _, err := mem.CreateLoginState(ctx, model.LoginStateInput{ProviderID: "google"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/keycloak-prod/callback?state="+state+"&code=code", nil)
	rr := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d body=%s", rr.Code, http.StatusBadRequest, rr.Body.String())
	}
}

func TestGoogleCallbackCreatesSessionForRegisteredUser(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	srv, mem := newHTTPTestServer(nil, fakeIDP{id: model.Identity{Provider: "google", Issuer: "https://accounts.google.com", Subject: "sub", Email: "alice@example.com"}})
	mem.AddTestUser(model.User{Provider: "google", Issuer: "https://accounts.google.com", Subject: "sub", Email: "alice@example.com"})
	state, _, err := mem.CreateLoginState(ctx, model.LoginStateInput{ProviderID: "google"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/oauth/google/callback?state="+state+"&code=code", nil)
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
	ctx := context.Background()
	srv, mem := newHTTPTestServer(nil, fakeIDP{id: model.Identity{Provider: "google", Issuer: "https://accounts.google.com", Subject: "sub", Email: "new@example.com"}})
	state, _, err := mem.CreateLoginState(ctx, model.LoginStateInput{ProviderID: "google"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth/google/callback?state="+state+"&code=code", nil)
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
	ctx := context.Background()
	srv, mem := newHTTPTestServer(nil, fakeIDP{id: model.Identity{Provider: "google", Issuer: "https://accounts.google.com", Subject: "sub", Email: "alice@example.com"}})
	mem.AddTestUser(model.User{Provider: "google", Issuer: "https://accounts.google.com", Subject: "sub", Email: "alice@example.com", Status: "disabled"})
	state, _, err := mem.CreateLoginState(ctx, model.LoginStateInput{ProviderID: "google"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth/google/callback?state="+state+"&code=code", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d body=%s", rr.Code, http.StatusForbidden, rr.Body.String())
	}
}

func TestGoogleCallbackLoginSessionStoreFailureIsInternal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	srv, mem := newHTTPTestServer(nil, fakeIDP{id: model.Identity{Provider: "google", Issuer: "https://accounts.google.com", Subject: "sub", Email: "alice@example.com"}})
	mem.AddTestUser(model.User{Provider: "google", Issuer: "https://accounts.google.com", Subject: "sub", Email: "alice@example.com"})
	idps := idpregistry.New("google")
	if err := idps.Register(fakeIDP{id: model.Identity{Provider: "google", Issuer: "https://accounts.google.com", Subject: "sub", Email: "alice@example.com"}}); err != nil {
		t.Fatal(err)
	}
	srv.login = service.NewLoginService(service.LoginConfig{PublicBaseURL: srv.cfg.Server.PublicBaseURL, SessionTTL: time.Hour}, idps, mem, failingNonceState{Store: mem}, srv.tokens)
	state, _, err := mem.CreateLoginState(ctx, model.LoginStateInput{ProviderID: "google", LoginURLNonce: "nonce"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/oauth/google/callback?state="+state+"&code=code", nil)
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

	getReq := httptest.NewRequest(http.MethodGet, "/tokens", nil)
	getReq.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	getRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(getRR, getReq)
	token := hiddenInputValue(t, getRR.Body.String(), "csrf_token")

	req := httptest.NewRequest(http.MethodPost, "/tokens/mint", strings.NewReader("repository=game-assets&csrf_token="+token))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://auth.example.com")
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

func TestTokenMintRequiresCSRFAndSameOrigin(t *testing.T) {
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

	missing := httptest.NewRequest(http.MethodPost, "/tokens/mint", strings.NewReader("repository=game-assets"))
	missing.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	missing.Header.Set("Origin", "https://auth.example.com")
	missing.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	missingRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(missingRR, missing)
	if missingRR.Code != http.StatusForbidden {
		t.Fatalf("missing csrf status = %d, want %d body=%s", missingRR.Code, http.StatusForbidden, missingRR.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/tokens", nil)
	getReq.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	getRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(getRR, getReq)
	token := hiddenInputValue(t, getRR.Body.String(), "csrf_token")

	badOrigin := httptest.NewRequest(http.MethodPost, "/tokens/mint", strings.NewReader("repository=game-assets&csrf_token="+token))
	badOrigin.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	badOrigin.Header.Set("Origin", "https://evil.example.com")
	badOrigin.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	badOriginRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(badOriginRR, badOrigin)
	if badOriginRR.Code != http.StatusForbidden {
		t.Fatalf("bad origin status = %d, want %d body=%s", badOriginRR.Code, http.StatusForbidden, badOriginRR.Body.String())
	}

	good := httptest.NewRequest(http.MethodPost, "/tokens/mint", strings.NewReader("repository=game-assets&csrf_token="+token))
	good.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	good.Header.Set("Origin", "https://auth.example.com")
	good.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	goodRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(goodRR, good)
	if goodRR.Code != http.StatusOK {
		t.Fatalf("good mint status = %d, want %d body=%s", goodRR.Code, http.StatusOK, goodRR.Body.String())
	}
	if !strings.Contains(goodRR.Body.String(), "lore auth login") {
		t.Fatalf("missing login command: %s", goodRR.Body.String())
	}

	reuse := httptest.NewRequest(http.MethodPost, "/tokens/mint", strings.NewReader("repository=game-assets&csrf_token="+token))
	reuse.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reuse.Header.Set("Origin", "https://auth.example.com")
	reuse.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	reuseRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(reuseRR, reuse)
	if reuseRR.Code != http.StatusForbidden {
		t.Fatalf("csrf reuse status = %d, want %d body=%s", reuseRR.Code, http.StatusForbidden, reuseRR.Body.String())
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

	getReq := httptest.NewRequest(http.MethodGet, "/tokens", nil)
	getReq.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	getRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(getRR, getReq)
	token := hiddenInputValue(t, getRR.Body.String(), "csrf_token")

	req := httptest.NewRequest(http.MethodPost, "/tokens/mint", strings.NewReader("repository=game-assets&csrf_token="+token))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://auth.example.com")
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

func TestTokenPageShowsOnlyWriterAccessibleRepositories(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	srv, mem := newHTTPTestServer(nil, fakeIDP{})
	u := mem.AddTestUser(model.User{Provider: "google", Issuer: "https://accounts.google.com", Subject: "sub", Email: "alice@example.com"})
	writer := mem.AddTestResource(model.Resource{Name: "writer-repo", RemoteURL: "lore://writer", LoreRepositoryID: "writer-id"})
	reader := mem.AddTestResource(model.Resource{Name: "reader-repo", RemoteURL: "lore://reader", LoreRepositoryID: "reader-id"})
	mem.AddTestResource(model.Resource{Name: "ungranted-repo", RemoteURL: "lore://ungranted", LoreRepositoryID: "ungranted-id"})
	mem.GrantRole(u.ID, writer.ResourceID, model.RoleWriter)
	mem.GrantRole(u.ID, reader.ResourceID, model.RoleReader)
	sess, err := mem.CreateBrowserSession(ctx, u.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/tokens", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "writer-repo") {
		t.Fatalf("writer repository missing from token page: %s", body)
	}
	if strings.Contains(body, "reader-repo") || strings.Contains(body, "ungranted-repo") {
		t.Fatalf("token page exposed inaccessible repository: %s", body)
	}
}

func TestTokenPageListsRepositoriesWithoutPerPermissionLookups(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	srv, mem := newHTTPTestServer(nil, fakeIDP{})
	u := mem.AddTestUser(model.User{Provider: "google", Issuer: "https://accounts.google.com", Subject: "sub", Email: "alice@example.com"})
	first := mem.AddTestResource(model.Resource{Name: "first-repo", RemoteURL: "lore://first", LoreRepositoryID: "first-id"})
	second := mem.AddTestResource(model.Resource{Name: "second-repo", RemoteURL: "lore://second", LoreRepositoryID: "second-id"})
	mem.GrantRole(u.ID, first.ResourceID, model.RoleWriter)
	mem.GrantRole(u.ID, second.ResourceID, model.RoleWriter)
	counting := &countingResourceStore{Store: mem}
	srv.resources = service.NewResourceService(counting)
	sess, err := mem.CreateBrowserSession(ctx, u.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/tokens", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if counting.listCalls != 1 {
		t.Fatalf("List called %d time(s), want 1", counting.listCalls)
	}
	if counting.getByResourceIDCalls != 0 {
		t.Fatalf("GetByResourceID called %d time(s), want 0", counting.getByResourceIDCalls)
	}
}

func TestLogoutRequiresCSRFAndSameOrigin(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	srv, mem := newHTTPTestServer(nil, fakeIDP{})
	u := mem.AddTestUser(model.User{Provider: "google", Issuer: "https://accounts.google.com", Subject: "sub", Email: "alice@example.com"})
	sess, err := mem.CreateBrowserSession(ctx, u.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	missing := httptest.NewRequest(http.MethodPost, "/api/logout", nil)
	missing.Header.Set("Origin", "https://auth.example.com")
	missing.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	missingRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(missingRR, missing)
	if missingRR.Code != http.StatusForbidden {
		t.Fatalf("missing csrf status = %d, want %d body=%s", missingRR.Code, http.StatusForbidden, missingRR.Body.String())
	}
	assertSessionStillValid(t, srv, sess.ID)

	token, err := mem.CreateCSRFToken(ctx, sess.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	badOrigin := httptest.NewRequest(http.MethodPost, "/api/logout", nil)
	badOrigin.Header.Set("Origin", "https://evil.example.com")
	badOrigin.Header.Set("X-CSRF-Token", token)
	badOrigin.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	badOriginRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(badOriginRR, badOrigin)
	if badOriginRR.Code != http.StatusForbidden {
		t.Fatalf("bad origin status = %d, want %d body=%s", badOriginRR.Code, http.StatusForbidden, badOriginRR.Body.String())
	}
	assertSessionStillValid(t, srv, sess.ID)

	good := httptest.NewRequest(http.MethodPost, "/api/logout", nil)
	good.Header.Set("Origin", "https://auth.example.com")
	good.Header.Set("X-CSRF-Token", token)
	good.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	goodRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(goodRR, good)
	if goodRR.Code != http.StatusNoContent {
		t.Fatalf("good logout status = %d, want %d body=%s", goodRR.Code, http.StatusNoContent, goodRR.Body.String())
	}

	me := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	me.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	meRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(meRR, me)
	if meRR.Code != http.StatusUnauthorized {
		t.Fatalf("session still valid after logout: status=%d body=%s", meRR.Code, meRR.Body.String())
	}
}

func TestSessionCSRFEndpointIssuesNoStoreToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	srv, mem := newHTTPTestServer(nil, fakeIDP{})
	u := mem.AddTestUser(model.User{Provider: "google", Issuer: "https://accounts.google.com", Subject: "sub", Email: "alice@example.com"})
	sess, err := mem.CreateBrowserSession(ctx, u.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/session/csrf", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	var body struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.CSRFToken == "" {
		t.Fatalf("missing csrf token: %s", rr.Body.String())
	}

	logout := httptest.NewRequest(http.MethodPost, "/api/logout", nil)
	logout.Header.Set("Origin", "https://auth.example.com")
	logout.Header.Set("X-CSRF-Token", body.CSRFToken)
	logout.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	logoutRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(logoutRR, logout)
	if logoutRR.Code != http.StatusNoContent {
		t.Fatalf("logout status = %d, want %d body=%s", logoutRR.Code, http.StatusNoContent, logoutRR.Body.String())
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

func TestPublicHTTPEndpointsAreRateLimitedByPeer(t *testing.T) {
	t.Parallel()
	srv, _ := newHTTPTestServer(nil, fakeIDP{})

	var last *httptest.ResponseRecorder
	for i := 0; i < 65; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/device/start", strings.NewReader(`{"remote_url":"lore://example","repository":"game-assets"}`))
		req.RemoteAddr = "203.0.113.10:12345"
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)
		last = rr
	}
	if last.Code != http.StatusTooManyRequests {
		t.Fatalf("last same-peer status = %d, want %d body=%s", last.Code, http.StatusTooManyRequests, last.Body.String())
	}

	otherPeer := httptest.NewRequest(http.MethodPost, "/api/device/start", strings.NewReader(`{"remote_url":"lore://example","repository":"game-assets"}`))
	otherPeer.RemoteAddr = "203.0.113.11:12345"
	otherPeer.Header.Set("Content-Type", "application/json")
	otherPeerRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(otherPeerRR, otherPeer)
	if otherPeerRR.Code != http.StatusOK {
		t.Fatalf("other peer status = %d, want %d body=%s", otherPeerRR.Code, http.StatusOK, otherPeerRR.Body.String())
	}
}

func TestDeviceJSONEndpointsRejectUnknownFieldsAndLargeBodies(t *testing.T) {
	t.Parallel()
	srv, _ := newHTTPTestServer(nil, fakeIDP{})

	unknownReq := httptest.NewRequest(http.MethodPost, "/api/device/start", strings.NewReader(`{"remote_url":"lore://example","repository":"game-assets","extra":true}`))
	unknownReq.Header.Set("Content-Type", "application/json")
	unknownRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(unknownRR, unknownReq)
	if unknownRR.Code != http.StatusBadRequest {
		t.Fatalf("unknown field status = %d, want %d body=%s", unknownRR.Code, http.StatusBadRequest, unknownRR.Body.String())
	}

	largeReq := httptest.NewRequest(http.MethodPost, "/api/device/token", strings.NewReader(`{"device_code":"`+strings.Repeat("A", maxJSONBodyBytes)+`"}`))
	largeReq.Header.Set("Content-Type", "application/json")
	largeRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(largeRR, largeReq)
	if largeRR.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large body status = %d, want %d body=%s", largeRR.Code, http.StatusRequestEntityTooLarge, largeRR.Body.String())
	}
}

func TestFormEndpointsRejectLargeBodies(t *testing.T) {
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

	tokenReq := httptest.NewRequest(http.MethodGet, "/tokens", nil)
	tokenReq.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	tokenRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(tokenRR, tokenReq)
	mintCSRF := hiddenInputValue(t, tokenRR.Body.String(), "csrf_token")

	largeMint := httptest.NewRequest(http.MethodPost, "/tokens/mint", strings.NewReader("repository="+strings.Repeat("A", maxJSONBodyBytes)+"&csrf_token="+mintCSRF))
	largeMint.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	largeMint.Header.Set("Origin", "https://auth.example.com")
	largeMint.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	largeMintRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(largeMintRR, largeMint)
	if largeMintRR.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large mint status = %d, want %d body=%s", largeMintRR.Code, http.StatusRequestEntityTooLarge, largeMintRR.Body.String())
	}

	deviceReq := httptest.NewRequest(http.MethodGet, "/device?user_code=ABCD-EFGH", nil)
	deviceReq.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	deviceRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(deviceRR, deviceReq)
	deviceCSRF := hiddenInputValue(t, deviceRR.Body.String(), "csrf_token")

	largeDevice := httptest.NewRequest(http.MethodPost, "/device/approve", strings.NewReader("user_code="+strings.Repeat("A", maxJSONBodyBytes)+"&csrf_token="+deviceCSRF))
	largeDevice.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	largeDevice.Header.Set("Origin", "https://auth.example.com")
	largeDevice.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	largeDeviceRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(largeDeviceRR, largeDevice)
	if largeDeviceRR.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large device status = %d, want %d body=%s", largeDeviceRR.Code, http.StatusRequestEntityTooLarge, largeDeviceRR.Body.String())
	}

	largeLogout := httptest.NewRequest(http.MethodPost, "/api/logout", strings.NewReader("csrf_token="+strings.Repeat("A", maxJSONBodyBytes)))
	largeLogout.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	largeLogout.Header.Set("Origin", "https://auth.example.com")
	largeLogout.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	largeLogoutRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(largeLogoutRR, largeLogout)
	if largeLogoutRR.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large logout status = %d, want %d body=%s", largeLogoutRR.Code, http.StatusRequestEntityTooLarge, largeLogoutRR.Body.String())
	}
	assertSessionStillValid(t, srv, sess.ID)
}

func TestDeviceGetShowsConfirmationWithoutApproving(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	srv, mem := newHTTPTestServer(nil, fakeIDP{})
	u := mem.AddTestUser(model.User{Provider: "google", Issuer: "https://accounts.google.com", Subject: "sub", Email: "alice@example.com"})
	sess, err := mem.CreateBrowserSession(ctx, u.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	srv.device = fakeDevice{approveCalls: &calls}

	req := httptest.NewRequest(http.MethodGet, "/device?user_code=ABCD-EFGH", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if calls != 0 {
		t.Fatalf("GET /device approved %d time(s), want 0", calls)
	}
	if !strings.Contains(rr.Body.String(), "lore://requested.example/repo") || !strings.Contains(rr.Body.String(), "game-assets") {
		t.Fatalf("confirmation missing repository or requested remote: %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `name="csrf_token"`) {
		t.Fatalf("confirmation missing csrf token: %s", rr.Body.String())
	}
}

func TestDeviceApprovePostRequiresCSRFAndSameOrigin(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	srv, mem := newHTTPTestServer(nil, fakeIDP{})
	u := mem.AddTestUser(model.User{Provider: "google", Issuer: "https://accounts.google.com", Subject: "sub", Email: "alice@example.com"})
	sess, err := mem.CreateBrowserSession(ctx, u.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	srv.device = fakeDevice{approveCalls: &calls}

	req := httptest.NewRequest(http.MethodPost, "/device/approve", strings.NewReader("user_code=ABCD-EFGH"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://auth.example.com")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("missing csrf status = %d, want %d body=%s", rr.Code, http.StatusForbidden, rr.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/device?user_code=ABCD-EFGH", nil)
	getReq.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	getRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(getRR, getReq)
	token := hiddenInputValue(t, getRR.Body.String(), "csrf_token")

	badOrigin := httptest.NewRequest(http.MethodPost, "/device/approve", strings.NewReader("user_code=ABCD-EFGH&csrf_token="+token))
	badOrigin.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	badOrigin.Header.Set("Origin", "https://evil.example.com")
	badOrigin.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	badOriginRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(badOriginRR, badOrigin)
	if badOriginRR.Code != http.StatusForbidden {
		t.Fatalf("bad origin status = %d, want %d body=%s", badOriginRR.Code, http.StatusForbidden, badOriginRR.Body.String())
	}

	good := httptest.NewRequest(http.MethodPost, "/device/approve", strings.NewReader("user_code=ABCD-EFGH&csrf_token="+token))
	good.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	good.Header.Set("Origin", "https://auth.example.com")
	good.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	goodRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(goodRR, good)
	if goodRR.Code != http.StatusOK {
		t.Fatalf("good approval status = %d, want %d body=%s", goodRR.Code, http.StatusOK, goodRR.Body.String())
	}
	if calls != 1 {
		t.Fatalf("Approve called %d time(s), want 1", calls)
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
	state, _, err := mem.CreateLoginState(ctx, model.LoginStateInput{ProviderID: "google", LoginURLNonce: sess.LoginURLNonce}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth/google/callback?state="+state+"&code=code", nil)
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

type countingLoginStateStore struct {
	*memory.Store
	createLoginStateCalls int
}

func (s *countingLoginStateStore) CreateLoginState(ctx context.Context, input model.LoginStateInput, ttl time.Duration) (string, model.LoginState, error) {
	s.createLoginStateCalls++
	return s.Store.CreateLoginState(ctx, input, ttl)
}

type countingResourceStore struct {
	*memory.Store
	getByResourceIDCalls int
	listCalls            int
}

func (s *countingResourceStore) GetByResourceID(ctx context.Context, resourceID string) (model.Resource, error) {
	s.getByResourceIDCalls++
	return s.Store.GetByResourceID(ctx, resourceID)
}

func (s *countingResourceStore) List(ctx context.Context) ([]model.Resource, error) {
	s.listCalls++
	return s.Store.List(ctx)
}

type failingBrowserSessionState struct {
	*memory.Store
}

func (s failingBrowserSessionState) UserByBrowserSession(ctx context.Context, sessionID string) (model.User, error) {
	return model.User{}, errors.New("session store failed")
}

func hiddenInputValue(t *testing.T, html, name string) string {
	t.Helper()
	marker := `name="` + name + `"`
	i := strings.Index(html, marker)
	if i < 0 {
		t.Fatalf("missing hidden input %q in %s", name, html)
	}
	v := strings.Index(html[i:], `value="`)
	if v < 0 {
		t.Fatalf("missing value for input %q in %s", name, html)
	}
	start := i + v + len(`value="`)
	end := strings.Index(html[start:], `"`)
	if end < 0 {
		t.Fatalf("unterminated value for input %q in %s", name, html)
	}
	return html[start : start+end]
}

func assertSessionStillValid(t *testing.T, srv *Server, sessionID string) {
	t.Helper()
	me := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	me.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionID})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, me)
	if rr.Code != http.StatusOK {
		t.Fatalf("session was revoked unexpectedly: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func assertSecurityHeaders(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	if got := rr.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := rr.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("Referrer-Policy = %q, want no-referrer", got)
	}
	csp := rr.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "form-action 'self'", "frame-ancestors 'none'", "script-src 'none'"} {
		if !strings.Contains(csp, want) {
			t.Fatalf("Content-Security-Policy = %q, missing %q", csp, want)
		}
	}
}
