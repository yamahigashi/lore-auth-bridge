package httpserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/yamahigashi/lore-auth-bridge/internal/config"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/ports"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/service"
	"github.com/yamahigashi/lore-auth-bridge/internal/device"
	"github.com/yamahigashi/lore-auth-bridge/internal/ratelimit"
)

const (
	sessionCookieName  = "lore_auth_session"
	stateCookieName    = "lore_oauth_state"
	loginSessionCookie = "lore_login_session"
	maxJSONBodyBytes   = 64 * 1024
	loginStateTTL      = 10 * time.Minute
)

type Server struct {
	cfg       *config.Config
	login     *service.LoginService
	tokens    *service.TokenService
	resources *service.ResourceService
	perms     *service.PermissionService
	state     ports.StateStore
	jwks      ports.TokenSigner
	device    DeviceService
	mux       *http.ServeMux
	limiter   *ratelimit.Limiter
}

type Options struct {
	Config      *config.Config
	Login       *service.LoginService
	Tokens      *service.TokenService
	Resources   *service.ResourceService
	Permissions *service.PermissionService
	State       ports.StateStore
	JWKS        ports.TokenSigner
	Device      DeviceService
}

type DeviceService interface {
	Start(ctx context.Context, remoteURL, repoName string) (*device.StartResult, error)
	Preview(ctx context.Context, userCode string) (*device.PreviewResult, error)
	Approve(ctx context.Context, userEmailOrID, userCode string) (*device.Repository, error)
	Token(ctx context.Context, deviceCode string) (*device.TokenResult, error)
}

func NewWithOptions(opts Options) *Server {
	s := &Server{cfg: opts.Config, login: opts.Login, tokens: opts.Tokens, resources: opts.Resources, perms: opts.Permissions, state: opts.State, jwks: opts.JWKS, device: opts.Device, mux: http.NewServeMux(), limiter: ratelimit.New(60, time.Minute)}
	if s.cfg == nil {
		s.cfg = &config.Config{}
		s.cfg.Security.SessionTTLSeconds = 3600
	}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler { return securityHeaders(s.rateLimitPublic(s.mux)) }

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; script-src 'none'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) rateLimitPublic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isRateLimitedHTTPPath(r.URL.Path) && !s.limiter.Allow(peerHost(r.RemoteAddr)) {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isRateLimitedHTTPPath(path string) bool {
	switch {
	case path == "/api/device/start", path == "/api/device/token", path == "/login":
		return true
	case strings.HasPrefix(path, "/auth/") && strings.HasSuffix(path, "/start"):
		return true
	default:
		return false
	}
}

func peerHost(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil && host != "" {
		return host
	}
	return remoteAddr
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /.well-known/jwks.json", s.handleJWKS)
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	s.mux.HandleFunc("GET /", s.handleIndex)
	s.mux.HandleFunc("GET /login", s.handleLogin)
	s.mux.HandleFunc("GET /auth/{provider}/start", s.handleAuthStart)
	s.mux.HandleFunc("GET /auth/{provider}/callback", s.handleAuthCallback)
	s.mux.HandleFunc("GET /login/session/{nonce}", s.handleLoginSession)
	s.mux.HandleFunc("GET /whoami", s.handleWhoami)
	s.mux.HandleFunc("GET /api/me", s.handleMe)
	s.mux.HandleFunc("GET /api/session/csrf", s.handleSessionCSRF)
	s.mux.HandleFunc("POST /api/logout", s.handleLogout)
	s.mux.HandleFunc("GET /tokens", s.handleTokenPage)
	s.mux.HandleFunc("POST /tokens/mint", s.handleTokenMint)
	s.mux.HandleFunc("GET /device", s.handleDevicePage)
	s.mux.HandleFunc("POST /device/approve", s.handleDeviceApprove)
	s.mux.HandleFunc("POST /api/device/start", s.handleDeviceStart)
	s.mux.HandleFunc("POST /api/device/token", s.handleDeviceToken)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	u, ok, err := s.currentUser(r)
	if err != nil {
		slog.Error("browser session lookup failed", "route", "/", "error", err)
		http.Error(w, "session unavailable", http.StatusInternalServerError)
		return
	}
	if ok {
		_, _ = fmt.Fprintf(w, "lore-auth-bridge\nlogged in as %s\n", stringOr(u.Email, u.BridgeSubject()))
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("lore-auth-bridge\nGET /login\n"))
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	body, err := s.jwks.JWKS(ctx)
	if err != nil {
		slog.Error("jwks failed", "error", err)
		http.Error(w, "jwks unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(body); err != nil {
		slog.Error("encode jwks failed", "error", err)
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.login == nil {
		http.Error(w, "identity provider login not configured", http.StatusServiceUnavailable)
		return
	}
	if providerID := r.URL.Query().Get("provider"); providerID != "" {
		http.Redirect(w, r, authStartPath(providerID, ""), http.StatusFound)
		return
	}
	providers := s.login.Providers()
	if len(providers) == 0 {
		http.Error(w, "identity provider login not configured", http.StatusServiceUnavailable)
		return
	}
	if len(providers) == 1 {
		http.Redirect(w, r, authStartPath(providers[0].ID, ""), http.StatusFound)
		return
	}
	renderProviderPicker(w, providers, "")
}

// handleLoginSession ties a CLI-initiated interactive login (StartAuthSession)
// to the selected identity provider. The OAuth state binds the provider and
// login nonce, so the callback does not trust browser cookies for that link.
func (s *Server) handleLoginSession(w http.ResponseWriter, r *http.Request) {
	if s.login == nil {
		http.Error(w, "identity provider login not configured", http.StatusServiceUnavailable)
		return
	}
	nonce := r.PathValue("nonce")
	if _, err := s.state.GetAuthSessionByNonce(r.Context(), nonce); err != nil {
		if !errors.Is(err, model.ErrNotFound) {
			slog.Error("login session lookup failed", "error", err)
			http.Error(w, "login session unavailable", http.StatusInternalServerError)
			return
		}
		http.Error(w, "unknown or expired login session", http.StatusNotFound)
		return
	}
	if providerID := r.URL.Query().Get("provider"); providerID != "" {
		http.Redirect(w, r, authStartPath(providerID, nonce), http.StatusFound)
		return
	}
	providers := s.login.Providers()
	if len(providers) == 0 {
		http.Error(w, "identity provider login not configured", http.StatusServiceUnavailable)
		return
	}
	if len(providers) == 1 {
		http.Redirect(w, r, authStartPath(providers[0].ID, nonce), http.StatusFound)
		return
	}
	renderProviderPicker(w, providers, nonce)
}

func (s *Server) handleAuthStart(w http.ResponseWriter, r *http.Request) {
	s.startAuthProvider(w, r, r.PathValue("provider"))
}

func (s *Server) startAuthProvider(w http.ResponseWriter, r *http.Request, providerID string) {
	if s.login == nil {
		http.Error(w, "identity provider login not configured", http.StatusServiceUnavailable)
		return
	}
	if !s.login.HasProvider(providerID) {
		http.Error(w, "unknown identity provider", http.StatusNotFound)
		return
	}
	loginNonce := r.URL.Query().Get("login_nonce")
	if loginNonce != "" {
		if _, err := s.state.GetAuthSessionByNonce(r.Context(), loginNonce); err != nil {
			if !errors.Is(err, model.ErrNotFound) {
				slog.Error("login session lookup failed", "error", err)
				http.Error(w, "login session unavailable", http.StatusInternalServerError)
				return
			}
			http.Error(w, "unknown or expired login session", http.StatusNotFound)
			return
		}
	}
	nonce, err := randomURLToken(32)
	if err != nil {
		slog.Error("oidc nonce generation failed", "provider", providerID, "error", err)
		http.Error(w, "state failed", http.StatusInternalServerError)
		return
	}
	state, _, err := s.state.CreateLoginState(r.Context(), model.LoginStateInput{ProviderID: providerID, Nonce: nonce, LoginURLNonce: loginNonce}, loginStateTTL)
	if err != nil {
		slog.Error("oauth state generation failed", "provider", providerID, "error", err)
		http.Error(w, "state failed", http.StatusInternalServerError)
		return
	}
	res, err := s.login.BeginAuth(r.Context(), providerID, ports.BeginAuthRequest{State: state, Nonce: nonce, RedirectURL: s.authCallbackURL(providerID)})
	if err != nil {
		writeLoginProviderError(w, err)
		return
	}
	if len(res.PrivateState) > 0 {
		if err := s.state.SetLoginStatePrivateState(r.Context(), state, res.PrivateState); err != nil {
			slog.Error("oauth private state persistence failed", "provider", providerID, "error", err)
			http.Error(w, "state failed", http.StatusInternalServerError)
			return
		}
	}
	http.Redirect(w, r, res.RedirectURL, http.StatusFound)
}

func (s *Server) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	s.completeAuthProvider(w, r, r.PathValue("provider"))
}

func (s *Server) completeAuthProvider(w http.ResponseWriter, r *http.Request, providerID string) {
	if s.login == nil {
		http.Error(w, "identity provider login not configured", http.StatusServiceUnavailable)
		return
	}
	state := r.URL.Query().Get("state")
	loginState, err := s.state.ConsumeLoginState(r.Context(), state)
	if err != nil || state == "" {
		http.Error(w, "invalid oauth state", http.StatusBadRequest)
		return
	}
	if loginState.ProviderID != providerID {
		http.Error(w, "invalid oauth state", http.StatusBadRequest)
		return
	}
	clearCookie(w, stateCookieName)
	res, err := s.login.CompleteAuth(r.Context(), providerID, ports.CompleteAuthRequest{Code: r.URL.Query().Get("code"), State: state, Nonce: loginState.Nonce, RedirectURL: s.authCallbackURL(providerID), Params: r.URL.Query(), PrivateState: loginState.PrivateState}, loginState.LoginURLNonce)
	if err != nil {
		switch {
		case errors.Is(err, model.ErrUnsupported):
			http.Error(w, "identity provider login not configured", http.StatusServiceUnavailable)
		case errors.Is(err, model.ErrNotFound):
			http.Error(w, "unknown identity provider", http.StatusNotFound)
		case errors.Is(err, model.ErrPermissionDenied):
			http.Error(w, "login forbidden", http.StatusForbidden)
		case errors.Is(err, model.ErrUnauthenticated):
			http.Error(w, "identity provider login failed", http.StatusUnauthorized)
		default:
			slog.Error("identity provider callback failed", "provider", providerID, "error", err)
			http.Error(w, "login unavailable", http.StatusInternalServerError)
		}
		return
	}
	if res.UnknownUser {
		renderWhoami(w, res.Identity)
		return
	}
	if res.CLIComplete {
		clearCookie(w, loginSessionCookie)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<h1>Login complete</h1><p>You can return to the Lore CLI.</p>"))
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: res.BrowserSession.ID, Path: "/", HttpOnly: true, Secure: isSecure(r), SameSite: http.SameSiteLaxMode, Expires: time.Unix(res.BrowserSession.ExpiresAt, 0)})
	http.Redirect(w, r, "/", http.StatusFound)
}

func randomURLToken(byteLen int) (string, error) {
	raw := make([]byte, byteLen)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (s *Server) handleTokenPage(w http.ResponseWriter, r *http.Request) {
	u, sessionID, ok, err := s.currentBrowserSession(r)
	if err != nil {
		slog.Error("browser session lookup failed", "route", "/tokens", "error", err)
		http.Error(w, "session unavailable", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if s.perms == nil {
		http.Error(w, "permissions unavailable", http.StatusInternalServerError)
		return
	}
	accessible, err := s.perms.Lookup(r.Context(), u.ID, model.ResourceFilter{})
	if err != nil {
		slog.Error("permission list failed", "route", "/tokens", "error", err)
		http.Error(w, "repositories unavailable", http.StatusInternalServerError)
		return
	}
	resources, err := s.resources.List(r.Context())
	if err != nil {
		slog.Error("repository list failed", "route", "/tokens", "error", err)
		http.Error(w, "repositories unavailable", http.StatusInternalServerError)
		return
	}
	resourcesByID := make(map[string]model.Resource, len(resources))
	for _, resource := range resources {
		resourcesByID[resource.ResourceID] = resource
	}
	repos := make([]model.Resource, 0, len(accessible))
	for _, perm := range accessible {
		if !hasPermission(perm.Permission, model.PermissionWrite) {
			continue
		}
		resource, ok := resourcesByID[perm.ResourceID]
		if !ok {
			continue
		}
		repos = append(repos, resource)
	}
	csrfToken, err := s.state.CreateCSRFToken(r.Context(), sessionID, 10*time.Minute)
	if err != nil {
		slog.Error("csrf token generation failed", "route", "/tokens", "error", err)
		http.Error(w, "token page unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tokenPageTemplate.Execute(w, struct {
		User      model.User
		Repos     []model.Resource
		CSRFToken string
	}{User: u, Repos: repos, CSRFToken: csrfToken})
}

func (s *Server) handleTokenMint(w http.ResponseWriter, r *http.Request) {
	u, sessionID, ok, err := s.currentBrowserSession(r)
	if err != nil {
		slog.Error("browser session lookup failed", "route", "/tokens/mint", "error", err)
		http.Error(w, "session unavailable", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if !s.sameOrigin(r) {
		http.Error(w, "invalid origin", http.StatusForbidden)
		return
	}
	if !parseFormBody(w, r) {
		return
	}
	csrfToken := r.FormValue("csrf_token")
	if csrfToken == "" {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return
	}
	if err := s.state.ConsumeCSRFToken(r.Context(), sessionID, csrfToken); err != nil {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return
	}
	repo := r.FormValue("repository")
	if repo == "" {
		http.Error(w, "repository is required", http.StatusBadRequest)
		return
	}
	res, err := s.tokens.ManualMintAuthz(r.Context(), u.ID, repo, "writer", 0)
	if err != nil {
		writeTokenIssueError(w, err)
		return
	}
	setTokenResponseHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tokenResultTemplate.Execute(w, struct {
		Token     string
		AuthURL   string
		RemoteURL string
		Repo      string
	}{Token: res.Token, AuthURL: s.cfg.Lore.AuthURL, RemoteURL: s.cfg.Lore.DefaultRemoteURL, Repo: repo})
}

func setTokenResponseHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func (s *Server) handleDevicePage(w http.ResponseWriter, r *http.Request) {
	if s.device == nil {
		http.Error(w, "device flow not configured", http.StatusServiceUnavailable)
		return
	}
	userCode := r.URL.Query().Get("user_code")
	if userCode == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<h1>Authorize device</h1><form method="get" action="/device"><input name="user_code" placeholder="AB12-CD34"><button type="submit">Continue</button></form>`))
		return
	}
	u, sessionID, ok, err := s.currentBrowserSession(r)
	if err != nil {
		slog.Error("browser session lookup failed", "route", "/device", "error", err)
		http.Error(w, "session unavailable", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	_ = u
	preview, err := s.device.Preview(r.Context(), userCode)
	if err != nil {
		writeDeviceError(w, "device preview", err)
		return
	}
	csrfToken, err := s.state.CreateCSRFToken(r.Context(), sessionID, 10*time.Minute)
	if err != nil {
		slog.Error("csrf token generation failed", "route", "/device", "error", err)
		http.Error(w, "device approval unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = deviceConfirmTemplate.Execute(w, struct {
		UserCode           string
		CSRFToken          string
		RepositoryName     string
		RepositoryRemote   string
		RequestedRemoteURL string
	}{
		UserCode:           userCode,
		CSRFToken:          csrfToken,
		RepositoryName:     preview.Repository.Name,
		RepositoryRemote:   preview.Repository.RemoteURL,
		RequestedRemoteURL: preview.RequestedRemoteURL,
	})
}

func (s *Server) handleDeviceApprove(w http.ResponseWriter, r *http.Request) {
	if s.device == nil {
		http.Error(w, "device flow not configured", http.StatusServiceUnavailable)
		return
	}
	u, sessionID, ok, err := s.currentBrowserSession(r)
	if err != nil {
		slog.Error("browser session lookup failed", "route", "/device/approve", "error", err)
		http.Error(w, "session unavailable", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if !s.sameOrigin(r) {
		http.Error(w, "invalid origin", http.StatusForbidden)
		return
	}
	if !parseFormBody(w, r) {
		return
	}
	userCode := r.FormValue("user_code")
	csrfToken := r.FormValue("csrf_token")
	if userCode == "" || csrfToken == "" {
		http.Error(w, "invalid device approval", http.StatusForbidden)
		return
	}
	if err := s.state.ConsumeCSRFToken(r.Context(), sessionID, csrfToken); err != nil {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return
	}
	repo, err := s.device.Approve(r.Context(), u.ID, userCode)
	if err != nil {
		writeDeviceError(w, "device approve", err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, "<h1>Device approved</h1><p>Repository: %s</p>", template.HTMLEscapeString(repo.Name))
}

func (s *Server) handleDeviceStart(w http.ResponseWriter, r *http.Request) {
	if s.device == nil {
		http.Error(w, "device flow not configured", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		RemoteURL  string `json:"remote_url"`
		Repository string `json:"repository"`
	}
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if req.RemoteURL == "" {
		req.RemoteURL = s.cfg.Lore.DefaultRemoteURL
	}
	res, err := s.device.Start(r.Context(), req.RemoteURL, req.Repository)
	if err != nil {
		writeDeviceError(w, "device start", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

func (s *Server) handleDeviceToken(w http.ResponseWriter, r *http.Request) {
	if s.device == nil {
		http.Error(w, "device flow not configured", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		DeviceCode string `json:"device_code"`
	}
	if !decodeJSONBody(w, r, &req) {
		return
	}
	res, err := s.device.Token(r.Context(), req.DeviceCode)
	if err != nil {
		writeDeviceError(w, "device token", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

func (s *Server) handleWhoami(w http.ResponseWriter, r *http.Request) {
	u, ok, err := s.currentUser(r)
	if err != nil {
		slog.Error("browser session lookup failed", "route", "/whoami", "error", err)
		http.Error(w, "session unavailable", http.StatusInternalServerError)
		return
	}
	if ok {
		identity := model.ExternalIdentity{Issuer: "bridge", Subject: u.BridgeSubject(), Email: u.Email, DisplayName: u.DisplayName}
		renderWhoami(w, identity)
		return
	}
	http.Error(w, "not logged in", http.StatusUnauthorized)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	u, ok, err := s.currentUser(r)
	if err != nil {
		slog.Error("browser session lookup failed", "route", "/api/me", "error", err)
		http.Error(w, "session unavailable", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "not logged in", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"id": u.ID, "email": u.Email, "subject": u.BridgeSubject(), "status": u.Status})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	_, sessionID, ok, err := s.currentBrowserSession(r)
	if err != nil {
		slog.Error("browser session lookup failed", "route", "/api/logout", "error", err)
		http.Error(w, "session unavailable", http.StatusInternalServerError)
		return
	}
	if ok {
		if !s.sameOrigin(r) {
			http.Error(w, "invalid origin", http.StatusForbidden)
			return
		}
		csrfToken, parsed := csrfTokenFromRequest(w, r)
		if !parsed {
			return
		}
		if csrfToken == "" {
			http.Error(w, "invalid csrf token", http.StatusForbidden)
			return
		}
		if err := s.state.ConsumeCSRFToken(r.Context(), sessionID, csrfToken); err != nil {
			http.Error(w, "invalid csrf token", http.StatusForbidden)
			return
		}
		if err := s.state.RevokeBrowserSession(r.Context(), sessionID); err != nil && !errors.Is(err, model.ErrNotFound) {
			slog.Error("browser session revoke failed", "error", err)
		}
	}
	clearCookie(w, sessionCookieName)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSessionCSRF(w http.ResponseWriter, r *http.Request) {
	_, sessionID, ok, err := s.currentBrowserSession(r)
	if err != nil {
		slog.Error("browser session lookup failed", "route", "/api/session/csrf", "error", err)
		http.Error(w, "session unavailable", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "not logged in", http.StatusUnauthorized)
		return
	}
	token, err := s.state.CreateCSRFToken(r.Context(), sessionID, 10*time.Minute)
	if err != nil {
		slog.Error("csrf token generation failed", "route", "/api/session/csrf", "error", err)
		http.Error(w, "csrf unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"csrf_token": token})
}

func csrfTokenFromRequest(w http.ResponseWriter, r *http.Request) (string, bool) {
	if token := strings.TrimSpace(r.Header.Get("X-CSRF-Token")); token != "" {
		return token, true
	}
	if !parseFormBody(w, r) {
		return "", false
	}
	return r.FormValue("csrf_token"), true
}

func (s *Server) currentUser(r *http.Request) (model.User, bool, error) {
	u, _, ok, err := s.currentBrowserSession(r)
	return u, ok, err
}

func (s *Server) currentBrowserSession(r *http.Request) (model.User, string, bool, error) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return model.User{}, "", false, nil
	}
	u, err := s.state.UserByBrowserSession(r.Context(), c.Value)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return model.User{}, "", false, nil
		}
		return model.User{}, "", false, err
	}
	return u, c.Value, true, nil
}

func (s *Server) sameOrigin(r *http.Request) bool {
	publicURL, err := url.Parse(s.cfg.Server.PublicBaseURL)
	if err != nil || publicURL.Scheme == "" || publicURL.Host == "" {
		return false
	}
	raw := r.Header.Get("Origin")
	if raw == "" {
		raw = r.Header.Get("Referer")
	}
	if raw == "" {
		return false
	}
	got, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return got.Scheme == publicURL.Scheme && got.Hostname() == publicURL.Hostname() && got.Port() == publicURL.Port()
}

func writeTokenIssueError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, model.ErrInvalidArgument):
		http.Error(w, "invalid token request", http.StatusBadRequest)
	case errors.Is(err, model.ErrNotFound), errors.Is(err, model.ErrPermissionDenied):
		http.Error(w, "token not authorized", http.StatusForbidden)
	default:
		slog.Error("token mint failed", "error", err)
		http.Error(w, "token unavailable", http.StatusInternalServerError)
	}
}

func writeLoginProviderError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, model.ErrUnsupported):
		http.Error(w, "identity provider login not configured", http.StatusServiceUnavailable)
	case errors.Is(err, model.ErrNotFound):
		http.Error(w, "unknown identity provider", http.StatusNotFound)
	default:
		slog.Error("identity provider start failed", "error", err)
		http.Error(w, "login unavailable", http.StatusInternalServerError)
	}
}

func writeDeviceError(w http.ResponseWriter, operation string, err error) {
	switch {
	case errors.Is(err, device.ErrInvalidCode):
		http.Error(w, "invalid device code", http.StatusBadRequest)
	case errors.Is(err, device.ErrExpiredCode):
		http.Error(w, "device code expired", http.StatusBadRequest)
	case errors.Is(err, device.ErrAuthorizationNotPending), errors.Is(err, model.ErrInvalidArgument):
		http.Error(w, "invalid device authorization", http.StatusBadRequest)
	case errors.Is(err, model.ErrNotFound):
		http.Error(w, "device repository not found", http.StatusNotFound)
	case errors.Is(err, model.ErrPermissionDenied):
		http.Error(w, "device authorization denied", http.StatusForbidden)
	default:
		slog.Error(operation+" failed", "error", err)
		http.Error(w, "device flow unavailable", http.StatusInternalServerError)
	}
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "json body too large", http.StatusRequestEntityTooLarge)
			return false
		}
		http.Error(w, "invalid json", http.StatusBadRequest)
		return false
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "json body too large", http.StatusRequestEntityTooLarge)
			return false
		}
		http.Error(w, "invalid json", http.StatusBadRequest)
		return false
	}
	return true
}

func parseFormBody(w http.ResponseWriter, r *http.Request) bool {
	if r.ContentLength > maxJSONBodyBytes {
		http.Error(w, "form body too large", http.StatusRequestEntityTooLarge)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
	if err := r.ParseForm(); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "form body too large", http.StatusRequestEntityTooLarge)
			return false
		}
		http.Error(w, "invalid form", http.StatusBadRequest)
		return false
	}
	return true
}

func renderWhoami(w http.ResponseWriter, id model.ExternalIdentity) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = whoamiTemplate.Execute(w, id)
}

func renderProviderPicker(w http.ResponseWriter, providers []ports.IdentityProviderDescriptor, loginNonce string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = providerPickerTemplate.Execute(w, struct {
		Providers  []ports.IdentityProviderDescriptor
		LoginNonce string
	}{Providers: providers, LoginNonce: loginNonce})
}

func authStartPath(providerID, loginNonce string) string {
	path := "/auth/" + url.PathEscape(providerID) + "/start"
	if loginNonce == "" {
		return path
	}
	return path + "?login_nonce=" + url.QueryEscape(loginNonce)
}

func (s *Server) authCallbackURL(providerID string) string {
	base := strings.TrimRight(s.cfg.Server.PublicBaseURL, "/")
	return base + "/auth/" + url.PathEscape(providerID) + "/callback"
}

var providerPickerTemplate = template.Must(template.New("provider-picker").Parse(`<h1>Choose identity provider</h1>
<ul>
{{range .Providers}}
  <li><a href="/auth/{{.ID}}/start{{if $.LoginNonce}}?login_nonce={{$.LoginNonce}}{{end}}">{{if .DisplayName}}{{.DisplayName}}{{else}}{{.ID}}{{end}}</a></li>
{{end}}
</ul>`))

var tokenPageTemplate = template.Must(template.New("tokens").Parse(`<h1>Issue Lore token</h1>
	<p>User: {{.User.Email}}</p>
	<form method="post" action="/tokens/mint">
	  <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
	  <label>Repository
	    <select name="repository">
      {{range .Repos}}<option value="{{.Name}}">{{.Name}}</option>{{end}}
    </select>
  </label>
  <button type="submit">Issue writer token</button>
</form>`))

var tokenResultTemplate = template.Must(template.New("token-result").Parse(`<h1>Lore token issued</h1>
<p>Repository: {{.Repo}}</p>
<p>Copy this command:</p>
<pre>lore auth login --token-type lore --token {{.Token}} --auth-url {{.AuthURL}} {{.RemoteURL}}</pre>
<p>Token:</p>
<textarea rows="8" cols="100">{{.Token}}</textarea>`))

var deviceConfirmTemplate = template.Must(template.New("device-confirm").Parse(`<h1>Authorize device</h1>
<dl>
  <dt>Repository</dt><dd>{{.RepositoryName}}</dd>
  <dt>Repository remote</dt><dd>{{.RepositoryRemote}}</dd>
  <dt>Requested remote</dt><dd>{{.RequestedRemoteURL}}</dd>
</dl>
<form method="post" action="/device/approve">
  <input type="hidden" name="user_code" value="{{.UserCode}}">
  <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
  <button type="submit">Approve</button>
</form>`))

var whoamiTemplate = template.Must(template.New("whoami").Parse(`<h1>Identity</h1>
<dl>
  <dt>issuer</dt><dd>{{.Issuer}}</dd>
  <dt>subject</dt><dd>{{.Subject}}</dd>
  <dt>email</dt><dd>{{.Email}}</dd>
  <dt>email_verified</dt><dd>{{.EmailVerified}}</dd>
  <dt>name</dt><dd>{{.DisplayName}}</dd>
  <dt>hosted_domain</dt><dd>{{.HostedDomain}}</dd>
</dl>
<p>Ask the administrator to invite this verified email. No Lore token was issued.</p>`))

func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}
func isSecure(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}
func stringOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func hasPermission(perms []string, want string) bool {
	for _, perm := range perms {
		if perm == want {
			return true
		}
	}
	return false
}
