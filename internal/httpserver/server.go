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
	"net/http"
	"net/url"
	"time"

	"github.com/yamahigashi/lore-auth-bridge/internal/config"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/ports"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/service"
	"github.com/yamahigashi/lore-auth-bridge/internal/device"
)

const (
	sessionCookieName  = "lore_auth_session"
	stateCookieName    = "lore_oauth_state"
	loginSessionCookie = "lore_login_session"
	maxJSONBodyBytes   = 64 * 1024
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
	s := &Server{cfg: opts.Config, login: opts.Login, tokens: opts.Tokens, resources: opts.Resources, perms: opts.Permissions, state: opts.State, jwks: opts.JWKS, device: opts.Device, mux: http.NewServeMux()}
	if s.cfg == nil {
		s.cfg = &config.Config{}
		s.cfg.Security.SessionTTLSeconds = 3600
	}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) routes() {
	s.mux.HandleFunc("GET /.well-known/jwks.json", s.handleJWKS)
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	s.mux.HandleFunc("GET /", s.handleIndex)
	s.mux.HandleFunc("GET /login", s.handleLogin)
	s.mux.HandleFunc("GET /oauth/google/start", s.handleLogin)
	s.mux.HandleFunc("GET /oauth/google/callback", s.handleGoogleCallback)
	s.mux.HandleFunc("GET /login/session/{nonce}", s.handleLoginSession)
	s.mux.HandleFunc("GET /whoami", s.handleWhoami)
	s.mux.HandleFunc("GET /api/me", s.handleMe)
	s.mux.HandleFunc("POST /api/logout", s.handleLogout)
	s.mux.HandleFunc("GET /tokens", s.handleTokenPage)
	s.mux.HandleFunc("POST /tokens/mint", s.handleTokenMint)
	s.mux.HandleFunc("GET /device", s.handleDevicePage)
	s.mux.HandleFunc("POST /device/approve", s.handleDeviceApprove)
	s.mux.HandleFunc("POST /api/device/start", s.handleDeviceStart)
	s.mux.HandleFunc("POST /api/device/token", s.handleDeviceToken)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	u, ok, err := s.currentUser(r)
	if err != nil {
		slog.Error("browser session lookup failed", "route", "/", "error", err)
		http.Error(w, "session unavailable", http.StatusInternalServerError)
		return
	}
	if ok {
		_, _ = fmt.Fprintf(w, "lore-auth-bridge\nlogged in as %s\n", stringOr(u.Email, u.Subject))
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
		http.Error(w, "google login not configured", http.StatusServiceUnavailable)
		return
	}
	state, err := randomURLString(32)
	if err != nil {
		slog.Error("oauth state generation failed", "error", err)
		http.Error(w, "state failed", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: stateCookieName, Value: state, Path: "/", HttpOnly: true, Secure: isSecure(r), SameSite: http.SameSiteLaxMode, MaxAge: 600})
	url, err := s.login.AuthCodeURL(state)
	if err != nil {
		http.Error(w, "google login not configured", http.StatusServiceUnavailable)
		return
	}
	http.Redirect(w, r, url, http.StatusFound)
}

// handleLoginSession ties a CLI-initiated interactive login (StartAuthSession)
// to the browser Google login. It records the session nonce in a cookie and
// starts the OAuth flow; on successful callback the session is completed.
func (s *Server) handleLoginSession(w http.ResponseWriter, r *http.Request) {
	if s.login == nil {
		http.Error(w, "google login not configured", http.StatusServiceUnavailable)
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
	state, err := randomURLString(32)
	if err != nil {
		slog.Error("oauth state generation failed", "route", "/login/session/{nonce}", "error", err)
		http.Error(w, "state failed", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: stateCookieName, Value: state, Path: "/", HttpOnly: true, Secure: isSecure(r), SameSite: http.SameSiteLaxMode, MaxAge: 600})
	http.SetCookie(w, &http.Cookie{Name: loginSessionCookie, Value: nonce, Path: "/", HttpOnly: true, Secure: isSecure(r), SameSite: http.SameSiteLaxMode, MaxAge: 600})
	url, err := s.login.AuthCodeURL(state)
	if err != nil {
		http.Error(w, "google login not configured", http.StatusServiceUnavailable)
		return
	}
	http.Redirect(w, r, url, http.StatusFound)
}

func (s *Server) handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	if s.login == nil {
		http.Error(w, "google login not configured", http.StatusServiceUnavailable)
		return
	}
	stateCookie, err := r.Cookie(stateCookieName)
	if err != nil || stateCookie.Value == "" || stateCookie.Value != r.URL.Query().Get("state") {
		http.Error(w, "invalid oauth state", http.StatusBadRequest)
		return
	}
	clearCookie(w, stateCookieName)
	loginNonce := ""
	if c, err := r.Cookie(loginSessionCookie); err == nil && c.Value != "" {
		loginNonce = c.Value
	}
	res, err := s.login.CompleteOAuthCallback(r.Context(), r.URL.Query().Get("code"), loginNonce)
	if err != nil {
		switch {
		case errors.Is(err, model.ErrUnsupported):
			http.Error(w, "google login not configured", http.StatusServiceUnavailable)
		case errors.Is(err, model.ErrPermissionDenied):
			http.Error(w, "login forbidden", http.StatusForbidden)
		case errors.Is(err, model.ErrUnauthenticated):
			http.Error(w, "google login failed", http.StatusUnauthorized)
		default:
			slog.Error("google callback failed", "error", err)
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

func (s *Server) handleTokenPage(w http.ResponseWriter, r *http.Request) {
	u, ok, err := s.currentUser(r)
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
	repos := make([]model.Resource, 0, len(accessible))
	for _, perm := range accessible {
		if !hasPermission(perm.Permission, model.PermissionWrite) {
			continue
		}
		resource, err := s.resources.Get(r.Context(), perm.ResourceID)
		if err != nil {
			if errors.Is(err, model.ErrNotFound) {
				continue
			}
			slog.Error("repository lookup failed", "route", "/tokens", "resource_id", perm.ResourceID, "error", err)
			http.Error(w, "repositories unavailable", http.StatusInternalServerError)
			return
		}
		repos = append(repos, resource)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tokenPageTemplate.Execute(w, struct {
		User  model.User
		Repos []model.Resource
	}{User: u, Repos: repos})
}

func (s *Server) handleTokenMint(w http.ResponseWriter, r *http.Request) {
	u, ok, err := s.currentUser(r)
	if err != nil {
		slog.Error("browser session lookup failed", "route", "/tokens/mint", "error", err)
		http.Error(w, "session unavailable", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
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
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
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
		identity := model.Identity{Issuer: u.Issuer, Subject: u.Subject, Email: u.Email, EmailVerified: u.EmailVerified, Name: u.DisplayName, HostedDomain: u.HostedDomain}
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
	_ = json.NewEncoder(w).Encode(map[string]any{"id": u.ID, "email": u.Email, "subject": u.Subject, "status": u.Status})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookieName); err == nil {
		if err := s.state.RevokeBrowserSession(r.Context(), c.Value); err != nil && !errors.Is(err, model.ErrNotFound) {
			slog.Error("browser session revoke failed", "error", err)
		}
	}
	clearCookie(w, sessionCookieName)
	w.WriteHeader(http.StatusNoContent)
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

func renderWhoami(w http.ResponseWriter, id model.Identity) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = whoamiTemplate.Execute(w, id)
}

var tokenPageTemplate = template.Must(template.New("tokens").Parse(`<h1>Issue Lore token</h1>
<p>User: {{.User.Email}}</p>
<form method="post" action="/tokens/mint">
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

var whoamiTemplate = template.Must(template.New("whoami").Parse(`<h1>Google identity</h1>
<dl>
  <dt>issuer</dt><dd>{{.Issuer}}</dd>
  <dt>subject</dt><dd>{{.Subject}}</dd>
  <dt>email</dt><dd>{{.Email}}</dd>
  <dt>email_verified</dt><dd>{{.EmailVerified}}</dd>
  <dt>name</dt><dd>{{.Name}}</dd>
  <dt>hosted_domain</dt><dd>{{.HostedDomain}}</dd>
</dl>
<p>Ask the administrator to invite this email or register this issuer and subject. No Lore token was issued.</p>`))

func randomURLString(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
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
