//go:build e2e

// Package e2e drives an end-to-end check of lore-auth-bridge against the real
// `lore` and `loreserver` binaries. It is excluded from the normal build by the
// e2e build tag and is opt-in via LORE_E2E=1.
package e2e

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"text/template"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/yamahigashi/lore-auth-bridge/internal/adapter/casbin"
	"github.com/yamahigashi/lore-auth-bridge/internal/adapter/rs256"
	"github.com/yamahigashi/lore-auth-bridge/internal/adapter/sqlite"
	"github.com/yamahigashi/lore-auth-bridge/internal/config"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/service"
	"github.com/yamahigashi/lore-auth-bridge/internal/device"
	"github.com/yamahigashi/lore-auth-bridge/internal/grpcauth"
	"github.com/yamahigashi/lore-auth-bridge/internal/grpcrebac"
	"github.com/yamahigashi/lore-auth-bridge/internal/httpserver"
	pbAuth "github.com/yamahigashi/lore-auth-bridge/internal/loreproto/epicurc"
	pbRebac "github.com/yamahigashi/lore-auth-bridge/internal/loreproto/ucsauth"
)

const (
	loreGRPCPort = 41337
	loreHTTPPort = 41339
	activeKID    = "e2e-key-1"
)

type harness struct {
	t          *testing.T
	dir        string
	httpURL    string // broker HTTP base (JWKS, issuer)
	grpcAddr   string // broker gRPC host:port (TLS)
	authURL    string // ucs-auth gRPC URL advertised to lore (https://...)
	caCertPath string
	audience   []string
	remoteURL  string

	store      *sqlite.Store
	cfg        *config.Config
	tokens     *service.TokenService
	httpServer *http.Server
	grpcServer *grpc.Server

	loreserver *exec.Cmd
	serverLog  string
}

var loreserverConfigTemplate = template.Must(template.New("loreserver").Parse(`
[environment.endpoint]
auth_url = "{{.AuthURL}}"

[server.auth]
jwt_issuer = "{{.Issuer}}"
jwt_audience = [{{range $i, $a := .Audience}}{{if $i}}, {{end}}"{{$a}}"{{end}}]

[server.auth.jwk]
endpoint = "{{.JWKSEndpoint}}"

[immutable_store.local]
path = "{{.DataDir}}"

[mutable_store.local]
path = "{{.DataDir}}"
`))

func requireE2E(t *testing.T) {
	t.Helper()
	if os.Getenv("LORE_E2E") != "1" {
		t.Skip("set LORE_E2E=1 to run end-to-end tests against lore/loreserver")
	}
	for _, bin := range []string{"lore", "loreserver"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not found on PATH; install the Lore CLI/server first", bin)
		}
	}
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	h := &harness{
		t:         t,
		dir:       dir,
		audience:  []string{"lore-service", "localhost"},
		remoteURL: fmt.Sprintf("lore://localhost:%d", loreGRPCPort),
	}
	h.startBroker()
	h.startLoreserver()
	return h
}

func (h *harness) startBroker() {
	t := h.t

	// HTTP listener (JWKS + login + issuer base).
	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen broker http: %v", err)
	}
	httpPort := httpLn.Addr().(*net.TCPAddr).Port
	h.httpURL = fmt.Sprintf("http://localhost:%d", httpPort)

	// gRPC TLS listener (UrcAuthApi + RebacApi).
	grpcLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen broker grpc: %v", err)
	}
	grpcPort := grpcLn.Addr().(*net.TCPAddr).Port
	h.grpcAddr = fmt.Sprintf("127.0.0.1:%d", grpcPort)
	h.authURL = fmt.Sprintf("https://localhost:%d", grpcPort)

	serverCert, caPEM := h.makeServerCert()
	h.caCertPath = filepath.Join(h.dir, "broker-ca.pem")
	if err := os.WriteFile(h.caCertPath, caPEM, 0o644); err != nil {
		t.Fatalf("write ca: %v", err)
	}

	dbPath := filepath.Join(h.dir, "broker.sqlite3")
	keyDir := filepath.Join(h.dir, "keys")
	st, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	key, err := rs256.GenerateSigningKey(activeKID, rs256.DefaultRSABits)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyPath := filepath.Join(keyDir, activeKID+".pem")
	if err := key.WritePrivatePEM(keyPath); err != nil {
		t.Fatalf("write key: %v", err)
	}
	jwk, err := json.Marshal(rs256.NewRSAJWK(key.Kid, key.Alg, key.Public()))
	if err != nil {
		t.Fatalf("marshal jwk: %v", err)
	}
	if _, err := st.AddSigningKey(context.Background(), sqlite.AddSigningKeyParams{Kid: key.Kid, Alg: key.Alg, PublicJWKJSON: string(jwk), PrivateKeyPath: keyPath, Status: "active"}); err != nil {
		t.Fatalf("add signing key: %v", err)
	}

	cfg := &config.Config{}
	cfg.Server.PublicBaseURL = h.httpURL
	cfg.Database.Path = dbPath
	cfg.JWT.Issuer = h.httpURL
	cfg.JWT.Audience = h.audience
	cfg.JWT.TTLSeconds = 3600
	cfg.JWT.SigningKeyDir = keyDir
	cfg.JWT.ActiveKID = activeKID
	cfg.Lore.AuthURL = h.authURL
	cfg.Lore.DefaultRemoteURL = h.remoteURL
	cfg.Security.SessionTTLSeconds = 600
	cfg.Security.DeviceCodeTTLSeconds = 600
	cfg.Security.DevicePollIntervalSeconds = 1
	h.store = st
	h.cfg = cfg

	coreStore := sqlite.NewCoreStore(st)
	authz := casbin.NewService(st)
	signer := rs256.NewSigner(cfg.JWT.ActiveKID, coreStore)
	tokenSvc := service.NewTokenService(service.TokenConfig{
		Issuer:              cfg.JWT.Issuer,
		Audience:            cfg.JWT.Audience,
		AuthServiceAudience: "localhost",
		AuthnTTL:            time.Duration(cfg.JWT.TTLSeconds) * time.Second,
		AuthzTTL:            15 * time.Minute,
	}, coreStore, coreStore, authz, signer, coreStore)
	loginSvc := service.NewLoginService(service.LoginConfig{PublicBaseURL: cfg.Server.PublicBaseURL, SessionTTL: time.Duration(cfg.Security.SessionTTLSeconds) * time.Second}, nil, coreStore, coreStore, tokenSvc)
	permissionSvc := service.NewPermissionService(coreStore, authz)
	resourceSvc := service.NewResourceService(coreStore)
	h.tokens = tokenSvc

	srv := httpserver.NewWithOptions(httpserver.Options{Config: cfg, Login: loginSvc, Tokens: tokenSvc, Resources: resourceSvc, State: coreStore, JWKS: signer, Device: device.NewService(cfg, st, tokenSvc)})
	h.httpServer = &http.Server{Handler: srv.Handler()}
	go func() { _ = h.httpServer.Serve(httpLn) }()

	h.grpcServer = grpc.NewServer(grpc.Creds(credentials.NewServerTLSFromCert(&serverCert)))
	pbAuth.RegisterUrcAuthApiServer(h.grpcServer, grpcauth.New(grpcauth.Services{Login: loginSvc, Tokens: tokenSvc, Permissions: permissionSvc}))
	pbRebac.RegisterRebacApiServer(h.grpcServer, grpcrebac.New(resourceSvc))
	go func() { _ = h.grpcServer.Serve(grpcLn) }()

	h.waitHTTP(h.httpURL+"/.well-known/jwks.json", 5*time.Second, "broker JWKS")
	t.Cleanup(h.stop)
	t.Logf("broker HTTP %s, gRPC(TLS) %s", h.httpURL, h.authURL)
}

func (h *harness) startLoreserver() {
	t := h.t
	dataDir := filepath.Join(h.dir, "data")
	cfgDir := filepath.Join(h.dir, "loreconfig")
	for _, d := range []string{dataDir, cfgDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	cfgFile := filepath.Join(cfgDir, "e2e.toml")
	f, err := os.Create(cfgFile)
	if err != nil {
		t.Fatalf("create loreserver config: %v", err)
	}
	if err := loreserverConfigTemplate.Execute(f, map[string]any{
		"AuthURL":      h.authURL,
		"Issuer":       h.cfg.JWT.Issuer,
		"Audience":     h.audience,
		"JWKSEndpoint": h.httpURL + "/.well-known/jwks.json",
		"DataDir":      dataDir,
	}); err != nil {
		_ = f.Close()
		t.Fatalf("render loreserver config: %v", err)
	}
	_ = f.Close()
	if base := os.Getenv("LORE_E2E_DEFAULT_TOML"); base != "" {
		copyFile(t, base, filepath.Join(cfgDir, "default.toml"))
	}

	h.serverLog = filepath.Join(h.dir, "loreserver.log")
	logFile, err := os.Create(h.serverLog)
	if err != nil {
		t.Fatalf("create loreserver log: %v", err)
	}
	cmd := exec.Command("loreserver")
	cmd.Dir = h.dir
	cmd.Env = append(h.loreEnv(),
		"LORE_CONFIG_PATH="+cfgDir,
		"LORE_ENV=e2e",
		"RUST_LOG="+envOr("RUST_LOG", "info"),
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start loreserver: %v", err)
	}
	h.loreserver = cmd

	if !h.waitHealth(fmt.Sprintf("http://127.0.0.1:%d/health_check", loreHTTPPort), 30*time.Second) {
		t.Fatalf("loreserver did not become healthy; log tail:\n%s", h.tailServerLog(40))
	}
	t.Logf("loreserver healthy on %s", h.remoteURL)
}

func (h *harness) stop() {
	if h.loreserver != nil && h.loreserver.Process != nil {
		_ = h.loreserver.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { _, _ = h.loreserver.Process.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = h.loreserver.Process.Kill()
		}
	}
	if h.grpcServer != nil {
		h.grpcServer.Stop()
	}
	if h.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = h.httpServer.Shutdown(ctx)
	}
	if h.store != nil {
		_ = h.store.Close()
	}
}

// loreEnv returns the environment for lore/loreserver processes: an isolated
// HOME and SSL_CERT_FILE so rustls trusts the broker's gRPC TLS certificate.
func (h *harness) loreEnv() []string {
	return append(os.Environ(),
		"HOME="+h.dir,
		"SSL_CERT_FILE="+h.caCertPath,
	)
}

func (h *harness) mintAuthnToken(userEmailOrID string) string {
	h.t.Helper()
	res, _, err := h.tokens.MintAuthn(context.Background(), userEmailOrID, 0)
	if err != nil {
		h.t.Fatalf("mint authn token: %v", err)
	}
	return res.Token
}

func (h *harness) mintAuthnTokenTTL(userEmailOrID string, ttl time.Duration) string {
	h.t.Helper()
	res, _, err := h.tokens.MintAuthn(context.Background(), userEmailOrID, ttl)
	if err != nil {
		h.t.Fatalf("mint authn token: %v", err)
	}
	return res.Token
}

func (h *harness) mintAuthnTokenAudience(userEmailOrID string, audience []string) string {
	h.t.Helper()
	coreStore := sqlite.NewCoreStore(h.store)
	authz := casbin.NewService(h.store)
	tokenSvc := service.NewTokenService(service.TokenConfig{
		Issuer:   h.cfg.JWT.Issuer,
		Audience: audience,
		AuthnTTL: time.Duration(h.cfg.JWT.TTLSeconds) * time.Second,
		AuthzTTL: 15 * time.Minute,
	}, coreStore, coreStore, authz, rs256.NewSigner(h.cfg.JWT.ActiveKID, coreStore), coreStore)
	res, _, err := tokenSvc.MintAuthn(context.Background(), userEmailOrID, 0)
	if err != nil {
		h.t.Fatalf("mint authn token: %v", err)
	}
	return res.Token
}

func (h *harness) authClient() (pbAuth.UrcAuthApiClient, func()) {
	h.t.Helper()
	conn := h.grpcClientConn()
	return pbAuth.NewUrcAuthApiClient(conn), func() { _ = conn.Close() }
}

func (h *harness) rebacClient() (pbRebac.RebacApiClient, func()) {
	h.t.Helper()
	conn := h.grpcClientConn()
	return pbRebac.NewRebacApiClient(conn), func() { _ = conn.Close() }
}

func (h *harness) grpcClientConn() *grpc.ClientConn {
	h.t.Helper()
	caPEM, err := os.ReadFile(h.caCertPath)
	if err != nil {
		h.t.Fatalf("read ca: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		h.t.Fatal("append ca failed")
	}
	conn, err := grpc.NewClient(h.grpcAddr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: pool, ServerName: "localhost"})))
	if err != nil {
		h.t.Fatalf("grpc client: %v", err)
	}
	return conn
}

func (h *harness) loreLoginAuthn(authnToken string) (string, error) {
	return h.runLore("auth", "login", "--token-type", "lore", "--token", authnToken, "--auth-url", h.authURL, h.remoteURL)
}

func (h *harness) runLore(args ...string) (string, error) {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "lore", args...)
	cmd.Dir = h.dir
	cmd.Env = h.loreEnv()
	out, err := cmd.CombinedOutput()
	h.t.Logf("lore %v -> err=%v\n%s", redactLoreArgs(args), err, string(out))
	return string(out), err
}

func (h *harness) makeServerCert() (tls.Certificate, []byte) {
	t := h.t
	// CA
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("ca genkey: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "lore-auth-bridge-e2e-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create ca: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	// Leaf server cert signed by the CA.
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("leaf genkey: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	leafKeyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}
	cert := tls.Certificate{
		Certificate: [][]byte{leafDER, caDER},
		PrivateKey:  leafKey,
	}
	_ = leafKeyDER
	return cert, caPEM
}

func (h *harness) waitHTTP(url string, timeout time.Duration, what string) {
	h.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	h.t.Fatalf("%s not reachable at %s", what, url)
}

func (h *harness) waitHealth(url string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode < 500 {
				return true
			}
		}
		if h.loreserver != nil && h.loreserver.ProcessState != nil && h.loreserver.ProcessState.Exited() {
			return false
		}
		time.Sleep(250 * time.Millisecond)
	}
	return false
}

func (h *harness) tailServerLog(n int) string {
	data, err := os.ReadFile(h.serverLog)
	if err != nil {
		return fmt.Sprintf("(no log: %v)", err)
	}
	return tail(string(data), n)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
}

func tail(s string, n int) string {
	lines := splitLines(s)
	if len(lines) <= n {
		return s
	}
	out := ""
	for _, l := range lines[len(lines)-n:] {
		out += l + "\n"
	}
	return out
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
