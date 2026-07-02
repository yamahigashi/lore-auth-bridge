//go:build e2e

// Package e2e drives an end-to-end check of lore-auth-bridge against the real
// `lore` and `loreserver` binaries. It is excluded from the normal build by the
// e2e build tag and is opt-in via LORE_E2E=1.
package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"text/template"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gopkg.in/yaml.v3"

	pbAuth "github.com/yamahigashi/lore-auth-bridge/test/e2e/internal/loreproto/epicurc"
	pbRebac "github.com/yamahigashi/lore-auth-bridge/test/e2e/internal/loreproto/ucsauth"
)

const (
	loreGRPCPort = 41337
	loreHTTPPort = 41339
	activeKID    = "e2e-key-1"

	bridgeBinEnv  = "LORE_E2E_BRIDGE_BIN"
	authctlBinEnv = "LORE_E2E_AUTHCTL_BIN"
)

type harness struct {
	t          *testing.T
	dir        string
	dbPath     string
	keyDir     string
	httpURL    string // broker HTTP base (JWKS, issuer)
	grpcAddr   string // broker gRPC host:port (TLS)
	authURL    string // ucs-auth gRPC URL advertised to lore (ucs-auth://...)
	caCertPath string
	audience   []string
	remoteURL  string

	bridgeConfigPath string
	bridgeLog        string
	bridge           *exec.Cmd
	bridgeDone       chan error

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
	if os.Getenv(bridgeBinEnv) == "" {
		t.Skipf("set %s to the Rust lore-auth-server binary; in-process Go broker mode has been removed", bridgeBinEnv)
	}
	if os.Getenv(authctlBinEnv) == "" {
		t.Skipf("set %s to the Rust lore-authctl binary; e2e setup no longer imports Go internals", authctlBinEnv)
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
	bridgeBin := os.Getenv(bridgeBinEnv)
	if bridgeBin == "" {
		h.t.Skipf("set %s to the Rust lore-auth-server binary; in-process Go broker mode has been removed", bridgeBinEnv)
	}
	h.startExternalBroker(bridgeBin)
}

func (h *harness) startExternalBroker(bridgeBin string) {
	t := h.t

	bridgeBin = resolveBridgeBin(t, bridgeBin)
	h.prepareBroker(freeTCPAddr(t), freeTCPAddr(t), true)
	h.bridgeLog = filepath.Join(h.dir, "bridge.log")
	logFile, err := os.Create(h.bridgeLog)
	if err != nil {
		t.Fatalf("create bridge log: %v", err)
	}
	cmd := h.bridgeCommand(bridgeBin)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start bridge %q: %v", bridgeBin, err)
	}
	h.bridge = cmd
	h.bridgeDone = make(chan error, 1)
	go func() {
		h.bridgeDone <- cmd.Wait()
		close(h.bridgeDone)
	}()

	t.Cleanup(h.stop)
	h.waitBridgeHTTP(h.httpURL+"/.well-known/jwks.json", 30*time.Second, "broker JWKS")
	t.Logf("broker external %s HTTP %s, gRPC(TLS) %s, config %s", bridgeBin, h.httpURL, h.authURL, h.bridgeConfigPath)
}

func (h *harness) bridgeCommand(bridgeBin string) *exec.Cmd {
	cmd := exec.Command(bridgeBin, "--config", h.bridgeConfigPath)
	cmd.Dir = h.dir
	cmd.Env = os.Environ()
	return cmd
}

func (h *harness) runAuthctl(args ...string) []byte {
	h.t.Helper()
	return h.runAuthctlWithConfig(h.bridgeConfigPath, args...)
}

func (h *harness) runAuthctlWithConfig(configPath string, args ...string) []byte {
	h.t.Helper()
	authctlBin := os.Getenv(authctlBinEnv)
	if authctlBin == "" {
		h.t.Skipf("set %s to the Rust lore-authctl binary; e2e setup no longer imports Go internals", authctlBinEnv)
	}
	authctlBin = resolveBin(h.t, authctlBin)
	fullArgs := append([]string{"--config", configPath}, args...)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, authctlBin, fullArgs...)
	cmd.Dir = h.dir
	cmd.Env = os.Environ()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		h.t.Fatalf("authctl %v failed: %v\nstdout:\n%s\nstderr:\n%s", args, err, stdout.String(), stderr.String())
	}
	return stdout.Bytes()
}

func resolveBridgeBin(t *testing.T, bridgeBin string) string {
	t.Helper()
	return resolveBin(t, bridgeBin)
}

func resolveBin(t *testing.T, bridgeBin string) string {
	t.Helper()
	if filepath.IsAbs(bridgeBin) {
		return bridgeBin
	}
	if filepath.Dir(bridgeBin) == "." {
		if resolved, err := exec.LookPath(bridgeBin); err == nil {
			return resolved
		}
	}
	if abs, ok := absIfExists(bridgeBin); ok {
		return abs
	}
	if root, ok := repoRoot(); ok {
		if abs, ok := absIfExists(filepath.Join(root, bridgeBin)); ok {
			return abs
		}
	}
	abs, err := filepath.Abs(bridgeBin)
	if err != nil {
		t.Fatalf("resolve bridge binary %q: %v", bridgeBin, err)
	}
	return abs
}

func absIfExists(path string) (string, bool) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", false
	}
	if _, err := os.Stat(abs); err != nil {
		return "", false
	}
	return abs, true
}

func repoRoot() (string, bool) {
	dir, err := os.Getwd()
	if err != nil {
		return "", false
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

type bridgeConfig struct {
	Server            bridgeServerConfig            `yaml:"server"`
	IdentityProviders bridgeIdentityProvidersConfig `yaml:"identity_providers"`
	Database          bridgeDatabaseConfig          `yaml:"database"`
	JWT               bridgeJWTConfig               `yaml:"jwt"`
	Lore              bridgeLoreConfig              `yaml:"lore"`
	Security          bridgeSecurityConfig          `yaml:"security"`
}

type bridgeServerConfig struct {
	Listen          string `yaml:"listen"`
	GRPCListen      string `yaml:"grpc_listen"`
	GRPCTLSCertFile string `yaml:"grpc_tls_cert_file"`
	GRPCTLSKeyFile  string `yaml:"grpc_tls_key_file"`
	PublicBaseURL   string `yaml:"public_base_url"`
}

type bridgeIdentityProvidersConfig struct {
	Default   string                          `yaml:"default"`
	Providers map[string]bridgeProviderConfig `yaml:"providers"`
}

type bridgeProviderConfig struct{}

type bridgeDatabaseConfig struct {
	Path string `yaml:"path"`
}

type bridgeJWTConfig struct {
	Issuer        string   `yaml:"issuer"`
	Audience      []string `yaml:"audience"`
	TTLSeconds    int      `yaml:"ttl_seconds"`
	SigningKeyDir string   `yaml:"signing_key_dir"`
	ActiveKID     string   `yaml:"active_kid"`
}

type bridgeLoreConfig struct {
	DefaultRemoteURL string `yaml:"default_remote_url"`
	AuthURL          string `yaml:"auth_url"`
}

type bridgeSecurityConfig struct {
	DeviceCodeTTLSeconds      int      `yaml:"device_code_ttl_seconds"`
	DevicePollIntervalSeconds int      `yaml:"device_poll_interval_seconds"`
	SessionTTLSeconds         int      `yaml:"session_ttl_seconds"`
	AuthSessionTTLSeconds     int      `yaml:"auth_session_ttl_seconds"`
	RebacAllowedPeerCIDRs     []string `yaml:"rebac_allowed_peer_cidrs"`
}

func (h *harness) prepareBroker(httpListen, grpcListen string, writeTLSFiles bool) {
	t := h.t

	httpPort := portFromAddr(t, httpListen, "broker http")
	grpcPort := portFromAddr(t, grpcListen, "broker grpc")
	h.httpURL = "http://localhost:" + httpPort
	h.grpcAddr = grpcListen
	// loreserver/lore CLI dial the auth endpoint with TLS only for https://;
	// ucs-auth:// is treated as plaintext and fails against our TLS gRPC port.
	h.authURL = "https://localhost:" + grpcPort

	_, caPEM, certPEM, keyPEM := h.makeServerCert()
	h.caCertPath = filepath.Join(h.dir, "broker-ca.pem")
	if err := os.WriteFile(h.caCertPath, caPEM, 0o644); err != nil {
		t.Fatalf("write ca: %v", err)
	}

	certPath := filepath.Join(h.dir, "broker-grpc.pem")
	keyPathTLS := filepath.Join(h.dir, "broker-grpc-key.pem")
	if writeTLSFiles {
		if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
			t.Fatalf("write grpc cert: %v", err)
		}
		if err := os.WriteFile(keyPathTLS, keyPEM, 0o600); err != nil {
			t.Fatalf("write grpc key: %v", err)
		}
	}

	h.dbPath = filepath.Join(h.dir, "broker.sqlite3")
	h.keyDir = filepath.Join(h.dir, "keys")
	cfg := bridgeConfig{
		Server: bridgeServerConfig{
			Listen:        httpListen,
			GRPCListen:    grpcListen,
			PublicBaseURL: h.httpURL,
		},
		IdentityProviders: bridgeIdentityProvidersConfig{
			Providers: map[string]bridgeProviderConfig{},
		},
		Database: bridgeDatabaseConfig{Path: h.dbPath},
		JWT: bridgeJWTConfig{
			Issuer:        h.httpURL,
			Audience:      h.audience,
			TTLSeconds:    3600,
			SigningKeyDir: h.keyDir,
			ActiveKID:     activeKID,
		},
		Lore: bridgeLoreConfig{
			AuthURL:          h.authURL,
			DefaultRemoteURL: h.remoteURL,
		},
		Security: bridgeSecurityConfig{
			SessionTTLSeconds:         600,
			AuthSessionTTLSeconds:     600,
			DeviceCodeTTLSeconds:      600,
			DevicePollIntervalSeconds: 1,
			RebacAllowedPeerCIDRs:     []string{"127.0.0.1/32", "::1/128"},
		},
	}
	if writeTLSFiles {
		cfg.Server.GRPCTLSCertFile = certPath
		cfg.Server.GRPCTLSKeyFile = keyPathTLS
	}
	h.writeBrokerConfig(cfg)
	h.runAuthctl("init-db")
	h.runAuthctl("key", "generate", "--kid", activeKID)
}

func (h *harness) writeBrokerConfig(cfg bridgeConfig) {
	h.t.Helper()
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		h.t.Fatalf("marshal bridge config: %v", err)
	}
	h.bridgeConfigPath = filepath.Join(h.dir, "bridge.yaml")
	if err := os.WriteFile(h.bridgeConfigPath, raw, 0o644); err != nil {
		h.t.Fatalf("write bridge config: %v", err)
	}
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
		"Issuer":       h.httpURL,
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
	if h.bridge != nil && h.bridge.Process != nil {
		_ = h.bridge.Process.Signal(os.Interrupt)
		if h.bridgeDone == nil {
			_ = h.bridge.Process.Kill()
		} else {
			select {
			case <-h.bridgeDone:
			case <-time.After(5 * time.Second):
				_ = h.bridge.Process.Kill()
				<-h.bridgeDone
			}
		}
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
	return h.mintAuthnTokenWithConfig(h.bridgeConfigPath, userEmailOrID, 0)
}

func (h *harness) mintAuthnTokenTTL(userEmailOrID string, ttl time.Duration) string {
	h.t.Helper()
	if ttl < 0 {
		token := h.mintAuthnTokenWithConfig(h.bridgeConfigPath, userEmailOrID, time.Second)
		time.Sleep(2 * time.Second)
		return token
	}
	return h.mintAuthnTokenWithConfig(h.bridgeConfigPath, userEmailOrID, ttl)
}

func (h *harness) mintAuthnTokenAudience(userEmailOrID string, audience []string) string {
	h.t.Helper()
	cfgPath := h.writeTokenMintConfig(audience)
	return h.mintAuthnTokenWithConfig(cfgPath, userEmailOrID, 0)
}

func (h *harness) mintAuthnTokenWithConfig(configPath, userEmailOrID string, ttl time.Duration) string {
	h.t.Helper()
	args := []string{"token", "mint-authn", userEmailOrID}
	if ttl > 0 {
		args = append(args, "--ttl", fmt.Sprintf("%ds", int64(ttl.Seconds())))
	}
	out := h.runAuthctlWithConfig(configPath, args...)
	token := string(bytes.TrimSpace(out))
	if token == "" {
		h.t.Fatal("authctl token mint-authn returned an empty token")
	}
	return token
}

func (h *harness) writeTokenMintConfig(audience []string) string {
	h.t.Helper()
	cfg := bridgeConfig{
		Server: bridgeServerConfig{
			Listen:     "127.0.0.1:0",
			GRPCListen: h.grpcAddr,
			// authctl token mint always appends the public_base_url host to
			// the audience, so a mismatched host here keeps the minted token
			// missing the bridge's real auth-service audience.
			PublicBaseURL: "http://mint-audience-override.invalid",
		},
		IdentityProviders: bridgeIdentityProvidersConfig{
			Providers: map[string]bridgeProviderConfig{},
		},
		Database: bridgeDatabaseConfig{Path: h.dbPath},
		JWT: bridgeJWTConfig{
			Issuer:        h.httpURL,
			Audience:      audience,
			TTLSeconds:    3600,
			SigningKeyDir: h.keyDir,
			ActiveKID:     activeKID,
		},
		Lore: bridgeLoreConfig{
			AuthURL: h.authURL,
		},
		Security: bridgeSecurityConfig{
			SessionTTLSeconds:         600,
			AuthSessionTTLSeconds:     600,
			DeviceCodeTTLSeconds:      600,
			DevicePollIntervalSeconds: 1,
		},
	}
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		h.t.Fatalf("marshal token mint config: %v", err)
	}
	path := filepath.Join(h.dir, "token-mint.yaml")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		h.t.Fatalf("write token mint config: %v", err)
	}
	return path
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

func (h *harness) makeServerCert() (tls.Certificate, []byte, []byte, []byte) {
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
	certPEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), caPEM...)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafKeyDER})
	cert := tls.Certificate{
		Certificate: [][]byte{leafDER, caDER},
		PrivateKey:  leafKey,
	}
	return cert, caPEM, certPEM, keyPEM
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

func (h *harness) waitBridgeHTTP(url string, timeout time.Duration, what string) {
	h.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case err := <-h.bridgeDone:
			h.t.Fatalf("bridge exited before %s was reachable: %v\nbridge log tail:\n%s", what, err, h.tailBridgeLog(80))
		default:
		}
		resp, err := http.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode < 500 {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	h.t.Fatalf("%s not reachable at %s\nbridge log tail:\n%s", what, url, h.tailBridgeLog(80))
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

func (h *harness) tailBridgeLog(n int) string {
	data, err := os.ReadFile(h.bridgeLog)
	if err != nil {
		return fmt.Sprintf("(no log: %v)", err)
	}
	return tail(string(data), n)
}

func freeTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if os.IsPermission(err) || errors.Is(err, syscall.EPERM) {
			t.Skipf("cannot reserve TCP addr in this sandbox: %v", err)
		}
		t.Fatalf("reserve tcp addr: %v", err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().String()
}

func portFromAddr(t *testing.T, addr, what string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("parse %s addr %q: %v", what, addr, err)
	}
	return port
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
