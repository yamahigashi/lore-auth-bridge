//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestBridgeHarnessWritesRustConfigFile(t *testing.T) {
	t.Setenv(authctlBinEnv, fakeAuthctl(t))
	h := &harness{
		t:         t,
		dir:       t.TempDir(),
		audience:  []string{"lore-service", "localhost"},
		remoteURL: "lore://localhost:41337",
	}

	h.prepareBroker("127.0.0.1:18080", "127.0.0.1:18081", true)

	if h.bridgeConfigPath == "" {
		t.Fatal("bridge config path was not recorded")
	}
	var loaded map[string]any
	raw, err := os.ReadFile(h.bridgeConfigPath)
	if err != nil {
		t.Fatalf("read generated bridge config: %v", err)
	}
	if err := yaml.Unmarshal(raw, &loaded); err != nil {
		t.Fatalf("parse generated bridge config: %v", err)
	}
	server := yamlMap(t, loaded, "server")
	if got := yamlString(t, server, "listen"); got != "127.0.0.1:18080" {
		t.Fatalf("server.listen = %q", got)
	}
	if got := yamlString(t, server, "grpc_listen"); got != "127.0.0.1:18081" {
		t.Fatalf("server.grpc_listen = %q", got)
	}
	if got := yamlString(t, server, "public_base_url"); got != "http://localhost:18080" {
		t.Fatalf("server.public_base_url = %q", got)
	}
	lore := yamlMap(t, loaded, "lore")
	if got := yamlString(t, lore, "auth_url"); got != "https://localhost:18081" {
		t.Fatalf("lore.auth_url = %q", got)
	}
	database := yamlMap(t, loaded, "database")
	if got := yamlString(t, database, "path"); got != h.dbPath {
		t.Fatalf("database.path = %q, want %q", got, h.dbPath)
	}
	jwt := yamlMap(t, loaded, "jwt")
	if got := yamlString(t, jwt, "active_kid"); got != activeKID {
		t.Fatalf("jwt.active_kid = %q", got)
	}
	if got := yamlString(t, jwt, "signing_key_dir"); got != h.keyDir {
		t.Fatalf("jwt.signing_key_dir = %q, want %q", got, h.keyDir)
	}
	if yamlString(t, server, "grpc_tls_cert_file") == "" || yamlString(t, server, "grpc_tls_key_file") == "" {
		t.Fatalf("gRPC TLS files were not written: %#v", server)
	}
	for _, path := range []string{yamlString(t, server, "grpc_tls_cert_file"), yamlString(t, server, "grpc_tls_key_file"), h.caCertPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected generated file %s: %v", path, err)
		}
	}
}

func TestBridgeHarnessExternalCommandUsesConfigPath(t *testing.T) {
	h := &harness{dir: t.TempDir(), bridgeConfigPath: filepath.Join(t.TempDir(), "bridge.yaml")}

	cmd := h.bridgeCommand("/tmp/lore-auth-bridge")

	if cmd.Path != "/tmp/lore-auth-bridge" {
		t.Fatalf("command path = %q", cmd.Path)
	}
	if len(cmd.Args) != 3 || cmd.Args[1] != "--config" || cmd.Args[2] != h.bridgeConfigPath {
		t.Fatalf("command args = %#v, want binary --config <generated yaml>", cmd.Args)
	}
	if cmd.Dir != h.dir {
		t.Fatalf("command dir = %q, want %q", cmd.Dir, h.dir)
	}
}

func TestResolveBridgeBinMakesRelativePathIndependentFromCommandDir(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "lore-auth-bridge")
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	rel, err := filepath.Rel(cwd, bin)
	if err != nil {
		t.Fatalf("relative path: %v", err)
	}
	want, err := filepath.Abs(rel)
	if err != nil {
		t.Fatalf("absolute path: %v", err)
	}

	got := resolveBridgeBin(t, rel)

	if got != want {
		t.Fatalf("resolved bridge bin = %q, want %q", got, want)
	}
}

func TestBridgeHarnessExternalModeStartsConfiguredBridge(t *testing.T) {
	if os.Getenv(bridgeBinEnv) == "" {
		t.Skipf("set %s to smoke-test external bridge spawn", bridgeBinEnv)
	}
	if os.Getenv(authctlBinEnv) == "" {
		t.Skipf("set %s to smoke-test external bridge spawn", authctlBinEnv)
	}
	h := &harness{
		t:         t,
		dir:       t.TempDir(),
		audience:  []string{"lore-service", "localhost"},
		remoteURL: "lore://localhost:41337",
	}

	h.startBroker()

	if h.bridge == nil {
		t.Fatal("external bridge process was not started")
	}
}

func yamlMap(t *testing.T, parent map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := parent[key]
	if !ok {
		t.Fatalf("missing YAML key %q", key)
	}
	child, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("YAML key %q has type %T, want map", key, value)
	}
	return child
}

func yamlString(t *testing.T, parent map[string]any, key string) string {
	t.Helper()
	value, ok := parent[key]
	if !ok {
		t.Fatalf("missing YAML key %q", key)
	}
	got, ok := value.(string)
	if !ok {
		t.Fatalf("YAML key %q has type %T, want string", key, value)
	}
	return got
}

func fakeAuthctl(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "lore-authctl")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write fake authctl: %v", err)
	}
	return path
}
