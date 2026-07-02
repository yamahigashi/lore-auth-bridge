//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yamahigashi/lore-auth-bridge/internal/config"
)

func TestBridgeHarnessWritesLoadableConfigFile(t *testing.T) {
	h := &harness{
		t:         t,
		dir:       t.TempDir(),
		audience:  []string{"lore-service", "localhost"},
		remoteURL: "lore://localhost:41337",
	}
	t.Cleanup(func() {
		if h.store != nil {
			_ = h.store.Close()
		}
	})

	h.prepareBroker("127.0.0.1:18080", "127.0.0.1:18081", true)

	if h.bridgeConfigPath == "" {
		t.Fatal("bridge config path was not recorded")
	}
	loaded, err := config.Load(h.bridgeConfigPath)
	if err != nil {
		t.Fatalf("load generated bridge config: %v", err)
	}
	if loaded.Server.Listen != "127.0.0.1:18080" {
		t.Fatalf("server.listen = %q", loaded.Server.Listen)
	}
	if loaded.Server.GRPCListen != "127.0.0.1:18081" {
		t.Fatalf("server.grpc_listen = %q", loaded.Server.GRPCListen)
	}
	if loaded.Server.PublicBaseURL != "http://localhost:18080" {
		t.Fatalf("server.public_base_url = %q", loaded.Server.PublicBaseURL)
	}
	if loaded.Lore.AuthURL != "https://localhost:18081" {
		t.Fatalf("lore.auth_url = %q", loaded.Lore.AuthURL)
	}
	if loaded.Server.GRPCTLSCertFile == "" || loaded.Server.GRPCTLSKeyFile == "" {
		t.Fatalf("gRPC TLS files were not written: %#v", loaded.Server)
	}
	for _, path := range []string{loaded.Server.GRPCTLSCertFile, loaded.Server.GRPCTLSKeyFile, h.caCertPath} {
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
	if h.httpServer != nil || h.grpcServer != nil {
		t.Fatal("external mode should not start in-process HTTP/gRPC servers")
	}
}
