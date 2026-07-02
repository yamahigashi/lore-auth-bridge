package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRunGeneratesGoldenVectorsIdempotently(t *testing.T) {
	t.Parallel()

	outDir := filepath.Join(t.TempDir(), "golden")
	args := []string{"lore-goldenvec", "--out-dir", outDir}
	if err := run(args); err != nil {
		t.Fatalf("first run: %v", err)
	}
	first := readGoldenFiles(t, outDir)
	if err := run(args); err != nil {
		t.Fatalf("second run: %v", err)
	}
	second := readGoldenFiles(t, outDir)
	for path, firstBytes := range first {
		if !bytes.Equal(firstBytes, second[path]) {
			t.Fatalf("%s changed between runs", path)
		}
	}
}

func readGoldenFiles(t *testing.T, outDir string) map[string][]byte {
	t.Helper()

	paths := []string{
		"key.pem",
		"authn.jwt",
		"authz.jwt",
		"authn.header.json",
		"authn.claims.json",
		"authz.header.json",
		"authz.claims.json",
		"jwks.json",
	}
	out := make(map[string][]byte, len(paths))
	for _, name := range paths {
		raw, err := os.ReadFile(filepath.Join(outDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if len(raw) == 0 {
			t.Fatalf("%s is empty", name)
		}
		out[name] = raw
	}
	return out
}
