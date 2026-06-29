package e2e

import (
	"strings"
	"testing"
)

func TestRedactLoreArgsHidesTokenValue(t *testing.T) {
	t.Parallel()

	args := redactLoreArgs([]string{"auth", "login", "--token-type", "lore", "--token", "header.payload.signature", "--auth-url", "https://localhost:8081"})

	joined := strings.Join(args, " ")
	if strings.Contains(joined, "header.payload.signature") {
		t.Fatalf("redacted args leaked token: %s", joined)
	}
	if !strings.Contains(joined, "<redacted>") {
		t.Fatalf("redacted args missing marker: %s", joined)
	}
}
