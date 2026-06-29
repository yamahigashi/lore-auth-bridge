package googleid

import (
	"errors"
	"testing"

	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
)

func TestValidateHostedDomainAllowsConfiguredWorkspaceDomain(t *testing.T) {
	t.Parallel()
	auth := New(Config{AllowedHostedDomains: []string{"Example.com"}})

	err := auth.validateHostedDomain(model.Identity{HostedDomain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestValidateHostedDomainRejectsUnlistedWorkspaceDomain(t *testing.T) {
	t.Parallel()
	auth := New(Config{AllowedHostedDomains: []string{"example.com"}})

	err := auth.validateHostedDomain(model.Identity{HostedDomain: "other.example"})
	if !errors.Is(err, model.ErrPermissionDenied) {
		t.Fatalf("err = %v, want ErrPermissionDenied", err)
	}
}

func TestValidateHostedDomainRejectsPersonalAccountWhenDisabled(t *testing.T) {
	t.Parallel()
	auth := New(Config{AllowPersonalAccounts: false})

	err := auth.validateHostedDomain(model.Identity{})
	if !errors.Is(err, model.ErrPermissionDenied) {
		t.Fatalf("err = %v, want ErrPermissionDenied", err)
	}
}

func TestValidateHostedDomainAllowsPersonalAccountWhenEnabled(t *testing.T) {
	t.Parallel()
	auth := New(Config{AllowPersonalAccounts: true})

	err := auth.validateHostedDomain(model.Identity{})
	if err != nil {
		t.Fatal(err)
	}
}
