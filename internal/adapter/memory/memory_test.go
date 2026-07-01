package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
)

func TestResolveLoginAppliesInvitationTrustPolicy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := New()
	user, invitation, err := store.AddInvitation(ctx, model.AddInvitationInput{
		ProviderID:    "keycloak-prod",
		Issuer:        "https://sso.example.com/realms/prod",
		Email:         "Alice@Example.com",
		DisplayName:   "Alice",
		BindingPolicy: "verified_email_invitation",
	})
	if err != nil {
		t.Fatal(err)
	}

	identity := model.ExternalIdentity{
		ProviderID:    "keycloak-prod",
		Issuer:        "https://sso.example.com/realms/prod",
		Subject:       "subject-1",
		Email:         "alice@example.com",
		EmailVerified: true,
	}
	_, _, err = store.ResolveLogin(ctx, model.LoginResolutionRequest{
		Identity: identity,
		Policy:   model.LoginTrustPolicy{EmailBinding: "disabled"},
	})
	if !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("ResolveLogin error = %v, want ErrNotFound", err)
	}
	if got := store.invitations[invitation.ID]; got.Status != "pending" || got.AcceptedIdentityID != "" {
		t.Fatalf("invitation should remain pending: %#v", got)
	}

	principal, binding, err := store.ResolveLogin(ctx, model.LoginResolutionRequest{
		Identity: identity,
		Policy: model.LoginTrustPolicy{
			EmailBinding:        "verified_email_invitation",
			AllowedEmailDomains: []string{"example.com"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if principal.UserID != user.ID || binding.Status != "bound_invitation" {
		t.Fatalf("unexpected login resolution: principal=%#v binding=%#v", principal, binding)
	}
}

func TestResolveLoginRequiresInvitationBindingPolicy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := New()
	_, invitation, err := store.AddInvitation(ctx, model.AddInvitationInput{
		ProviderID:    "keycloak-prod",
		Issuer:        "https://sso.example.com/realms/prod",
		Email:         "Alice@Example.com",
		BindingPolicy: "unknown_policy",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = store.ResolveLogin(ctx, model.LoginResolutionRequest{
		Identity: model.ExternalIdentity{
			ProviderID:    "keycloak-prod",
			Issuer:        "https://sso.example.com/realms/prod",
			Subject:       "subject-1",
			Email:         "alice@example.com",
			EmailVerified: true,
		},
		Policy: model.LoginTrustPolicy{EmailBinding: "verified_email_invitation"},
	})
	if !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("ResolveLogin error = %v, want ErrNotFound", err)
	}
	if got := store.invitations[invitation.ID]; got.Status != "pending" || got.AcceptedIdentityID != "" {
		t.Fatalf("invitation should remain pending: %#v", got)
	}
}

func TestResolveLoginRequiresAllowedEmailDomain(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := New()
	_, invitation, err := store.AddInvitation(ctx, model.AddInvitationInput{
		ProviderID:    "keycloak-prod",
		Issuer:        "https://sso.example.com/realms/prod",
		Email:         "Alice@Example.com",
		BindingPolicy: "verified_email_invitation",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = store.ResolveLogin(ctx, model.LoginResolutionRequest{
		Identity: model.ExternalIdentity{
			ProviderID:    "keycloak-prod",
			Issuer:        "https://sso.example.com/realms/prod",
			Subject:       "subject-1",
			Email:         "alice@example.com",
			EmailVerified: true,
		},
		Policy: model.LoginTrustPolicy{
			EmailBinding:        "verified_email_invitation",
			AllowedEmailDomains: []string{"contractor.example"},
		},
	})
	if !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("ResolveLogin error = %v, want ErrNotFound", err)
	}
	if got := store.invitations[invitation.ID]; got.Status != "pending" || got.AcceptedIdentityID != "" {
		t.Fatalf("invitation should remain pending: %#v", got)
	}
}

func TestResolveLoginRejectsExpiredInvitation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := New()
	_, invitation, err := store.AddInvitation(ctx, model.AddInvitationInput{
		ProviderID:    "keycloak-prod",
		Issuer:        "https://sso.example.com/realms/prod",
		Email:         "Alice@Example.com",
		BindingPolicy: "verified_email_invitation",
		ExpiresAt:     time.Now().Add(-time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = store.ResolveLogin(ctx, model.LoginResolutionRequest{
		Identity: model.ExternalIdentity{
			ProviderID:    "keycloak-prod",
			Issuer:        "https://sso.example.com/realms/prod",
			Subject:       "subject-1",
			Email:         "alice@example.com",
			EmailVerified: true,
		},
		Policy: model.LoginTrustPolicy{EmailBinding: "verified_email_invitation"},
	})
	if !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("ResolveLogin error = %v, want ErrNotFound", err)
	}
	if got := store.invitations[invitation.ID]; got.Status != "pending" || got.AcceptedIdentityID != "" {
		t.Fatalf("invitation should remain pending: %#v", got)
	}
}
