package rs256

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
)

func TestResourceIDForRepositoryID(t *testing.T) {
	t.Parallel()

	if got := ResourceIDForRepositoryID("0194b726b34e72b0b45550b88a967076"); got != "urc-0194b726b34e72b0b45550b88a967076" {
		t.Fatalf("unexpected resource id: %s", got)
	}
	if got := ResourceIDForRepositoryID("urc-*"); got != "urc-*" {
		t.Fatalf("unexpected explicit resource id: %s", got)
	}
}

func TestJWKSContainsRSAExponentAndKid(t *testing.T) {
	t.Parallel()

	key, err := GenerateSigningKey("test-kid", 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := key.JWKS()
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected one JWK, got %d", len(jwks.Keys))
	}
	jwk := jwks.Keys[0]
	if jwk.Kid != "test-kid" {
		t.Fatalf("unexpected kid: %s", jwk.Kid)
	}
	if jwk.Alg != AlgRS256 {
		t.Fatalf("unexpected alg: %s", jwk.Alg)
	}
	if jwk.E != "AQAB" {
		t.Fatalf("unexpected exponent: %s", jwk.E)
	}
	if _, err := json.Marshal(jwks); err != nil {
		t.Fatal(err)
	}
}

func TestSignLoreClaimsCanBeDecodedInsecurely(t *testing.T) {
	t.Parallel()

	key, err := GenerateSigningKey("test-kid", 2048)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := NewLoreClaims(ClaimsOptions{
		Issuer:            "https://auth.example.com",
		Audience:          []string{"lore-service", "lore.example.com"},
		Subject:           "google:TEST",
		Name:              "Test User",
		PreferredUsername: "test@example.com",
		ResourceID:        "urc-0194b726b34e72b0b45550b88a967076",
		Permissions:       []string{"read", "write"},
		Now:               time.Unix(1000, 0).UTC(),
		TTL:               time.Hour,
		JTI:               "jti-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	compact, err := key.SignLoreClaims(claims)
	if err != nil {
		t.Fatal(err)
	}
	header, payload, err := DecodeInsecure(compact)
	if err != nil {
		t.Fatal(err)
	}
	if header["kid"] != "test-kid" {
		t.Fatalf("unexpected kid: %#v", header["kid"])
	}
	if payload["iss"] != "https://auth.example.com" {
		t.Fatalf("unexpected iss: %#v", payload["iss"])
	}
	if payload["jti"] != "jti-test" {
		t.Fatalf("unexpected jti: %#v", payload["jti"])
	}
}

func TestNewLoreClaimsCanOmitResourcesForNegativeProbe(t *testing.T) {
	t.Parallel()

	claims, err := NewLoreClaims(ClaimsOptions{
		Issuer:           "https://auth.example.com",
		Audience:         []string{"lore-service", "lore.example.com"},
		Subject:          "google:TEST",
		WithoutResources: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(claims.Resources) != 0 {
		t.Fatalf("expected no resources, got %#v", claims.Resources)
	}
}

func TestSignerValidateReportsMissingActiveKeyAsSigningKeyUnavailable(t *testing.T) {
	t.Parallel()

	signer := NewSigner("missing-kid", signerKeyStoreStub{activeErr: model.ErrNotFound})
	err := signer.Validate(context.Background())
	if !errors.Is(err, model.ErrSigningKeyUnavailable) {
		t.Fatalf("Validate error = %v, want ErrSigningKeyUnavailable", err)
	}
	if errors.Is(err, model.ErrNotFound) {
		t.Fatalf("Validate error should not expose generic ErrNotFound: %v", err)
	}
}

type signerKeyStoreStub struct {
	activeErr error
}

func (s signerKeyStoreStub) ActiveSigningKey(ctx context.Context, kid string) (model.SigningKeyMeta, error) {
	return model.SigningKeyMeta{}, s.activeErr
}

func (s signerKeyStoreStub) SigningKeyByKID(ctx context.Context, kid string) (model.SigningKeyMeta, error) {
	return model.SigningKeyMeta{}, model.ErrNotFound
}

func (s signerKeyStoreStub) PublicJWKS(ctx context.Context) ([]json.RawMessage, error) {
	return nil, nil
}
