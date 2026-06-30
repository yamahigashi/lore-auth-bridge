package oidcadapter

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/ports"
)

func TestBeginAuthUsesDiscoveredAuthorizationEndpoint(t *testing.T) {
	t.Parallel()
	issuer := newOIDCTestIssuer(t, nil)

	provider, err := New(context.Background(), Config{
		ProviderID:          "keycloak-prod",
		DisplayName:         "Company SSO",
		Issuer:              issuer.URL,
		ClientID:            "client-id",
		ClientSecret:        "client-secret",
		RedirectURL:         "https://auth.example.com/auth/keycloak-prod/callback",
		Scopes:              []string{"openid", "email"},
		ClaimMapping:        nil,
		AllowedEmailDomains: nil,
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err := provider.BeginAuth(context.Background(), ports.BeginAuthRequest{
		State:     "state-123",
		Nonce:     "nonce-123",
		LoginHint: "alice@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}

	redirect, err := url.Parse(result.RedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	if redirect.Scheme+"://"+redirect.Host+redirect.Path != issuer.URL+"/authorize" {
		t.Fatalf("redirect endpoint = %s, want %s", redirect.String(), issuer.URL+"/authorize")
	}
	values := redirect.Query()
	assertQueryValue(t, values, "client_id", "client-id")
	assertQueryValue(t, values, "redirect_uri", "https://auth.example.com/auth/keycloak-prod/callback")
	assertQueryValue(t, values, "response_type", "code")
	assertQueryValue(t, values, "scope", "openid email")
	assertQueryValue(t, values, "state", "state-123")
	assertQueryValue(t, values, "nonce", "nonce-123")
	assertQueryValue(t, values, "login_hint", "alice@example.com")
}

func TestCompleteAuthVerifiesIDTokenAndMapsClaims(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var rawIDToken string
	issuer := newOIDCTestIssuer(t, func(issuerURL string) oidcTestHandlerConfig {
		rawIDToken = signOIDCTestToken(t, key, map[string]any{
			"iss":            issuerURL,
			"aud":            "client-id",
			"sub":            "subject:with:colon",
			"exp":            time.Now().Add(time.Hour).Unix(),
			"iat":            time.Now().Add(-time.Minute).Unix(),
			"nonce":          "nonce-123",
			"mail":           "alice@example.com",
			"mail_verified":  true,
			"display_name":   "Alice Example",
			"avatar":         "https://example.com/alice.png",
			"hosted_domain":  "example.com",
			"ignored_groups": []string{"developers"},
		})
		return oidcTestHandlerConfig{Key: key, IDToken: rawIDToken}
	})

	provider, err := New(context.Background(), Config{
		ProviderID:   "keycloak-prod",
		DisplayName:  "Company SSO",
		Issuer:       issuer.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURL:  "https://auth.example.com/auth/keycloak-prod/callback",
		Scopes:       []string{"openid", "email", "profile"},
		ClaimMapping: map[string]string{
			"email":          "mail",
			"email_verified": "mail_verified",
			"name":           "display_name",
			"picture":        "avatar",
			"hosted_domain":  "hosted_domain",
		},
		AllowedEmailDomains: []string{"example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}

	identity, err := provider.CompleteAuth(context.Background(), ports.CompleteAuthRequest{
		Code:  "auth-code",
		Nonce: "nonce-123",
	})
	if err != nil {
		t.Fatal(err)
	}

	if identity.Provider != "keycloak-prod" || identity.Issuer != issuer.URL || identity.Subject != "subject:with:colon" {
		t.Fatalf("unexpected canonical identity key: %#v", identity)
	}
	if identity.Email != "alice@example.com" || !identity.EmailVerified || identity.Name != "Alice Example" {
		t.Fatalf("unexpected mapped identity: %#v", identity)
	}
	if identity.PictureURL != "https://example.com/alice.png" || identity.HostedDomain != "example.com" {
		t.Fatalf("unexpected optional mapped identity fields: %#v", identity)
	}
}

func TestCompleteAuthRejectsAllowedDomainWhenEmailIsUnverified(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var rawIDToken string
	issuer := newOIDCTestIssuer(t, func(issuerURL string) oidcTestHandlerConfig {
		rawIDToken = signOIDCTestToken(t, key, map[string]any{
			"iss":            issuerURL,
			"aud":            "client-id",
			"sub":            "subject-1",
			"exp":            time.Now().Add(time.Hour).Unix(),
			"iat":            time.Now().Add(-time.Minute).Unix(),
			"nonce":          "nonce-123",
			"email":          "alice@example.com",
			"email_verified": false,
		})
		return oidcTestHandlerConfig{Key: key, IDToken: rawIDToken}
	})
	provider, err := New(context.Background(), Config{
		ProviderID:          "keycloak-prod",
		Issuer:              issuer.URL,
		ClientID:            "client-id",
		ClientSecret:        "client-secret",
		RedirectURL:         "https://auth.example.com/auth/keycloak-prod/callback",
		Scopes:              []string{"openid", "email", "profile"},
		AllowedEmailDomains: []string{"example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = provider.CompleteAuth(context.Background(), ports.CompleteAuthRequest{
		Code:  "auth-code",
		Nonce: "nonce-123",
	})
	if !errors.Is(err, model.ErrPermissionDenied) {
		t.Fatalf("CompleteAuth error = %v, want ErrPermissionDenied", err)
	}
}

func TestBoolClaimAcceptsStringBooleans(t *testing.T) {
	t.Parallel()
	if !boolClaim(map[string]any{"email_verified": "true"}, "email_verified") {
		t.Fatal(`boolClaim should accept string "true"`)
	}
	if boolClaim(map[string]any{"email_verified": "false"}, "email_verified") {
		t.Fatal(`boolClaim should accept string "false"`)
	}
}

func assertQueryValue(t *testing.T, values url.Values, key, want string) {
	t.Helper()
	if got := values.Get(key); got != want {
		t.Fatalf("query %s = %q, want %q in %s", key, got, want, values.Encode())
	}
}

type oidcTestHandlerConfig struct {
	Key     *rsa.PrivateKey
	IDToken string
}

func newOIDCTestIssuer(t *testing.T, configFn func(issuerURL string) oidcTestHandlerConfig) *httptest.Server {
	t.Helper()
	var server *httptest.Server
	var cfg oidcTestHandlerConfig
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cfg.Key == nil && configFn != nil {
			cfg = configFn(server.URL)
		}
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeJSON(t, w, map[string]any{
				"issuer":                                server.URL,
				"authorization_endpoint":                server.URL + "/authorize",
				"token_endpoint":                        server.URL + "/token",
				"jwks_uri":                              server.URL + "/jwks",
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/jwks":
			writeJSON(t, w, map[string]any{"keys": []map[string]any{rsaPublicJWK(&cfg.Key.PublicKey)}})
		case "/token":
			if cfg.IDToken == "" {
				http.Error(w, "test id token not configured", http.StatusInternalServerError)
				return
			}
			writeJSON(t, w, map[string]any{
				"access_token": "access-token",
				"token_type":   "Bearer",
				"id_token":     cfg.IDToken,
			})
		case "/authorize":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatal(err)
	}
}

func rsaPublicJWK(key *rsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"use": "sig",
		"kid": "test-key",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

func signOIDCTestToken(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "kid": "test-key", "typ": "JWT"}
	signingInput := strings.Join([]string{base64JSON(t, header), base64JSON(t, claims)}, ".")
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func base64JSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}
