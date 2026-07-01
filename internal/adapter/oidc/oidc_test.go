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

func TestDescriptorIncludesLoginTrustPolicy(t *testing.T) {
	t.Parallel()
	issuer := newOIDCTestIssuer(t, nil)

	provider, err := New(context.Background(), Config{
		ProviderID:          "keycloak-prod",
		Issuer:              issuer.URL,
		ClientID:            "client-id",
		ClientSecret:        "client-secret",
		RedirectURL:         "https://auth.example.com/auth/keycloak-prod/callback",
		EmailBinding:        "verified_email_invitation",
		AllowedEmailDomains: []string{"Example.com", "example.com", "contractor.example"},
	})
	if err != nil {
		t.Fatal(err)
	}

	descriptor := provider.Descriptor()
	if descriptor.TrustPolicy.EmailBinding != "verified_email_invitation" {
		t.Fatalf("email binding = %q, want verified_email_invitation", descriptor.TrustPolicy.EmailBinding)
	}
	if got := strings.Join(descriptor.TrustPolicy.AllowedEmailDomains, ","); got != "example.com,contractor.example" {
		t.Fatalf("allowed email domains = %q", got)
	}
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
		Profile:      "keycloak",
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

	if identity.ProviderID != "keycloak-prod" || identity.Issuer != issuer.URL || identity.Subject != "subject:with:colon" {
		t.Fatalf("unexpected canonical identity key: %#v", identity)
	}
	if identity.Email != "alice@example.com" || !identity.EmailVerified || identity.DisplayName != "Alice Example" {
		t.Fatalf("unexpected mapped identity: %#v", identity)
	}
	if identity.PictureURL != "https://example.com/alice.png" || identity.HostedDomain != "example.com" {
		t.Fatalf("unexpected optional mapped identity fields: %#v", identity)
	}
}

func TestCompleteAuthDoesNotApplyAllowedEmailDomainsBeforeLoginResolution(t *testing.T) {
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
			"email":          "alice@other.example",
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

	identity, err := provider.CompleteAuth(context.Background(), ports.CompleteAuthRequest{
		Code:  "auth-code",
		Nonce: "nonce-123",
	})
	if err != nil {
		t.Fatalf("CompleteAuth error = %v, want identity for login resolution", err)
	}
	if identity.Email != "alice@other.example" || identity.EmailVerified {
		t.Fatalf("unexpected identity email claims: %#v", identity)
	}
}

func TestGoogleProfileAcceptsAllowedHostedDomainClaim(t *testing.T) {
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
			"sub":            "google-subject",
			"exp":            time.Now().Add(time.Hour).Unix(),
			"iat":            time.Now().Add(-time.Minute).Unix(),
			"email":          "alice@personal.example",
			"email_verified": true,
			"hd":             "example.com",
		})
		return oidcTestHandlerConfig{Key: key, IDToken: rawIDToken}
	})
	provider, err := New(context.Background(), Config{
		ProviderID:           "google",
		Profile:              "google",
		Issuer:               issuer.URL,
		ClientID:             "client-id",
		ClientSecret:         "client-secret",
		RedirectURL:          "https://auth.example.com/auth/google/callback",
		Scopes:               []string{"openid", "email", "profile"},
		AllowedHostedDomains: []string{"example.com"},
		PersonalAccounts:     "deny",
	})
	if err != nil {
		t.Fatal(err)
	}

	identity, err := provider.CompleteAuth(context.Background(), ports.CompleteAuthRequest{Code: "auth-code"})
	if err != nil {
		t.Fatal(err)
	}
	if identity.ProviderID != "google" || identity.Subject != "google-subject" || identity.HostedDomain != "example.com" {
		t.Fatalf("unexpected google identity: %#v", identity)
	}
}

func TestGoogleProfileDoesNotUseEmailDomainForWorkspaceRestriction(t *testing.T) {
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
			"sub":            "google-subject",
			"exp":            time.Now().Add(time.Hour).Unix(),
			"iat":            time.Now().Add(-time.Minute).Unix(),
			"email":          "alice@example.com",
			"email_verified": true,
		})
		return oidcTestHandlerConfig{Key: key, IDToken: rawIDToken}
	})
	provider, err := New(context.Background(), Config{
		ProviderID:           "google",
		Profile:              "google",
		Issuer:               issuer.URL,
		ClientID:             "client-id",
		ClientSecret:         "client-secret",
		RedirectURL:          "https://auth.example.com/auth/google/callback",
		Scopes:               []string{"openid", "email", "profile"},
		AllowedHostedDomains: []string{"example.com"},
		PersonalAccounts:     "deny",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = provider.CompleteAuth(context.Background(), ports.CompleteAuthRequest{Code: "auth-code"})
	if !errors.Is(err, model.ErrPermissionDenied) {
		t.Fatalf("CompleteAuth error = %v, want ErrPermissionDenied", err)
	}
}

func TestNewRejectsUnknownGooglePersonalAccountsPolicy(t *testing.T) {
	t.Parallel()
	issuer := newOIDCTestIssuer(t, nil)

	_, err := New(context.Background(), Config{
		ProviderID:       "google",
		Profile:          "google",
		Issuer:           issuer.URL,
		ClientID:         "client-id",
		ClientSecret:     "client-secret",
		RedirectURL:      "https://auth.example.com/auth/google/callback",
		Scopes:           []string{"openid", "email", "profile"},
		PersonalAccounts: "denny",
	})
	if err == nil {
		t.Fatal("expected unknown personal_accounts policy to fail")
	}
	if !strings.Contains(err.Error(), "personal_accounts") {
		t.Fatalf("error = %q, want personal_accounts context", err)
	}
}

func TestEntraSubjectStrategyUsesTenantAndObjectID(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var rawIDToken string
	issuer := newOIDCTestIssuer(t, func(issuerURL string) oidcTestHandlerConfig {
		rawIDToken = signOIDCTestToken(t, key, map[string]any{
			"iss":   issuerURL,
			"aud":   "client-id",
			"sub":   "pairwise-subject",
			"tid":   "tenant-1",
			"oid":   "object-1",
			"exp":   time.Now().Add(time.Hour).Unix(),
			"iat":   time.Now().Add(-time.Minute).Unix(),
			"email": "alice@example.com",
		})
		return oidcTestHandlerConfig{Key: key, IDToken: rawIDToken}
	})
	provider, err := New(context.Background(), Config{
		ProviderID:       "entra",
		Profile:          "entra",
		Issuer:           issuer.URL,
		ClientID:         "client-id",
		ClientSecret:     "client-secret",
		RedirectURL:      "https://auth.example.com/auth/entra/callback",
		Scopes:           []string{"openid", "email", "profile"},
		SubjectStrategy:  "entra_oid_tid",
		RequiredTenantID: "tenant-1",
	})
	if err != nil {
		t.Fatal(err)
	}

	identity, err := provider.CompleteAuth(context.Background(), ports.CompleteAuthRequest{Code: "auth-code"})
	if err != nil {
		t.Fatal(err)
	}
	if identity.Subject != "tenant-1:object-1" || identity.SubjectStrategy != "entra_oid_tid" {
		t.Fatalf("unexpected entra subject: %#v", identity)
	}
}

func TestBeginAuthWithRequiredPKCEStoresVerifierAndSendsChallenge(t *testing.T) {
	t.Parallel()
	issuer := newOIDCTestIssuer(t, nil)
	provider, err := New(context.Background(), Config{
		ProviderID:   "keycloak-prod",
		Issuer:       issuer.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURL:  "https://auth.example.com/auth/keycloak-prod/callback",
		Scopes:       []string{"openid", "email", "profile"},
		PKCE:         "required",
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err := provider.BeginAuth(context.Background(), ports.BeginAuthRequest{State: "state-123"})
	if err != nil {
		t.Fatal(err)
	}
	var privateState oidcPrivateState
	if err := json.Unmarshal(result.PrivateState, &privateState); err != nil {
		t.Fatalf("private state should contain pkce verifier json: %v", err)
	}
	if privateState.CodeVerifier == "" {
		t.Fatal("private state code_verifier is empty")
	}
	redirect, err := url.Parse(result.RedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	values := redirect.Query()
	assertQueryValue(t, values, "code_challenge_method", "S256")
	assertQueryValue(t, values, "code_challenge", codeChallengeS256(privateState.CodeVerifier))
}

func TestCompleteAuthWithRequiredPKCERequiresPrivateVerifier(t *testing.T) {
	t.Parallel()
	issuer := newOIDCTestIssuer(t, nil)
	provider, err := New(context.Background(), Config{
		ProviderID:   "keycloak-prod",
		Issuer:       issuer.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURL:  "https://auth.example.com/auth/keycloak-prod/callback",
		Scopes:       []string{"openid", "email", "profile"},
		PKCE:         "required",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = provider.CompleteAuth(context.Background(), ports.CompleteAuthRequest{Code: "auth-code"})
	if err == nil || !strings.Contains(err.Error(), "code_verifier missing") {
		t.Fatalf("CompleteAuth error = %v, want missing pkce verifier", err)
	}
}

func TestCompleteAuthWithRequiredPKCESendsCodeVerifier(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const verifier = "test-pkce-verifier"
	var rawIDToken string
	issuer := newOIDCTestIssuer(t, func(issuerURL string) oidcTestHandlerConfig {
		rawIDToken = signOIDCTestToken(t, key, map[string]any{
			"iss":            issuerURL,
			"aud":            "client-id",
			"sub":            "subject-1",
			"exp":            time.Now().Add(time.Hour).Unix(),
			"iat":            time.Now().Add(-time.Minute).Unix(),
			"email":          "alice@example.com",
			"email_verified": true,
		})
		return oidcTestHandlerConfig{Key: key, IDToken: rawIDToken, ExpectedCodeVerifier: verifier}
	})
	provider, err := New(context.Background(), Config{
		ProviderID:   "keycloak-prod",
		Issuer:       issuer.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURL:  "https://auth.example.com/auth/keycloak-prod/callback",
		Scopes:       []string{"openid", "email", "profile"},
		PKCE:         "required",
	})
	if err != nil {
		t.Fatal(err)
	}
	privateState, err := json.Marshal(oidcPrivateState{CodeVerifier: verifier})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := provider.CompleteAuth(context.Background(), ports.CompleteAuthRequest{Code: "auth-code", PrivateState: privateState}); err != nil {
		t.Fatal(err)
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
	Key                  *rsa.PrivateKey
	IDToken              string
	ExpectedCodeVerifier string
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
			if cfg.ExpectedCodeVerifier != "" {
				if err := r.ParseForm(); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				if got := r.Form.Get("code_verifier"); got != cfg.ExpectedCodeVerifier {
					http.Error(w, "unexpected code_verifier", http.StatusBadRequest)
					return
				}
			}
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
