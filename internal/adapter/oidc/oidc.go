package oidcadapter

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/ports"
)

type Provider struct {
	id                     string
	profile                string
	displayName            string
	issuer                 string
	oauth2Config           oauth2.Config
	verifier               *oidc.IDTokenVerifier
	claimMapping           map[string]string
	subjectStrategy        string
	requiredTenantID       string
	emailBinding           string
	pkce                   string
	allowedEmailDomainList []string
	allowedHostedDomains   map[string]struct{}
	personalAccounts       string
}

type Config struct {
	ProviderID           string
	Profile              string
	DisplayName          string
	Issuer               string
	ClientID             string
	ClientSecret         string
	RedirectURL          string
	Scopes               []string
	ClaimMapping         map[string]string
	SubjectStrategy      string
	RequiredTenantID     string
	EmailBinding         string
	PKCE                 string
	AllowedEmailDomains  []string
	AllowedHostedDomains []string
	PersonalAccounts     string
}

func New(ctx context.Context, cfg Config) (*Provider, error) {
	if cfg.ProviderID == "" {
		return nil, fmt.Errorf("oidc: provider id is required")
	}
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("oidc: issuer is required")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("oidc: client id is required")
	}
	profile := strings.TrimSpace(cfg.Profile)
	personalAccounts := strings.TrimSpace(cfg.PersonalAccounts)
	switch personalAccounts {
	case "", "allow", "deny":
	default:
		return nil, fmt.Errorf("oidc: personal_accounts %q is unknown", cfg.PersonalAccounts)
	}
	if personalAccounts != "" && profile != "google" {
		return nil, fmt.Errorf("oidc: personal_accounts is only valid for google profile")
	}
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: discover provider %q: %w", cfg.Issuer, err)
	}
	var discoveryClaims struct {
		Issuer string `json:"issuer"`
	}
	if err := provider.Claims(&discoveryClaims); err != nil {
		return nil, fmt.Errorf("oidc: decode discovery claims for %q: %w", cfg.Issuer, err)
	}
	issuer := strings.TrimSpace(discoveryClaims.Issuer)
	if issuer == "" {
		issuer = cfg.Issuer
	}
	scopes := append([]string(nil), cfg.Scopes...)
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "email", "profile"}
	}
	allowedEmailDomainList := normalizeDomainList(cfg.AllowedEmailDomains)
	return &Provider{
		id:          cfg.ProviderID,
		profile:     profile,
		displayName: displayNameOrDefault(cfg.DisplayName, cfg.ProviderID),
		issuer:      issuer,
		oauth2Config: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       scopes,
			Endpoint:     provider.Endpoint(),
		},
		verifier:               provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		claimMapping:           copyClaimMapping(cfg.ClaimMapping),
		subjectStrategy:        defaultString(cfg.SubjectStrategy, "oidc_sub"),
		requiredTenantID:       strings.TrimSpace(cfg.RequiredTenantID),
		emailBinding:           defaultString(cfg.EmailBinding, "disabled"),
		pkce:                   strings.TrimSpace(cfg.PKCE),
		allowedEmailDomainList: allowedEmailDomainList,
		allowedHostedDomains:   normalizeDomains(cfg.AllowedHostedDomains),
		personalAccounts:       personalAccounts,
	}, nil
}

func (p *Provider) Descriptor() ports.IdentityProviderDescriptor {
	return ports.IdentityProviderDescriptor{
		ID:          p.id,
		Type:        "oidc",
		DisplayName: p.displayName,
		Issuer:      p.issuer,
		TrustPolicy: model.LoginTrustPolicy{
			EmailBinding:        p.emailBinding,
			AllowedEmailDomains: append([]string(nil), p.allowedEmailDomainList...),
		},
	}
}

func (p *Provider) BeginAuth(ctx context.Context, req ports.BeginAuthRequest) (ports.BeginAuthResult, error) {
	options := []oauth2.AuthCodeOption{oauth2.AccessTypeOnline}
	privateState := oidcPrivateState{}
	if req.Nonce != "" {
		options = append(options, oidc.Nonce(req.Nonce))
	}
	if req.LoginHint != "" {
		options = append(options, oauth2.SetAuthURLParam("login_hint", req.LoginHint))
	}
	if p.pkce == "required" {
		verifier, err := randomVerifier()
		if err != nil {
			return ports.BeginAuthResult{}, err
		}
		privateState.CodeVerifier = verifier
		options = append(options,
			oauth2.SetAuthURLParam("code_challenge", codeChallengeS256(verifier)),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		)
	}
	rawPrivateState, err := json.Marshal(privateState)
	if err != nil {
		return ports.BeginAuthResult{}, err
	}
	if privateState.CodeVerifier == "" {
		rawPrivateState = nil
	}
	return ports.BeginAuthResult{RedirectURL: p.oauth2Config.AuthCodeURL(req.State, options...), PrivateState: rawPrivateState}, nil
}

func (p *Provider) CompleteAuth(ctx context.Context, req ports.CompleteAuthRequest) (model.ExternalIdentity, error) {
	options, err := p.tokenExchangeOptions(req.PrivateState)
	if err != nil {
		return model.ExternalIdentity{}, err
	}
	token, err := p.oauth2Config.Exchange(ctx, req.Code, options...)
	if err != nil {
		return model.ExternalIdentity{}, fmt.Errorf("oidc: exchange code: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return model.ExternalIdentity{}, fmt.Errorf("oidc: oauth response missing id_token")
	}
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return model.ExternalIdentity{}, fmt.Errorf("oidc: verify id token: %w", err)
	}
	if req.Nonce != "" && idToken.Nonce != req.Nonce {
		return model.ExternalIdentity{}, fmt.Errorf("oidc: id token nonce mismatch")
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return model.ExternalIdentity{}, fmt.Errorf("oidc: decode id token claims: %w", err)
	}
	subject, err := p.subject(claims, idToken.Subject)
	if err != nil {
		return model.ExternalIdentity{}, err
	}
	identity := model.ExternalIdentity{ProviderID: p.id, Issuer: idToken.Issuer, Subject: subject, SubjectStrategy: p.subjectStrategy}
	identity.Email = stringClaim(claims, p.claim("email", "email"))
	identity.EmailVerified = boolClaim(claims, p.claim("email_verified", "email_verified"))
	identity.DisplayName = stringClaim(claims, p.claim("name", "name"))
	identity.PictureURL = stringClaim(claims, p.claim("picture", "picture"))
	identity.HostedDomain = stringClaim(claims, p.claim("hosted_domain", "hd"))
	if err := p.validateTrust(identity); err != nil {
		return model.ExternalIdentity{}, err
	}
	return identity, nil
}

func (p *Provider) subject(claims map[string]any, oidcSubject string) (string, error) {
	switch p.subjectStrategy {
	case "", "oidc_sub":
		return oidcSubject, nil
	case "entra_oid_tid":
		tid := stringClaim(claims, "tid")
		if p.requiredTenantID != "" && tid != p.requiredTenantID {
			return "", fmt.Errorf("%w: oidc tenant mismatch", model.ErrPermissionDenied)
		}
		oid := stringClaim(claims, "oid")
		if tid == "" || oid == "" {
			return "", fmt.Errorf("oidc: entra_oid_tid requires tid and oid claims")
		}
		return tid + ":" + oid, nil
	default:
		return "", fmt.Errorf("oidc: unsupported subject strategy %q", p.subjectStrategy)
	}
}

func (p *Provider) validateTrust(identity model.ExternalIdentity) error {
	if p.profile == "google" {
		if err := p.validateHostedDomain(identity); err != nil {
			return err
		}
	}
	return nil
}

func (p *Provider) claim(canonical, fallback string) string {
	if name := strings.TrimSpace(p.claimMapping[canonical]); name != "" {
		return name
	}
	return fallback
}

func (p *Provider) validateHostedDomain(id model.ExternalIdentity) error {
	hostedDomain := strings.ToLower(strings.TrimSpace(id.HostedDomain))
	if len(p.allowedHostedDomains) > 0 {
		if _, ok := p.allowedHostedDomains[hostedDomain]; !ok {
			return fmt.Errorf("%w: google hosted domain is not allowed", model.ErrPermissionDenied)
		}
		return nil
	}
	if hostedDomain == "" && p.personalAccounts == "deny" {
		return fmt.Errorf("%w: google personal accounts are not allowed", model.ErrPermissionDenied)
	}
	return nil
}

type oidcPrivateState struct {
	CodeVerifier string `json:"code_verifier,omitempty"`
}

func (p *Provider) tokenExchangeOptions(raw []byte) ([]oauth2.AuthCodeOption, error) {
	if len(raw) == 0 {
		if p.pkce == "required" {
			return nil, fmt.Errorf("oidc: pkce code_verifier missing")
		}
		return nil, nil
	}
	var privateState oidcPrivateState
	if err := json.Unmarshal(raw, &privateState); err != nil {
		return nil, fmt.Errorf("oidc: decode private state: %w", err)
	}
	if privateState.CodeVerifier == "" {
		if p.pkce == "required" {
			return nil, fmt.Errorf("oidc: pkce code_verifier missing")
		}
		return nil, nil
	}
	return []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("code_verifier", privateState.CodeVerifier)}, nil
}

func copyClaimMapping(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return out
}

func normalizeDomains(values []string) map[string]struct{} {
	return domainsToSet(normalizeDomainList(values))
}

func normalizeDomainList(values []string) []string {
	seen := map[string]struct{}{}
	list := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		list = append(list, value)
	}
	return list
}

func domainsToSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		out[value] = struct{}{}
	}
	return out
}

func stringClaim(claims map[string]any, name string) string {
	value, _ := claims[name].(string)
	return value
}

func boolClaim(claims map[string]any, name string) bool {
	switch value := claims[name].(type) {
	case bool:
		return value
	case string:
		return strings.EqualFold(strings.TrimSpace(value), "true")
	default:
		return false
	}
}

func displayNameOrDefault(displayName, providerID string) string {
	if displayName = strings.TrimSpace(displayName); displayName != "" {
		return displayName
	}
	return providerID
}

func defaultString(value, fallback string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return fallback
}

func randomVerifier() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("oidc: generate pkce verifier: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func codeChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
