package rs256

import (
	"errors"
	"time"
)

const (
	// WildcardResourceID is accepted by current Lore Server source as "all
	// repositories". It must remain an explicit probe/admin-only choice.
	WildcardResourceID = "urc-*"

	// DefaultEnv is the environment claim used by the probe unless overridden.
	DefaultEnv = "prod"
)

// LoreClaims is the provisional AuthorizationToken contract observed in the
// current Lore source. It intentionally remains small and explicit until the
// claim contract probe has been run against the user's actual Lore binary.
type LoreClaims struct {
	Subject           string                   `json:"sub"`
	Issuer            string                   `json:"iss"`
	IssuedAt          int64                    `json:"iat"`
	ExpiresAt         int64                    `json:"exp"`
	Audience          []string                 `json:"aud"`
	Env               string                   `json:"env"`
	Name              string                   `json:"name"`
	PreferredUsername string                   `json:"preferred_username"`
	Resources         []LoreResourcePermission `json:"resources,omitempty"`
	Groups            []string                 `json:"groups,omitempty"`
	IsServiceAccount  *bool                    `json:"is_service_account,omitempty"`
	IDP               string                   `json:"idp"`

	// JTI is not part of the observed Lore AuthorizationToken struct. It is kept
	// for broker-side audit/issued-token tracking and should not be assumed to
	// affect Lore Server authorization decisions.
	JTI string `json:"jti,omitempty"`
}

type LoreResourcePermission struct {
	ResourceID string   `json:"resource_id"`
	Permission []string `json:"permission"`
}

type ClaimsOptions struct {
	Issuer            string
	Audience          []string
	Subject           string
	Env               string
	Name              string
	PreferredUsername string
	Groups            []string
	IDP               string
	IsServiceAccount  bool
	ResourceID        string
	Permissions       []string
	WithoutResources  bool
	TTL               time.Duration
	Now               time.Time
	JTI               string
}

func NewLoreClaims(opts ClaimsOptions) (LoreClaims, error) {
	if opts.Issuer == "" {
		return LoreClaims{}, errors.New("token: issuer must not be empty")
	}
	if len(opts.Audience) == 0 {
		return LoreClaims{}, errors.New("token: audience must not be empty")
	}
	if opts.Subject == "" {
		return LoreClaims{}, errors.New("token: subject must not be empty")
	}
	if opts.ResourceID == "" && !opts.WithoutResources {
		return LoreClaims{}, errors.New("token: resource id must not be empty")
	}
	if opts.TTL == 0 {
		opts.TTL = time.Hour
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	if opts.Env == "" {
		opts.Env = DefaultEnv
	}
	if opts.IDP == "" {
		return LoreClaims{}, errors.New("token: idp must not be empty")
	}
	if opts.Name == "" {
		opts.Name = opts.Subject
	}
	if opts.PreferredUsername == "" {
		opts.PreferredUsername = opts.Subject
	}
	isServiceAccount := opts.IsServiceAccount
	claims := LoreClaims{
		Subject:           opts.Subject,
		Issuer:            opts.Issuer,
		IssuedAt:          opts.Now.Unix(),
		ExpiresAt:         opts.Now.Add(opts.TTL).Unix(),
		Audience:          append([]string(nil), opts.Audience...),
		Env:               opts.Env,
		Name:              opts.Name,
		PreferredUsername: opts.PreferredUsername,
		Groups:            append([]string(nil), opts.Groups...),
		IsServiceAccount:  &isServiceAccount,
		IDP:               opts.IDP,
		JTI:               opts.JTI,
	}
	if !opts.WithoutResources {
		claims.Resources = []LoreResourcePermission{
			{
				ResourceID: opts.ResourceID,
				Permission: append([]string(nil), opts.Permissions...),
			},
		}
	}
	return claims, nil
}

// ResourceIDForRepositoryID converts a Lore repository id into the resource id
// current Lore Server source checks in AuthorizationToken.resources.
func ResourceIDForRepositoryID(repositoryID string) string {
	if repositoryID == "" {
		return ""
	}
	if len(repositoryID) >= 4 && repositoryID[:4] == "urc-" {
		return repositoryID
	}
	return "urc-" + repositoryID
}

// AuthnOptions builds an authentication token: it identifies the user and
// carries no repository resources. The Lore CLI stores it and exchanges it for
// resource-scoped authz tokens.
type AuthnOptions struct {
	Issuer            string
	Audience          []string
	Subject           string
	Env               string
	Name              string
	PreferredUsername string
	Groups            []string
	IDP               string
	IsServiceAccount  bool
	TTL               time.Duration
	Now               time.Time
	JTI               string
}

func NewAuthnClaims(opts AuthnOptions) (LoreClaims, error) {
	if opts.Issuer == "" {
		return LoreClaims{}, errors.New("token: issuer must not be empty")
	}
	if len(opts.Audience) == 0 {
		return LoreClaims{}, errors.New("token: audience must not be empty")
	}
	if opts.Subject == "" {
		return LoreClaims{}, errors.New("token: subject must not be empty")
	}
	if opts.TTL == 0 {
		opts.TTL = time.Hour
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	if opts.Env == "" {
		opts.Env = DefaultEnv
	}
	if opts.IDP == "" {
		return LoreClaims{}, errors.New("token: idp must not be empty")
	}
	if opts.Name == "" {
		opts.Name = opts.Subject
	}
	if opts.PreferredUsername == "" {
		opts.PreferredUsername = opts.Subject
	}
	isServiceAccount := opts.IsServiceAccount
	return LoreClaims{
		Subject:           opts.Subject,
		Issuer:            opts.Issuer,
		IssuedAt:          opts.Now.Unix(),
		ExpiresAt:         opts.Now.Add(opts.TTL).Unix(),
		Audience:          append([]string(nil), opts.Audience...),
		Env:               opts.Env,
		Name:              opts.Name,
		PreferredUsername: opts.PreferredUsername,
		Groups:            append([]string(nil), opts.Groups...),
		IsServiceAccount:  &isServiceAccount,
		IDP:               opts.IDP,
		JTI:               opts.JTI,
	}, nil
}

// AuthzOptions builds a resource-scoped authorization token covering one or
// more resources. Returned by ExchangeUserTokenForMultiresourceToken.
type AuthzOptions struct {
	Issuer            string
	Audience          []string
	Subject           string
	Env               string
	Name              string
	PreferredUsername string
	Groups            []string
	IDP               string
	IsServiceAccount  bool
	Resources         []LoreResourcePermission
	TTL               time.Duration
	Now               time.Time
	JTI               string
}

func NewAuthzClaims(opts AuthzOptions) (LoreClaims, error) {
	if len(opts.Resources) == 0 {
		return LoreClaims{}, errors.New("token: authz token requires at least one resource")
	}
	base, err := NewAuthnClaims(AuthnOptions{
		Issuer:            opts.Issuer,
		Audience:          opts.Audience,
		Subject:           opts.Subject,
		Env:               opts.Env,
		Name:              opts.Name,
		PreferredUsername: opts.PreferredUsername,
		Groups:            opts.Groups,
		IDP:               opts.IDP,
		IsServiceAccount:  opts.IsServiceAccount,
		TTL:               opts.TTL,
		Now:               opts.Now,
		JTI:               opts.JTI,
	})
	if err != nil {
		return LoreClaims{}, err
	}
	base.Resources = append([]LoreResourcePermission(nil), opts.Resources...)
	return base, nil
}
