package rs256

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"

	"github.com/google/uuid"

	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
)

type KeyStore interface {
	ActiveSigningKey(ctx context.Context, kid string) (model.SigningKeyMeta, error)
	SigningKeyByKID(ctx context.Context, kid string) (model.SigningKeyMeta, error)
	PublicJWKS(ctx context.Context) ([]json.RawMessage, error)
}

type KeyAdminStore interface {
	SigningKeyByKID(ctx context.Context, kid string) (model.SigningKeyMeta, error)
	AddSigningKeyMeta(ctx context.Context, key model.SigningKeyMeta) (model.SigningKeyMeta, error)
	ListSigningKeyMeta(ctx context.Context) ([]model.SigningKeyMeta, error)
}

var validKIDPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

type Signer struct {
	activeKID string
	keys      KeyStore
}

func NewSigner(activeKID string, keys KeyStore) *Signer {
	return &Signer{activeKID: activeKID, keys: keys}
}

func (s *Signer) SignAuthn(ctx context.Context, input model.AuthnTokenInput) (model.SignedToken, error) {
	key, meta, err := s.activeSigningKey(ctx)
	if err != nil {
		return model.SignedToken{}, err
	}
	if input.JTI == "" {
		input.JTI = uuid.NewString()
	}
	claims, err := NewAuthnClaims(AuthnOptions{
		Issuer:            input.Issuer,
		Audience:          input.Audience,
		Subject:           input.Subject,
		Name:              input.Name,
		PreferredUsername: input.PreferredUsername,
		Groups:            input.Groups,
		IDP:               input.IDP,
		TTL:               input.TTL,
		JTI:               input.JTI,
	})
	if err != nil {
		return model.SignedToken{}, err
	}
	jwt, err := key.SignLoreClaims(claims)
	if err != nil {
		return model.SignedToken{}, err
	}
	return model.SignedToken{Token: jwt, JTI: input.JTI, Kid: meta.Kid, IssuedAt: claims.IssuedAt, ExpiresAt: claims.ExpiresAt, Audience: claims.Audience}, nil
}

func (s *Signer) SignAuthz(ctx context.Context, input model.AuthzTokenInput) (model.SignedToken, error) {
	key, meta, err := s.activeSigningKey(ctx)
	if err != nil {
		return model.SignedToken{}, err
	}
	if input.JTI == "" {
		input.JTI = uuid.NewString()
	}
	resources := make([]LoreResourcePermission, 0, len(input.Resources))
	for _, resource := range input.Resources {
		resources = append(resources, LoreResourcePermission{ResourceID: resource.ResourceID, Permission: append([]string(nil), resource.Permission...)})
	}
	claims, err := NewAuthzClaims(AuthzOptions{
		Issuer:            input.Issuer,
		Audience:          input.Audience,
		Subject:           input.Subject,
		Name:              input.Name,
		PreferredUsername: input.PreferredUsername,
		Groups:            input.Groups,
		IDP:               input.IDP,
		Resources:         resources,
		TTL:               input.TTL,
		JTI:               input.JTI,
	})
	if err != nil {
		return model.SignedToken{}, err
	}
	jwt, err := key.SignLoreClaims(claims)
	if err != nil {
		return model.SignedToken{}, err
	}
	firstResource := ""
	var permissions []string
	if len(claims.Resources) > 0 {
		firstResource = claims.Resources[0].ResourceID
		permissions = append([]string(nil), claims.Resources[0].Permission...)
	}
	return model.SignedToken{Token: jwt, JTI: input.JTI, Kid: meta.Kid, LoreResourceID: firstResource, IssuedAt: claims.IssuedAt, ExpiresAt: claims.ExpiresAt, Permissions: permissions, Audience: claims.Audience}, nil
}

func (s *Signer) Verify(ctx context.Context, compact string, opts model.VerifyOptions) (model.VerifiedToken, error) {
	kid, err := KidFromCompact(compact)
	if err != nil {
		return model.VerifiedToken{}, err
	}
	keyMeta, err := s.keys.SigningKeyByKID(ctx, kid)
	if err != nil {
		return model.VerifiedToken{}, err
	}
	pub, err := publicKeyFromJWKJSON(keyMeta.PublicJWKJSON)
	if err != nil {
		return model.VerifiedToken{}, err
	}
	claims, err := ParseAndVerify(compact, pub, VerifyOptions{Issuer: opts.Issuer, Audience: opts.Audience})
	if err != nil {
		return model.VerifiedToken{}, err
	}
	raw, _ := json.Marshal(claims)
	return model.VerifiedToken{Subject: claims.Subject, JTI: claims.JTI, IDP: claims.IDP, ExpiresAt: claims.ExpiresAt, Audience: append([]string(nil), claims.Audience...), RawClaims: raw}, nil
}

func (s *Signer) JWKS(ctx context.Context) (json.RawMessage, error) {
	keys, err := s.keys.PublicJWKS(ctx)
	if err != nil {
		return nil, err
	}
	body := struct {
		Keys []json.RawMessage `json:"keys"`
	}{Keys: keys}
	return json.Marshal(body)
}

func (s *Signer) Validate(ctx context.Context) error {
	key, meta, err := s.activeSigningKey(ctx)
	if err != nil {
		return fmt.Errorf("token: validate active signing key: %w", err)
	}
	jwkPub, err := publicKeyFromJWKJSON(meta.PublicJWKJSON)
	if err != nil {
		return fmt.Errorf("token: validate public jwk: %w", err)
	}
	privatePub := key.Public()
	if privatePub.E != jwkPub.E || privatePub.N.Cmp(jwkPub.N) != 0 {
		return fmt.Errorf("%w: active kid %q public jwk does not match private key", model.ErrSigningKeyUnavailable, meta.Kid)
	}
	if _, err := s.JWKS(ctx); err != nil {
		return fmt.Errorf("token: validate jwks: %w", err)
	}
	return nil
}

func (s *Signer) activeSigningKey(ctx context.Context) (*SigningKey, model.SigningKeyMeta, error) {
	meta, err := s.keys.ActiveSigningKey(ctx, s.activeKID)
	if err != nil {
		return nil, model.SigningKeyMeta{}, fmt.Errorf("%w: active kid %q: %v", model.ErrSigningKeyUnavailable, s.activeKID, err)
	}
	key, err := LoadSigningKeyPEM(meta.PrivateKeyPath, meta.Kid)
	if err != nil {
		return nil, model.SigningKeyMeta{}, fmt.Errorf("%w: active kid %q key material: %v", model.ErrSigningKeyUnavailable, meta.Kid, err)
	}
	return key, meta, nil
}

type SigningKeyAdmin struct {
	dir   string
	store KeyAdminStore
}

func NewSigningKeyAdmin(dir string, store KeyAdminStore) *SigningKeyAdmin {
	return &SigningKeyAdmin{dir: dir, store: store}
}

func (a *SigningKeyAdmin) GenerateActiveKey(ctx context.Context, kid, alg string, bits int) (model.SigningKeyMeta, error) {
	if alg == "" {
		alg = AlgRS256
	}
	if alg != AlgRS256 {
		return model.SigningKeyMeta{}, fmt.Errorf("only RS256 is supported")
	}
	if !validKIDPattern.MatchString(kid) {
		return model.SigningKeyMeta{}, fmt.Errorf("%w: kid contains unsupported characters", model.ErrInvalidArgument)
	}
	if _, err := a.store.SigningKeyByKID(ctx, kid); err == nil {
		return model.SigningKeyMeta{}, fmt.Errorf("%w: signing key kid %q already exists", model.ErrInvalidArgument, kid)
	} else if !errors.Is(err, model.ErrNotFound) {
		return model.SigningKeyMeta{}, fmt.Errorf("token: check existing signing key: %w", err)
	}
	key, err := GenerateSigningKey(kid, bits)
	if err != nil {
		return model.SigningKeyMeta{}, err
	}
	if err := os.MkdirAll(a.dir, 0o700); err != nil {
		return model.SigningKeyMeta{}, err
	}
	privatePath := filepath.Join(a.dir, kid+".pem")
	if err := key.WritePrivatePEMExclusive(privatePath); err != nil {
		return model.SigningKeyMeta{}, err
	}
	jwkJSON, err := json.Marshal(NewRSAJWK(key.Kid, key.Alg, key.Public()))
	if err != nil {
		_ = os.Remove(privatePath)
		return model.SigningKeyMeta{}, err
	}
	meta, err := a.store.AddSigningKeyMeta(ctx, model.SigningKeyMeta{Kid: key.Kid, Alg: key.Alg, PublicJWKJSON: string(jwkJSON), PrivateKeyPath: privatePath, Status: "active"})
	if err != nil {
		if removeErr := os.Remove(privatePath); removeErr != nil {
			return model.SigningKeyMeta{}, errors.Join(err, fmt.Errorf("token: cleanup private key: %w", removeErr))
		}
		return model.SigningKeyMeta{}, err
	}
	return meta, nil
}

func (a *SigningKeyAdmin) ListKeys(ctx context.Context) ([]model.SigningKeyMeta, error) {
	return a.store.ListSigningKeyMeta(ctx)
}

func publicKeyFromJWKJSON(raw string) (*rsa.PublicKey, error) {
	var jwk JWK
	if err := json.Unmarshal([]byte(raw), &jwk); err != nil {
		return nil, err
	}
	nBytes, err := base64URLDecode(jwk.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64URLDecode(jwk.E)
	if err != nil {
		return nil, err
	}
	e := big.NewInt(0).SetBytes(eBytes).Int64()
	if e == 0 {
		return nil, fmt.Errorf("token: invalid jwk exponent")
	}
	return &rsa.PublicKey{N: big.NewInt(0).SetBytes(nBytes), E: int(e)}, nil
}

func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
