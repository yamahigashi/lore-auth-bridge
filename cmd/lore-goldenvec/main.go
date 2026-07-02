package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yamahigashi/lore-auth-bridge/internal/adapter/rs256"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
)

const (
	defaultOutDir     = ".probe/golden"
	defaultKeyName    = "key.pem"
	defaultKid        = "lore-golden-2026-07-02-01"
	defaultIssuer     = "https://auth.example.com"
	defaultSubject    = "google:golden-user-0001"
	defaultName       = "Golden Vector User"
	defaultUsername   = "golden@example.com"
	defaultIDP        = "google"
	defaultRepository = "0194b726b34e72b0b45550b88a967076"
	defaultAuthnJTI   = "00000000-0000-4000-8000-000000000001"
	defaultAuthzJTI   = "00000000-0000-4000-8000-000000000002"
)

var defaultNow = time.Date(2026, 7, 2, 0, 0, 0, 0, time.UTC)

func main() {
	log.SetFlags(0)
	if err := run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		args = []string{"lore-goldenvec"}
	}
	fs := flag.NewFlagSet("lore-goldenvec", flag.ContinueOnError)
	outDir := fs.String("out-dir", defaultOutDir, "output directory")
	keyPath := fs.String("key", "", "RSA private key PEM; default is <out-dir>/key.pem")
	kid := fs.String("kid", defaultKid, "JWK/JWT key id")
	bits := fs.Int("bits", rs256.DefaultRSABits, "RSA modulus bits used when generating a missing key")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *outDir == "" {
		return errors.New("--out-dir must not be empty")
	}
	if *keyPath == "" {
		*keyPath = filepath.Join(*outDir, defaultKeyName)
	}

	if err := os.MkdirAll(*outDir, 0o700); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	key, err := loadOrGenerateKey(*keyPath, *kid, *bits)
	if err != nil {
		return err
	}
	signer, err := newGoldenSigner(key, *keyPath)
	if err != nil {
		return err
	}
	ctx := context.Background()

	authn, err := signer.SignAuthn(ctx, model.AuthnTokenInput{
		Issuer:            defaultIssuer,
		Audience:          []string{"lore-service", "127.0.0.1"},
		Subject:           defaultSubject,
		Name:              defaultName,
		PreferredUsername: defaultUsername,
		Groups:            []string{"golden-testers", "writers"},
		IDP:               defaultIDP,
		TTL:               time.Hour,
		Now:               defaultNow,
		JTI:               defaultAuthnJTI,
	})
	if err != nil {
		return fmt.Errorf("sign authn token: %w", err)
	}
	authz, err := signer.SignAuthz(ctx, model.AuthzTokenInput{
		Issuer:            defaultIssuer,
		Audience:          []string{"lore-service", "127.0.0.1"},
		Subject:           defaultSubject,
		Name:              defaultName,
		PreferredUsername: defaultUsername,
		Groups:            []string{"golden-testers", "writers"},
		IDP:               defaultIDP,
		Resources: []model.ResourcePermission{{
			ResourceID: rs256.ResourceIDForRepositoryID(defaultRepository),
			Permission: []string{"read", "write"},
		}},
		TTL: 15 * time.Minute,
		Now: defaultNow,
		JTI: defaultAuthzJTI,
	})
	if err != nil {
		return fmt.Errorf("sign authz token: %w", err)
	}
	jwks, err := signer.JWKS(ctx)
	if err != nil {
		return fmt.Errorf("export jwks: %w", err)
	}
	if err := writeTokenOutputs(*outDir, "authn", authn.Token); err != nil {
		return err
	}
	if err := writeTokenOutputs(*outDir, "authz", authz.Token); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(*outDir, "jwks.json"), appendNewline(jwks), 0o644); err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "wrote golden vectors to %s\n", *outDir)
	return nil
}

func loadOrGenerateKey(path, kid string, bits int) (*rs256.SigningKey, error) {
	if path == "" {
		return nil, errors.New("key path must not be empty")
	}
	if _, err := os.Stat(path); err == nil {
		return rs256.LoadSigningKeyPEM(path, kid)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("stat key: %w", err)
	}
	key, err := rs256.GenerateSigningKey(kid, bits)
	if err != nil {
		return nil, err
	}
	if err := key.WritePrivatePEMExclusive(path); err != nil {
		return nil, err
	}
	return key, nil
}

func newGoldenSigner(key *rs256.SigningKey, keyPath string) (*rs256.Signer, error) {
	jwkJSON, err := json.Marshal(rs256.NewRSAJWK(key.Kid, key.Alg, key.Public()))
	if err != nil {
		return nil, fmt.Errorf("marshal public jwk: %w", err)
	}
	store := goldenKeyStore{meta: model.SigningKeyMeta{
		Kid:            key.Kid,
		Alg:            key.Alg,
		PublicJWKJSON:  string(jwkJSON),
		PrivateKeyPath: keyPath,
		Status:         "active",
	}}
	return rs256.NewSigner(key.Kid, store), nil
}

type goldenKeyStore struct {
	meta model.SigningKeyMeta
}

func (s goldenKeyStore) ActiveSigningKey(ctx context.Context, kid string) (model.SigningKeyMeta, error) {
	return s.SigningKeyByKID(ctx, kid)
}

func (s goldenKeyStore) SigningKeyByKID(ctx context.Context, kid string) (model.SigningKeyMeta, error) {
	if kid != s.meta.Kid {
		return model.SigningKeyMeta{}, model.ErrNotFound
	}
	return s.meta, nil
}

func (s goldenKeyStore) PublicJWKS(ctx context.Context) ([]json.RawMessage, error) {
	return []json.RawMessage{json.RawMessage(s.meta.PublicJWKJSON)}, nil
}

func writeTokenOutputs(outDir, prefix, compact string) error {
	if err := writeFile(filepath.Join(outDir, prefix+".jwt"), []byte(compact+"\n"), 0o644); err != nil {
		return err
	}
	headerJSON, claimsJSON, err := decodeCompactJSON(compact)
	if err != nil {
		return fmt.Errorf("decode %s token: %w", prefix, err)
	}
	if err := writeFile(filepath.Join(outDir, prefix+".header.json"), appendNewline(headerJSON), 0o644); err != nil {
		return err
	}
	return writeFile(filepath.Join(outDir, prefix+".claims.json"), appendNewline(claimsJSON), 0o644)
}

func decodeCompactJSON(compact string) ([]byte, []byte, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("compact JWT must have 3 parts, got %d", len(parts))
	}
	headerJSON, err := decodeAndIndent(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("header: %w", err)
	}
	claimsJSON, err := decodeAndIndent(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("claims: %w", err)
	}
	return headerJSON, claimsJSON, nil
}

func decodeAndIndent(encoded string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, raw, "", "  "); err != nil {
		return nil, err
	}
	return pretty.Bytes(), nil
}

func appendNewline(raw []byte) []byte {
	if len(raw) == 0 || raw[len(raw)-1] == '\n' {
		return raw
	}
	out := append([]byte(nil), raw...)
	out = append(out, '\n')
	return out
}

func writeFile(path string, raw []byte, perm os.FileMode) error {
	if err := os.WriteFile(path, raw, perm); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
