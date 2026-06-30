// Package token implements the Lore JWT issuing primitives shared by the broker
// server, the admin CLI, and the claim-contract probe: RSA signing keys, the
// JWKS document published to Lore Server, and the Lore claim contract itself.
package rs256

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// AlgRS256 is the only signing algorithm the broker issues. Lore Server reads
// the algorithm from the JWK and decodes accordingly; RS256 keeps the private
// key off every verifier while the public JWK stays freely publishable.
const AlgRS256 = "RS256"

// DefaultRSABits is the modulus size used when generating new signing keys.
const DefaultRSABits = 2048

// SigningKey is a private RSA key paired with the key id advertised in JWS
// headers and the JWKS document. The kid is what lets Lore Server pick the
// right public key during rotation, so it travels with the key everywhere.
type SigningKey struct {
	Kid     string
	Alg     string
	Private *rsa.PrivateKey
}

// GenerateSigningKey creates a fresh RS256 signing key with the given kid.
func GenerateSigningKey(kid string, bits int) (*SigningKey, error) {
	if kid == "" {
		return nil, errors.New("token: kid must not be empty")
	}
	if bits == 0 {
		bits = DefaultRSABits
	}
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("token: generate rsa key: %w", err)
	}
	return &SigningKey{Kid: kid, Alg: AlgRS256, Private: priv}, nil
}

// Public returns the public half of the signing key.
func (k *SigningKey) Public() *rsa.PublicKey {
	return &k.Private.PublicKey
}

// WritePrivatePEM serialises the private key as PKCS#8 PEM with 0600
// permissions. The private key never enters the database or the JWKS; the
// filesystem with restrictive mode is the only place it lives.
func (k *SigningKey) WritePrivatePEM(path string) error {
	return k.writePrivatePEM(path, false)
}

func (k *SigningKey) WritePrivatePEMExclusive(path string) error {
	return k.writePrivatePEM(path, true)
}

func (k *SigningKey) writePrivatePEM(path string, exclusive bool) error {
	der, err := x509.MarshalPKCS8PrivateKey(k.Private)
	if err != nil {
		return fmt.Errorf("token: marshal private key: %w", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("token: create key dir: %w", err)
		}
	}
	if !exclusive {
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
			return fmt.Errorf("token: write private key: %w", err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return fmt.Errorf("token: chmod private key: %w", err)
		}
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("token: create private key: %w", err)
	}
	closeFile := true
	cleanupFile := true
	defer func() {
		if closeFile {
			_ = f.Close()
		}
		if cleanupFile {
			_ = os.Remove(path)
		}
	}()
	if _, err := f.Write(pem.EncodeToMemory(block)); err != nil {
		return fmt.Errorf("token: write private key: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("token: sync private key: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("token: close private key: %w", err)
	}
	closeFile = false
	cleanupFile = false
	return nil
}

// WritePublicPEM serialises the public key as PKIX PEM. The public key is not
// secret; this is a convenience for inspection and for tooling that prefers PEM
// over the JWKS document.
func (k *SigningKey) WritePublicPEM(path string) error {
	der, err := x509.MarshalPKIXPublicKey(k.Public())
	if err != nil {
		return fmt.Errorf("token: marshal public key: %w", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o644); err != nil {
		return fmt.Errorf("token: write public key: %w", err)
	}
	return nil
}

// LoadSigningKeyPEM reads a PKCS#8 (or PKCS#1) RSA private key from a PEM file
// and pairs it with the supplied kid.
func LoadSigningKeyPEM(path, kid string) (*SigningKey, error) {
	if kid == "" {
		return nil, errors.New("token: kid must not be empty")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("token: read private key: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("token: no PEM block in %s", path)
	}
	priv, err := parseRSAPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return &SigningKey{Kid: kid, Alg: AlgRS256, Private: priv}, nil
}

func parseRSAPrivateKey(der []byte) (*rsa.PrivateKey, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("token: PKCS#8 key is not RSA")
		}
		return rsaKey, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("token: unsupported private key format (want PKCS#8 or PKCS#1 RSA)")
}
