package rs256

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// KidFromCompact returns the `kid` JWS header parameter without verifying.
func KidFromCompact(compact string) (string, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("token: compact JWT must have 3 parts")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("token: decode header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return "", fmt.Errorf("token: parse header: %w", err)
	}
	if header.Alg != AlgRS256 {
		return "", fmt.Errorf("token: unexpected alg %q", header.Alg)
	}
	if header.Kid == "" {
		return "", errors.New("token: missing kid")
	}
	return header.Kid, nil
}

type VerifyOptions struct {
	Issuer   string
	Audience string // if set, must be present in claims aud
	Now      time.Time
}

// ParseAndVerify validates the RS256 signature and standard claims of a compact
// JWT against the provided public key.
func ParseAndVerify(compact string, pub *rsa.PublicKey, opts VerifyOptions) (*LoreClaims, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("token: compact JWT must have 3 parts")
	}
	signingInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("token: decode signature: %w", err)
	}
	hash := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], sig); err != nil {
		return nil, fmt.Errorf("token: signature verification failed: %w", err)
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("token: decode payload: %w", err)
	}
	var claims LoreClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("token: parse claims: %w", err)
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if claims.ExpiresAt != 0 && now.Unix() >= claims.ExpiresAt {
		return nil, errors.New("token: expired")
	}
	if opts.Issuer != "" && claims.Issuer != opts.Issuer {
		return nil, fmt.Errorf("token: unexpected issuer %q", claims.Issuer)
	}
	if opts.Audience != "" && !containsString(claims.Audience, opts.Audience) {
		return nil, fmt.Errorf("token: audience %q not present", opts.Audience)
	}
	return &claims, nil
}

func containsString(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}
