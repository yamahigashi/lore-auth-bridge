package rs256

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// SignLoreClaims signs the supplied provisional Lore claims as an RS256 compact
// JWS. No external JWT library is used here; the small explicit implementation
// makes the emitted contract easy to inspect during the probe.
func (k *SigningKey) SignLoreClaims(claims LoreClaims) (string, error) {
	header := jwtHeader{
		Alg: k.Alg,
		Typ: "JWT",
		Kid: k.Kid,
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("token: marshal JWT header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("token: marshal JWT claims: %w", err)
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := encodedHeader + "." + encodedClaims
	hash := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k.Private, crypto.SHA256, hash[:])
	if err != nil {
		return "", fmt.Errorf("token: sign JWT: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// DecodeInsecure splits a compact JWT and decodes the JSON header and payload
// without verifying the signature. It is probe/debug-only.
func DecodeInsecure(compact string) (map[string]any, map[string]any, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("token: compact JWT must have 3 parts, got %d", len(parts))
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("token: decode JWT header: %w", err)
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("token: decode JWT payload: %w", err)
	}
	var header map[string]any
	var payload map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, nil, fmt.Errorf("token: unmarshal JWT header: %w", err)
	}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, nil, fmt.Errorf("token: unmarshal JWT payload: %w", err)
	}
	return header, payload, nil
}
