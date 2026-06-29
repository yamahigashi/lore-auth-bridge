package rs256

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
)

// JWKSet is the public key document served at /.well-known/jwks.json.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// JWK is the RSA public-key subset Lore Server needs. The jsonwebtoken Rust
// crate used by Lore reads kid and alg from the common JWK fields, then builds a
// decoding key from n/e.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS returns a one-key set for this signing key. During rotation the broker
// server will publish active + retiring keys; the probe only needs one.
func (k *SigningKey) JWKS() JWKSet {
	return JWKSet{Keys: []JWK{NewRSAJWK(k.Kid, k.Alg, k.Public())}}
}

// NewRSAJWK converts an RSA public key into an RFC 7517/7518-compatible JWK.
func NewRSAJWK(kid, alg string, pub *rsa.PublicKey) JWK {
	return JWK{
		Kty: "RSA",
		Use: "sig",
		Kid: kid,
		Alg: alg,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// MarshalJWKS renders a stable, indented JWKS document suitable for writing to a
// file or serving over HTTP.
func MarshalJWKS(set JWKSet) ([]byte, error) {
	return json.MarshalIndent(set, "", "  ")
}
