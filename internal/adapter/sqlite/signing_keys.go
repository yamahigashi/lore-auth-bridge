package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

type AddSigningKeyParams struct {
	Kid            string
	Alg            string
	PublicJWKJSON  string
	PrivateKeyPath string
	Status         string
}

func (s *Store) AddSigningKey(ctx context.Context, p AddSigningKeyParams) (*SigningKeyMetadata, error) {
	if p.Status == "" {
		p.Status = "active"
	}
	now := UnixNow()
	_, err := s.db.ExecContext(ctx, `INSERT INTO signing_keys (kid, alg, public_jwk_json, private_key_path, status, created_at) VALUES (?, ?, ?, ?, ?, ?)`, p.Kid, p.Alg, p.PublicJWKJSON, p.PrivateKeyPath, p.Status, now)
	if err != nil {
		return nil, fmt.Errorf("store: add signing key: %w", err)
	}
	return &SigningKeyMetadata{Kid: p.Kid, Alg: p.Alg, PublicJWKJSON: p.PublicJWKJSON, PrivateKeyPath: p.PrivateKeyPath, Status: p.Status, CreatedAt: now}, nil
}

func (s *Store) ActiveSigningKey(ctx context.Context, kid string) (*SigningKeyMetadata, error) {
	query := `SELECT kid, alg, public_jwk_json, private_key_path, status, created_at, not_before, retired_at FROM signing_keys WHERE status = 'active'`
	var args []any
	if kid != "" {
		query += ` AND kid = ?`
		args = append(args, kid)
	}
	query += ` ORDER BY created_at DESC LIMIT 1`
	return s.scanSigningKey(s.db.QueryRowContext(ctx, query, args...))
}

func (s *Store) SigningKeyByKID(ctx context.Context, kid string) (*SigningKeyMetadata, error) {
	return s.scanSigningKey(s.db.QueryRowContext(ctx, `SELECT kid, alg, public_jwk_json, private_key_path, status, created_at, not_before, retired_at FROM signing_keys WHERE kid = ?`, kid))
}

func (s *Store) ListSigningKeys(ctx context.Context) ([]SigningKeyMetadata, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT kid, alg, public_jwk_json, private_key_path, status, created_at, not_before, retired_at FROM signing_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SigningKeyMetadata
	for rows.Next() {
		k, err := s.scanSigningKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *k)
	}
	return out, rows.Err()
}

func (s *Store) PublicJWKS(ctx context.Context) ([]json.RawMessage, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT public_jwk_json FROM signing_keys WHERE status IN ('active', 'retiring') ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []json.RawMessage
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		if !json.Valid([]byte(raw)) {
			return nil, fmt.Errorf("store: invalid public_jwk_json")
		}
		out = append(out, json.RawMessage(raw))
	}
	return out, rows.Err()
}

func (s *Store) scanSigningKey(row rowScanner) (*SigningKeyMetadata, error) {
	var k SigningKeyMetadata
	err := row.Scan(&k.Kid, &k.Alg, &k.PublicJWKJSON, &k.PrivateKeyPath, &k.Status, &k.CreatedAt, &k.NotBefore, &k.RetiredAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &k, nil
}
