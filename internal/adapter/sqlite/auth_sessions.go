package sqlite

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

type AuthSession struct {
	ID              string
	SessionCodeHash string
	ClientStateHash string
	Status          string
	UserID          sql.NullString
	LoginURLNonce   string
	CreatedAt       int64
	ExpiresAt       int64
	CompletedAt     sql.NullInt64
	ConsumedAt      sql.NullInt64
}

func HashAuthCode(code string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(code)))
	return hex.EncodeToString(sum[:])
}

func randomToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// CreateAuthSession starts a pending interactive-login session and returns the
// plaintext session_code (stored only as a hash).
func (s *Store) CreateAuthSession(ctx context.Context, clientState string, ttlSeconds int) (string, *AuthSession, error) {
	code, err := randomToken(32)
	if err != nil {
		return "", nil, err
	}
	nonce, err := randomToken(16)
	if err != nil {
		return "", nil, err
	}
	now := UnixNow()
	sess := &AuthSession{ID: NewID(), SessionCodeHash: HashAuthCode(code), ClientStateHash: HashAuthCode(clientState), Status: "pending", LoginURLNonce: nonce, CreatedAt: now, ExpiresAt: now + int64(ttlSeconds)}
	_, err = s.db.ExecContext(ctx, `INSERT INTO auth_sessions (id, session_code_hash, client_state_hash, status, login_url_nonce, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`, sess.ID, sess.SessionCodeHash, sess.ClientStateHash, sess.Status, sess.LoginURLNonce, sess.CreatedAt, sess.ExpiresAt)
	if err != nil {
		return "", nil, fmt.Errorf("store: create auth session: %w", err)
	}
	return code, sess, nil
}

func (s *Store) AuthSessionByCode(ctx context.Context, code string) (*AuthSession, error) {
	return s.scanAuthSession(s.db.QueryRowContext(ctx, `SELECT id, session_code_hash, client_state_hash, status, user_id, login_url_nonce, created_at, expires_at, completed_at, consumed_at FROM auth_sessions WHERE session_code_hash = ?`, HashAuthCode(code)))
}

func (s *Store) AuthSessionByNonce(ctx context.Context, nonce string) (*AuthSession, error) {
	return s.scanAuthSession(s.db.QueryRowContext(ctx, `SELECT id, session_code_hash, client_state_hash, status, user_id, login_url_nonce, created_at, expires_at, completed_at, consumed_at FROM auth_sessions WHERE login_url_nonce = ?`, nonce))
}

func (s *Store) CompleteAuthSession(ctx context.Context, id, userID string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE auth_sessions SET status = 'completed', user_id = ?, completed_at = ? WHERE id = ? AND status = 'pending' AND expires_at > ?`, userID, UnixNow(), id, UnixNow())
	if err != nil {
		return err
	}
	return requireAffected(res)
}

func (s *Store) ConsumeAuthSession(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE auth_sessions SET status = 'consumed', consumed_at = ? WHERE id = ? AND status = 'completed'`, UnixNow(), id)
	if err != nil {
		return err
	}
	return requireAffected(res)
}

func (s *Store) scanAuthSession(row rowScanner) (*AuthSession, error) {
	var a AuthSession
	err := row.Scan(&a.ID, &a.SessionCodeHash, &a.ClientStateHash, &a.Status, &a.UserID, &a.LoginURLNonce, &a.CreatedAt, &a.ExpiresAt, &a.CompletedAt, &a.ConsumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}
