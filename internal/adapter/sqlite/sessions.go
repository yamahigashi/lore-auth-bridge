package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
)

func NewSessionID() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (s *Store) CreateSession(ctx context.Context, userID string, ttlSeconds int) (*Session, error) {
	id, err := NewSessionID()
	if err != nil {
		return nil, err
	}
	now := UnixNow()
	sess := &Session{ID: id, UserID: userID, CreatedAt: now, ExpiresAt: now + int64(ttlSeconds)}
	_, err = s.db.ExecContext(ctx, `INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)`, sess.ID, sess.UserID, sess.CreatedAt, sess.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("store: create session: %w", err)
	}
	return sess, nil
}

func (s *Store) RevokeSession(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, UnixNow(), id)
	if err != nil {
		return err
	}
	return requireAffected(res)
}

func (s *Store) UserBySession(ctx context.Context, id string) (*User, error) {
	var userID string
	err := s.db.QueryRowContext(ctx, `SELECT user_id FROM sessions WHERE id = ? AND revoked_at IS NULL AND expires_at > ?`, id, UnixNow()).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return s.UserByID(ctx, userID)
}

func (s *Store) CreateCSRFToken(ctx context.Context, sessionID string, ttlSeconds int) (string, error) {
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	now := UnixNow()
	_, err = s.db.ExecContext(ctx, `INSERT INTO csrf_tokens (token_hash, session_id, created_at, expires_at) VALUES (?, ?, ?, ?)`, HashAuthCode(token), sessionID, now, now+int64(ttlSeconds))
	if err != nil {
		return "", fmt.Errorf("store: create csrf token: %w", err)
	}
	return token, nil
}

func (s *Store) ConsumeCSRFToken(ctx context.Context, sessionID, token string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE csrf_tokens SET consumed_at = ? WHERE token_hash = ? AND session_id = ? AND consumed_at IS NULL AND expires_at > ?`, UnixNow(), HashAuthCode(token), sessionID, UnixNow())
	if err != nil {
		return err
	}
	return requireAffected(res)
}
