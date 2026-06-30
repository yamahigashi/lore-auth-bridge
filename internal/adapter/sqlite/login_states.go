package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

type CreateLoginStateParams struct {
	ProviderID    string
	Nonce         string
	LoginURLNonce string
	ReturnPath    string
	TTLSeconds    int
}

func (s *Store) CreateLoginState(ctx context.Context, p CreateLoginStateParams) (string, *LoginState, error) {
	state, err := randomToken(32)
	if err != nil {
		return "", nil, err
	}
	now := UnixNow()
	loginState := &LoginState{
		ID:            NewID(),
		StateHash:     HashAuthCode(state),
		ProviderID:    p.ProviderID,
		Nonce:         nullString(p.Nonce),
		LoginURLNonce: nullString(p.LoginURLNonce),
		ReturnPath:    nullString(p.ReturnPath),
		CreatedAt:     now,
		ExpiresAt:     now + int64(p.TTLSeconds),
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO login_states (id, state_hash, provider_id, nonce, login_url_nonce, return_path, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		loginState.ID, loginState.StateHash, loginState.ProviderID, loginState.Nonce, loginState.LoginURLNonce, loginState.ReturnPath, loginState.CreatedAt, loginState.ExpiresAt)
	if err != nil {
		return "", nil, fmt.Errorf("store: create login state: %w", err)
	}
	return state, loginState, nil
}

func (s *Store) ConsumeLoginState(ctx context.Context, state string) (*LoginState, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	loginState, err := scanLoginState(tx.QueryRowContext(ctx, `SELECT id, state_hash, provider_id, nonce, login_url_nonce, return_path, created_at, expires_at, consumed_at FROM login_states WHERE state_hash = ?`, HashAuthCode(state)))
	if err != nil {
		return nil, err
	}
	if loginState.ConsumedAt.Valid || loginState.ExpiresAt <= UnixNow() {
		return nil, ErrNotFound
	}
	res, err := tx.ExecContext(ctx, `UPDATE login_states SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL AND expires_at > ?`, UnixNow(), loginState.ID, UnixNow())
	if err != nil {
		return nil, err
	}
	if err := requireAffected(res); err != nil {
		return nil, err
	}
	return loginState, tx.Commit()
}

func scanLoginState(row rowScanner) (*LoginState, error) {
	var s LoginState
	err := row.Scan(&s.ID, &s.StateHash, &s.ProviderID, &s.Nonce, &s.LoginURLNonce, &s.ReturnPath, &s.CreatedAt, &s.ExpiresAt, &s.ConsumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}
