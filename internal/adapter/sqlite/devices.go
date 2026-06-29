package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

type CreateDeviceAuthorizationParams struct {
	DeviceCodeHash        string
	UserCodeHash          string
	RequestedRemoteURL    string
	RequestedRepositoryID string
	TTLSeconds            int
}

func (s *Store) CreateDeviceAuthorization(ctx context.Context, p CreateDeviceAuthorizationParams) (*DeviceAuthorization, error) {
	now := UnixNow()
	d := &DeviceAuthorization{ID: NewID(), DeviceCodeHash: p.DeviceCodeHash, UserCodeHash: p.UserCodeHash, RequestedRemoteURL: p.RequestedRemoteURL, RequestedRepositoryID: sql.NullString{String: p.RequestedRepositoryID, Valid: p.RequestedRepositoryID != ""}, Status: "pending", CreatedAt: now, ExpiresAt: now + int64(p.TTLSeconds)}
	_, err := s.db.ExecContext(ctx, `INSERT INTO device_authorizations (id, device_code_hash, user_code_hash, requested_remote_url, requested_repository_id, status, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, d.ID, d.DeviceCodeHash, d.UserCodeHash, d.RequestedRemoteURL, d.RequestedRepositoryID, d.Status, d.CreatedAt, d.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("store: create device authorization: %w", err)
	}
	return d, nil
}

func (s *Store) DeviceByUserCodeHash(ctx context.Context, hash string) (*DeviceAuthorization, error) {
	return s.scanDevice(s.db.QueryRowContext(ctx, `SELECT id, device_code_hash, user_code_hash, requested_remote_url, requested_repository_id, approved_user_id, status, created_at, expires_at, approved_at, consumed_at FROM device_authorizations WHERE user_code_hash = ?`, hash))
}

func (s *Store) DeviceByDeviceCodeHash(ctx context.Context, hash string) (*DeviceAuthorization, error) {
	return s.scanDevice(s.db.QueryRowContext(ctx, `SELECT id, device_code_hash, user_code_hash, requested_remote_url, requested_repository_id, approved_user_id, status, created_at, expires_at, approved_at, consumed_at FROM device_authorizations WHERE device_code_hash = ?`, hash))
}

func (s *Store) ApproveDeviceAuthorization(ctx context.Context, id, userID string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE device_authorizations SET status = 'approved', approved_user_id = ?, approved_at = ? WHERE id = ? AND status = 'pending' AND expires_at > ?`, userID, UnixNow(), id, UnixNow())
	if err != nil {
		return err
	}
	return requireAffected(res)
}

func (s *Store) ConsumeDeviceAuthorization(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE device_authorizations SET status = 'consumed', consumed_at = ? WHERE id = ? AND status = 'approved'`, UnixNow(), id)
	if err != nil {
		return err
	}
	return requireAffected(res)
}

func (s *Store) ExpireDeviceAuthorization(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE device_authorizations SET status = 'expired' WHERE id = ? AND status = 'pending'`, id)
	return err
}

func (s *Store) scanDevice(row rowScanner) (*DeviceAuthorization, error) {
	var d DeviceAuthorization
	err := row.Scan(&d.ID, &d.DeviceCodeHash, &d.UserCodeHash, &d.RequestedRemoteURL, &d.RequestedRepositoryID, &d.ApprovedUserID, &d.Status, &d.CreatedAt, &d.ExpiresAt, &d.ApprovedAt, &d.ConsumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &d, nil
}
