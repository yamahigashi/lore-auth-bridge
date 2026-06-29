package model

import "errors"

var (
	ErrNotFound              = errors.New("core: not found")
	ErrAuthSessionNotFound   = errors.New("core: auth session not found")
	ErrInvalidArgument       = errors.New("core: invalid argument")
	ErrPermissionDenied      = errors.New("core: permission denied")
	ErrUnauthenticated       = errors.New("core: unauthenticated")
	ErrUnsupported           = errors.New("core: unsupported")
	ErrSigningKeyUnavailable = errors.New("core: signing key unavailable")
	ErrTokenIssueFailed      = errors.New("core: token issue failed")
)
