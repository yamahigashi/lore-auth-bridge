package ports

import (
	"context"
	"encoding/json"

	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
)

type TokenSigner interface {
	SignAuthn(ctx context.Context, input model.AuthnTokenInput) (model.SignedToken, error)
	SignAuthz(ctx context.Context, input model.AuthzTokenInput) (model.SignedToken, error)
	Verify(ctx context.Context, compact string, opts model.VerifyOptions) (model.VerifiedToken, error)
	JWKS(ctx context.Context) (json.RawMessage, error)
}

type IssuedTokenLog interface {
	Record(ctx context.Context, token model.IssuedToken) error
}
