package ports

import (
	"context"

	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
)

type IdentityProvider interface {
	AuthCodeURL(state string) string
	ExchangeAndVerify(ctx context.Context, code string) (model.Identity, error)
	Issuer() string
}
