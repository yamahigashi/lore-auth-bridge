package ports

import (
	"context"
	"time"

	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
)

type StateStore interface {
	CreateAuthSession(ctx context.Context, clientState string, ttl time.Duration) (code string, session model.AuthSession, err error)
	GetAuthSessionByCode(ctx context.Context, code string) (model.AuthSession, error)
	GetAuthSessionByNonce(ctx context.Context, nonce string) (model.AuthSession, error)
	CompleteAuthSession(ctx context.Context, id, userID string) error
	ConsumeAuthSession(ctx context.Context, id string) error
	CreateLoginState(ctx context.Context, input model.LoginStateInput, ttl time.Duration) (state string, loginState model.LoginState, err error)
	ConsumeLoginState(ctx context.Context, state string) (model.LoginState, error)
	CreateBrowserSession(ctx context.Context, userID string, ttl time.Duration) (model.BrowserSession, error)
	UserByBrowserSession(ctx context.Context, sessionID string) (model.User, error)
	RevokeBrowserSession(ctx context.Context, sessionID string) error
	CreateCSRFToken(ctx context.Context, sessionID string, ttl time.Duration) (string, error)
	ConsumeCSRFToken(ctx context.Context, sessionID, token string) error
	MatchClientState(session model.AuthSession, clientState string) bool
}
