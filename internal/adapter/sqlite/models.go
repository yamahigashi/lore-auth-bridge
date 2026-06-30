package sqlite

import "database/sql"

type User struct {
	ID            string
	Provider      string
	Issuer        string
	Subject       string
	Email         sql.NullString
	EmailVerified bool
	DisplayName   sql.NullString
	PictureURL    sql.NullString
	HostedDomain  sql.NullString
	Status        string
	CreatedAt     int64
	UpdatedAt     int64
	LastLoginAt   sql.NullInt64
}

type Group struct {
	ID          string
	Name        string
	Description sql.NullString
	CreatedAt   int64
	UpdatedAt   int64
}

type Repository struct {
	ID               string
	Name             string
	RemoteURL        string
	LoreRepositoryID string
	Status           string
	CreatedBySource  string
	CreatedAt        int64
	UpdatedAt        int64
}

type Grant struct {
	ID           string
	SubjectType  string
	SubjectID    string
	RepositoryID string
	Role         string
	CreatedAt    int64
	UpdatedAt    int64
}

type SigningKeyMetadata struct {
	Kid            string
	Alg            string
	PublicJWKJSON  string
	PrivateKeyPath string
	Status         string
	CreatedAt      int64
	NotBefore      sql.NullInt64
	RetiredAt      sql.NullInt64
}

type IssuedToken struct {
	JTI              string
	UserID           sql.NullString
	ServiceAccountID sql.NullString
	RepositoryID     string
	LoreResourceID   string
	Role             string
	Kid              string
	IssuedAt         int64
	ExpiresAt        int64
	RevokedAt        sql.NullInt64
}

type DeviceAuthorization struct {
	ID                    string
	DeviceCodeHash        string
	UserCodeHash          string
	RequestedRemoteURL    string
	RequestedRepositoryID sql.NullString
	ApprovedUserID        sql.NullString
	Status                string
	CreatedAt             int64
	ExpiresAt             int64
	ApprovedAt            sql.NullInt64
	ConsumedAt            sql.NullInt64
}

type LoginState struct {
	ID            string
	StateHash     string
	ProviderID    string
	Nonce         sql.NullString
	LoginURLNonce sql.NullString
	ReturnPath    sql.NullString
	CreatedAt     int64
	ExpiresAt     int64
	ConsumedAt    sql.NullInt64
}

type Session struct {
	ID        string
	UserID    string
	CreatedAt int64
	ExpiresAt int64
	RevokedAt sql.NullInt64
}
