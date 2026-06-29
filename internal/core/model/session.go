package model

type AuthSession struct {
	ID              string
	ClientStateHash string
	Status          string
	UserID          string
	LoginURLNonce   string
	ExpiresAt       int64
}

type BrowserSession struct {
	ID        string
	UserID    string
	ExpiresAt int64
}
