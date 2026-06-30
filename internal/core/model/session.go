package model

type AuthSession struct {
	ID              string
	ClientStateHash string
	Status          string
	UserID          string
	LoginURLNonce   string
	ExpiresAt       int64
}

type LoginStateInput struct {
	ProviderID    string
	Nonce         string
	LoginURLNonce string
	ReturnPath    string
}

type LoginState struct {
	ID            string
	ProviderID    string
	Nonce         string
	LoginURLNonce string
	ReturnPath    string
	ExpiresAt     int64
}

type BrowserSession struct {
	ID        string
	UserID    string
	ExpiresAt int64
}
