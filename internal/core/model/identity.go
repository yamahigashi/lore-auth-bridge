package model

type ExternalIdentity struct {
	ID              string
	UserID          string
	ProviderID      string
	Issuer          string
	Subject         string
	SubjectStrategy string
	Email           string
	EmailVerified   bool
	DisplayName     string
	PictureURL      string
	HostedDomain    string
	Status          string
}

type User struct {
	ID          string
	Email       string
	DisplayName string
	Status      string
}

type TokenPrincipal struct {
	UserID            string
	TokenSubject      string
	TokenIDP          string
	DisplayName       string
	PreferredUsername string
	Groups            []string
}

type LoginBindingResult struct {
	Status             string
	ExternalIdentityID string
	InvitationID       string
}

const (
	LoginEmailBindingDisabled                = "disabled"
	LoginEmailBindingVerifiedEmailInvitation = "verified_email_invitation"
)

type LoginTrustPolicy struct {
	EmailBinding        string
	AllowedEmailDomains []string
}

type LoginResolutionRequest struct {
	Identity ExternalIdentity
	Policy   LoginTrustPolicy
}

type AddUserInput struct {
	Email       string
	DisplayName string
}

type IdentityInvitation struct {
	ID                 string
	UserID             string
	ProviderID         string
	Issuer             string
	Email              string
	BindingPolicy      string
	Status             string
	AcceptedIdentityID string
	ExpiresAt          int64
	AcceptedAt         int64
}

type AddInvitationInput struct {
	ProviderID    string
	Issuer        string
	Email         string
	DisplayName   string
	BindingPolicy string
	ExpiresAt     int64
}

func (u User) BridgeSubject() string {
	return "user:" + u.ID
}

func (u User) Display() string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.BridgeSubject()
}

func (u User) PreferredUsername() string {
	if u.Email != "" {
		return u.Email
	}
	return u.BridgeSubject()
}
