package model

type Identity struct {
	Provider      string
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	PictureURL    string
	HostedDomain  string
}

type User struct {
	ID            string
	Provider      string
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	DisplayName   string
	PictureURL    string
	HostedDomain  string
	Status        string
}

type AddUserInput struct {
	Provider      string
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	DisplayName   string
	PictureURL    string
	HostedDomain  string
}

type AddPreRegisteredUserInput struct {
	Provider    string
	Issuer      string
	Email       string
	DisplayName string
}

func (u User) SubjectClaim() string {
	if u.Provider == "" {
		return u.Subject
	}
	return u.Provider + ":" + u.Subject
}

func (u User) Display() string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.Subject
}

func (u User) PreferredUsername() string {
	if u.Email != "" {
		return u.Email
	}
	return u.Subject
}
