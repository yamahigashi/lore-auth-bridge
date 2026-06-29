package model

type Group struct {
	ID          string
	Name        string
	Description string
}

type Grant struct {
	ID           string
	SubjectType  string
	SubjectID    string
	RepositoryID string
	Role         string
}

type SigningKeyMeta struct {
	Kid            string
	Alg            string
	PublicJWKJSON  string
	PrivateKeyPath string
	Status         string
}
