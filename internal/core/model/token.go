package model

import (
	"encoding/json"
	"time"
)

type AuthnTokenInput struct {
	Issuer            string
	Audience          []string
	Subject           string
	Name              string
	PreferredUsername string
	Groups            []string
	IDP               string
	TTL               time.Duration
	JTI               string
}

type AuthzTokenInput struct {
	Issuer            string
	Audience          []string
	Subject           string
	Name              string
	PreferredUsername string
	Groups            []string
	IDP               string
	Resources         []ResourcePermission
	TTL               time.Duration
	JTI               string
}

type SignedToken struct {
	Token          string
	JTI            string
	Kid            string
	LoreResourceID string
	IssuedAt       int64
	ExpiresAt      int64
	Permissions    []string
	Audience       []string
}

type VerifiedToken struct {
	Subject   string
	ExpiresAt int64
	Audience  []string
	RawClaims json.RawMessage
}

type VerifyOptions struct {
	Issuer   string
	Audience string
}

type IssuedToken struct {
	JTI            string
	Kind           string
	UserID         string
	RepositoryID   string
	LoreResourceID string
	Role           string
	Kid            string
	Audience       []string
	IssuedAt       int64
	ExpiresAt      int64
}

type VerifiedAuthn struct {
	Subject string
	User    User
}
