package model

import "strings"

const WildcardResourceID = "urc-*"

type Resource struct {
	ID               string
	Name             string
	RemoteURL        string
	LoreRepositoryID string
	ResourceID       string
	Status           string
}

type ResourcePermission struct {
	ResourceID string
	Permission []string
}

type ResourceFilter struct {
	Prefix string
}

func ResourceIDForRepositoryID(repositoryID string) string {
	if repositoryID == "" {
		return ""
	}
	if strings.HasPrefix(repositoryID, "urc-") {
		return repositoryID
	}
	return "urc-" + repositoryID
}

func RepositoryIDFromResourceID(resourceID string) string {
	return strings.TrimPrefix(resourceID, "urc-")
}
