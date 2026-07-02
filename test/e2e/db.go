//go:build e2e

package e2e

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

type e2eUser struct {
	ID          string
	Email       string
	DisplayName string
	Status      string
}

type e2eRepository struct {
	ID               string
	Name             string
	RemoteURL        string
	LoreRepositoryID string
	Status           string
}

func (h *harness) db(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", h.dbPath)
	if err != nil {
		t.Fatalf("open e2e sqlite db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func (h *harness) userByEmail(t *testing.T, email string) *e2eUser {
	t.Helper()
	db := h.db(t)
	row := db.QueryRow(`
		SELECT id, primary_email, COALESCE(display_name, ''), status
		FROM users
		WHERE primary_email_normalized = lower(?1)
		ORDER BY created_at
		LIMIT 1
	`, email)
	user := &e2eUser{}
	if err := row.Scan(&user.ID, &user.Email, &user.DisplayName, &user.Status); err != nil {
		t.Fatalf("find user %q: %v", email, err)
	}
	return user
}

func (h *harness) listRepositories(t *testing.T) []e2eRepository {
	t.Helper()
	db := h.db(t)
	rows, err := db.Query(`
		SELECT id, name, remote_url, lore_repository_id, status
		FROM repositories
		WHERE status = 'active'
		ORDER BY name
	`)
	if err != nil {
		t.Fatalf("list repositories: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var repos []e2eRepository
	for rows.Next() {
		var repo e2eRepository
		if err := rows.Scan(&repo.ID, &repo.Name, &repo.RemoteURL, &repo.LoreRepositoryID, &repo.Status); err != nil {
			t.Fatalf("scan repository: %v", err)
		}
		repos = append(repos, repo)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate repositories: %v", err)
	}
	return repos
}

func (h *harness) findRepositoryByResourceID(t *testing.T, resourceID string, includeDeleted bool) *e2eRepository {
	t.Helper()
	db := h.db(t)
	whereStatus := "AND status = 'active'"
	if includeDeleted {
		whereStatus = ""
	}
	row := db.QueryRow(fmt.Sprintf(`
		SELECT id, name, remote_url, lore_repository_id, status
		FROM repositories
		WHERE lore_repository_id = ?1 %s
	`, whereStatus), loreRepositoryIDFromResourceID(resourceID))
	repo := &e2eRepository{}
	if err := row.Scan(&repo.ID, &repo.Name, &repo.RemoteURL, &repo.LoreRepositoryID, &repo.Status); err != nil {
		t.Fatalf("find repository by resource_id %q: %v", resourceID, err)
	}
	return repo
}

func loreRepositoryIDFromResourceID(resourceID string) string {
	return strings.TrimPrefix(resourceID, "urc-")
}
