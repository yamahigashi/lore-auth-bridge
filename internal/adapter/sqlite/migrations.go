package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"sort"
	"strings"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

type Migration struct {
	Version string
	Path    string
	SQL     string
}

func Migrations() ([]Migration, error) {
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return nil, fmt.Errorf("store: read migrations: %w", err)
	}
	var migrations []Migration
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		path := "migrations/" + entry.Name()
		raw, err := migrationsFS.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("store: read migration %s: %w", entry.Name(), err)
		}
		version := strings.TrimSuffix(entry.Name(), ".sql")
		migrations = append(migrations, Migration{Version: version, Path: path, SQL: string(raw)})
	}
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].Version < migrations[j].Version })
	return migrations, nil
}

func (s *Store) Migrate(ctx context.Context) error {
	migrations, err := Migrations()
	if err != nil {
		return err
	}
	for _, migration := range migrations {
		if err := s.applyMigration(ctx, migration); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ValidateSchema(ctx context.Context) error {
	migrations, err := Migrations()
	if err != nil {
		return err
	}
	for _, migration := range migrations {
		var applied string
		err := s.db.QueryRowContext(ctx, `SELECT version FROM schema_migrations WHERE version = ?`, migration.Version).Scan(&applied)
		if err == nil {
			continue
		}
		if err == sql.ErrNoRows {
			return fmt.Errorf("store: schema migration %s has not been applied", migration.Version)
		}
		return fmt.Errorf("store: validate schema_migrations for %s: %w", migration.Version, err)
	}
	return nil
}

func (s *Store) applyMigration(ctx context.Context, migration Migration) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		return fmt.Errorf("store: prepare schema_migrations: %w", err)
	}
	var applied string
	err = tx.QueryRowContext(ctx, `SELECT version FROM schema_migrations WHERE version = ?`, migration.Version).Scan(&applied)
	if err == nil {
		return tx.Commit()
	}
	if err != sql.ErrNoRows {
		return fmt.Errorf("store: check migration %s: %w", migration.Version, err)
	}
	if _, err := tx.ExecContext(ctx, migration.SQL); err != nil {
		return fmt.Errorf("store: apply migration %s: %w", migration.Version, err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`, migration.Version, UnixNow()); err != nil {
		return fmt.Errorf("store: record migration %s: %w", migration.Version, err)
	}
	return tx.Commit()
}
