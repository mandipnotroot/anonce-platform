// SPDX-License-Identifier: AGPL-3.0-only
package db

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schema string

// Init initializes a fresh database or preserves an already-current schema.
// Unsupported schemas must be recreated, not upgraded.
func Init(ctx context.Context, p *pgxpool.Pool) error {
	tx, err := p.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin schema initialization: %w", err)
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(728619470120)"); err != nil {
		return fmt.Errorf("lock schema initialization: %w", err)
	}
	var unsupportedMarker bool
	if err = tx.QueryRow(ctx, "SELECT to_regclass('public.anonce_migrations') IS NOT NULL").Scan(&unsupportedMarker); err != nil {
		return fmt.Errorf("check schema marker: %w", err)
	}
	if unsupportedMarker {
		return fmt.Errorf("unsupported public.anonce_migrations marker found: unreleased database must be recreated")
	}
	if _, err = tx.Exec(ctx, "CREATE TABLE IF NOT EXISTS public.anonce_schema_version(version integer PRIMARY KEY)"); err != nil {
		return fmt.Errorf("create schema version marker: %w", err)
	}
	var count, version int
	if err = tx.QueryRow(ctx, "SELECT count(*), COALESCE(min(version), 0) FROM public.anonce_schema_version").Scan(&count, &version); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if count > 1 || (count == 1 && version != 3) {
		return fmt.Errorf("unsupported schema version (rows=%d, version=%d): unreleased database must be recreated", count, version)
	}
	if count == 0 {
		if _, err = tx.Exec(ctx, schema); err != nil {
			return fmt.Errorf("initialize schema: %w", err)
		}
		if _, err = tx.Exec(ctx, "INSERT INTO public.anonce_schema_version(version) VALUES(3)"); err != nil {
			return fmt.Errorf("record schema version: %w", err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit schema initialization: %w", err)
	}
	return nil
}
