// SPDX-License-Identifier: AGPL-3.0-only
package db

import (
	"context"
	"embed"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrations embed.FS

func Migrate(ctx context.Context, p *pgxpool.Pool) error {
	c, e := p.Acquire(ctx)
	if e != nil {
		return e
	}
	defer c.Release()
	if _, e = c.Exec(ctx, "SELECT pg_advisory_lock(728619470120)"); e != nil {
		return e
	}
	defer c.Exec(context.Background(), "SELECT pg_advisory_unlock(728619470120)")
	if _, e = c.Exec(ctx, "CREATE TABLE IF NOT EXISTS public.anonce_migrations(version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())"); e != nil {
		return e
	}
	entries, e := migrations.ReadDir("migrations")
	if e != nil {
		return e
	}
	for _, f := range entries {
		var exists bool
		if e = c.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM public.anonce_migrations WHERE version=$1)", f.Name()).Scan(&exists); e != nil {
			return e
		}
		if exists {
			continue
		}
		tx, e := c.Begin(ctx)
		if e != nil {
			return e
		}
		b, _ := migrations.ReadFile("migrations/" + f.Name())
		if _, e = tx.Exec(ctx, string(b)); e == nil {
			_, e = tx.Exec(ctx, "INSERT INTO public.anonce_migrations(version) VALUES($1)", f.Name())
		}
		if e != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("migration %s: %w", f.Name(), e)
		}
		if e = tx.Commit(ctx); e != nil {
			return e
		}
	}
	return nil
}
