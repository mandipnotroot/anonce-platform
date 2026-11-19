// SPDX-License-Identifier: AGPL-3.0-only
package db

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestInit(t *testing.T) {
	// DESTRUCTIVE: this explicitly separate disposable database is reset between cases.
	// Provision the same roles as db/init/010-anonce.sh; never use deployment data.
	url := os.Getenv("ANONCE_TEST_INIT_DATABASE_URL")
	if url == "" {
		if os.Getenv("ANONCE_REQUIRE_DATABASE_TESTS") == "1" {
			t.Fatal("ANONCE_REQUIRE_DATABASE_TESTS=1 requires ANONCE_TEST_INIT_DATABASE_URL")
		}
		t.Skip("separate disposable initialization database URL not configured")
	}
	if url == os.Getenv("ANONCE_TEST_DATABASE_URL") || url == os.Getenv("ANONCE_TEST_ANON_DATABASE_URL") {
		t.Fatal("initialization tests require a separate disposable database")
	}
	p, err := pgxpool.New(t.Context(), url)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	exec := func(sql string) {
		t.Helper()
		if _, err := p.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
	}
	resetSQL := "DROP SCHEMA IF EXISTS member CASCADE; DROP SCHEMA IF EXISTS anon CASCADE; DROP TABLE IF EXISTS public.anonce_schema_version; DROP TABLE IF EXISTS public.anonce_migrations"
	exec(resetSQL)
	defer func() {
		if _, err := p.Exec(context.Background(), resetSQL); err != nil {
			t.Error(err)
		}
	}()
	t.Run("fresh concurrent and repeat", func(t *testing.T) {
		var wg sync.WaitGroup
		errs := make([]error, 8)
		start := make(chan struct{})
		for i := range errs {
			wg.Go(func() {
				<-start
				errs[i] = Init(t.Context(), p)
			})
		}
		close(start)
		wg.Wait()
		for _, err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		exec("INSERT INTO member.challenges(id,account_id,action,epoch,payload_hash,nonce,expires) VALUES('c','a','test',1,''::bytea,''::bytea,1); INSERT INTO member.invites(id_hash,expires_at) VALUES(''::bytea,now()); INSERT INTO member.settings VALUES('sentinel','value'::bytea)")
		var used bool
		var role string
		if err := p.QueryRow(t.Context(), "SELECT used FROM member.challenges WHERE id='c'").Scan(&used); err != nil || used {
			t.Fatalf("challenge default: used=%v error=%v", used, err)
		}
		if err := p.QueryRow(t.Context(), "SELECT role FROM member.invites").Scan(&role); err != nil || role != "respondent" {
			t.Fatalf("invite default: role=%q error=%v", role, err)
		}
		for _, sql := range []string{
			"UPDATE member.challenges SET used=NULL",
			"UPDATE member.invites SET role=NULL",
			"UPDATE member.invites SET role='owner'",
		} {
			if _, err := p.Exec(t.Context(), sql); err == nil {
				t.Fatalf("accepted invalid column value: %s", sql)
			}
		}
		if err := Init(t.Context(), p); err != nil {
			t.Fatal(err)
		}
		var preserved bool
		if err := p.QueryRow(t.Context(), "SELECT (SELECT value='value'::bytea FROM member.settings WHERE name='sentinel') AND (SELECT count(*)=1 AND min(version)=2 FROM public.anonce_schema_version)").Scan(&preserved); err != nil || !preserved {
			t.Fatalf("repeat lost state: %v", err)
		}
	})
	for _, tc := range []struct {
		name, setup, want string
	}{
		{"unsupported", "CREATE TABLE public.anonce_schema_version(version integer PRIMARY KEY); INSERT INTO public.anonce_schema_version VALUES(3)", "unsupported schema version"},
		{"multiple versions", "CREATE TABLE public.anonce_schema_version(version integer PRIMARY KEY); INSERT INTO public.anonce_schema_version VALUES(1),(2)", "unsupported schema version"},
		{"legacy", "CREATE TABLE public.anonce_migrations(version text PRIMARY KEY); INSERT INTO public.anonce_migrations VALUES('001_initial.sql')", "must be recreated"},
		{"rollback", "CREATE SCHEMA member; CREATE TABLE member.accounts(sentinel text); INSERT INTO member.accounts VALUES('preserve')", "initialize schema"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exec(resetSQL)
			exec(tc.setup)
			if err := Init(t.Context(), p); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q, got %v", tc.want, err)
			}
			var unchanged bool
			query := "SELECT to_regclass('member.settings') IS NULL AND to_regclass('anon.reviews') IS NULL"
			switch tc.name {
			case "unsupported":
				query += " AND (SELECT count(*)=1 AND min(version)=3 FROM public.anonce_schema_version)"
			case "multiple versions":
				query += " AND (SELECT count(*)=2 FROM public.anonce_schema_version)"
			case "legacy":
				query += " AND to_regclass('public.anonce_schema_version') IS NULL AND (SELECT version='001_initial.sql' FROM public.anonce_migrations)"
			case "rollback":
				query += " AND to_regclass('public.anonce_schema_version') IS NULL AND (SELECT sentinel='preserve' FROM member.accounts)"
			}
			if err := p.QueryRow(t.Context(), query).Scan(&unchanged); err != nil || !unchanged {
				t.Fatalf("failed initialization changed database: %v", err)
			}
		})
	}
}
