// SPDX-License-Identifier: AGPL-3.0-only
package server

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mandipnotroot/anonce-platform/internal/protocol"
)

// This fixture only grows a browser-created, disposable organization. It never
// deletes data. Synthetic recipients have real identity/encryption keys and CA
// certificates, but no usable login vault; their private keys are discarded.
func TestLivePublicationBenchmarkFixture(t *testing.T) {
	if os.Getenv("ANONCE_LIVE_BENCHMARK_FIXTURE") != "1" {
		t.Skip("live benchmark fixture requires explicit opt-in")
	}
	start := time.Now()
	memberURL := os.Getenv("ANONCE_BENCHMARK_DATABASE_URL")
	anonURL := os.Getenv("ANONCE_BENCHMARK_ANON_DATABASE_URL")
	origin := os.Getenv("ANONCE_BENCHMARK_ORIGIN")
	org := os.Getenv("ANONCE_BENCHMARK_ORG_ID")
	key := os.Getenv("ANONCE_BENCHMARK_KEY_FILE")
	total, err := strconv.Atoi(os.Getenv("ANONCE_BENCHMARK_MEMBERS"))
	if err != nil || total < 1 || total > 100000 {
		t.Fatal("fixture requires a member count between 1 and 100000")
	}
	if err := liveBenchmarkURLs(memberURL, anonURL, origin); err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.Decode(org, 16); err != nil || key == "" {
		t.Fatal("fixture requires organization ID and existing shared master key file")
	}
	if info, err := os.Stat(key); err != nil || !info.Mode().IsRegular() {
		t.Fatal("shared master key file must already exist")
	}
	ctx := t.Context()
	// Check markers before New can initialize schema or keys.
	preflight, err := pgxpool.New(ctx, memberURL)
	if err != nil {
		t.Fatal("fixture database connection failed")
	}
	defer preflight.Close()
	var dbName, role string
	var initialized bool
	if err := preflight.QueryRow(ctx, `SELECT current_database(),current_user,to_regclass('member.settings') IS NOT NULL`).Scan(&dbName, &role, &initialized); err != nil || dbName != "anonce_publication_benchmark" || role != "anonce_member" || !initialized {
		t.Fatal("refusing database without initialized disposable fixture markers")
	}
	if err := preflight.QueryRow(ctx, `SELECT count(*)=4 FROM member.settings WHERE name IN ('deployment','ca','receipt','ca-certificate')`).Scan(&initialized); err != nil || !initialized {
		t.Fatal("browser deployment keys must already exist")
	}
	s, err := New(ctx, Config{DatabaseURL: memberURL, AnonymousURL: anonURL, Origin: origin, KeyFile: key, SourceURL: "https://github.com/mandipnotroot/anonce-platform"})
	if err != nil {
		t.Fatal("fixture server initialization failed")
	}
	defer s.Close()
	tx, err := s.member.Begin(ctx)
	if err != nil {
		t.Fatal("fixture transaction failed")
	}
	defer tx.Rollback(context.Background())
	// Block concurrent roster/account changes for the entire atomic seed.
	if _, err := tx.Exec(ctx, `LOCK TABLE member.orgs,member.accounts,member.memberships IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		t.Fatal("fixture locking failed")
	}
	var safe bool
	if err := tx.QueryRow(ctx, `SELECT
		NOT EXISTS(SELECT 1 FROM member.orgs WHERE name<>'publication-benchmark') AND
		EXISTS(SELECT 1 FROM member.orgs WHERE id=$1 AND name='publication-benchmark') AND
		(SELECT count(*)=1 FROM member.memberships WHERE org_id=$1 AND role='owner' AND state='approved') AND
		NOT EXISTS(SELECT 1 FROM member.memberships m WHERE state<>'approved' OR role NOT IN ('owner','respondent') OR certificate IS NULL
		 OR NOT EXISTS(SELECT 1 FROM member.orgs o WHERE o.id=m.org_id AND o.name='publication-benchmark')) AND
		NOT EXISTS(SELECT 1 FROM member.accounts a WHERE email NOT LIKE '%@benchmark.invalid'
		 OR NOT EXISTS(SELECT 1 FROM member.memberships m WHERE m.account_id=a.id))
		AND NOT EXISTS(SELECT 1 FROM member.memberships m JOIN member.accounts a ON a.id=m.account_id
		 WHERE m.role<>'owner' AND a.email NOT LIKE 'publication-fixture-%@benchmark.invalid')`, org).Scan(&safe); err != nil || !safe {
		t.Fatal("refusing nonfixture organization, owner, accounts or memberships")
	}
	var current int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM member.memberships WHERE org_id=$1`, org).Scan(&current); err != nil || current > total {
		t.Fatal("fixture cannot shrink roster")
	}
	if os.Getenv("ANONCE_BENCHMARK_VERIFY") == "1" {
		review := os.Getenv("ANONCE_BENCHMARK_REVIEW_ID")
		if _, err := protocol.Decode(review, 16); err != nil || current != total {
			t.Fatal("verification requires review ID and exact roster count")
		}
		var state string
		var envelopes, staged, recipients int
		err := tx.QueryRow(ctx, `SELECT r.state,
			(SELECT count(*) FROM member.review_content_keys k JOIN member.memberships m ON m.id=k.membership_id WHERE k.review_id=r.id AND m.org_id=r.org_id AND m.state='approved'),
			(SELECT count(*) FROM member.review_publications p WHERE p.review_id=r.id),
			(SELECT count(*) FROM member.publication_recipients pr JOIN member.review_publications p ON p.id=pr.publication_id WHERE p.review_id=r.id)
			FROM member.reviews r JOIN member.memberships m ON m.id=r.membership_id
			WHERE r.id=$1 AND r.org_id=$2 AND m.role='owner' AND m.account_id=r.account_id`, review, org).Scan(&state, &envelopes, &staged, &recipients)
		if err != nil || state != "published" || envelopes != total || staged != 0 || recipients != 0 {
			t.Fatal("publication state, envelope count or staging cleanup mismatch")
		}
		var denied bool
		// Resolve member table names through the member connection: the
		// anonymous role cannot even resolve names in this denied schema.
		if err := tx.QueryRow(ctx, `SELECT NOT has_schema_privilege('anonce_anon','member','USAGE')
			AND NOT has_table_privilege('anonce_anon','member.accounts','SELECT')
			AND NOT has_table_privilege('anonce_anon','member.memberships','SELECT')
			AND NOT has_table_privilege('anonce_anon','member.review_content_keys','SELECT')`).Scan(&denied); err != nil || !denied {
			t.Fatal("anonymous role privilege boundary mismatch")
		}
		for _, query := range []string{
			`SELECT id FROM member.accounts LIMIT 0`,
			`SELECT id FROM member.memberships LIMIT 0`,
			`SELECT review_id FROM member.review_content_keys LIMIT 0`,
		} {
			_, err := s.anonymous.Exec(ctx, query)
			if pg, ok := errors.AsType[*pgconn.PgError](err); !ok || pg.Code != "42501" {
				t.Fatal("anonymous member-table query did not fail with insufficient_privilege")
			}
		}
		// Database privilege evidence is not a substitute for HTTP creator/member
		// authorization tests: the member role is intentionally shared by the app.
		t.Logf("state=published members=%d envelopes=%d staged=%d duration=%s", total, envelopes, staged, time.Since(start))
		return
	}
	for remaining := total - current; remaining > 0; {
		n := min(remaining, 500)
		accounts := make([][]any, 0, n)
		memberships := make([][]any, 0, n)
		for range n {
			account, membership := protocol.ID(), protocol.ID()
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal("identity generation failed")
			}
			encryption, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal("encryption key generation failed")
			}
			accountBytes, _ := protocol.Decode(account, 16)
			binding := ed25519.Sign(private, protocol.E("member-encryption-key", s.deployment, accountBytes, public, encryption.PublicKey().Bytes(), protocol.U64(1)))
			certificate, err := s.cert(org, membership, public)
			if err != nil || !s.validCertificate(certificate, public, org, membership) {
				t.Fatal("membership certificate generation failed")
			}
			password, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal("credential generation failed")
			}
			recovery, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal("credential generation failed")
			}
			accounts = append(accounts, []any{account, "publication-fixture-" + strings.ToLower(account) + "@benchmark.invalid", password, recovery, public, encryption.PublicKey().Bytes(), binding, `{"v":19,"length":32,"memory_kib":65536,"iterations":3,"parallelism":1,"salt":"` + protocol.B64(protocol.Random(16)) + `"}`, protocol.B64(protocol.Random(32)), `{}`})
			memberships = append(memberships, []any{membership, org, account, "respondent", "approved", certificate})
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"member", "accounts"}, []string{"id", "email", "password_public", "recovery_public", "membership_public", "encryption_public", "encryption_key_signature", "password_kdf", "recovery_salt", "vault"}, pgx.CopyFromRows(accounts)); err != nil {
			t.Fatal("account COPY failed")
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"member", "memberships"}, []string{"id", "org_id", "account_id", "role", "state", "certificate"}, pgx.CopyFromRows(memberships)); err != nil {
			t.Fatal("membership COPY failed")
		}
		remaining -= n
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal("fixture commit failed")
	}
	t.Logf("members=%d added=%d duration=%s", total, total-current, time.Since(start))
}

func liveBenchmarkURLs(member, anonymous, origin string) error {
	loopback := func(host string) bool {
		return host == "localhost" || host == "127.0.0.1" || host == "::1"
	}
	for _, raw := range []string{member, anonymous} {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || !loopback(u.Hostname()) || u.Path != "/anonce_publication_benchmark" || u.Fragment != "" {
			return errors.New("fixture requires dedicated loopback PostgreSQL URLs with disposable database marker")
		}
		// Disallow host/database overrides through PostgreSQL query parameters.
		for name := range u.Query() {
			if name != "sslmode" {
				return errors.New("fixture database URLs permit only sslmode query parameter")
			}
		}
	}
	u, err := url.Parse(origin)
	if member == anonymous || err != nil || u.Scheme != "https" || !loopback(u.Hostname()) || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("fixture requires distinct database URLs and loopback HTTPS origin")
	}
	return nil
}

func TestLivePublicationBenchmarkURLSafety(t *testing.T) {
	member := "postgres://anonce_member:fixture@localhost:15432/anonce_publication_benchmark?sslmode=disable"
	anon := strings.Replace(member, "anonce_member", "anonce_anon", 1)
	for _, tc := range []struct {
		name, member, anonymous, origin string
		valid                           bool
	}{
		{"valid", member, anon, "https://localhost:18443", true},
		{"production name", strings.Replace(member, "anonce_publication_benchmark", "anonce", 1), anon, "https://localhost:18443", false},
		{"remote database", strings.Replace(member, "localhost", "example.com", 1), anon, "https://localhost:18443", false},
		{"database override", member + "&dbname=anonce", anon, "https://localhost:18443", false},
		{"host override", member + "&host=example.com", anon, "https://localhost:18443", false},
		{"same roles", member, member, "https://localhost:18443", false},
		{"remote origin", member, anon, "https://example.com", false},
		{"plain HTTP", member, anon, "http://localhost:18443", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if (liveBenchmarkURLs(tc.member, tc.anonymous, tc.origin) == nil) != tc.valid {
				t.Fatal("URL safety result mismatch")
			}
		})
	}
}
