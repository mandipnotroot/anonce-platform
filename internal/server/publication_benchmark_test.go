// SPDX-License-Identifier: AGPL-3.0-only
package server

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mandipnotroot/anonce-platform/db"
	"github.com/mandipnotroot/anonce-platform/internal/protocol"
)

// BenchmarkPublicationStorage is opt-in (-bench PublicationStorage). It measures
// PostgreSQL freeze, 100-recipient pages, production batch validation/storage,
// and atomic promotion, not HTTP, signatures, rate limiting, or browser HPKE.
// Synthetic setup and rollback are excluded. No persistent fixtures are kept.
func BenchmarkPublicationStorage(b *testing.B) {
	url := os.Getenv("ANONCE_TEST_DATABASE_URL")
	if url == "" {
		b.Skip("disposable PostgreSQL URL not configured")
	}
	p, err := pgxpool.New(b.Context(), url)
	if err != nil {
		b.Fatal(err)
	}
	defer p.Close()
	if err = db.Init(b.Context(), p); err != nil {
		b.Fatal(err)
	}
	for _, size := range []int{1000, 10000, 100000} {
		b.Run(fmt.Sprintf("N=%d", size), func(b *testing.B) {
			key, _ := ecdh.X25519().GenerateKey(rand.Reader)
			public := key.PublicKey().Bytes()
			r := httptest.NewRequest("POST", "https://anonce.test/benchmark", nil).WithContext(b.Context())
			var freezeTime, pageTime, stageTime, promoteTime time.Duration
			for b.Loop() {
				b.StopTimer()
				tx, err := p.Begin(b.Context())
				if err != nil {
					b.Fatal(err)
				}
				// Fatal exits must release the transaction before the pool closes.
				b.Cleanup(func() { _ = tx.Rollback(context.Background()) })
				org, id, pub := protocol.ID(), protocol.ID(), protocol.ID()
				prefix := protocol.ID()[:15]
				_, err = tx.Exec(b.Context(), `INSERT INTO member.accounts(id,email,password_public,recovery_public,membership_public,encryption_public,encryption_key_signature,password_kdf,recovery_salt,vault)
 SELECT $1||lpad(i::text,6,'0')||'A',lower($1||i)||'@bench.test',$2,$2,$2,$2,$3,'{}','synthetic','{}' FROM generate_series(1,$4) i`, prefix, public, make([]byte, 64), size)
				if err != nil {
					b.Fatal(err)
				}
				_, err = tx.Exec(b.Context(), "INSERT INTO member.orgs VALUES($1,'benchmark synthetic')", org)
				if err != nil {
					b.Fatal(err)
				}
				_, err = tx.Exec(b.Context(), `INSERT INTO member.memberships(id,org_id,account_id,role,state,certificate) SELECT $1||lpad(i::text,6,'0')||'A',$2,$1||lpad(i::text,6,'0')||'A','respondent','approved',$3 FROM generate_series(1,$4) i`, prefix, org, strings.Repeat("synthetic-certificate", 50), size)
				if err != nil {
					b.Fatal(err)
				}
				_, err = tx.Exec(b.Context(), `INSERT INTO member.reviews(id,org_id,account_id,membership_id,encrypted_content,issuer_private,issuer_public,issuer_key_id,max_responses) VALUES($1,$2,$3,$3,'{}',$4,$4,'synthetic',1)`, id, org, prefix+"000001A", public)
				if err != nil {
					b.Fatal(err)
				}
				_, err = tx.Exec(b.Context(), `INSERT INTO member.review_publications VALUES($1,$2,1,$3,$4,now()+interval '24 hours',$5)`, id, pub, []byte("synthetic"), make([]byte, 64), size)
				if err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
				at := time.Now()
				if _, err = freezeRecipients(r, tx, &review{Org: org}, pub); err != nil {
					b.Fatal(err)
				}
				freezeTime += time.Since(at)
				after := ""
				planReported := false
				for {
					at = time.Now()
					rows, err := tx.Query(b.Context(), frozenRecipientPageSQL, pub, after)
					if err != nil {
						b.Fatal(err)
					}
					envelopes := make([]contentKeyEnvelope, 0, 100)
					more := false
					for rows.Next() {
						var member, account, cert string
						var pk, sig []byte
						if err = rows.Scan(&member, &account, &cert, &pk, &sig); err != nil {
							b.Fatal(err)
						}
						if len(envelopes) == 100 {
							more = true
							break
						}
						envelopes = append(envelopes, contentKeyEnvelope{1, member, protocol.B64(protocol.Hash(pk)), protocol.B64(public), protocol.B64(make([]byte, 48))})
					}
					err = rows.Err()
					rows.Close()
					if err != nil {
						b.Fatal(err)
					}
					pageTime += time.Since(at)
					if size == 100000 && !planReported {
						b.StopTimer()
						ids := make([]string, len(envelopes))
						keys, encs, cts := [][]byte{}, [][]byte{}, [][]byte{}
						for i, env := range envelopes {
							ids[i] = env.Membership
							keys = append(keys, mustDecode(env.Key))
							encs = append(encs, mustDecode(env.Enc))
							cts = append(cts, mustDecode(env.Ciphertext))
						}
						plans, err := tx.Query(b.Context(), "EXPLAIN "+stageEnvelopeSQL, pub, ids, keys, encs, cts)
						if err != nil {
							b.Fatal(err)
						}
						for plans.Next() {
							var line string
							if err = plans.Scan(&line); err != nil {
								b.Fatal(err)
							}
							b.Log(line)
						}
						err = plans.Err()
						plans.Close()
						if err != nil {
							b.Fatal(err)
						}
						planReported = true
						b.StartTimer()
					}
					at = time.Now()
					if err = stageEnvelopes(r, tx, pub, envelopes); err != nil {
						b.Fatal(err)
					}
					stageTime += time.Since(at)
					if !more {
						break
					}
					after = envelopes[len(envelopes)-1].Membership
				}
				at = time.Now()
				if err = promoteEnvelopes(r, tx, id, pub, size); err != nil {
					b.Fatal(err)
				}
				_, err = tx.Exec(b.Context(), "UPDATE member.reviews SET state='published',revision=revision+1 WHERE id=$1", id)
				if err != nil {
					b.Fatal(err)
				}
				_, err = tx.Exec(b.Context(), "DELETE FROM member.review_publications WHERE id=$1", pub)
				if err != nil {
					b.Fatal(err)
				}
				promoteTime += time.Since(at)
				b.StopTimer()
				if err = tx.Rollback(context.Background()); err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
			}
			b.ReportMetric(float64(freezeTime.Microseconds())/float64(b.N), "freeze-us/op")
			b.ReportMetric(float64(pageTime.Microseconds())/float64(b.N), "pages-us/op")
			b.ReportMetric(float64(stageTime.Microseconds())/float64(b.N), "stage-us/op")
			b.ReportMetric(float64(stageTime.Microseconds())/float64(b.N*size/100), "stage-us/batch")
			b.ReportMetric(float64(promoteTime.Microseconds())/float64(b.N), "promote-us/op")
		})
	}
}
