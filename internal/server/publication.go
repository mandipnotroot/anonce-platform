// SPDX-License-Identifier: AGPL-3.0-only
package server

import (
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/mandipnotroot/anonce-platform/internal/protocol"
)

func promoteEnvelopes(r *http.Request, tx pgx.Tx, reviewID, publication string, count int) error {
	tag, err := tx.Exec(r.Context(), "INSERT INTO member.review_content_keys(review_id,membership_id,encryption_key_id,enc,ciphertext) SELECT $1,membership_id,encryption_key_id,enc,ciphertext FROM member.publication_recipients WHERE publication_id=$2 AND enc IS NOT NULL", reviewID, publication)
	if err == nil && tag.RowsAffected() != int64(count) {
		return problem{409, "recipient_set_conflict"}
	}
	return err
}

// freezeRecipients is called with the organization and review locked, in that
// order. Account encryption keys are immutable; certificates are copied because
// certificate renewal must not change a publication's signed input.
func freezeRecipients(r *http.Request, tx pgx.Tx, v *review, id string) (int64, error) {
	tag, err := tx.Exec(r.Context(), `INSERT INTO member.publication_recipients(publication_id,membership_id,account_id,certificate,encryption_key_id)
 SELECT $1,m.id,m.account_id,m.certificate,sha256(a.encryption_public)
 FROM member.memberships m JOIN member.accounts a ON a.id=m.account_id
 WHERE m.org_id=$2 AND m.state='approved' ORDER BY m.id COLLATE "C" LIMIT 100001`, id, v.Org)
	if err != nil {
		return 0, err
	}
	if tag.RowsAffected() > 100000 || tag.RowsAffected() == 0 {
		return 0, problem{409, "recipient_limit"}
	}
	return tag.RowsAffected(), nil
}

func (s *Server) startPublication(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Request    string `json:"request_id"`
		Expected   string `json:"expected_revision"`
		Descriptor string `json:"descriptor"`
		Signature  string `json:"descriptor_signature"`
	}
	x, err := s.verify(r, "review-publication-start", &p, false)
	if err != nil {
		fail(w, err)
		return
	}
	v, err := s.loadReview(r, x.Session, true)
	if err != nil {
		fail(w, err)
		return
	}
	rev, err := decimal(p.Expected)
	if err != nil {
		fail(w, err)
		return
	}
	b, err := protocol.Decode(p.Descriptor, -1)
	if err != nil {
		fail(w, bad("invalid_descriptor"))
		return
	}
	d, err := decodeDescriptor(b)
	if err != nil {
		fail(w, err)
		return
	}
	tx, err := s.member.Begin(r.Context())
	if err != nil {
		fail(w, err)
		return
	}
	defer tx.Rollback(r.Context())
	old, err := operation(r, tx, x, p.Request)
	if err != nil {
		fail(w, err)
		return
	}
	if old != nil {
		write(w, 200, old)
		return
	}
	v, err = scanReview(tx.QueryRow(r.Context(), "SELECT "+reviewColumns+" FROM member.reviews r WHERE r.id=$1 FOR UPDATE OF r", v.ID))
	if err != nil {
		fail(w, err)
		return
	}
	if v.Account != x.Session.Account {
		fail(w, problem{403, "forbidden"})
		return
	}
	if v.State != "draft" || v.Revision != rev {
		fail(w, problem{409, "revision_conflict"})
		return
	}
	var cert string
	err = tx.QueryRow(r.Context(), "SELECT certificate FROM member.memberships WHERE id=$1 AND org_id=$2 AND account_id=$3 AND state='approved'", v.Membership, v.Org, x.Session.Account).Scan(&cert)
	if err != nil {
		if err == pgx.ErrNoRows {
			err = problem{403, "forbidden"}
		}
		fail(w, err)
		return
	}
	_, recipientErr := protocol.Decode(d.Recipient, 32)
	sig, se := protocol.Decode(p.Signature, 64)
	if d.Deployment != protocol.B64(s.deployment) || d.Review != v.ID || d.Org != v.Org || d.Membership != v.Membership || d.Certificate != cert || d.Content != v.Content || d.Public != protocol.B64(v.Public) || d.Issuer != v.Issuer || recipientErr != nil || se != nil || !s.validCertificate(cert, x.Session.Membership, v.Org, v.Membership) || !checkSig(x.Session.Membership, p.Signature, protocol.E("review-descriptor", b)) {
		fail(w, bad("descriptor_mismatch"))
		return
	}
	var active bool
	err = tx.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM member.review_publications WHERE review_id=$1 AND revision=$2 AND expires_at>now())", v.ID, rev).Scan(&active)
	if err != nil {
		fail(w, err)
		return
	}
	if active {
		fail(w, problem{409, "publication_conflict"})
		return
	}
	_, err = tx.Exec(r.Context(), "DELETE FROM member.review_publications WHERE review_id=$1", v.ID)
	id, expires := protocol.ID(), time.Now().Add(24*time.Hour).Truncate(time.Second)
	if err == nil {
		_, err = tx.Exec(r.Context(), "INSERT INTO member.review_publications(review_id,id,revision,descriptor,descriptor_signature,expires_at,recipient_count) VALUES($1,$2,$3,$4,$5,$6,1)", v.ID, id, rev, b, sig, expires)
	}
	var count int64
	if err == nil {
		count, err = freezeRecipients(r, tx, v, id)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), "UPDATE member.review_publications SET recipient_count=$1 WHERE id=$2", count, id)
	}
	result := map[string]any{"publication_id": id, "recipient_count": count, "expires_at": format(expires.Unix())}
	if err == nil {
		err = cache(r, tx, x, p.Request, result)
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		fail(w, err)
		return
	}
	write(w, 200, result)
}

// stageEnvelopes validates a bounded batch in one query, then updates it in one
// statement. A row can only be filled once; exact request retries use operation.
func stageEnvelopes(r *http.Request, tx pgx.Tx, publication string, envelopes []contentKeyEnvelope) error {
	if len(envelopes) == 0 || len(envelopes) > 100 {
		return bad("invalid_content_key_envelopes")
	}
	ids := make([]string, 0, len(envelopes))
	keys, encs, cts := [][]byte{}, [][]byte{}, [][]byte{}
	seen := map[string]bool{}
	for _, env := range envelopes {
		if !env.valid() {
			return bad("invalid_content_key_envelope")
		}
		if seen[env.Membership] {
			return problem{409, "recipient_set_conflict"}
		}
		seen[env.Membership] = true
		ids = append(ids, env.Membership)
		keys = append(keys, mustDecode(env.Key))
		encs = append(encs, mustDecode(env.Enc))
		cts = append(cts, mustDecode(env.Ciphertext))
	}
	// A new publication has no useful planner statistics yet. Keep the batch
	// outermost and force parameterized primary-key lookups, rather than an
	// estimated-small snapshot scan repeated for every upload.
	tag, err := tx.Exec(r.Context(), stageEnvelopeSQL, publication, ids, keys, encs, cts)
	if err == nil && tag.RowsAffected() != int64(len(envelopes)) {
		return problem{409, "recipient_set_conflict"}
	}
	return err
}

const stageEnvelopeSQL = `WITH matched AS MATERIALIZED (
 SELECT p.ctid,b.enc,b.ciphertext
 FROM unnest($2::text[],$3::bytea[],$4::bytea[],$5::bytea[]) AS b(id,key,enc,ciphertext)
 CROSS JOIN LATERAL (
   SELECT ctid FROM member.publication_recipients
   WHERE publication_id=$1 AND membership_id=b.id COLLATE "C" AND encryption_key_id=b.key AND enc IS NULL OFFSET 0
 ) p
 )
 UPDATE member.publication_recipients p SET enc=b.enc,ciphertext=b.ciphertext
 FROM matched b WHERE p.ctid=b.ctid`

func (s *Server) publicationEnvelopes(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Request     string               `json:"request_id"`
		Publication string               `json:"publication_id"`
		Envelopes   []contentKeyEnvelope `json:"content_key_envelopes"`
	}
	x, err := s.verify(r, "review-publication-envelopes", &p, false)
	if err != nil {
		fail(w, err)
		return
	}
	v, err := s.loadReview(r, x.Session, true)
	if err != nil {
		fail(w, err)
		return
	}
	tx, err := s.member.Begin(r.Context())
	if err != nil {
		fail(w, err)
		return
	}
	defer tx.Rollback(r.Context())
	old, err := operation(r, tx, x, p.Request)
	if err != nil {
		fail(w, err)
		return
	}
	if old != nil {
		write(w, 200, old)
		return
	}
	v, err = scanReview(tx.QueryRow(r.Context(), "SELECT "+reviewColumns+" FROM member.reviews r WHERE r.id=$1 FOR UPDATE OF r", v.ID))
	if err != nil {
		fail(w, err)
		return
	}
	var valid bool
	err = tx.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM member.review_publications WHERE review_id=$1 AND id=$2 AND revision=$3 AND expires_at>now())", v.ID, p.Publication, v.Revision).Scan(&valid)
	if err != nil {
		fail(w, err)
		return
	}
	if !valid || v.State != "draft" {
		fail(w, problem{409, "publication_conflict"})
		return
	}
	err = stageEnvelopes(r, tx, p.Publication, p.Envelopes)
	result := map[string]any{"ok": true}
	if err == nil {
		err = cache(r, tx, x, p.Request, result)
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		fail(w, err)
		return
	}
	write(w, 200, result)
}
